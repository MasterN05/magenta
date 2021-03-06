// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <hypervisor/block.h>
#include <hypervisor/vcpu.h>
#include <magenta/syscalls.h>
#include <magenta/syscalls/hypervisor.h>
#include <virtio/block.h>
#include <virtio/virtio.h>
#include <virtio/virtio_ring.h>

#define PCI_INTERRUPT_VIRTIO_BLOCK  33u
#define PCI_ALIGN(n)                ((((uintptr_t)n) + 4095) & ~4095)

typedef mx_status_t (* virtio_req_fn_t)(void* ctx, void* req, void* addr, uint32_t len);

mx_status_t handle_virtio_block_read(guest_state_t* guest_state, uint16_t port,
                                     mx_vcpu_io_t* vcpu_io) {
    virtio_queue_t* queue = &guest_state->block_queue;
    switch (port) {
    case VIRTIO_PCI_DEVICE_FEATURES:
        vcpu_io->access_size = 4;
        vcpu_io->u32 = 0;
        return MX_OK;
    case VIRTIO_PCI_QUEUE_PFN:
        vcpu_io->access_size = 4;
        vcpu_io->u32 = queue->pfn;
        return MX_OK;
    case VIRTIO_PCI_QUEUE_SIZE:
        vcpu_io->access_size = 2;
        vcpu_io->u16 = queue->size;
        return MX_OK;
    case VIRTIO_PCI_DEVICE_STATUS:
        vcpu_io->access_size = 1;
        vcpu_io->u8 = guest_state->block_status;
        return MX_OK;
    case VIRTIO_PCI_ISR_STATUS:
        vcpu_io->access_size = 1;
        vcpu_io->u8 = 1;
        return MX_OK;
    case VIRTIO_PCI_CONFIG_OFFSET_NOMSI ...
         VIRTIO_PCI_CONFIG_OFFSET_NOMSI + sizeof(virtio_blk_config_t) - 1: {
        virtio_blk_config_t config;
        memset(&config, 0, sizeof(virtio_blk_config_t));
        config.capacity = guest_state->block_size / SECTOR_SIZE;
        config.blk_size = PAGE_SIZE;

        uint8_t* buf = (uint8_t*)&config;
        vcpu_io->access_size = 1;
        vcpu_io->u8 = buf[port - VIRTIO_PCI_CONFIG_OFFSET_NOMSI];
        return MX_OK;
    }}

    fprintf(stderr, "Unhandled block read %#x\n", port);
    return MX_ERR_NOT_SUPPORTED;
}

mx_status_t handle_virtio_block_write(vcpu_context_t* vcpu_context, uint16_t port,
                                      const mx_guest_io_t* io) {
    void* mem_addr = vcpu_context->guest_state->mem_addr;
    size_t mem_size = vcpu_context->guest_state->mem_size;
    int block_fd = vcpu_context->guest_state->block_fd;
    virtio_queue_t* queue = &vcpu_context->guest_state->block_queue;
    switch (port) {
    case VIRTIO_PCI_DRIVER_FEATURES:
        if (io->access_size != 4)
            return MX_ERR_IO_DATA_INTEGRITY;
        // Currently no feature bits are implemented.
        if (io->u32 != 0)
            return MX_ERR_INVALID_ARGS;
        return MX_OK;
    case VIRTIO_PCI_DEVICE_STATUS:
        if (io->access_size != 1)
            return MX_ERR_IO_DATA_INTEGRITY;
        vcpu_context->guest_state->block_status = io->u8;
        return MX_OK;
    case VIRTIO_PCI_QUEUE_PFN: {
        if (io->access_size != 4)
            return MX_ERR_IO_DATA_INTEGRITY;
        queue->pfn = io->u32;
        queue->desc = mem_addr + (queue->pfn * PAGE_SIZE);
        queue->avail = (void*)&queue->desc[queue->size];
        queue->used_event = (void*)&queue->avail->ring[queue->size];
        queue->used = (void*)PCI_ALIGN(queue->used_event + sizeof(uint16_t));
        queue->avail_event = (void*)&queue->used->ring[queue->size];
        volatile const void* end = queue->avail_event + 1;
        if (end < (void*)queue->desc || end > mem_addr + mem_size) {
            fprintf(stderr, "Ring is outside of guest memory\n");
            memset(queue, 0, sizeof(virtio_queue_t));
            return MX_ERR_OUT_OF_RANGE;
        }
        return MX_OK;
    }
    case VIRTIO_PCI_QUEUE_SIZE:
        if (io->access_size != 2)
            return MX_ERR_IO_DATA_INTEGRITY;
        queue->size = io->u16;
        return MX_OK;
    case VIRTIO_PCI_QUEUE_SELECT:
        if (io->access_size != 2)
            return MX_ERR_IO_DATA_INTEGRITY;
        if (io->u16 != 0) {
            fprintf(stderr, "Only one queue per device is supported\n");
            return MX_ERR_NOT_SUPPORTED;
        }
        return MX_OK;
    case VIRTIO_PCI_QUEUE_NOTIFY: {
        if (io->access_size != 2)
            return MX_ERR_IO_DATA_INTEGRITY;
        if (io->u16 != 0) {
            fprintf(stderr, "Only one queue per device is supported\n");
            return MX_ERR_NOT_SUPPORTED;
        }
        mx_status_t status;
        if (block_fd < 0) {
            status = null_block_device(queue, mem_addr, mem_size);
        } else {
            status = file_block_device(queue, mem_addr, mem_size, block_fd);
        }
        if (status != MX_OK) {
            fprintf(stderr, "Block device operation failed %d\n", status);
            return status;
        }
        uint32_t interrupt = irq_redirect(&vcpu_context->guest_state->io_apic_state,
                                          PCI_INTERRUPT_VIRTIO_BLOCK);
        return mx_vcpu_interrupt(vcpu_context->vcpu, interrupt);
    }}

    fprintf(stderr, "Unhandled block write %#x\n", port);
    return MX_ERR_NOT_SUPPORTED;
}

mx_status_t null_req(void* ctx, void* req, void* addr, uint32_t len) {
    virtio_blk_req_t* blk_req = req;
    switch (blk_req->type) {
    case VIRTIO_BLK_T_IN:
        memset(addr, 0, len);
        /* fallthrough */
    case VIRTIO_BLK_T_OUT:
        return MX_OK;
    case VIRTIO_BLK_T_FLUSH:
        // See note in file_req.
        if (blk_req->sector != 0)
            return MX_ERR_IO_DATA_INTEGRITY;
        return MX_OK;
    }
    return MX_ERR_INVALID_ARGS;
}

mx_status_t null_block_device(virtio_queue_t* queue, void* mem_addr, size_t mem_size) {
    return handle_virtio_queue(queue, mem_addr, mem_size, sizeof(virtio_blk_req_t), null_req, NULL);
}

typedef struct file_state {
    int fd;
    off_t off;
} file_state_t;

mx_status_t file_req(void* ctx, void* req, void* addr, uint32_t len) {
    file_state_t* state = ctx;
    virtio_blk_req_t* blk_req = req;

    off_t ret;
    if (blk_req->type != VIRTIO_BLK_T_FLUSH) {
        off_t off = blk_req->sector * SECTOR_SIZE + state->off;
        state->off += len;
        ret = lseek(state->fd, off, SEEK_SET);
        if (ret < 0)
            return MX_ERR_IO;
    }

    switch (blk_req->type) {
    case VIRTIO_BLK_T_IN:
        ret = read(state->fd, addr, len);
        break;
    case VIRTIO_BLK_T_OUT:
        ret = write(state->fd, addr, len);
        break;
    case VIRTIO_BLK_T_FLUSH:
        // From VIRTIO Version 1.0: A driver MUST set sector to 0 for a
        // VIRTIO_BLK_T_FLUSH request. A driver SHOULD NOT include any data in a
        // VIRTIO_BLK_T_FLUSH request.
        if (blk_req->sector != 0)
            return MX_ERR_IO_DATA_INTEGRITY;
        len = 0;
        ret = fsync(state->fd);
        break;
    default:
        return MX_ERR_INVALID_ARGS;
    }
    return ret != len ? MX_ERR_IO : MX_OK;
}

mx_status_t file_block_device(virtio_queue_t* queue, void* mem_addr, size_t mem_size, int fd) {
    file_state_t state = { fd, 0 };
    return handle_virtio_queue(queue, mem_addr, mem_size, sizeof(virtio_blk_req_t), file_req,
                               &state);
}
