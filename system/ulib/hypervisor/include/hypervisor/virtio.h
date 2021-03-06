// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <magenta/types.h>

struct vring_desc;
struct vring_avail;
struct vring_used;

enum {
    VIRTIO_STATUS_OK            = 0,
    VIRTIO_STATUS_ERROR         = 1,
    VIRTIO_STATUS_UNSUPPORTED   = 2,
};

/* Stores the Virtio queue based on the ring provided by the guest.
 *
 * NOTE(abdulla): This structure points to guest-controlled memory.
 */
typedef struct virtio_queue {
    // Queue PFN used to locate this queue in guest physical address space.
    uint32_t pfn;
    uint32_t size;
    uint16_t index;
    volatile struct vring_desc* desc;   // guest-controlled

    volatile struct vring_avail* avail; // guest-controlled
    volatile uint16_t* used_event;      // guest-controlled

    volatile struct vring_used* used;   // guest-controlled
    volatile uint16_t* avail_event;     // guest-controlled
} virtio_queue_t;

typedef mx_status_t (* virtio_req_fn_t)(void* ctx, void* req, void* addr, uint32_t len);

/* Handles a Virtio queue, calling req_fn to process individual requests.
 */
mx_status_t handle_virtio_queue(virtio_queue_t* queue, void* mem_addr, size_t mem_size,
                                uint32_t hdr_size, virtio_req_fn_t req_fn, void* ctx);
