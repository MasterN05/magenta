// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ddk/binding.h>
#include <ddk/device.h>
#include <ddk/driver.h>
#include <ddk/iotxn.h>
#include <ddk/protocol/usb-function.h>
#include <magenta/device/usb-device.h>

#include "ums-hw.h"

 static struct {
    usb_interface_descriptor_t intf;
    usb_endpoint_descriptor_t out_ep;
    usb_endpoint_descriptor_t in_ep;
} descriptors = {
    .intf = {
        .bLength = sizeof(usb_interface_descriptor_t),
        .bDescriptorType = USB_DT_INTERFACE,
//      .bInterfaceNumber set later
        .bAlternateSetting = 0,
        .bNumEndpoints = 2,
        .bInterfaceClass = USB_CLASS_MSC,
        .bInterfaceSubClass = USB_SUBCLASS_MSC_SCSI,
        .bInterfaceProtocol = USB_PROTOCOL_MSC_BULK_ONLY,
        .iInterface = 0,
    },
    .out_ep = {
        .bLength = sizeof(usb_endpoint_descriptor_t),
        .bDescriptorType = USB_DT_ENDPOINT,
//      .bEndpointAddress set later
        .bmAttributes = USB_ENDPOINT_BULK,
        .wMaxPacketSize = htole16(512),
        .bInterval = 0,
    },
    .in_ep = {
        .bLength = sizeof(usb_endpoint_descriptor_t),
        .bDescriptorType = USB_DT_ENDPOINT,
//      .bEndpointAddress set later
        .bmAttributes = USB_ENDPOINT_BULK,
        .wMaxPacketSize = htole16(512),
        .bInterval = 0,
    },
};

typedef struct {
    mx_device_t* mxdev;
    usb_function_protocol_t function;
    iotxn_t* cbw_iotxn;
    iotxn_t* data_iotxn;
    iotxn_t* csw_iotxn;
} usb_ums_t;

static void ums_handle_cbw(usb_ums_t* ums, ums_cbw_t* cbw) {
    if (le32toh(cbw->dCBWSignature) != CBW_SIGNATURE) {
        printf("ums_handle_cbw: bad dCBWSignature 0x%x\n", le32toh(cbw->dCBWSignature));
        return;
    }

    // all SCSI commands have opcode in the same place, so using scsi_command6_t works here.
    scsi_command6_t* command = (scsi_command6_t *)cbw->CBWCB;
    switch (command->opcode) {
    case UMS_INQUIRY:
        ums_handle_inquiry(ums, cbw);
        break; 
    case UMS_TEST_UNIT_READY:
    case UMS_REQUEST_SENSE:
    case UMS_READ_CAPACITY10:
    case UMS_READ_CAPACITY16:
    case UMS_MODE_SENSE6:
    case UMS_READ10:
    case UMS_READ12:
    case UMS_READ16:
    case UMS_WRITE10:
    case UMS_WRITE12:
    case UMS_WRITE16:
    default:
        printf("ums_handle_cbw: unsupported opcode %d\n", command->opcode);
        break;
    }
}

static void ums_cbw_complete(iotxn_t* txn, void* cookie) {
    usb_ums_t* ums = cookie;

    printf("ums_cbw_complete %d %ld\n", txn->status, txn->actual);

    if (txn->status == MX_OK && txn->actual == sizeof(ums_cbw_t)) {
        ums_cbw_t   cbw;
        iotxn_copyfrom(txn, &cbw, sizeof(cbw), 0);
        ums_handle_cbw(ums, &cbw);
    }
}

static void ums_data_complete(iotxn_t* txn, void* cookie) {
    printf("ums_data_complete %d %ld\n", txn->status, txn->actual);
}

static void ums_csw_complete(iotxn_t* txn, void* cookie) {
    printf("ums_csw_complete %d %ld\n", txn->status, txn->actual);

}

static const usb_descriptor_header_t* ums_get_descriptors(void* ctx, size_t* out_length) {
    *out_length = sizeof(descriptors);
    return (const usb_descriptor_header_t *)&descriptors;
}

static mx_status_t ums_control(void* ctx, const usb_setup_t* setup, void* buffer,
                                         size_t length, size_t* out_actual) {
    if (setup->bmRequestType == (USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE) &&
        setup->bRequest == USB_REQ_GET_MAX_LUN && setup->wValue == 0 && setup->wIndex == 0 &&
        setup->wLength >= sizeof(uint8_t)) {
        *((uint8_t *)buffer) = 0;
        *out_actual = sizeof(uint8_t);
        return MX_OK;
    }

    return MX_ERR_NOT_SUPPORTED;
}

usb_function_interface_ops_t device_ops = {
    .get_descriptors = ums_get_descriptors,
    .control = ums_control,
};

static void usb_ums_unbind(void* ctx) {
printf("usb_ums_unbind\n");
    usb_ums_t* ums = ctx;
    device_remove(ums->mxdev);
}

static void usb_ums_release(void* ctx) {
printf("usb_ums_release\n");
    usb_ums_t* ums = ctx;

    if (ums->cbw_iotxn) {
        iotxn_release(ums->cbw_iotxn);
    }
    if (ums->data_iotxn) {
        iotxn_release(ums->data_iotxn);
    }
    if (ums->cbw_iotxn) {
        iotxn_release(ums->csw_iotxn);
    }
    free(ums);
}

static mx_protocol_device_t usb_ums_proto = {
    .version = DEVICE_OPS_VERSION,
    .unbind = usb_ums_unbind,
    .release = usb_ums_release,
};

mx_status_t usb_ums_bind(void* ctx, mx_device_t* parent, void** cookie) {
    printf("usb_ums_bind\n");

    usb_ums_t* ums = calloc(1, sizeof(usb_ums_t));
    if (!ums) {
        return MX_ERR_NO_MEMORY;
    }

    mx_status_t status =device_get_protocol(parent, MX_PROTOCOL_USB_FUNCTION, &ums->function);
    if (status != MX_OK) {
        goto fail;
    }

    status =  iotxn_alloc(&ums->cbw_iotxn, 0, PAGE_SIZE);
    if (status != MX_OK) {
        goto fail;
    }
    status =  iotxn_alloc(&ums->data_iotxn, 0, PAGE_SIZE);
    if (status != MX_OK) {
        goto fail;
    }
    status =  iotxn_alloc(&ums->csw_iotxn, 0, PAGE_SIZE);
    if (status != MX_OK) {
        goto fail;
    }

    ums->cbw_iotxn->length = sizeof(ums_cbw_t);
    ums->csw_iotxn->length = sizeof(ums_csw_t);
    ums->cbw_iotxn->complete_cb = ums_cbw_complete;
    ums->data_iotxn->complete_cb = ums_data_complete;
    ums->csw_iotxn->complete_cb = ums_csw_complete;
    ums->cbw_iotxn->cookie = ums;
    ums->data_iotxn->cookie = ums;
    ums->csw_iotxn->cookie = ums;

    descriptors.intf.bInterfaceNumber = usb_function_get_interface_number(&ums->function);

    status = usb_function_alloc_endpoint(&ums->function, USB_DIR_OUT,
                                                     &descriptors.out_ep.bEndpointAddress);
    if (status != MX_OK) {
        printf("usb_ums_bind: usb_function_alloc_endpoint failed\n");
        goto fail;
    }
    status = usb_function_alloc_endpoint(&ums->function, USB_DIR_IN,
                                                     &descriptors.in_ep.bEndpointAddress);
    if (status != MX_OK) {
        printf("usb_ums_bind: usb_function_alloc_endpoint failed\n");
        goto fail;
    }

    device_add_args_t args = {
        .version = DEVICE_ADD_ARGS_VERSION,
        .name = "usb-ums-function",
        .ctx = ums,
        .ops = &usb_ums_proto,
    };

    status = device_add(parent, &args, &ums->mxdev);
    if (status != MX_OK) {
        printf("usb_device_bind add_device failed %d\n", status);
        goto fail;
    }

printf("queue cbw_iotxn\n");
    usb_function_queue(&ums->function, ums->cbw_iotxn, descriptors.out_ep.bEndpointAddress);

    usb_function_interface_t intf = {
        .ops = &device_ops,
        .ctx = ums,
    };
    usb_function_register(&ums->function, &intf);

    return MX_OK;

fail:
    usb_ums_release(ums);
    return status;
}

static mx_driver_ops_t usb_ums_ops = {
    .version = DRIVER_OPS_VERSION,
    .bind = usb_ums_bind,
};

// clang-format off
MAGENTA_DRIVER_BEGIN(usb_ums, usb_ums_ops, "magenta", "0.1", 4)
    BI_ABORT_IF(NE, BIND_PROTOCOL, MX_PROTOCOL_USB_FUNCTION),
    BI_MATCH_IF(EQ, BIND_USB_CLASS, USB_CLASS_MSC),
    BI_MATCH_IF(EQ, BIND_USB_SUBCLASS, USB_SUBCLASS_MSC_SCSI),
    BI_MATCH_IF(EQ, BIND_USB_PROTOCOL, USB_PROTOCOL_MSC_BULK_ONLY),
MAGENTA_DRIVER_END(usb_ums)
