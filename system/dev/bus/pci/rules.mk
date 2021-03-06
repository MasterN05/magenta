# Copyright 2017 The Fuchsia Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_TYPE := driver

MODULE_NAME := bus-pci

ifeq ($(ENABLE_ACPI_BUS),true)
    MODULE_DEFINES += ACPI_BUS_DRV=1
endif

MODULE_SRCS := $(LOCAL_DIR)/kpci.c

MODULE_STATIC_LIBS := system/ulib/ddk

MODULE_LIBS := system/ulib/driver system/ulib/magenta system/ulib/c

include make/module.mk
