// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fs/mapped-vmo.h>
#include <magenta/process.h>
#include <magenta/syscalls.h>
#include <mxtl/alloc_checker.h>
#include <mxtl/unique_ptr.h>

mx_status_t MappedVmo::Create(size_t size, const char* name, mxtl::unique_ptr<MappedVmo>* out) {
    mx_handle_t vmo;
    uintptr_t addr;
    mx_status_t status;
    if ((status = mx_vmo_create(size, 0, &vmo)) != MX_OK) {
        return status;
    } else if ((status = mx_vmar_map(mx_vmar_root_self(), 0, vmo, 0,
                                     size, MX_VM_FLAG_PERM_READ | MX_VM_FLAG_PERM_WRITE,
                                     &addr)) != MX_OK) {
        mx_handle_close(vmo);
        return status;
    }

    mx_object_set_property(vmo, MX_PROP_NAME, name, strlen(name));

    mxtl::AllocChecker ac;
    mxtl::unique_ptr<MappedVmo> mvmo(new (&ac) MappedVmo(vmo, addr, size));
    if (!ac.check()) {
        mx_vmar_unmap(mx_vmar_root_self(), addr, size);
        mx_handle_close(vmo);
        return MX_ERR_NO_MEMORY;
    }

    *out = mxtl::move(mvmo);
    return MX_OK;
}

mx_handle_t MappedVmo::GetVmo(void) const { return vmo_; }
void* MappedVmo::GetData(void) const { return (void*) addr_; }

MappedVmo::MappedVmo(mx_handle_t vmo, uintptr_t addr, size_t len) :
    vmo_(vmo), addr_(addr), len_(len) {}

MappedVmo::~MappedVmo() {
    mx_vmar_unmap(mx_vmar_root_self(), addr_, len_);
    mx_handle_close(vmo_);
}
