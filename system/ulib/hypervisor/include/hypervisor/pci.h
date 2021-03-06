// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <magenta/types.h>
#include <sys/types.h>

#define PCI_DEVICE_ROOT_COMPLEX                 0u
#define PCI_DEVICE_VIRTIO_BLOCK                 1u
#define PCI_DEVICE_INVALID                      UINT16_MAX
#define PCI_MAX_DEVICES                         2u
#define PCI_MAX_BARS                            1u

// PCI configuration constants.
#define PCI_BAR_IO_TYPE_MASK                    0x0001
#define PCI_BAR_IO_TYPE_PIO                     0x0001
#define PCI_BAR_IO_TYPE_MMIO                    0x0000
#define PCI_VENDOR_ID_VIRTIO                    0x1af4
#define PCI_VENDOR_ID_INTEL                     0x8086
#define PCI_DEVICE_ID_VIRTIO_BLOCK_LEGACY       0x1001
#define PCI_DEVICE_ID_INTEL_Q35                 0x29c0
#define PCI_CLASS_BRIDGE_HOST                   0x0600
#define PCI_CLASS_MASS_STORAGE                  0x0100

// PCI type 1 address manipulation.
#define PCI_TYPE1_BUS(addr)                     (((addr) >> 16) & 0xff)
#define PCI_TYPE1_DEVICE(addr)                  (((addr) >> 11) & 0x1f)
#define PCI_TYPE1_FUNCTION(addr)                (((addr) >> 8) & 0x7)
#define PCI_TYPE1_REGISTER_MASK                 0xfc
#define PCI_TYPE1_REGISTER(addr)                ((addr) & PCI_TYPE1_REGISTER_MASK)

#define PCI_TYPE1_ADDR(bus, device, function, reg) \
    (0x80000000 | ((bus) << 16) | ((device) << 11) | ((function) << 8) \
     | ((reg) & PCI_TYPE1_REGISTER_MASK))

// PCI ECAM address manipulation.
#define PCI_ECAM_BUS(addr)                     (((addr) >> 20) & 0xff)
#define PCI_ECAM_DEVICE(addr)                  (((addr) >> 15) & 0x1f)
#define PCI_ECAM_FUNCTION(addr)                (((addr) >> 12) & 0x7)
#define PCI_ECAM_REGISTER(addr)                ((addr) & 0xfff)

/* The size of an ECAM region depends on values in the MCFG ACPI table. For
 * each ECAM region there is a defined physical base address as well as a bus
 * start/end value for that region.
 *
 * When creating an ECAM address for a PCI configuration register, the bus
 * value must be relative to the starting bus number for that ECAM region.
 */
#define PCI_ECAM_SIZE(start_bus, end_bus) \
    (((end_bus) - (start_bus) + 1) << 20)

#define PCI_ECAM_ADDR(base, bus, device, function, reg) \
    ((base) | ((bus) << 20) | ((device) << 15) | ((function) << 12) | (reg))


/* Stores the state of PCI devices across VM exists. */
typedef struct pci_device_state {
    // Command register.
    uint16_t command;
    // Base address registers.
    uint32_t bar[PCI_MAX_BARS];
} pci_device_state_t;


/* Read a value from PCI config space. */
mx_status_t pci_config_read(pci_device_state_t* pci_device_state,
                            uint8_t bus, uint8_t device,
                            uint8_t func, uint16_t reg,
                            size_t len, uint32_t* value);

/* Write a value to PCI config space. */
mx_status_t pci_config_write(pci_device_state_t* pci_device_state,
                             uint8_t bus, uint8_t device,
                             uint8_t func, uint16_t reg,
                             size_t len, uint32_t value);

/* Return the device number for the PCI device that has a BAR mapped to the
 * given address with the specified IO type. Returns PCI_DEVICE_INVALID if no
 * mapping exists or IO is disabled for the mapping.
 */
uint16_t pci_device(pci_device_state_t* pci_device_states, uint8_t io_type,
                    uint32_t address, uint32_t* offset);

/* Returns the bar size for the device. The device is the same value used to
 * index the device in PCI config space.
 */
uint16_t pci_bar_size(uint8_t device);
