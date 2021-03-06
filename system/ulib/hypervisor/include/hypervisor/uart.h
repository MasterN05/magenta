// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <magenta/types.h>

typedef struct guest_state guest_state_t;
typedef struct mx_guest_io mx_guest_io_t;
typedef struct mx_vcpu_io mx_vcpu_io_t;

/* Stores the UART state. */
typedef struct uart_state {
    // State of the UART interrupt enable register.
    uint8_t interrupt_enable;
    // State of the UART interrupt id register.
    uint8_t interrupt_id;
    // State of the UART line control register.
    uint8_t line_control;
} uart_state_t;

/* Initialize the UART state. */
mx_status_t uart_init(uart_state_t* uart_state);

/* Handles reads to the UART. */
mx_status_t uart_read(uart_state_t* uart_state, uint16_t port, mx_vcpu_io_t* vcpu_io);

/* Handles writes to the UART. */
mx_status_t uart_write(mx_guest_io_t* io, guest_state_t* guest_state, mx_handle_t vcpu);
