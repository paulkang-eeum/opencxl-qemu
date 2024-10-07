/*
 * Copyright (c) 2024 EEUM, Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef OPENCXL_SOCKET_H
#define OPENCXL_SOCKET_H

#include <stdbool.h>
#include <stdint.h>

#include "opencxl_packet.h"
#include "qemu/osdep.h"

// Sideband
bool send_sideband_connection_request(int socket_fd, uint32_t port);
bool wait_for_base_sideband_packet(int socket_fd, base_sideband_packet_t * sideband);

// CXL.mem

// CXL.io
bool wait_for_tlp_header_dw0(int socket_fd, cxl_io_header_t *tlp_dw0);
bool wait_for_tlp_header_without_dw0(int socket_fd, opencxl_tlp_header_t *tlp_header);

// Socket

int32_t create_socket_client(const char *host, uint32_t port);
bool wait_for_system_header(int socket_fd,
                            system_header_packet_t *system_header);
bool wait_for_payload(int socket_fd, uint8_t *buffer, size_t buffer_size,
                      size_t payload_size);
bool send_payload(int socket_fd, uint8_t *buffer, size_t buffer_size);

#endif  // OPENCXL_SOCKET_H
