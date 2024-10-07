/*
 * Copyright (c) 2024 EEUM, Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef CXL_REMOTE_H
#define CXL_REMOTE_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "exec/hwaddr.h"
#include "hw/cxl/opencxl_packet.h"
#include "qemu/typedefs.h"

#define CXL_MAX_IO_TAG 256     // 2^8
#define CXL_MAX_MEM_TAG 65536  // 2^16
#define MAX_PACKET_SIZE 512

// Packet Request Entry for requests
typedef struct
{
    uint8_t packet[MAX_PACKET_SIZE];
    size_t packet_size;
    uint16_t tag;
} PacketRequestEntry;

// Packet Response Entry for responses
typedef struct
{
    uint8_t packet[MAX_PACKET_SIZE];
    size_t packet_size;
    bool requested;
    bool received;

    PacketRequestEntry *request_entry;  // Associated request entry
} PacketResponseEntry;

// Circular Queue for Entries
typedef struct
{
    PacketRequestEntry **entries;
    uint32_t max_size;
    uint32_t head;
    uint32_t tail;
} EntryQueue;

// Unified Request Queue (combining available and submitted entries)
typedef struct
{
    EntryQueue available_queue;  // Queue for available entries
    EntryQueue submitted_queue;  // Queue for submitted entries
    PacketRequestEntry *entries;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} RequestQueue;

// Response Table to track responses and submission status
typedef struct
{
    PacketResponseEntry *entries;  // Array to store response entries
    uint32_t size;
    pthread_mutex_t lock;  // Lock for thread-safe access
    pthread_cond_t cond;   // Condition variable to wait for response
    RequestQueue *request_queue;
} ResponseTable;

// CXL Remote Root Port Structure
typedef struct
{
    RequestQueue io_request_queue;      // Queue for CXL.io request
                                        // and CXL.io DMA response
    RequestQueue io_dma_request_queue;  // Queue for CXL.io DMA request
    ResponseTable io_response_table;    // Response tracking table for IO

    RequestQueue mem_request_queue;    // Queue for CXL.mem request
    ResponseTable mem_response_table;  // Response tracking table for memory

    int32_t socket_fd;
    pthread_mutex_t socket_tx_lock;

    pthread_t rx_thread;
    pthread_t io_tx_thread;
    pthread_t mem_tx_thread;

    QEMUBH *bh;
    AddressSpace *dma_address_space;
} CXLRemoteRootPort;

// Function declarations
bool cxl_remote_rp_init(CXLRemoteRootPort *port, const char *tcp_host,
                        uint32_t tcp_port, uint32_t switch_port);

void cxl_remote_rp_cxl_io_mem_write(CXLRemoteRootPort *port, hwaddr addr,
                                    uint16_t length_dw, uint8_t first_dw_be,
                                    uint8_t last_dw_be, void *buffer);
tlp_cpl_status_t cxl_remote_rp_cxl_io_mem_read(CXLRemoteRootPort *port,
                                               hwaddr addr, uint16_t length_dw,
                                               uint8_t first_dw_be,
                                               uint8_t last_dw_be,
                                               void *buffer);

void cxl_remote_rp_cxl_io_mmio_write(CXLRemoteRootPort *port, hwaddr addr,
                                     uint64_t data, uint8_t size);
uint64_t cxl_remote_rp_cxl_io_mmio_read(CXLRemoteRootPort *port, hwaddr addr,
                                        int8_t size);

tlp_cpl_status_t cxl_remote_rp_cxl_io_cfg_read(CXLRemoteRootPort *port,
                                               uint16_t bdf, uint16_t offset,
                                               uint32_t *data, uint8_t size,
                                               bool type0);

tlp_cpl_status_t cxl_remote_rp_cxl_io_cfg_write(CXLRemoteRootPort *port,
                                                uint16_t bdf, uint16_t offset,
                                                uint32_t data, uint8_t size,
                                                bool type0);

#endif  // CXL_REMOTE_H
