/*
 * Copyright (c) 2024 EEUM, Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef CXL_REMOTE_H
#define CXL_REMOTE_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "exec/hwaddr.h"

#define CXL_MAX_IO_TAG 1024     // 2^10
#define CXL_MAX_MEM_TAG 65536   // 2^16
#define MAX_PACKET_SIZE 512

// Packet Request Entry for requests
typedef struct {
    uint8_t packet[MAX_PACKET_SIZE];
    size_t packet_size;
    uint16_t tag;
} PacketRequestEntry;

// Packet Response Entry for responses
typedef struct {
    uint8_t packet[MAX_PACKET_SIZE];
    size_t packet_size;
    bool requested;                      // Whether the request for this tag has been submitted
    bool received;                       // Whether the response has been received
    PacketRequestEntry* request_entry;   // Pointer to the associated request entry
} PacketResponseEntry;

// Circular Queue for Entries
typedef struct {
    PacketRequestEntry** entries;  // Queue for entries (either available or submitted)
    uint32_t max_size;
    uint32_t head;
    uint32_t tail;
} EntryQueue;

// Unified Request Queue (combining available and submitted entries)
typedef struct {
    EntryQueue available_queue;   // Queue for available entries
    EntryQueue submitted_queue;   // Queue for submitted entries
    PacketRequestEntry* entries;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} RequestQueue;

// Response Table to track responses and submission status
typedef struct {
    PacketResponseEntry* entries;         // Array to store response entries
    uint32_t size;
    pthread_mutex_t lock;                 // Lock for thread-safe access
    pthread_cond_t cond;                  // Condition variable to wait for response
    RequestQueue *request_queue;
} ResponseTable;

// CXL Remote Root Port Structure
typedef struct {
    RequestQueue io_request_queue;  // Unified request queue for IO
    ResponseTable io_response_table; // Response tracking table for IO

    RequestQueue mem_request_queue; // Unified request queue for memory
    ResponseTable mem_response_table; // Response tracking table for memory

    int32_t socket_fd;
    pthread_mutex_t socket_tx_lock;
} CXLRemoteRootPort;

// Function declarations
void cxl_remote_init(CXLRemoteRootPort* port);

PacketRequestEntry* get_request_entry(RequestQueue* queue);  // Get an available entry
void enqueue_request(RequestQueue* queue, PacketRequestEntry* entry);  // Submit the request
PacketRequestEntry* dequeue_request(RequestQueue* queue);  // Dequeue a processed request
void return_request_entry(RequestQueue* queue, PacketRequestEntry* entry);  // Return a request entry to the back of available queue

void mark_request_submitted(ResponseTable* table, uint16_t tag, PacketRequestEntry* entry);  // Mark request as submitted
PacketResponseEntry* get_entry_by_tag(ResponseTable* table, uint16_t tag);  // Get entry by tag
void clear_request_submitted(ResponseTable* table, uint16_t tag);  // Clear the request_submitted flag

void mark_packet_received(ResponseTable* table, uint16_t tag);  // Mark a packet as received
PacketResponseEntry* wait_for_received_packet(ResponseTable* table, uint16_t tag);  // Wait for a received packet

void cxl_remote_rp_cxl_io_mem_write(CXLRemoteRootPort *port, hwaddr addr, uint64_t val, uint8_t size);
uint64_t cxl_remote_rp_cxl_io_mem_read(CXLRemoteRootPort *port, hwaddr addr, uint8_t size);

void cxl_remote_rp_cxl_io_cfg_write(CXLRemoteRootPort *port, uint16_t bdf, uint32_t offset, uint32_t val, int size, bool type0);
uint32_t cxl_remote_rp_cxl_io_cfg_read(CXLRemoteRootPort *port, uint16_t bdf, uint32_t offset, int size, bool type0);

#endif // CXL_REMOTE_H
