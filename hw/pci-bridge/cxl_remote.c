// clang-format off

// Due to implicit dependencies from QEMU header files, we
// don't want include reordering from clang format.

#include <assert.h>
#include <byteswap.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include "hw/cxl/cxl_remote.h"
#include "exec/memattrs.h"
#include "hw/cxl/opencxl_socket.h"
#include "hw/cxl/opencxl_packet.h"
#include "qemu/main-loop.h"
#include "sysemu/dma.h"
#include "trace.h"
#include "trace/trace-hw_pci_bridge.h"

#include <glib.h>

// clang-format on

/*

    Queue Management API

*/

// Helper functions for EntryQueue
static void init_entry_queue(EntryQueue *queue, uint32_t size)
{
    const uint32_t queue_size = size + 1;
    queue->entries = (PacketRequestEntry **)g_malloc0(
        queue_size * sizeof(PacketRequestEntry *));  // Allocate entries
    queue->max_size = queue_size;
    queue->head = 0;
    queue->tail = 0;
}

// Check if the queue is full
static bool is_queue_full(EntryQueue *queue)
{
    return (queue->tail + 1) % queue->max_size == queue->head;
}

// Check if the queue is empty
static bool is_queue_empty(EntryQueue *queue)
{
    return queue->head == queue->tail;
}

static void inc_tail(EntryQueue *queue)
{
    assert(!is_queue_full(queue));
    queue->tail = (queue->tail + 1) % queue->max_size;
}

static void inc_head(EntryQueue *queue)
{
    assert(!is_queue_empty(queue));
    queue->head = (queue->head + 1) % queue->max_size;
}

static void push_item(EntryQueue *queue, PacketRequestEntry *entry)
{
    assert(!is_queue_full(queue));
    const uint32_t tail = queue->tail;
    queue->entries[tail] = entry;
    inc_tail(queue);
}

static PacketRequestEntry *pop_item(EntryQueue *queue)
{
    assert(!is_queue_empty(queue));
    const uint32_t head = queue->head;
    PacketRequestEntry *entry = queue->entries[head];
    inc_head(queue);
    return entry;
}

// Initialize the RequestQueue
static void init_request_queue(RequestQueue *queue, uint32_t size)
{
    queue->entries =
        (PacketRequestEntry *)g_malloc0(size * sizeof(PacketRequestEntry));

    // Initialize the available queue
    init_entry_queue(&queue->available_queue, size);

    // Initialize the submitted queue
    init_entry_queue(&queue->submitted_queue, size);

    // Fill available queue
    for (uint32_t i = 0; i < size; i++) {
        queue->entries[i].tag = i;
        push_item(&queue->available_queue, &queue->entries[i]);
    }

    // Initialize the lock and condition variable for thread-safe access
    pthread_mutex_init(&queue->lock, NULL);
    pthread_cond_init(&queue->cond, NULL);
}

/*

    Response Table Management API

*/

// Initialize the ResponseTable
static void init_response_table(ResponseTable *table, uint32_t size,
                                RequestQueue *request_queue)
{
    table->entries =
        (PacketResponseEntry *)g_malloc0(size * sizeof(PacketResponseEntry));
    table->size = size;
    table->request_queue = request_queue;
    pthread_mutex_init(&table->lock, NULL);
    pthread_cond_init(&table->cond, NULL);
}

/*

    Request & Response Management API

*/

// Get an available entry from the available queue
static PacketRequestEntry *get_request_entry(RequestQueue *queue)
{
    pthread_mutex_lock(&queue->lock);
    while (is_queue_empty(&queue->available_queue)) {
        pthread_cond_wait(&queue->cond, &queue->lock);
    }

    // Retrieve the next available entry
    PacketRequestEntry *entry = pop_item(&queue->available_queue);

    pthread_mutex_unlock(&queue->lock);
    return entry;
}

// Return a request entry to the back of the available queue
static void return_request_entry(RequestQueue *queue, PacketRequestEntry *entry)
{
    pthread_mutex_lock(&queue->lock);

    // Add the entry back to the available queue
    push_item(&queue->available_queue, entry);

    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->lock);
}

// Enqueue the request entry into the submitted queue after modification
static void enqueue_request(RequestQueue *queue, PacketRequestEntry *entry)
{
    pthread_mutex_lock(&queue->lock);

    // Check if the submitted queue is full
    while (is_queue_full(&queue->submitted_queue)) {
        pthread_cond_wait(&queue->cond, &queue->lock);
    }

    push_item(&queue->submitted_queue, entry);

    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->lock);
}

// Dequeue the request entry from the submitted queue and put it back into the
// available queue
static PacketRequestEntry *dequeue_request(RequestQueue *queue)
{
    pthread_mutex_lock(&queue->lock);

    // Check if the submitted queue is empty
    while (is_queue_empty(&queue->submitted_queue)) {
        pthread_cond_wait(&queue->cond, &queue->lock);
    }

    PacketRequestEntry *entry = pop_item(&queue->submitted_queue);

    pthread_mutex_unlock(&queue->lock);
    return entry;
}

static PacketRequestEntry *dequeue_request_non_block(RequestQueue *queue)
{
    pthread_mutex_lock(&queue->lock);

    // Check if the submitted queue is empty
    if (is_queue_empty(&queue->submitted_queue)) {
        pthread_mutex_unlock(&queue->lock);
        return NULL;
    }

    PacketRequestEntry *entry = pop_item(&queue->submitted_queue);

    pthread_mutex_unlock(&queue->lock);
    return entry;
}

// Mark a request as submitted in the ResponseTable
static void mark_request_submitted(ResponseTable *table, uint16_t tag,
                                   PacketRequestEntry *entry)
{
    assert(tag < table->size);  // Ensure the tag is within bounds

    pthread_mutex_lock(&table->lock);

    assert(!table->entries[tag].requested);
    assert(!table->entries[tag].request_entry);

    table->entries[tag].requested = true;  // Mark the request as submitted
    table->entries[tag].request_entry =
        entry;  // Save the pointer to the request entry

    pthread_mutex_unlock(&table->lock);
}

// Get the response entry based on a tag, ensuring the request was submitted
static PacketResponseEntry *get_entry_by_tag(ResponseTable *table, uint16_t tag)
{
    assert(tag < table->size);  // Ensure the tag is within bounds

    pthread_mutex_lock(&table->lock);

    // Ensure that a request was submitted for the given tag
    assert(table->entries[tag].requested);

    PacketResponseEntry *entry = &table->entries[tag];  // Retrieve the entry

    pthread_mutex_unlock(&table->lock);
    return entry;
}

// Wait for a received packet
static PacketResponseEntry *wait_for_received_packet(ResponseTable *table,
                                                     uint16_t tag)
{
    assert(tag < table->size);  // Ensure the tag is within bounds

    pthread_mutex_lock(&table->lock);

    assert(table->entries[tag].requested);
    assert(table->entries[tag].request_entry);

    // Wait until the packet has been received
    while (!table->entries[tag].received) {
        pthread_cond_wait(&table->cond, &table->lock);
    }

    PacketResponseEntry *entry = &table->entries[tag];
    pthread_mutex_unlock(&table->lock);
    return entry;
}

// Mark a packet as received
static void mark_packet_received(ResponseTable *table, uint16_t tag)
{
    assert(tag < table->size);  // Ensure the tag is within bounds

    pthread_mutex_lock(&table->lock);

    // Mark the response as received
    assert(table->entries[tag].requested);
    assert(table->entries[tag].request_entry);

    table->entries[tag].received = true;

    // Notify any threads waiting for this response
    pthread_cond_signal(&table->cond);
    pthread_mutex_unlock(&table->lock);
}

// Clear the request_submitted flag and clear the request entry pointer
static void clear_request_submitted(ResponseTable *table, uint16_t tag)
{
    assert(tag < table->size);  // Ensure the tag is within bounds

    pthread_mutex_lock(&table->lock);

    assert(table->entries[tag].requested);
    assert(table->entries[tag].request_entry);

    table->entries[tag].requested = false;

    if (table->entries[tag].request_entry) {
        return_request_entry(table->request_queue,
                             table->entries[tag].request_entry);
        table->entries[tag].request_entry = NULL;
    }
    table->entries[tag].received = false;
    table->entries[tag].packet_size = 0;

    pthread_mutex_unlock(&table->lock);
}

/*

    Socket API

*/

static bool transmit_socket_payload(CXLRemoteRootPort *port,
                                    PacketRequestEntry *entry)
{
    bool successful = false;

    pthread_mutex_lock(&port->socket_tx_lock);

    successful =
        send_payload(port->socket_fd, entry->packet, entry->packet_size);

    pthread_mutex_unlock(&port->socket_tx_lock);

    return successful;
}

static bool init_socket_client(CXLRemoteRootPort *remote_rp,
                               const char *tcp_host, uint32_t tcp_port,
                               uint32_t switch_port)
{
    remote_rp->socket_fd = create_socket_client(tcp_host, tcp_port);
    if (remote_rp->socket_fd < 0) {
        trace_cxl_root_error_msg("Failed to initialize TCP socket");
        return false;
    }
    trace_cxl_root_debug_message("Successfully created TCP socket client");

    if (!send_sideband_connection_request(remote_rp->socket_fd, switch_port)) {
        trace_cxl_root_error_msg("Failed to send connection request");
        return false;
    }
    trace_cxl_root_debug_message(
        "Successfully sent OpenCXL connection reqeust");

    base_sideband_packet_t packet = {};
    if (!wait_for_base_sideband_packet(remote_rp->socket_fd, &packet)) {
        trace_cxl_root_error_msg("Failed to get connection response");
        return false;
    }

    const uint8_t sideband_type = packet.sideband_header.type;
    if (sideband_type != SIDEBAND_CONNECTION_ACCEPT) {
        trace_cxl_root_error_msg("Connection request was not accepted");
        return false;
    }
    trace_cxl_root_error_msg("Successfully connected to switch");

    return true;
}

/*

    Command & Response Processors

*/

static void process_io_outgoing(CXLRemoteRootPort *port)
{
    trace_cxl_root_debug_message("Waiting for a new CXL.io request");
    PacketRequestEntry *entry = dequeue_request(&port->io_request_queue);
    assert(entry);

    trace_cxl_root_debug_message("Received a new CXL.io request");
    opencxl_tlp_header_t *tlp_header = (opencxl_tlp_header_t *)entry;
    assert(tlp_header->system_header.payload_type == CXL_IO);
    const uint8_t header_size = parse_openxcl_tlp_header_size(tlp_header);
    const uint16_t data_length =
        parse_opencxl_tlp_data_payload_length(tlp_header);
    assert(header_size + data_length ==
           tlp_header->system_header.payload_length);

    print_io_packet(tlp_header, true);

    entry->packet_size = tlp_header->system_header.payload_length;
    if (!transmit_socket_payload(port, entry)) {
        trace_cxl_root_error_msg("Failed to send CXL.io request");
        assert(0);
    }

    if (tlp_header->dw0.fmt_type == CPL || tlp_header->dw0.fmt_type == CPLD) {
        return_request_entry(&port->io_request_queue, entry);
    } else if (!parse_opencxl_tlp_response_expected(tlp_header)) {
        return_request_entry(&port->io_request_queue, entry);
    }

    trace_cxl_root_debug_message("Successfully processed a CXL.io request");
}

static void process_mem_req(CXLRemoteRootPort *port)
{
    trace_cxl_root_debug_message("Waiting for a new CXL.mem request");
    PacketRequestEntry *entry = dequeue_request(&port->mem_request_queue);
    assert(entry);

    // TODO: Check payload size
    trace_cxl_root_debug_message("Received a new CXL.mem request");
    opencxl_tlp_header_t *tlp_header = (opencxl_tlp_header_t *)entry;
    assert(tlp_header->system_header.payload_type == CXL_MEM);

    mark_request_submitted(&port->mem_response_table, entry->tag, entry);

    entry->packet_size = tlp_header->system_header.payload_length;
    if (!transmit_socket_payload(port, entry)) {
        trace_cxl_root_error_msg("Failed to send CXL.mem request");
        assert(0);
    }

    trace_cxl_root_debug_message("Successfully processed a CXL.mem request");
}

static void process_io_resp(CXLRemoteRootPort *port,
                            opencxl_tlp_header_t *tlp_header,
                            uint16_t bytes_read)
{
    assert(tlp_header->system_header.payload_type == CXL_IO);
    assert(tlp_header->dw0.fmt_type == CPL || tlp_header->dw0.fmt_type == CPLD);

    uint16_t remaining = tlp_header->system_header.payload_length - bytes_read;
    const uint8_t opencxl_tlp_header_size =
        parse_openxcl_tlp_header_size(tlp_header);

    // Read tag
    uint16_t tag = parse_opencxl_tlp_header_tag(tlp_header);

    // Get received entry using tag
    // TODO: Consider the case that MWR returning CPL with an error
    PacketResponseEntry *entry =
        get_entry_by_tag(&port->io_response_table, tag);

    // Copy CPL Header
    memcpy((void *)&entry->packet[0], (void *)(tlp_header),
           opencxl_tlp_header_size);
    entry->packet_size = opencxl_tlp_header_size;

    // Move TLP header pointer
    tlp_header = (opencxl_tlp_header_t *)entry->packet;

    // Read TLP data
    if (tlp_header->dw0.fmt_type == CPLD) {
        trace_cxl_root_debug_message(
            "Waiting for data payload of CXL.io packet from TCP socket");
        const uint16_t data_length =
            parse_opencxl_tlp_data_payload_length(tlp_header);
        void *data_buffer = parse_opencxl_tlp_data_pointer(tlp_header);
        assert(remaining == data_length);
        assert(MAX_PACKET_BUFFER_SIZE - opencxl_tlp_header_size >= remaining);
        assert(wait_for_payload(port->socket_fd, (uint8_t *)data_buffer,
                                data_length, data_length));
        remaining -= data_length;
        entry->packet_size += data_length;
        trace_cxl_root_debug_message(
            "Received data payload of CXL.io packet from TCP socket");
    }

    print_io_packet(tlp_header, false);

    assert(entry->packet_size == tlp_header->system_header.payload_length);
    assert(remaining == 0);

    char msg[100];
    sprintf(msg, "Entire CXL.io packet for tag %d is received", tag);
    trace_cxl_root_debug_message(msg);

    mark_packet_received(&port->io_response_table, tag);
}

static void process_io_dma_req(CXLRemoteRootPort *port,
                               opencxl_tlp_header_t *tlp_header,
                               uint16_t bytes_read)
{
    assert(tlp_header->system_header.payload_type == CXL_IO);
    assert(tlp_header->dw0.fmt_type == MRD_64B ||
           tlp_header->dw0.fmt_type == MWR_64B ||
           tlp_header->dw0.fmt_type == MRD_32B ||
           tlp_header->dw0.fmt_type == MWR_32B);

    uint16_t remaining = tlp_header->system_header.payload_length - bytes_read;
    const uint8_t opencxl_tlp_header_size =
        parse_openxcl_tlp_header_size(tlp_header);

    // Read tag
    uint16_t tag = parse_opencxl_tlp_header_tag(tlp_header);

    // Get a request entry
    PacketRequestEntry *req_entry =
        get_request_entry(&port->io_dma_request_queue);

    // Copy MRD/MWR Header
    memcpy((void *)&req_entry->packet[0], (void *)(tlp_header),
           opencxl_tlp_header_size);
    req_entry->packet_size = opencxl_tlp_header_size;
    req_entry->tag = tag;

    // Move TLP header pointer
    tlp_header = (opencxl_tlp_header_t *)req_entry->packet;

    // Read TLP data
    if (tlp_header->dw0.fmt_type == MWR_64B ||
        tlp_header->dw0.fmt_type == MWR_32B) {
        trace_cxl_root_debug_message(
            "Waiting for data payload of CXL.io packet from TCP socket");
        const uint16_t data_length =
            parse_opencxl_tlp_data_payload_length(tlp_header);
        void *data_buffer = parse_opencxl_tlp_data_pointer(tlp_header);
        assert(remaining == data_length);
        assert(MAX_PACKET_BUFFER_SIZE - opencxl_tlp_header_size >= remaining);
        assert(wait_for_payload(port->socket_fd, (uint8_t *)data_buffer,
                                data_length, data_length));
        remaining -= data_length;
        req_entry->packet_size += data_length;
        trace_cxl_root_debug_message(
            "Received data payload of CXL.io packet from TCP socket");
    }

    print_io_packet(tlp_header, false);

    assert(req_entry->packet_size == tlp_header->system_header.payload_length);
    assert(remaining == 0);

    char msg[100];
    sprintf(msg, "Entire CXL.io packet for tag %d is received", tag);
    trace_cxl_root_debug_message(msg);

    // Submit received IO request to the DMA request queue
    enqueue_request(&port->io_dma_request_queue, req_entry);

    // Schedule QEMU BH
    qemu_bh_schedule(port->bh);
}

static void process_io_incoming(CXLRemoteRootPort *port,
                                system_header_packet_t *header)
{
    const uint16_t payload_size = header->payload_length;
    uint16_t bytes_read = sizeof(system_header_packet_t);
    uint16_t remaining = payload_size - bytes_read;

    // Make sure at least TLP DW0 is remaining
    assert(remaining >= sizeof(cxl_io_header_t));

    // Create OpenCXL TLP header
    opencxl_tlp_header_t tlp_header;
    tlp_header.system_header = *header;

    // Read DW0 first
    trace_cxl_root_debug_message("Waiting for TLP DW0 from TCP socket");
    assert(wait_for_tlp_header_dw0(port->socket_fd, &tlp_header.dw0));
    bytes_read += sizeof(uint32_t);
    trace_cxl_root_debug_message("Received TLP DW0 from TCP socket");

    assert(tlp_header.system_header.payload_length >= bytes_read);
    remaining = tlp_header.system_header.payload_length - bytes_read;
    const uint8_t opencxl_tlp_header_size =
        parse_openxcl_tlp_header_size(&tlp_header);
    uint32_t remaining_header_length = opencxl_tlp_header_size - bytes_read;

    // NOTE: We may not have to worry about Prefix TLP from the host
    assert(remaining_header_length > 0);
    assert(remaining_header_length <= remaining);

    // Read remainin TLP header without DW0
    trace_cxl_root_debug_message(
        "Waiting for packets beyond CXL.io DW0 from TCP socket");
    assert(wait_for_tlp_header_without_dw0(port->socket_fd, &tlp_header));
    trace_cxl_root_debug_message(
        "Received entire CXL.io header packet from TCP socket");

    remaining -= remaining_header_length;
    bytes_read += remaining_header_length;

    switch (tlp_header.dw0.fmt_type) {
        case CPL:
            trace_cxl_root_debug_message("Received CXL.io packet is CPL");
            process_io_resp(port, &tlp_header, bytes_read);
            break;
        case CPLD:
            trace_cxl_root_debug_message("Received CXL.io packet is CPLD");
            process_io_resp(port, &tlp_header, bytes_read);
            break;
        case MRD_32B:
            trace_cxl_root_debug_message("Received CXL.io packet is MRD_32B");
            process_io_dma_req(port, &tlp_header, bytes_read);
            break;
        case MRD_64B:
            trace_cxl_root_debug_message("Received CXL.io packet is MRD_64B");
            process_io_dma_req(port, &tlp_header, bytes_read);
            break;
        case MWR_32B:
            trace_cxl_root_debug_message("Received CXL.io packet is MWR_32B");
            process_io_dma_req(port, &tlp_header, bytes_read);
            break;
        case MWR_64B:
            trace_cxl_root_debug_message("Received CXL.io packet is MWR_64B");
            process_io_dma_req(port, &tlp_header, bytes_read);
            break;
        default:
            trace_cxl_root_error_msg("Unexpected TLP type");
            assert(0);
    }
}

static void process_mem_incoming(CXLRemoteRootPort *port,
                                 system_header_packet_t *header)
{
    trace_cxl_root_error_msg("CXL.mem response handling is not supported yet");
    assert(0);
}

static void process_incoming(CXLRemoteRootPort *port)
{
    system_header_packet_t system_header;
    assert(wait_for_system_header(port->socket_fd, &system_header));

    switch (system_header.payload_type) {
        case CXL_IO:
            trace_cxl_root_debug_message(
                "Received a CXL.io packet from TCP socket");
            process_io_incoming(port, &system_header);
            break;
        case CXL_MEM:
            trace_cxl_root_debug_message(
                "Received a CXL.mem packet from TCP socket");
            process_mem_incoming(port, &system_header);
            break;
        default:
            trace_cxl_root_error_msg("Unsupported OpenCXL packet");
            assert(0);
    }
}

static void *thread_incoming_socket(void *context)
{
    CXLRemoteRootPort *port = (CXLRemoteRootPort *)context;
    while (true) {
        process_incoming(port);
    }

    return NULL;
}

static void *thread_io_outgoing_socket(void *context)
{
    trace_cxl_root_debug_message("Started CXL.io TX thread");

    CXLRemoteRootPort *port = (CXLRemoteRootPort *)context;
    while (true) {
        process_io_outgoing(port);
    }

    trace_cxl_root_debug_message("Terminating CXL.io TX thread");
    return NULL;
}

static void *thread_mem_outgoing_socket(void *context)
{
    trace_cxl_root_debug_message("Started CXL.mem TX thread");

    CXLRemoteRootPort *port = (CXLRemoteRootPort *)context;
    while (true) {
        process_mem_req(port);
    }

    trace_cxl_root_debug_message("Terminating CXL.mem TX thread");
    return NULL;
}

static void process_dma_read_request(CXLRemoteRootPort *port,
                                     PacketRequestEntry *req_entry)
{
    char msg[100];

    opencxl_tlp_header_t *req_tlp_header =
        (opencxl_tlp_header_t *)req_entry->packet;
    const uint16_t data_length = parse_opencxl_tlp_data_length(req_tlp_header);
    const uint64_t address = parse_opencxl_mem_address(req_tlp_header);
    const uint16_t req_id = parse_opencxl_req_id(req_tlp_header);
    DMADirection dir = DMA_DIRECTION_TO_DEVICE;

    assert(data_length % 4 == 0);
    // assert(mem_header->mreq_header.first_dw_be == 0xF);
    // assert(mem_header->mreq_header.last_dw_be ==
    //    (data_length > 4 ? 0xF : 0));

    PacketRequestEntry *resp_entry = get_request_entry(&port->io_request_queue);
    memset(resp_entry->packet, 0, sizeof(opencxl_tlp_header_t));
    opencxl_tlp_header_t *resp_tlp_header =
        (opencxl_tlp_header_t *)resp_entry->packet;

    const uint16_t comp_id = 0;
    const uint8_t lower_address = address & 0x7F;
    const uint16_t byte_counts = data_length;
    const tlp_cpl_status_t status = TLP_CPL_STATUS_SC;

    fill_cpl_header(resp_tlp_header, req_id, comp_id, data_length / 4, status,
                    byte_counts, lower_address, req_entry->tag);

    sprintf(msg, "DMA Read Request from device: Address: 0x%lx, Size: %d",
            address, data_length);
    trace_cxl_root_debug_message(msg);

    uint32_t *data_buffer = parse_opencxl_tlp_data_pointer(resp_tlp_header);
    MemTxResult result =
        dma_memory_rw(port->dma_address_space, (dma_addr_t)address, data_buffer,
                      data_length, dir, MEMTXATTRS_UNSPECIFIED);

    sprintf(msg, "DMA Status: %d", (uint32_t)result);
    trace_cxl_root_debug_message(msg);
    assert(result == MEMTX_OK);

    for (uint16_t dw_index = 0; dw_index < data_length / 4; ++dw_index) {
        sprintf(msg, "DATA[0x%04x]: 0x0%08x", dw_index * 4,
                data_buffer[dw_index]);
        trace_cxl_root_debug_message(msg);
    }

    resp_tlp_header->system_header.payload_type = CXL_IO;
    resp_tlp_header->system_header.payload_length =
        parse_openxcl_tlp_header_size(resp_tlp_header) +
        parse_opencxl_tlp_data_payload_length(resp_tlp_header);
    resp_entry->tag = req_entry->tag;
    resp_entry->packet_size = resp_tlp_header->system_header.payload_length;

    trace_cxl_root_debug_message(msg);

    enqueue_request(&port->io_request_queue, resp_entry);
}

static void process_dma_write_request(CXLRemoteRootPort *port,
                                      PacketRequestEntry *req_entry)
{
    char msg[100];

    opencxl_tlp_header_t *tlp_header =
        (opencxl_tlp_header_t *)req_entry->packet;
    const uint16_t data_length = parse_opencxl_tlp_data_length(tlp_header);
    const uint64_t address = parse_opencxl_mem_address(tlp_header);
    uint32_t *data_buffer = parse_opencxl_tlp_data_pointer(tlp_header);
    DMADirection dir = DMA_DIRECTION_FROM_DEVICE;

    sprintf(msg, "DMA Write Request from device: Address: 0x%lx, Size: %d",
            address, data_length);
    trace_cxl_root_debug_message(msg);

    assert(data_length % 4 == 0);
    // assert(mem_header->mreq_header.first_dw_be == 0xF);
    // assert(mem_header->mreq_header.last_dw_be ==
    //    (data_length > 4 ? 0xF : 0));

    for (uint16_t dw_index = 0; dw_index < data_length / 4; ++dw_index) {
        sprintf(msg, "DATA[0x%04x]: 0x0%08x", dw_index * 4,
                data_buffer[dw_index]);
        trace_cxl_root_debug_message(msg);
    }

    MemTxResult result =
        dma_memory_rw(port->dma_address_space, (dma_addr_t)address, data_buffer,
                      data_length, dir, MEMTXATTRS_UNSPECIFIED);

    sprintf(msg, "DMA Status: %d", (uint32_t)result);
    trace_cxl_root_debug_message(msg);
    assert(result == MEMTX_OK);
}

static void process_dma_request(void *context)
{
    trace_cxl_root_debug_message("DMA process request scheduled");

    CXLRemoteRootPort *port = (CXLRemoteRootPort *)context;
    PacketRequestEntry *entry =
        dequeue_request_non_block(&port->io_dma_request_queue);
    while (entry) {
        opencxl_tlp_header_t *tlp_header =
            (opencxl_tlp_header_t *)entry->packet;
        cxl_io_fmt_type_t fmt_type = tlp_header->dw0.fmt_type;
        switch (fmt_type) {
            case MRD_32B:
            case MRD_64B: {
                process_dma_read_request(port, entry);
                break;
            }
            case MWR_32B:
            case MWR_64B: {
                process_dma_write_request(port, entry);
                break;
            }
            default:
                trace_cxl_root_error_msg("Unsupported DMA Request Type");
                assert(0);
        }

        return_request_entry(&port->io_dma_request_queue, entry);
        entry = dequeue_request_non_block(&port->io_dma_request_queue);
    }
}

/*

    PCIe APIs

*/

void cxl_remote_rp_cxl_io_mem_write(CXLRemoteRootPort *port, hwaddr addr,
                                    uint16_t length_dw, uint8_t first_dw_be,
                                    uint8_t last_dw_be, void *buffer)
{
    PacketRequestEntry *req_entry = get_request_entry(&port->io_request_queue);
    opencxl_tlp_header_t *req_tlp_header =
        (opencxl_tlp_header_t *)req_entry->packet;
    memset(req_entry->packet, 0, sizeof(opencxl_tlp_header_t));

    // Fill TLP Header
    const uint16_t req_id = 0;
    fill_tlp_mwr_header(req_tlp_header, req_id, addr, length_dw, first_dw_be,
                        last_dw_be, req_entry->tag);

    // Fill TLP Data
    void *dest_buffer = parse_opencxl_tlp_data_pointer(req_tlp_header);
    memcpy(dest_buffer, buffer, length_dw * sizeof(uint32_t));

    // Fill System Header
    const uint16_t header_size = parse_openxcl_tlp_header_size(req_tlp_header);
    const uint16_t data_length =
        parse_opencxl_tlp_data_payload_length(req_tlp_header);
    req_tlp_header->system_header.payload_type = CXL_IO;
    req_tlp_header->system_header.payload_length = header_size + data_length;

    // Submit request
    // mark_request_submitted(&port->io_response_table, req_entry->tag, req_entry);
    enqueue_request(&port->io_request_queue, req_entry);
}

tlp_cpl_status_t cxl_remote_rp_cxl_io_mem_read(CXLRemoteRootPort *port,
                                               hwaddr addr, uint16_t length_dw,
                                               uint8_t first_dw_be,
                                               uint8_t last_dw_be, void *buffer)
{
    PacketRequestEntry *req_entry = get_request_entry(&port->io_request_queue);
    opencxl_tlp_header_t *req_tlp_header =
        (opencxl_tlp_header_t *)req_entry->packet;
    memset(req_entry->packet, 0, sizeof(opencxl_tlp_header_t));

    // Fill TLP Header
    const uint16_t req_id = 0;
    fill_tlp_mrd_header(req_tlp_header, req_id, addr, length_dw, first_dw_be,
                        last_dw_be, req_entry->tag);

    // Fill System Header
    const uint16_t header_size = parse_openxcl_tlp_header_size(req_tlp_header);
    req_tlp_header->system_header.payload_type = CXL_IO;
    req_tlp_header->system_header.payload_length = header_size;

    // Submit request
    mark_request_submitted(&port->io_response_table, req_entry->tag, req_entry);
    enqueue_request(&port->io_request_queue, req_entry);

    // Wait for response
    trace_cxl_root_debug_message(
        "Waiting a response packet entry for a CXL.io request");
    PacketResponseEntry *resp_entry =
        wait_for_received_packet(&port->io_response_table, req_entry->tag);
    trace_cxl_root_debug_message(
        "Received a response packet entry for a CXL.io request");

    // Check response TLP type
    opencxl_tlp_header_t *resp_tlp_header =
        (opencxl_tlp_header_t *)resp_entry->packet;
    const cxl_io_fmt_type_t format_type = resp_tlp_header->dw0.fmt_type;

    assert(parse_opencxl_tlp_header_tag(resp_tlp_header) == req_entry->tag);
    assert(resp_tlp_header->system_header.payload_type == CXL_IO);
    assert(format_type == CPL || format_type == CPLD);

    tlp_cpl_status_t status = TLP_CPL_STATUS_SC;
    if (format_type == CPL) {
        status = parse_opencxl_tlp_cpl_status(resp_tlp_header);
    } else if (format_type == CPLD) {
        status = parse_opencxl_tlp_cpl_status(resp_tlp_header);
        const uint16_t resp_tlp_header_size =
            parse_openxcl_tlp_header_size(resp_tlp_header);
        const uint16_t remaining =
            resp_tlp_header->system_header.payload_length -
            resp_tlp_header_size;
        const uint16_t data_length =
            parse_opencxl_tlp_data_payload_length(resp_tlp_header);
        assert(remaining % 4 == 0);
        assert(remaining == data_length);
        void *src_buffer = parse_opencxl_tlp_data_pointer(resp_tlp_header);
        memcpy(buffer, src_buffer, data_length);
    } else {
        trace_cxl_root_error_msg(
            "Unexpected TLP packet format for MRD response");
        assert(0);
    }

    // Release response table entry and request entry
    clear_request_submitted(&port->io_response_table, req_entry->tag);

    return status;
}

void cxl_remote_rp_cxl_io_mmio_write(CXLRemoteRootPort *port, hwaddr addr,
                                     uint64_t data, uint8_t size)
{
    uint8_t first_be;
    uint8_t last_be;
    uint16_t length_dw;

    get_tlp_length_and_be(addr, size, &length_dw, &first_be, &last_be);

    if (size == 8) {
        uint64_t sent_data = get_mmio_wr_data_with_be(data, first_be, last_be);
        cxl_remote_rp_cxl_io_mem_write(port, addr, length_dw, first_be, last_be,
                                    &sent_data);
        return;
    } else if (size == 4) {
        uint32_t sent_data = get_cfg_wr_data_with_be(data, first_be);
        cxl_remote_rp_cxl_io_mem_write(port, addr, length_dw, first_be, last_be,
                                    &sent_data);
        return;
    }

    trace_cxl_root_error_msg("Unsupported MMIO write size");
    assert(0);
}

uint64_t cxl_remote_rp_cxl_io_mmio_read(CXLRemoteRootPort *port, hwaddr addr,
                                        int8_t size)
{
    uint8_t first_be;
    uint8_t last_be;
    uint16_t length_dw;

    get_tlp_length_and_be(addr, size, &length_dw, &first_be, &last_be);

    if (size == 8) {
        uint64_t received_data = (uint64_t)-1;
        cxl_remote_rp_cxl_io_mem_read(port, addr, length_dw, first_be, last_be,
                                    &received_data);
        uint64_t data = get_mmio_rd_data_with_be(received_data, first_be, last_be);
        return data;
    } else if (size == 4) {
        uint32_t received_data = (uint32_t)-1;
        cxl_remote_rp_cxl_io_mem_read(port, addr, length_dw, first_be, last_be,
                                    &received_data);
        
        char msg[100];
        sprintf(msg, "Received Data: 0x%08x", received_data);
        trace_cxl_root_debug_message(msg);

        uint32_t data = get_cfg_rd_data_with_be(received_data, first_be);
        return data;
    }

    trace_cxl_root_error_msg("Unsupported MMIO read size");
    assert(0);
}

tlp_cpl_status_t cxl_remote_rp_cxl_io_cfg_write(CXLRemoteRootPort *port,
                                                uint16_t bdf, uint16_t offset,
                                                uint32_t data, uint8_t size,
                                                bool type0)
{
    const uint8_t bus = bdf >> 8;
    const uint8_t device = (bdf >> 3) & 0x1F;
    const uint8_t function = bdf & 0x7;

    uint16_t reg_num;
    uint8_t be;

    get_tlp_reg_num_and_be(offset, size, &reg_num, &be);

    if (type0 && (bdf & 0xFF) != 0) {
        return TLP_CPL_STATUS_UR;
    }

    if (type0) {
        trace_cxl_root_cxl_io_config_space_write0(bus, device, function, offset,
                                                  size, data);
    } else {
        trace_cxl_root_cxl_io_config_space_write1(bus, device, function, offset,
                                                  size, data);
    }

    PacketRequestEntry *req_entry = get_request_entry(&port->io_request_queue);
    opencxl_tlp_header_t *req_tlp_header =
        (opencxl_tlp_header_t *)req_entry->packet;
    memset(req_entry->packet, 0, sizeof(opencxl_tlp_header_t));

    // Fill TLP Header
    uint16_t req_id = 0;  // Request ID is 0 for Root Complex
    fill_cfg_wr_header(req_tlp_header, req_id, bdf, reg_num, be, req_entry->tag,
                       type0);

    // Fill TLP Data
    void *dest_buffer = parse_opencxl_tlp_data_pointer(req_tlp_header);
    uint32_t sent_data = get_cfg_wr_data_with_be(data, be);
    memcpy(dest_buffer, &sent_data, sizeof(uint32_t));

    // Fill System Header
    uint16_t header_size = parse_openxcl_tlp_header_size(req_tlp_header);
    req_tlp_header->system_header.payload_type = CXL_IO;
    req_tlp_header->system_header.payload_length =
        header_size + sizeof(uint32_t);

    // Submit request
    mark_request_submitted(&port->io_response_table, req_entry->tag, req_entry);
    enqueue_request(&port->io_request_queue, req_entry);

    // Wait for response
    trace_cxl_root_debug_message(
        "Waiting a response packet entry for a CXL.io request");
    PacketResponseEntry *resp_entry =
        wait_for_received_packet(&port->io_response_table, req_entry->tag);
    trace_cxl_root_debug_message(
        "Received a response packet entry for a CXL.io request");

    // Check response TLP type
    opencxl_tlp_header_t *resp_tlp_header =
        (opencxl_tlp_header_t *)resp_entry->packet;
    const cxl_io_fmt_type_t fmt_type = resp_tlp_header->dw0.fmt_type;

    assert(parse_opencxl_tlp_header_tag(resp_tlp_header) == req_entry->tag);
    assert(resp_tlp_header->system_header.payload_type == CXL_IO);
    assert(fmt_type == CPL);

    tlp_cpl_status_t status = parse_opencxl_tlp_cpl_status(resp_tlp_header);
    trace_cxl_root_cxl_io_config_cpl(bus, device, function, (uint8_t)status);

    if (status != TLP_CPL_STATUS_SC) {
        trace_cxl_root_error_msg(
            "Received TLP CPL with status other than SC for CFG WR");
    }

    // Release response table entry and request entry
    clear_request_submitted(&port->io_response_table, req_entry->tag);

    return status;
}

uint32_t cxl_remote_rp_cxl_io_cfg_read(CXLRemoteRootPort *port, uint16_t bdf,
                                       uint16_t offset, uint32_t *data,
                                       uint8_t size, bool type0)
{
    const uint8_t bus = bdf >> 8;
    const uint8_t device = (bdf >> 3) & 0x1F;
    const uint8_t function = bdf & 0x7;

    uint16_t reg_num;
    uint8_t be;

    get_tlp_reg_num_and_be(offset, size, &reg_num, &be);

    if (type0 && (bdf & 0xFF) != 0) {
        *data = get_cfg_rd_data_with_be(0xFFFFFFFF, be);
        return TLP_CPL_STATUS_UR;
    }

    if (type0) {
        trace_cxl_root_cxl_io_config_space_read0(bus, device, function, offset,
                                                 size);
    } else {
        trace_cxl_root_cxl_io_config_space_read1(bus, device, function, offset,
                                                 size);
    }

    PacketRequestEntry *req_entry = get_request_entry(&port->io_request_queue);
    opencxl_tlp_header_t *req_tlp_header =
        (opencxl_tlp_header_t *)req_entry->packet;
    memset(req_entry->packet, 0, sizeof(opencxl_tlp_header_t));

    // Fill TLP Header
    const uint16_t req_id = 0;  // Request ID is 0 for Root Complex
    fill_cfg_rd_header(req_tlp_header, req_id, bdf, reg_num, be, req_entry->tag,
                       type0);

    // Fill System Header
    uint16_t header_size = parse_openxcl_tlp_header_size(req_tlp_header);
    req_tlp_header->system_header.payload_type = CXL_IO;
    req_tlp_header->system_header.payload_length = header_size;

    // Submit request
    mark_request_submitted(&port->io_response_table, req_entry->tag, req_entry);
    enqueue_request(&port->io_request_queue, req_entry);

    // Wait for response
    trace_cxl_root_debug_message(
        "Waiting a response packet entry for a CXL.io request");
    PacketResponseEntry *resp_entry =
        wait_for_received_packet(&port->io_response_table, req_entry->tag);
    trace_cxl_root_debug_message(
        "Received a response packet entry for a CXL.io request");

    // Check response TLP type
    opencxl_tlp_header_t *resp_tlp_header =
        (opencxl_tlp_header_t *)resp_entry->packet;
    const cxl_io_fmt_type_t fmt_type = resp_tlp_header->dw0.fmt_type;

    assert(parse_opencxl_tlp_header_tag(resp_tlp_header) == req_entry->tag);
    assert(resp_tlp_header->system_header.payload_type == CXL_IO);
    assert(fmt_type == CPL || fmt_type == CPLD);

    uint32_t received_data = 0xFFFFFFFF;
    tlp_cpl_status_t status = parse_opencxl_tlp_cpl_status(resp_tlp_header);
    if (fmt_type == CPL) {
        trace_cxl_root_debug_message(
            "Received a CPL packet for a CXL.io request");
        assert(resp_tlp_header->system_header.payload_length ==
               parse_openxcl_tlp_header_size(resp_tlp_header));
        if (status == TLP_CPL_STATUS_SC) {
            trace_cxl_root_error_msg(
                "TLP CPLD is expected for successful CFG RD");
            assert(0);
        }
    } else if (fmt_type == CPLD) {
        trace_cxl_root_debug_message(
            "Received a CPLD packet for a CXL.io request");
        assert(status == TLP_CPL_STATUS_SC);
        void *src_buffer = parse_opencxl_tlp_data_pointer(resp_tlp_header);
        memcpy(&received_data, src_buffer, sizeof(uint32_t));

        char msg[100];
        sprintf(msg, "Received Data: 0x%08x", received_data);
        trace_cxl_root_debug_message(msg);
    } else {
        trace_cxl_root_error_msg(
            "Unexpected TLP packet format for MRD response");
        assert(0);
    }

    // Release response table entry and request entry
    clear_request_submitted(&port->io_response_table, req_entry->tag);

    // Adjust data using byte enable
    received_data = get_cfg_rd_data_with_be(received_data, be);
    char msg[100];
    sprintf(msg, "Adjusted Received Data: 0x%08x. BE: %d", received_data, be);
    trace_cxl_root_debug_message(msg);
    *data = received_data;

    if (fmt_type == CPL) {
        trace_cxl_root_cxl_io_config_cpl(bus, device, function,
                                         (uint8_t)status);
    } else if (fmt_type == CPLD) {
        trace_cxl_root_cxl_io_config_cpld(bus, device, function, *data);
    }

    return status;
}

// CXL Remote Root Port Initialization
bool cxl_remote_rp_init(CXLRemoteRootPort *port, const char *tcp_host,
                        uint32_t tcp_port, uint32_t switch_port)
{
    init_request_queue(&port->io_request_queue, CXL_MAX_IO_TAG);
    init_request_queue(&port->io_dma_request_queue, CXL_MAX_IO_TAG);
    init_request_queue(&port->mem_request_queue, CXL_MAX_MEM_TAG);

    init_response_table(&port->io_response_table, CXL_MAX_IO_TAG,
                        &port->io_request_queue);
    init_response_table(&port->mem_response_table, CXL_MAX_MEM_TAG,
                        &port->mem_request_queue);

    pthread_mutex_init(&port->socket_tx_lock, NULL);

    if (!init_socket_client(port, tcp_host, tcp_port, switch_port)) {
        return false;
    }

    trace_cxl_root_debug_message("Creating CXL.io TX thread");
    if (pthread_create(&port->io_tx_thread, NULL, thread_io_outgoing_socket,
                       (void *)port) != 0) {
        trace_cxl_root_error_msg("Failed to create CXL.io TX thread");
        return false;
    }

    trace_cxl_root_debug_message("Creating CXL.mem TX thread");
    if (pthread_create(&port->mem_tx_thread, NULL, thread_mem_outgoing_socket,
                       (void *)port) != 0) {
        trace_cxl_root_error_msg("Failed to create CXL.mem TX thread");
        return false;
    }

    trace_cxl_root_debug_message("Creating RX thread");
    if (pthread_create(&port->rx_thread, NULL, thread_incoming_socket,
                       (void *)port) != 0) {
        trace_cxl_root_error_msg("Failed to create RX thread");
        return 1;
    }

    port->bh = qemu_bh_new(process_dma_request, (void *)port);

    return true;
}
