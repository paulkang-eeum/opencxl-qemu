#include "hw/cxl/cxl_remote.h"

#include <assert.h>
#include <glib.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include "hw/cxl/cxl_emulator_packet.h"
#include "hw/cxl/cxl_socket_transport.h"
#include "trace/trace-hw_pci_bridge.h"

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
    return queue->head == queue->tail + 1;
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

// Get an available entry from the available queue
PacketRequestEntry *get_request_entry(RequestQueue *queue)
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
void return_request_entry(RequestQueue *queue, PacketRequestEntry *entry)
{
    pthread_mutex_lock(&queue->lock);

    // Add the entry back to the available queue
    push_item(&queue->available_queue, entry);

    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->lock);
}

// Enqueue the request entry into the submitted queue after modification
void enqueue_request(RequestQueue *queue, PacketRequestEntry *entry)
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
PacketRequestEntry *dequeue_request(RequestQueue *queue)
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

// Mark a request as submitted in the ResponseTable
void mark_request_submitted(ResponseTable *table, uint16_t tag,
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
PacketResponseEntry *get_entry_by_tag(ResponseTable *table, uint16_t tag)
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
PacketResponseEntry *wait_for_received_packet(ResponseTable *table,
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
void mark_packet_received(ResponseTable *table, uint16_t tag)
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
void clear_request_submitted(ResponseTable *table, uint16_t tag)
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

    pthread_mutex_unlock(&table->lock);
}

static bool cxl_remote_rp_init_socket_client(CXLRemoteRootPort *remote_rp,
                                             const char *host, uint32_t port)
{
    remote_rp->socket_fd = create_socket_client(host, port);
    return remote_rp->socket_fd != -1;
}

// CXL Remote Root Port Initialization
void cxl_remote_init(CXLRemoteRootPort *port)
{
    // Initialize request queues for IO and memory, each entry already has a tag
    // assigned
    init_request_queue(&port->io_request_queue, CXL_MAX_IO_TAG);
    init_request_queue(&port->mem_request_queue, CXL_MAX_MEM_TAG);

    // Initialize response tables for IO and memory
    init_response_table(&port->io_response_table, CXL_MAX_IO_TAG,
                        &port->io_request_queue);
    init_response_table(&port->mem_response_table, CXL_MAX_MEM_TAG,
                        &port->mem_request_queue);

    pthread_mutex_init(&port->socket_tx_lock, NULL);
}

static void transmit_socket_payload(CXLRemoteRootPort *port,
                                    PacketRequestEntry *entry)
{
    pthread_mutex_lock(&port->socket_tx_lock);

    send_payload(port->socket_fd, entry->packet, entry->packet_size);

    pthread_mutex_unlock(&port->socket_tx_lock);
}

static void process_io_req(CXLRemoteRootPort *port)
{
    PacketRequestEntry *entry = dequeue_request(&port->io_request_queue);
    assert(entry);

    // TODO: Check system header
    // TODO: Check payload size
    // mark_request_submitted(&port->io_response_table, entry->tag, entry);

    transmit_socket_payload(port, entry);

    cxl_io_header_t *tlp_dw0 =
        (cxl_io_header_t *)&entry->packet[sizeof(system_header_packet_t)];
    if (!cxl_io_expect_response(tlp_dw0)) {
        mark_packet_received(&port->io_response_table, entry->tag);
    }
}

static void process_mem_req(CXLRemoteRootPort *port)
{
    PacketRequestEntry *entry = dequeue_request(&port->mem_request_queue);
    assert(entry);

    // TODO: Check system header
    // TODO: Check payload size

    mark_request_submitted(&port->mem_response_table, entry->tag, entry);

    transmit_socket_payload(port, entry);
}

static void process_io_resp(CXLRemoteRootPort *port, opencxl_tlp_header_t *opencxl_tlp,
                            uint16_t bytes_read)
{
    assert(opencxl_tlp->system_header.payload_type == CXL_IO);
    assert(opencxl_tlp->dw0.fmt_type == CPL || opencxl_tlp->dw0.fmt_type == CPL_D);

    assert(opencxl_tlp->system_header.payload_length >= bytes_read);
    uint16_t remaining = opencxl_tlp->system_header.payload_length - bytes_read;
    const uint8_t opencxl_tlp_header_size = parse_openxcl_tlp_header_size(opencxl_tlp);
    uint32_t remaining_header_length = opencxl_tlp_header_size - bytes_read;

    // NOTE: We may not have to worry about Prefix TLP from the host
    assert(remaining_header_length > 0);
    assert(remaining_header_length >= remaining);

    // Read remainin TLP header without DW0
    assert(wait_for_tlp_header_without_dw0(port->socket_fd, opencxl_tlp));
    remaining -= remaining_header_length;

    // Read tag
    uint16_t tag = parse_opencxl_tlp_header_tag(opencxl_tlp);

    // Get received entry using tag
    PacketResponseEntry *entry =
        get_entry_by_tag(&port->io_response_table, tag);

    // Copy CPL Header
    memcpy((void *)&entry->packet[0], (void *)(opencxl_tlp),
           opencxl_tlp_header_size);
    entry->packet_size += opencxl_tlp_header_size;
    
    // Read TLP data
    if (opencxl_tlp->dw0.fmt_type == CPL_D) {
        const size_t data_length = parse_opencxl_tlp_data_length(opencxl_tlp);
        assert(remaining == data_length);
        assert(MAX_PACKET_SIZE - opencxl_tlp_header_size >= remaining);
        assert(wait_for_payload(
            port->socket_fd,
            (uint8_t *)&entry->packet[opencxl_tlp_header_size], data_length,
            data_length));
        remaining -= data_length;
        entry->packet_size += data_length;
    }

    assert(remaining == 0);

    mark_packet_received(&port->io_response_table, tag);
}

static void process_io_dma_req(CXLRemoteRootPort *port,
                               opencxl_tlp_header_t *tlp_header, uint16_t bytes_read)
{
}

static void process_io_incoming(CXLRemoteRootPort *port,
                                system_header_packet_t *header)
{
    const uint16_t payload_size = header->payload_length;
    uint16_t bytes_read = sizeof(system_header_packet_t);
    const uint16_t remaining = payload_size - bytes_read;

    // Make sure at least TLP DW0 is remaining 
    assert(remaining >= sizeof(cxl_io_header_t));

    // Create OpenCXL TLP header
    opencxl_tlp_header_t opencxl_tlp;
    opencxl_tlp.system_header = *header;

    assert(wait_for_tlp_header_dw0(port->socket_fd, &opencxl_tlp.dw0));
    bytes_read += sizeof(uint32_t);

    switch (opencxl_tlp.dw0.fmt_type) {
        case CPL:
        case CPL_D:
            process_io_resp(port, &opencxl_tlp,
                            bytes_read);
            break;
        case MRD_32B:
        case MRD_64B:
        case MWR_32B:
        case MWR_64B:
            process_io_dma_req(port, &opencxl_tlp,
                               bytes_read);
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
            process_io_incoming(port, &system_header);
            break;
        case CXL_MEM:
            process_mem_incoming(port, &system_header);
            break;
        default:
            trace_cxl_root_error_msg("Unsupported OpenCXL packet");
            assert(0);
    }
}

static void thread_incoming_socket(void *context)
{
    CXLRemoteRootPort *port = (CXLRemoteRootPort *)context;
    while (true) {
        process_incoming(port);
    }
}

static void thread_io_outgoing_socket(void *context)
{
    CXLRemoteRootPort *port = (CXLRemoteRootPort *)context;
    while (true) {
        process_io_req(port);
    }
}

static void thread_mem_outgoing_socket(void *context)
{
    CXLRemoteRootPort *port = (CXLRemoteRootPort *)context;
    while (true) {
        process_mem_req(port);
    }
}

void cxl_remote_rp_cxl_io_mem_write(CXLRemoteRootPort *port, hwaddr addr,
                                     uint64_t val, uint8_t size)
{
    PacketRequestEntry *entry = get_request_entry(&port->io_request_queue);
    cxl_io_mem_base_packet_t *io_mem_header = (cxl_io_mem_base_packet_t *)entry->packet;

    // Fill System Header
    io_mem_header->system_header.payload_type = CXL_IO;
    io_mem_header->system_header.payload_length = sizeof(cxl_io_mem_base_packet_t) + size;

    // Fill TLP Header
    const uint16_t req_id = 0;
    fill_tlp_mwr_header(io_mem_header, req_id, addr, size, entry->tag);

    // Fill TLP Data
    memcpy(&entry->packet[sizeof(*io_mem_header)], (void *)(&val), size);

    // Submit request
    mark_request_submitted(&port->io_response_table, entry->tag, entry);
    enqueue_request(&port->io_request_queue, entry);

}
uint64_t cxl_remote_rp_cxl_io_mem_read(CXLRemoteRootPort *port, hwaddr addr,
                                        uint8_t size)
{
    PacketRequestEntry *req_entry = get_request_entry(&port->io_request_queue);
    cxl_io_mem_base_packet_t *io_mem_header = (cxl_io_mem_base_packet_t *)req_entry->packet;

    // Fill System Header
    io_mem_header->system_header.payload_type = CXL_IO;
    io_mem_header->system_header.payload_length = sizeof(cxl_io_mem_base_packet_t) + size;

    // Fill TLP Header
    const uint16_t req_id = 0;
    fill_tlp_mrd_header(io_mem_header, req_id, addr, size, req_entry->tag);

    // Submit request
    mark_request_submitted(&port->io_response_table, req_entry->tag, req_entry);
    enqueue_request(&port->io_request_queue, req_entry);

    // Wait for response
    PacketResponseEntry *resp_entry = wait_for_received_packet(&port->io_response_table, req_entry->tag);

    // Check response TLP type
    opencxl_tlp_header_t *resp_tlp_header = (opencxl_tlp_header_t *)resp_entry->packet;
    cxl_io_fmt_t format = parse_cxl_io_fmt(&resp_tlp_header->dw0);

    assert(parse_opencxl_tlp_header_tag(resp_tlp_header) == req_entry->tag);
    assert(resp_tlp_header->system_header.payload_type == CXL_IO);
    assert(format == CPL || format == CPL_D);

    if (format == CPL) {
        
    }

    // Read data
    uint64_t val = 0;
    read_mrd_data()
}

void cxl_remote_rp_cxl_io_cfg_write(CXLRemoteRootPort *port, uint16_t bdf,
                                    uint32_t offset, uint32_t val, int size,
                                    bool type0)
{
}
uint32_t cxl_remote_rp_cxl_io_cfg_read(CXLRemoteRootPort *port, uint16_t bdf,
                                       uint32_t offset, int size, bool type0)
{
}
