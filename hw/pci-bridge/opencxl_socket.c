#include "hw/cxl/opencxl_socket.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "hw/cxl/opencxl_packet.h"
#include "qemu/osdep.h"
#include "trace.h"
#include "trace/trace-hw_pci_bridge.h"

#define MAX_DURATION 30

/*

    Sideband API

*/

bool send_sideband_connection_request(int socket_fd, uint32_t port)
{
    trace_cxl_socket_debug_msg("Sending Sideband Connection Request Packet");

    sideband_connection_request_packet_t packet = {};
    packet.system_header.payload_type = SIDEBAND;
    packet.system_header.payload_length = sizeof(packet);
    packet.sideband_header.type = SIDEBAND_CONNECTION_REQUEST;
    packet.port = port;

    base_sideband_packet_t *sb_header = (base_sideband_packet_t *)(&packet);
    print_sideband_packet(sb_header, true);

    if (write(socket_fd, &packet, sizeof(packet)) == -1) {
        return false;
    }

    return true;
}

bool wait_for_base_sideband_packet(int socket_fd,
                                   base_sideband_packet_t *sideband)
{
    trace_cxl_socket_debug_msg("Waiting for Base Sideband Packet");
    char msg0[100];
    sprintf(msg0, "Size of base_sideband_packet_t is %lu", sizeof(*sideband));
    trace_cxl_socket_debug_msg(msg0);

    if (!wait_for_system_header(socket_fd,
                                (system_header_packet_t *)sideband)) {
        return false;
    }

    assert(sideband->system_header.payload_type == SIDEBAND);

    const uint16_t payload_size = sideband->system_header.payload_length;
    uint16_t bytes_read = sizeof(system_header_packet_t);
    const uint16_t remaining = payload_size - bytes_read;
    assert(payload_size == sizeof(base_sideband_packet_t));

    bool succesful = wait_for_payload(
        socket_fd, (uint8_t *)&sideband->sideband_header, remaining, remaining);

    print_sideband_packet(sideband, false);

    return succesful;
}

//
// CXL.mem
//

// bool send_cxl_mem_mem_write(int socket_fd, hwaddr hpa, uint8_t *data,
//                             uint16_t *tag)
// {
//     trace_cxl_socket_debug_msg("[Sending Packet] START");

//     *tag = get_next_tag();

//     cxl_mem_m2s_rwd_packet_t packet = {};
//     packet.system_header.payload_type = CXL_MEM;
//     packet.system_header.payload_length = sizeof(packet);
//     packet.cxl_mem_header.cxl_mem_channel_t = M2S_RWD;
//     packet.m2s_rwd_header.valid = 1;
//     packet.m2s_rwd_header.mem_opcode = MEM_WR;
//     packet.m2s_rwd_header.addr = hpa >> 6;
//     memcpy(packet.data, data, CXL_MEM_ACCESS_UNIT);

//     trace_cxl_socket_debug_num("CXL.mem M2S_RWD Packet Size",
//     sizeof(packet));

//     bool successful = write(socket_fd, &packet, sizeof(packet)) != -1;

//     trace_cxl_socket_debug_msg("[Sending Packet] END");

//     return successful;
// }

// bool send_cxl_mem_mem_read(int socket_fd, hwaddr hpa, uint16_t *tag)
// {
//     trace_cxl_socket_debug_msg("[Sending Packet] START");

//     *tag = get_next_tag();

//     cxl_mem_m2s_req_packet_t packet = {};
//     packet.system_header.payload_type = CXL_MEM;
//     packet.system_header.payload_length = sizeof(packet);
//     packet.cxl_mem_header.cxl_mem_channel_t = M2S_REQ;
//     packet.m2s_req_header.valid = 1;
//     packet.m2s_req_header.mem_opcode = MEM_RD;
//     packet.m2s_req_header.addr = hpa >> 6;

//     trace_cxl_socket_debug_num("CXL.mem M2S_REQ Packet Size",
//     sizeof(packet));

//     bool successful = write(socket_fd, &packet, sizeof(packet)) != -1;

//     trace_cxl_socket_debug_msg("[Sending Packet] END");

//     return successful;
// }

// cxl_mem_s2m_ndr_packet_t *wait_for_cxl_mem_completion(int socket_fd,
//                                                       uint16_t tag)
// {
//     while (true) {
//         packet_table_entry_t *entry = get_packet_entry(tag);
//         if (entry->packet_size == sizeof(cxl_mem_s2m_ndr_packet_t)) {
//             return (cxl_mem_s2m_ndr_packet_t *)(entry->packet);
//         }
//         if (!process_incoming_packets(socket_fd)) {
//             return NULL;
//         }
//     }
// }

// cxl_mem_s2m_drs_packet_t *wait_for_cxl_mem_mem_data(int socket_fd, uint16_t
// tag)
// {
//     while (true) {
//         packet_table_entry_t *entry = get_packet_entry(tag);
//         if (entry->packet_size == sizeof(cxl_mem_s2m_drs_packet_t)) {
//             return (cxl_mem_s2m_drs_packet_t *)(entry->packet);
//         }
//         if (!process_incoming_packets(socket_fd)) {
//             return NULL;
//         }
//     }
// }

/*

    CXL.io API

*/

bool wait_for_tlp_header_dw0(int socket_fd, cxl_io_header_t *tlp_dw0)
{
    return wait_for_payload(socket_fd, (uint8_t *)tlp_dw0, sizeof(*tlp_dw0),
                            sizeof(*tlp_dw0));
}

bool wait_for_tlp_header_without_dw0(int socket_fd,
                                     opencxl_tlp_header_t *tlp_header)
{
    size_t header_size = parse_openxcl_tlp_header_size(tlp_header);
    size_t payload_size =
        header_size - sizeof(system_header_packet_t) - sizeof(uint32_t);
    return wait_for_payload(socket_fd, (uint8_t *)&tlp_header->dw1,
                            payload_size, payload_size);
}

/*

    Common Socket API

*/

int32_t create_socket_client(const char *host, uint32_t port)
{
    // Create a socket
    int32_t sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        trace_cxl_socket_debug_msg("Failed to create socket");
        return -1;
    }

    // Set the socket address
    struct sockaddr_in addr;
    struct hostent *he;
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        /* could be a hostname */
        if ((he = gethostbyname(host)) == NULL) {
            trace_cxl_socket_debug_msg("Invalid address or hostname");
            return -1;
        }
        bcopy(he->h_addr_list[0], &addr.sin_addr, he->h_length);
    }

    // Connect to the socket
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        trace_cxl_socket_debug_msg("Failed to connect to socket server");
        return -1;
    }

    struct timeval timeout;
    timeout.tv_sec = MAX_DURATION;  // 5 seconds timeout
    timeout.tv_usec = 0;            // 0 microseconds

    // Set the receive timeout
    // if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
    //                sizeof(timeout)) < 0) {
    //     trace_cxl_socket_debug_msg("setsockopt failed for receive");
    // }

    // Set the send timeout
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
                   sizeof(timeout)) < 0) {
        trace_cxl_socket_debug_msg("setsockopt failed for send");
    }

    return sockfd;
}

bool wait_for_payload(int socket_fd, uint8_t *buffer, size_t buffer_size,
                      size_t payload_size)
{
    time_t start_time = time(NULL);  // Record the start time
    time_t current_time;
    size_t total_bytes_read = 0;
    trace_cxl_socket_debug_num("Waiting for payload, Payload Size",
                               payload_size);
    while (total_bytes_read < payload_size) {
        current_time = time(NULL);

        // Check if the time elapsed exceeds the maximum duration
        if (difftime(current_time, start_time) > MAX_DURATION) {
            trace_cxl_socket_error_msg("Socket timeout exceeded!");
            return false;
        }

        size_t remaining_size = payload_size - total_bytes_read;
        ssize_t bytes_read =
            read(socket_fd, &buffer[total_bytes_read], remaining_size);
        if (bytes_read == 0) {
            trace_cxl_socket_error_msg("Socket connection is disconnected");
            return false;
        } else if (bytes_read == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                trace_cxl_socket_error_msg(
                    "Resource temporarily not available. Retrying");
                continue;
            }
            char msg[100];
            sprintf(msg, "Socket error encountered. Error: %s",
                    strerror(errno));
            trace_cxl_socket_error_msg(msg);
            return false;
        }
        trace_cxl_socket_debug_num("Received data from socket. Bytes Read:", bytes_read);
        if (bytes_read > 0 && bytes_read + total_bytes_read > buffer_size) {
            trace_cxl_socket_error_msg("Buffer overflowed");
            return false;
        }
        if (bytes_read > 0) {
            total_bytes_read += bytes_read;
        }
    }

    trace_cxl_socket_debug_msg("Done Waiting for payload");
    return true;
}

bool wait_for_system_header(int socket_fd,
                            system_header_packet_t *system_header)
{
    trace_cxl_socket_debug_msg("Waiting for OpenCXL System Header");
    bool successful =
        wait_for_payload(socket_fd, (uint8_t *)system_header,
                         sizeof(*system_header), sizeof(*system_header));

    trace_cxl_socket_debug_msg("Received OpenCXL System Header");

    print_system_header(system_header, false);

    return successful;
}

bool send_payload(int socket_fd, uint8_t *buffer, size_t buffer_size)
{
    trace_cxl_socket_debug_msg("Transmitting data over TCP socket");

    char msg[100];
    sprintf(msg, "Socket ID: %d, Buffer Address: %p, Buffer Size: %lu", socket_fd, buffer, buffer_size);
    trace_cxl_socket_debug_msg(msg);

    if (write(socket_fd, buffer, buffer_size) == -1) {
        trace_cxl_socket_error_msg("Failed to transmit data over TCP socket");
        return false;
    }
    trace_cxl_socket_debug_msg("Successfully transmitted data over TCP socket");
    return true;
}
