// clang-format off

// Due to implicit dependencies from QEMU header files, we
// don't want include reordering from clang format.

#include "hw/cxl/opencxl_packet.h"

#include <assert.h>
#include <byteswap.h>
#include <stdbool.h>
#include <stdint.h>

#include "qemu/osdep.h" // NOLINT(unused-includes)
#include "trace.h"
#include "trace/trace-hw_pci_bridge.h"

#include <glib.h>

// clang-format on

const char *tlp_type_names[256] = {
    [0x00] = "MRD_32B",  [0x20] = "MRD_64B", [0x40] = "MWR_32B",
    [0x60] = "MWR_64B",  [0x02] = "IORD",    [0x42] = "IOWR",
    [0x04] = "CFG_RD0",  [0x44] = "CFG_WR0", [0x05] = "CFG_RD1",
    [0x45] = "CFG_WR1",  [0x0A] = "CPL",     [0x4A] = "CPLD",
    [0x10] = "MSG_32B",  [0x30] = "MSG_64B", [0x50] = "MSGD_32B",
    [0x70] = "MSGD_64B",
    // Additional entries can be added here
};

cxl_io_fmt_t parse_opencxl_tlp_fmt(const opencxl_tlp_header_t *tlp_header)
{
    // The format field in the PCI Express header is a combination of bits in
    // the fmt_type. Specifically, the format is determined by the upper 3 bits
    // (7:5) of the fmt_type field.

    uint8_t format =
        (tlp_header->dw0.fmt_type >> 5) & 0x07;  // Extract bits 7:5

    switch (format) {
        case 0b000:
            return TLP_FORMAT_DW3;  // 3DW without data
        case 0b001:
            return TLP_FORMAT_DW4;  // 4DW without data
        case 0b010:
            return TLP_FORMAT_DW3_DATA;  // 3DW with data
        case 0b011:
            return TLP_FORMAT_DW4_DATA;  // 4DW with data
        case 0b100:
            return TLP_FORMAT_PREFIX;  // TLP with prefix
        default:
            return TLP_FORMAT_UNDEFINED;  // Undefined format
    }
}

uint8_t parse_openxcl_tlp_header_size(const opencxl_tlp_header_t *tlp_header)
{
    // Get the TLP format using the parse_cxl_io_fmt function
    cxl_io_fmt_t fmt = parse_opencxl_tlp_fmt(tlp_header);

    // Determine the size of the TLP header based on the format
    uint8_t tlp_header_size = 0;

    switch (fmt) {
        case TLP_FORMAT_DW3:
            tlp_header_size = 12;  // 3DW TLP header size (3 * 4 bytes)
            break;
        case TLP_FORMAT_DW4:
            tlp_header_size = 16;  // 4DW TLP header size (4 * 4 bytes)
            break;
        case TLP_FORMAT_DW3_DATA:
            tlp_header_size = 12;  // 3DW TLP header size with data
            break;
        case TLP_FORMAT_DW4_DATA:
            tlp_header_size = 16;  // 4DW TLP header size with data
            break;
        case TLP_FORMAT_PREFIX:
            tlp_header_size = 4;
            break;
        default:
            tlp_header_size = 0;  // Undefined case, return 0
            break;
    }

    // Return total size: system_header + TLP header size
    return sizeof(tlp_header->system_header) + tlp_header_size;
}

uint16_t parse_opencxl_tlp_header_tag(const opencxl_tlp_header_t *tlp_header)
{
    uint16_t tag = 0;

    // Extract the fmt_type field from dw0 (which includes both format and type)
    switch (tlp_header->dw0.fmt_type) {
        // Handle CFG RD0, WR0, RD1, WR1
        case CFG_RD0:
        case CFG_WR0:
        case CFG_RD1:
        case CFG_WR1: {
            const opencxl_tlp_cfg_header_t *cfg_header =
                (const opencxl_tlp_cfg_header_t *)tlp_header;
            tag = cfg_header->cfg_req_header.tag;
            break;
        }
        // Handle MWR (64B), MRD (64B)
        case MRD_64B:
        case MWR_64B: {
            const opencxl_tlp_mem64_header_t *mem64_header =
                (const opencxl_tlp_mem64_header_t *)tlp_header;
            tag = mem64_header->mreq_header.tag;
            break;
        }
        // Handle MWR (32B), MRD (32B)
        case MRD_32B:
        case MWR_32B: {
            const opencxl_tlp_mem32_header_t *mem32_header =
                (const opencxl_tlp_mem32_header_t *)tlp_header;
            tag = mem32_header->mreq_header.tag;
            break;
        }
        // Handle CPL and CPLD
        case CPL:
        case CPLD: {
            const opencxl_tlp_cpl_header_t *cpl_header =
                (const opencxl_tlp_cpl_header_t *)tlp_header;
            tag = cpl_header->dw2_3.tag;
            break;
        }
        default:
            // trace_cxl_root_error_msg("Unsupported TLP type");
            assert(0);
    }

    return tag;
}

uint16_t parse_opencxl_tlp_data_length(const opencxl_tlp_header_t *tlp_header)
{
    // Mask the 2 bits and shift to upper bits
    uint16_t length_upper = (tlp_header->dw0.length_upper & 0x03) << 8;

    // Mask the 8 lower bits
    uint16_t length_lower = tlp_header->dw0.length_lower & 0xFF;

    // Combine the upper and lower parts to form a 10-bit length
    uint16_t data_length = length_upper | length_lower;

    return data_length * sizeof(uint32_t);
}

uint16_t parse_opencxl_tlp_data_payload_length(
    const opencxl_tlp_header_t *tlp_header)
{
    cxl_io_fmt_t fmt = parse_opencxl_tlp_fmt(tlp_header);
    if (fmt == TLP_FORMAT_DW3 || fmt == TLP_FORMAT_DW4) {
        return 0;
    }
    return parse_opencxl_tlp_data_length(tlp_header);
}

tlp_cpl_status_t parse_opencxl_tlp_cpl_status(
    const opencxl_tlp_header_t *tlp_header)
{
    opencxl_tlp_cpl_header_t *spl_header =
        (opencxl_tlp_cpl_header_t *)tlp_header;

    uint8_t status = spl_header->dw2_3.status;
    switch (status) {
        case TLP_CPL_STATUS_SC:
            return TLP_CPL_STATUS_SC;  // Successful Completion
        case TLP_CPL_STATUS_UR:
            return TLP_CPL_STATUS_UR;  // Unsupported Request
        case TLP_CPL_STATUS_RRS:
            return TLP_CPL_STATUS_RRS;  // Reserved/Retry Status
        case TLP_CPL_STATUS_CA:
            return TLP_CPL_STATUS_CA;  // Completion Abort
        default:
            return TLP_CPL_STATUS_UNDEFIEND;
    }
}

void *parse_opencxl_tlp_data_pointer(const opencxl_tlp_header_t *tlp_header)
{
    // First, determine the size of the header
    uint8_t header_size = parse_openxcl_tlp_header_size(tlp_header);

    // The data pointer is located immediately after the header
    // Cast the TLP header to a byte pointer and then offset by the header size
    void *data_pointer = (void *)((uint8_t *)tlp_header + header_size);

    return data_pointer;
}

uint32_t parse_opencxl_mem32_address(const opencxl_tlp_header_t *tlp_header)
{
    assert(tlp_header->dw0.fmt_type == MRD_32B ||
           tlp_header->dw0.fmt_type == MWR_32B);
    uint32_t address = bswap_32(tlp_header->dw2) & 0xFFFFFFFC;
    return address;
}

uint64_t parse_opencxl_mem64_address(const opencxl_tlp_header_t *tlp_header)
{
    assert(tlp_header->dw0.fmt_type == MRD_64B ||
           tlp_header->dw0.fmt_type == MWR_64B);
    uint64_t address = bswap_32(tlp_header->dw2);
    address <<= 32;
    address |= (bswap_32(tlp_header->dw3) & 0xFFFFFFFC);
    return address;
}

uint64_t parse_opencxl_mem_address(const opencxl_tlp_header_t *tlp_header)
{
    if (tlp_header->dw0.fmt_type == MRD_32B ||
        tlp_header->dw0.fmt_type == MWR_32B) {
        return (uint64_t)(parse_opencxl_mem32_address(tlp_header));
    } else if (tlp_header->dw0.fmt_type == MRD_64B ||
               tlp_header->dw0.fmt_type == MWR_64B) {
        return parse_opencxl_mem64_address(tlp_header);
    } else {
        trace_cxl_opencxl_packet_error_msg("Unexpected TLP Type");
        assert(0);
    }
}

uint16_t parse_opencxl_req_id(const opencxl_tlp_header_t *tlp_header)
{
    uint16_t req_id;
    switch (tlp_header->dw0.fmt_type) {
        case MWR_64B:
        case MRD_64B: {
            opencxl_tlp_mem64_header_t *mem_header =
                (opencxl_tlp_mem64_header_t *)tlp_header;
            req_id = bswap_16(mem_header->mreq_header.req_id);
            break;
        }
        case MWR_32B:
        case MRD_32B: {
            opencxl_tlp_mem32_header_t *mem_header =
                (opencxl_tlp_mem32_header_t *)tlp_header;
            req_id = bswap_16(mem_header->mreq_header.req_id);
            break;
        }
        case CFG_WR0:
        case CFG_WR1:
        case CFG_RD0:
        case CFG_RD1: {
            opencxl_tlp_cfg_header_t *cfg_header =
                (opencxl_tlp_cfg_header_t *)tlp_header;
            req_id = bswap_16(cfg_header->cfg_req_header.req_id);
            break;
        }
        case CPL:
        case CPLD: {
            opencxl_tlp_cpl_header_t *cpl_header =
                (opencxl_tlp_cpl_header_t *)tlp_header;
            req_id = bswap_16(cpl_header->dw2_3.req_id);
            break;
        }
        default:
            trace_cxl_opencxl_packet_error_msg("Unexpected TLP Type");
            assert(0);
    }
    return req_id;
}

uint32_t get_cfg_rd_data_with_be(uint32_t data, uint8_t be)
{
    // Ensure that be is non-zero and uses only the lower 4 bits
    assert(be > 0 && (be >> 4 == 0));

    // Count number of bits set in be
    int num_bits_set = __builtin_popcount(be);
    if (num_bits_set == 4) {
        return data;
    }

    // Count trailing zeros in be
    int trailing_zeros = __builtin_ctz(be);

    // Check that the bits set in be are contiguous
    uint8_t be_shifted = be >> trailing_zeros;
    assert((be_shifted & (be_shifted + 1)) == 0);

    // Shift and mask based on trailing zeros and number of set bits
    uint32_t mask = ((1U << (num_bits_set * 8)) - 1);
    data >>= (trailing_zeros * 8);
    return mask & data;
}

uint32_t get_cfg_wr_data_with_be(uint32_t data, uint8_t be)
{
    // Ensure that be is non-zero and uses only the lower 4 bits
    assert(be > 0 && (be >> 4 == 0));

    // Count number of bits set in be
    int num_bits_set = __builtin_popcount(be);
    if (num_bits_set == 4) {
        return data;
    }

    // Count trailing zeros in be
    int trailing_zeros = __builtin_ctz(be);

    // Check that the bits set in be are contiguous
    uint8_t be_shifted = be >> trailing_zeros;
    assert((be_shifted & (be_shifted + 1)) == 0);

    // Ensure data fits within the enabled byte window
    uint64_t max_data_value = (1ULL << (num_bits_set * 8)) - 1;
    assert(data <= max_data_value);

    // Shift the data to the correct position and mask the result
    uint32_t shift_amount = trailing_zeros * 8;
    uint32_t shifted_data = data << shift_amount;
    uint32_t mask = ((1ULL << (num_bits_set * 8)) - 1) << shift_amount;
    return shifted_data & mask;
}

uint64_t get_mmio_rd_data_with_be(uint64_t data, uint8_t first_be,
                                  uint8_t last_be)
{
    assert(first_be > 0 && (first_be >> 4 == 0));
    assert(last_be >> 4 == 0);

    // Combine first_be and last_be into a single 8-bit enable
    uint16_t combined_be = ((uint16_t)last_be << 4) | first_be;

    // Count number of bits set in combined_be
    int num_bits_set = __builtin_popcount(combined_be);
    if (num_bits_set == 8) {
        return data;
    }

    // Count trailing zeros in combined_be
    int trailing_zeros = __builtin_ctz(combined_be);

    // Check that the bits set in combined_be are contiguous
    uint16_t be_shifted = combined_be >> trailing_zeros;
    assert((be_shifted & (be_shifted + 1)) == 0);

    // Shift and mask data based on trailing zeros and number of set bits
    uint64_t mask = (1ULL << (num_bits_set * 8)) - 1;
    data >>= (trailing_zeros * 8);
    return data * mask;
}

uint64_t get_mmio_wr_data_with_be(uint64_t data, uint8_t first_be,
                                  uint8_t last_be)
{
    assert(first_be > 0 && (first_be >> 4 == 0));
    assert(last_be >> 4 == 0);

    // Combine first_be and last_be into a single 8-bit enable
    uint16_t combined_be = ((uint16_t)last_be << 4) | first_be;

    // Count number of bits set in combined_be
    int num_bits_set = __builtin_popcount(combined_be);

    if (num_bits_set == 8) {
        return data;
    }

    // Count trailing zeros in combined_be
    int trailing_zeros = __builtin_ctz(combined_be);

    // Check that the bits set in combined_be are contiguous
    uint16_t be_shifted = combined_be >> trailing_zeros;
    assert((be_shifted & (be_shifted + 1)) == 0);

    // Ensure data fits within the enabled byte window
    uint64_t max_data_value = (1ULL << (num_bits_set * 8)) - 1;
    assert(data <= max_data_value);

    // Shift and mask data based on trailing zeros and number of set bits
    uint64_t shift_amount = trailing_zeros * 8;
    uint64_t shifted_data = data << shift_amount;
    uint64_t mask = (1ULL << (num_bits_set * 8)) - 1;
    mask <<= shift_amount;
    return shifted_data & mask;
}

void get_tlp_reg_num_and_be(uint32_t offset, uint8_t size, uint16_t *reg_num,
                            uint8_t *be)
{
    // Ensure that size is between 1 and 4
    assert(size >= 1 && size <= 4);

    // Extract the byte offset within the DWORD
    uint8_t byte_offset = offset & 0x3;  // Extract the lower 2 bits

    // Ensure that offset + size doesn't cross the DWORD boundary
    assert(byte_offset + size <= 4);

    // Extract reg_num from the upper bits of the offset (offset[15:2] gives the
    // DWORD address)
    *reg_num =
        (offset >> 2) & 0xFFFF;  // Extract offset[15:2] and store it in reg_num

    // Initialize the byte enable (BE) value to 0
    *be = 0;

    // Set the appropriate bits in the BE based on size and byte_offset
    for (uint8_t i = 0; i < size; ++i) {
        *be |=
            (1 << (byte_offset +
                   i));  // Enable the byte positions corresponding to the size
    }
}

void get_tlp_length_and_be(uint64_t addr, uint8_t size, uint16_t *length_dw,
                           uint8_t *first_be, uint8_t *last_be)
{
    // Ensure that size is between 1 and 8 (we assume size fits within this
    // range)
    assert(size >= 1 && size <= 8);

    // Calculate the byte offset within the first DW
    uint8_t byte_offset =
        addr & 0x3;  // Get the lower 2 bits of the address (offset within DW)

    uint16_t start_position = byte_offset;       // Inclusive
    uint16_t end_position = byte_offset + size;  // Exclusive

    // Calculate the number of DWORDs the transaction spans
    if (end_position % 4 == 0) {
        *length_dw = end_position / 4;
    } else {
        *length_dw = end_position / 4 + 1;
    }

    *first_be = 0;
    *last_be = 0;

    if (*length_dw == 1) {
        for (uint8_t byte_offset = start_position; byte_offset < end_position;
             ++byte_offset) {
            *first_be |= (1 << byte_offset);
        }
    } else {  // *length_dw >= 2
        for (uint8_t byte_offset = start_position; byte_offset < 4;
             ++byte_offset) {
            *first_be |= (1 << byte_offset);
        }
        for (uint8_t byte_offset = 0; byte_offset <= (end_position - 1) % 4;
             ++byte_offset) {
            *last_be |= (1 << byte_offset);
        }
    }
}

static void fill_tlp_mem64_header(opencxl_tlp_header_t *tlp_header,
                                  cxl_io_fmt_type_t fmt_type, uint16_t req_id,
                                  uint64_t addr, uint16_t length_dw,
                                  uint8_t first_dw_be, uint8_t last_dw_be,
                                  uint16_t tag)
{
    assert(length_dw <= 0x3FF);
    assert(first_dw_be <= 0xF);
    assert(last_dw_be <= 0xF);
    assert(tag <= 0xFF);  // Supports 8-bit tag only for now.

    opencxl_tlp_mem64_header_t *mem64_header =
        (opencxl_tlp_mem64_header_t *)tlp_header;
    mem64_header->cxl_io_header.fmt_type = fmt_type;
    mem64_header->cxl_io_header.length_upper = (length_dw >> 8) & 0x3;
    mem64_header->cxl_io_header.length_lower = length_dw & 0xFF;

    mem64_header->mreq_header.req_id = bswap_16(req_id);
    mem64_header->mreq_header.tag = tag;
    mem64_header->mreq_header.addr_lower = (addr & 0xFF) >> 2;
    mem64_header->mreq_header.addr_upper = bswap_64(addr) & 0xFFFFFFFFFFFFFF;
    mem64_header->mreq_header.first_dw_be = first_dw_be;
    mem64_header->mreq_header.last_dw_be = last_dw_be;
}

void fill_tlp_mwr_header(opencxl_tlp_header_t *tlp_header, uint16_t req_id,
                         uint64_t addr, uint16_t length_dw, uint8_t first_dw_be,
                         uint8_t last_dw_be, uint16_t tag)
{
    fill_tlp_mem64_header(tlp_header, MWR_64B, req_id, addr, length_dw,
                          first_dw_be, last_dw_be, tag);
}

void fill_tlp_mrd_header(opencxl_tlp_header_t *tlp_header, uint16_t req_id,
                         uint64_t addr, uint32_t length_dw, uint8_t first_dw_be,
                         uint8_t last_dw_be, uint16_t tag)
{
    fill_tlp_mem64_header(tlp_header, MRD_64B, req_id, addr, length_dw,
                          first_dw_be, last_dw_be, tag);
}

static void fill_cfg_header(opencxl_tlp_header_t *tlp_header,
                            cxl_io_fmt_type_t fmt_type, uint16_t req_id,
                            uint16_t dest_id, uint16_t reg_num, uint8_t be,
                            uint16_t tag)
{
    assert(reg_num <= 0x3FF);
    assert(be <= 0xF);
    assert(tag <= 0xFF);  // Supports 8-bit tag only for now.

    opencxl_tlp_cfg_header_t *cfg_header =
        (opencxl_tlp_cfg_header_t *)tlp_header;

    cfg_header->cxl_io_header.fmt_type = fmt_type;
    cfg_header->cxl_io_header.length_upper = 0;
    cfg_header->cxl_io_header.length_lower = 1;

    cfg_header->cfg_req_header.req_id = bswap_16(req_id);
    cfg_header->cfg_req_header.tag = tag;
    cfg_header->cfg_req_header.first_dw_be = be;
    cfg_header->cfg_req_header.last_dw_be = 0;
    cfg_header->cfg_req_header.dest_id = bswap_16(dest_id);
    cfg_header->cfg_req_header.ext_reg_num = (reg_num >> 6) & 0xF;
    cfg_header->cfg_req_header.reg_num = (reg_num) & 0x3F;
}

void fill_cfg_rd_header(opencxl_tlp_header_t *tlp_header, uint16_t req_id,
                        uint16_t dest_id, uint16_t reg_num, uint8_t be,
                        uint16_t tag, bool type0)
{
    fill_cfg_header(tlp_header, type0 ? CFG_RD0 : CFG_RD1, req_id, dest_id,
                    reg_num, be, tag);
}

void fill_cfg_wr_header(opencxl_tlp_header_t *tlp_header, uint16_t req_id,
                        uint16_t dest_id, uint16_t reg_num, uint8_t be,
                        uint16_t tag, bool type0)
{
    fill_cfg_header(tlp_header, type0 ? CFG_WR0 : CFG_WR1, req_id, dest_id,
                    reg_num, be, tag);
}

void fill_cpl_header(opencxl_tlp_header_t *tlp_header, uint16_t req_id,
                     uint16_t cpl_id, uint16_t length_dw,
                     tlp_cpl_status_t status, uint16_t byte_counts,
                     uint8_t lower_addr, uint16_t tag)
{
    assert(status < (uint8_t)(TLP_CPL_STATUS_UNDEFIEND));
    assert(length_dw < (1 << 10));
    assert(lower_addr < (1 << 7));
    assert(byte_counts < (1 << 12));
    assert(tag <= 0xFF);  // Supports 8-bit tag only for now.

    opencxl_tlp_cpl_header_t *cpl_header = (opencxl_tlp_cpl_header_t *)tlp_header;
    cpl_header->dw0.fmt_type = length_dw == 0 ? CPL : CPLD;
    cpl_header->dw0.length_upper = (length_dw >> 8) & 0x3;
    cpl_header->dw0.length_lower = length_dw & 0xFF;

    cpl_header->dw2_3.req_id = bswap_16(req_id);
    cpl_header->dw2_3.cpl_id = bswap_16(cpl_id);
    cpl_header->dw2_3.status = (uint8_t)status;
    cpl_header->dw2_3.byte_count_lower = byte_counts & 0xFF;
    cpl_header->dw2_3.byte_count_upper = (byte_counts >> 8) & 0xF;
    cpl_header->dw2_3.lower_addr = lower_addr & 0x7F;
    cpl_header->dw2_3.tag = tag & 0xFF;
}

bool parse_opencxl_tlp_response_expected(const opencxl_tlp_header_t *tlp_header)
{
    bool resp_expected = false;

    cxl_io_fmt_type_t fmt_type = tlp_header->dw0.fmt_type;
    switch (fmt_type) {
        case CPL:
        case CPLD:
        case MRD_64B:
        case CFG_RD0:
        case CFG_RD1:
        case CFG_WR0:
        case CFG_WR1:
            resp_expected = true;
            break;
        case MWR_64B:
            resp_expected = false;
            break;
        default:
            assert(0);
    }

    return resp_expected;
}

void print_system_header(system_header_packet_t *system_header, bool is_tx)
{
    if (!trace_event_get_state(TRACE_CXL_OPENCXL_PACKET_DEBUG_MSG)) {
        return;
    }

    const char *tx_header = "[OpenCXL] TX";
    const char *rx_header = "[OpenCXL] RX";
    const char *log_header = is_tx ? tx_header : rx_header;
    char msg[100];

    sprintf(msg, "%s: SystemHeader, Payload Type: %u, Payload Length: %u",
            log_header, system_header->payload_type,
            system_header->payload_length);
    trace_cxl_opencxl_packet_debug_msg(msg);
}

void print_sideband_packet(base_sideband_packet_t *sb_header, bool is_tx)
{
    const char *tx_header = "[OpenCXL] TX";
    const char *rx_header = "[OpenCXL] RX";
    const char *log_header = is_tx ? tx_header : rx_header;
    char msg[100];

    sprintf(msg, "%s: SystemHeader, Payload Type: %u, Payload Length: %u",
            log_header, sb_header->system_header.payload_type,
            sb_header->system_header.payload_length);
    trace_cxl_opencxl_packet_debug_msg(msg);

    sprintf(msg, "%s: Sideband Header. Type: %d", log_header,
            sb_header->sideband_header.type);
    trace_cxl_opencxl_packet_debug_msg(msg);
}

static void print_io_mreq_64(const char *log_header,
                             opencxl_tlp_header_t *tlp_header)
{
    char msg[100];
    opencxl_tlp_mem64_header_t *mem_header =
        (opencxl_tlp_mem64_header_t *)tlp_header;

    sprintf(msg,
            "%s: TLP DW1 (0x%08x), REQ ID: 0x%04x, Tag: %d, Last "
            "BE: 0x%x, First BE: 0x%x",
            log_header, tlp_header->dw1,
            bswap_16(mem_header->mreq_header.req_id),
            mem_header->mreq_header.tag, mem_header->mreq_header.last_dw_be,
            mem_header->mreq_header.first_dw_be);
    trace_cxl_opencxl_packet_debug_msg(msg);

    uint64_t address = parse_opencxl_mem64_address(tlp_header);
    sprintf(msg, "%s: TLP DW2/3 (0x%08x, 0x%08x), Address: 0x%16lx", log_header,
            tlp_header->dw2, tlp_header->dw3, address);
    trace_cxl_opencxl_packet_debug_msg(msg);
}

static void print_io_mreq_32(const char *log_header,
                             opencxl_tlp_header_t *tlp_header)
{
    char msg[100];
    opencxl_tlp_mem32_header_t *mem_header =
        (opencxl_tlp_mem32_header_t *)tlp_header;

    sprintf(msg,
            "%s: TLP DW1 (0x%08x), REQ ID: 0x%04x, Tag: %d, Last "
            "BE: 0x%x, First BE: 0x%x",
            log_header, tlp_header->dw1,
            bswap_16(mem_header->mreq_header.req_id),
            mem_header->mreq_header.tag, mem_header->mreq_header.last_dw_be,
            mem_header->mreq_header.first_dw_be);
    trace_cxl_opencxl_packet_debug_msg(msg);

    uint32_t address = parse_opencxl_mem32_address(tlp_header);
    sprintf(msg, "%s: TLP DW2 (0x%08x), Address: 0x%8x", log_header,
            tlp_header->dw2, address);
    trace_cxl_opencxl_packet_debug_msg(msg);
}

static void print_io_cfg(const char *log_header,
                         opencxl_tlp_header_t *tlp_header)
{
    char msg[100];
    opencxl_tlp_cfg_header_t *cfg_header =
        (opencxl_tlp_cfg_header_t *)tlp_header;
    sprintf(msg,
            "%s: TLP DW1 (0x%08x), REQ ID: 0x%04x, Tag: %d, Last "
            "BE: 0x%x, First BE: 0x%x",
            log_header, tlp_header->dw1,
            bswap_16(cfg_header->cfg_req_header.req_id),
            cfg_header->cfg_req_header.tag,
            cfg_header->cfg_req_header.last_dw_be,
            cfg_header->cfg_req_header.first_dw_be);
    trace_cxl_opencxl_packet_debug_msg(msg);

    sprintf(msg,
            "%s: TLP DW2 (0x%08x), DST ID: 0x%04x, Reg Num: "
            "0x%03x",
            log_header, tlp_header->dw2,
            bswap_16(cfg_header->cfg_req_header.dest_id),
            (cfg_header->cfg_req_header.ext_reg_num << 6) |
                cfg_header->cfg_req_header.reg_num);
    trace_cxl_opencxl_packet_debug_msg(msg);

    cxl_io_fmt_type_t fmt_type = tlp_header->dw0.fmt_type;
    if (fmt_type == CFG_WR0 || fmt_type == CFG_WR1) {
        uint32_t *data = (uint32_t *)parse_opencxl_tlp_data_pointer(tlp_header);
        uint16_t data_length_dw = parse_opencxl_tlp_data_length(tlp_header) / 4;

        for (uint16_t dw_index = 0; dw_index < data_length_dw; ++dw_index) {
            sprintf(msg, "%s: TLP DW%d (0x%08x)", log_header, dw_index + 3,
                    data[dw_index]);
            trace_cxl_opencxl_packet_debug_msg(msg);
        }
    }
}

static void print_io_cpl(const char *log_header,
                         opencxl_tlp_header_t *tlp_header)
{
    char msg[100];
    opencxl_tlp_cpl_header_t *cpl_header =
        (opencxl_tlp_cpl_header_t *)tlp_header;

    sprintf(msg,
            "%s: TLP DW1 (0x%08x), CPL ID: 0x%04x, Status: %d, "
            "Bytes Count: %d",
            log_header, tlp_header->dw1, bswap_16(cpl_header->dw2_3.cpl_id),
            cpl_header->dw2_3.status,
            (cpl_header->dw2_3.byte_count_upper << 8) |
                cpl_header->dw2_3.byte_count_lower);
    trace_cxl_opencxl_packet_debug_msg(msg);

    sprintf(msg,
            "%s: TLP DW2 (0x%08x), REQ ID: 0x%04x, Tag: %d, "
            "Lower Address: %02x",
            log_header, tlp_header->dw2, bswap_16(cpl_header->dw2_3.req_id),
            cpl_header->dw2_3.tag, cpl_header->dw2_3.lower_addr);
    trace_cxl_opencxl_packet_debug_msg(msg);

    cxl_io_fmt_type_t fmt_type = tlp_header->dw0.fmt_type;
    if (fmt_type == CPLD) {
        uint32_t *data = (uint32_t *)parse_opencxl_tlp_data_pointer(tlp_header);
        uint16_t data_length_dw = ((cpl_header->dw2_3.byte_count_upper << 8) |
                                   cpl_header->dw2_3.byte_count_lower) /
                                  4;
        for (uint16_t dw_index = 0; dw_index < data_length_dw; ++dw_index) {
            sprintf(msg, "%s: TLP DW%d (0x%08x)", log_header, dw_index + 3,
                    data[dw_index]);
            trace_cxl_opencxl_packet_debug_msg(msg);
        }
    }
}

void print_io_packet(opencxl_tlp_header_t *tlp_header, bool is_tx)
{
    const char *tx_header = "[OpenCXL] TX";
    const char *rx_header = "[OpenCXL] RX";
    const char *log_header = is_tx ? tx_header : rx_header;
    char msg[100];

    sprintf(msg, "%s: SystemHeader, Payload Type: %u, Payload Length: %u",
            log_header, tlp_header->system_header.payload_type,
            tlp_header->system_header.payload_length);
    trace_cxl_opencxl_packet_debug_msg(msg);

    cxl_io_fmt_type_t fmt_type = tlp_header->dw0.fmt_type;
    const char *fmt_type_str = tlp_type_names[fmt_type];
    sprintf(msg, "%s: TLP Format: %s", log_header, fmt_type_str);
    trace_cxl_opencxl_packet_debug_msg(msg);

    sprintf(msg, "%s: TLP DW0 (0x%08x), Format/Type: 0x%02x, Length: %u",
            log_header, *(uint32_t *)&tlp_header->dw0, tlp_header->dw0.fmt_type,
            (tlp_header->dw0.length_upper) << 8 | tlp_header->dw0.length_lower);
    trace_cxl_opencxl_packet_debug_msg(msg);

    switch (fmt_type) {
        case MRD_64B:
        case MWR_64B:
            print_io_mreq_64(log_header, tlp_header);
            break;
        case MRD_32B:
        case MWR_32B:
            print_io_mreq_32(log_header, tlp_header);
            break;
        case CFG_RD0:
        case CFG_RD1:
        case CFG_WR0:
        case CFG_WR1:
            print_io_cfg(log_header, tlp_header);
            break;
        case CPL:
        case CPLD:
            print_io_cpl(log_header, tlp_header);
            break;
        default:
            trace_cxl_opencxl_packet_error_msg("Unsupported TLP type");
            assert(0);
    }
}
