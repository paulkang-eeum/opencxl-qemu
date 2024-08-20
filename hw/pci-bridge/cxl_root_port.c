/*
 * CXL 2.0 Root Port Implementation
 *
 * Copyright(C) 2020 Intel Corporation.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/range.h"
#include "hw/pci/pci_bridge.h"
#include "hw/pci/pcie_port.h"
#include "hw/pci/msi.h"
#include "hw/qdev-properties.h"
#include "hw/sysbus.h"
#include "qapi/error.h"
#include "hw/cxl/cxl.h"
#include "hw/cxl/cxl_emulator_packet.h"
#include "hw/cxl/cxl_socket_transport.h"
#include "hw/pci-bridge/pci_expander_bridge.h"
#include "standard-headers/linux/pci_regs.h"
#include "trace.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define CXL_ROOT_PORT_DID 0x7075

#define CXL_RP_MSI_OFFSET 0x60
#define CXL_RP_MSI_SUPPORTED_FLAGS PCI_MSI_FLAGS_MASKBIT
#define CXL_RP_MSI_NR_VECTOR 2

/* Copied from the gen root port which we derive */
#define GEN_PCIE_ROOT_PORT_AER_OFFSET 0x100
#define GEN_PCIE_ROOT_PORT_ACS_OFFSET \
    (GEN_PCIE_ROOT_PORT_AER_OFFSET + PCI_ERR_SIZEOF)
#define CXL_ROOT_PORT_DVSEC_OFFSET \
    (GEN_PCIE_ROOT_PORT_ACS_OFFSET + PCI_ACS_SIZEOF)


typedef enum REMOTE_MEMORY_STATE {
    REMOTE_MEMORY_UNINIT = 0,
    REMOTE_MEMORY_SIZE_DISCOVERY,
    REMOTE_MEMORY_SIZE_SET,
    REMOTE_MEMORY_ADDRESS_SET  
} remote_memory_state_t;

typedef struct RemoteMemoryRegion {
    MemoryRegion mr;
    remote_memory_state_t state;
    bool is_high_address;
    hwaddr address;
    uint64_t size_lower;
    uint64_t size;
    PCIDevice *root_port;
    uint16_t bdf;
} remote_memory_region_t;

#define MAX_PCI_DEVICES 0x10000

typedef struct RemoteDeviceInfo {
    remote_memory_region_t memory_regions[PCI_NUM_REGIONS];
    bool found;
    bool type0;
} remote_device_info_t;

typedef struct CXLRootPort {
    /*< private >*/
    PCIESlot parent_obj;

    CXLComponentState cxl_cstate;
    PCIResReserve res_reserve;

    char *socket_host;
    uint32_t socket_port;
    uint32_t switch_port;
    int socket_fd;
    remote_device_info_t remote_devices[MAX_PCI_DEVICES];
} CXLRootPort;


#define TYPE_CXL_ROOT_PORT "cxl-rp"
DECLARE_INSTANCE_CHECKER(CXLRootPort, CXL_ROOT_PORT, TYPE_CXL_ROOT_PORT)

typedef struct cxl_mem_rw_buffer_struct {
    hwaddr page_num[CXL_RW_NUM_BUFFERS];
    uint64_t last_access_time[CXL_RW_NUM_BUFFERS];
    uint8_t data[CXL_RW_NUM_BUFFERS][CXL_MEM_ACCESS_UNIT];
    bool inited[CXL_RW_NUM_BUFFERS];
} cxl_mem_rw_buffer_struct;

static cxl_mem_rw_buffer_struct cxl_mem_rw_buffer = {
    .page_num = { 0 },
    .last_access_time = { 0 },
    .inited = { 0 },
};

bool cxl_is_remote_root_port(PCIDevice *d)
{
    if (!object_dynamic_cast(OBJECT(d), TYPE_CXL_ROOT_PORT)) {
        return false;
    }
    CXLRootPort *crp = CXL_ROOT_PORT(d);
    return crp->socket_host != NULL;
}

PCIDevice *cxl_get_root_port(PCIDevice *d)
{
    PCIBus *bus = pci_get_bus(d);

    while (!pci_bus_is_root(bus)) {
        d = bus->parent_dev;
        if (cxl_is_remote_root_port(d)) {
            return d;
        }

        bus = pci_get_bus(d);
    }
    return NULL;
}

PCIDevice *cxl_get_remote_root_port(uint8_t bus_nr) {
    PCIDevice *bridge = find_pxb_bridge_device_from_bus_nr(bus_nr);
    if (bridge == NULL) {
        return NULL;
    }

    if (!cxl_is_remote_root_port(bridge)) {
        return NULL;
    }

    trace_cxl_root_cxl_remote_root_port(bus_nr);
    return bridge;
}


MemTxResult cxl_remote_cxl_mem_read_with_cache(PCIDevice *d, hwaddr host_addr,
                                               uint64_t *data, unsigned size,
                                               MemTxAttrs attrs)
{
    uint64_t cache_candidate = cxl_get_dest_cache(d, host_addr, attrs);
    memcpy(data,
           &cxl_mem_rw_buffer
                .data[cache_candidate][host_addr & CXL_MEM_ACCESS_OFFSET_MASK],
           size);
    return MEMTX_OK;
}

MemTxResult cxl_remote_cxl_mem_read(PCIDevice *d, hwaddr host_addr,
                                    uint8_t *data, unsigned size,
                                    MemTxAttrs attrs)
{
    trace_cxl_root_cxl_cxl_mem_read(host_addr);

    CXLRootPort *crp = CXL_ROOT_PORT(d);

    uint16_t tag;
    if (!send_cxl_mem_mem_read(crp->socket_fd, host_addr, &tag)) {
        trace_cxl_root_debug_message("Failed to send CXL.mem MEM RD request");
        *data = 0xFF;
        return MEMTX_OK;
    }

    cxl_mem_s2m_drs_packet_t *cxl_packet =
        wait_for_cxl_mem_mem_data(crp->socket_fd, tag);
    if (cxl_packet == NULL) {
        release_packet_entry(tag);
        trace_cxl_root_debug_message("Failed to get CXL.mem MEM DATA response");
        *data = 0xFF;
        return MEMTX_OK;
    }

    memcpy(data, cxl_packet->data, CXL_MEM_ACCESS_UNIT);
    release_packet_entry(tag);

    return MEMTX_OK;
}

uint64_t cxl_get_dest_cache(PCIDevice *d, hwaddr host_addr, MemTxAttrs attrs)
{
    /* TODO: maybe a lock mechanism here? */
    uint32_t cache_idx;
    bool cache_hit = false;
    uint64_t oldest_cache_ts = ULLONG_MAX;
    int oldest_cache_candidate = -1;

    for (cache_idx = 0; cache_idx < CXL_RW_NUM_BUFFERS; cache_idx++) {
        if (!cxl_mem_rw_buffer.inited[cache_idx]) {
            cxl_mem_rw_buffer.inited[cache_idx] = true;
            cxl_mem_rw_buffer.page_num[cache_idx] = host_addr >> 6;
        }
        if (cxl_mem_rw_buffer.page_num[cache_idx] == host_addr >> 6) {
            cache_hit = true;
            cxl_mem_rw_buffer.last_access_time[cache_idx] =
                qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
            break;
        }
        if (cxl_mem_rw_buffer.last_access_time[cache_idx] < oldest_cache_ts) {
            oldest_cache_ts = cxl_mem_rw_buffer.last_access_time[cache_idx];
            oldest_cache_candidate = cache_idx;
        }
    }
    if (!cache_hit) {
        if (unlikely(oldest_cache_candidate == -1)) {
            oldest_cache_candidate = 0;
            trace_cxl_root_debug_message(
                "unexpected: oldest_cache_candidate is -1\n");
        }
        /* Flush an existing cache to the backend */
        cache_idx = oldest_cache_candidate;
        cxl_remote_cxl_mem_write(d, cxl_mem_rw_buffer.page_num[cache_idx] << 6,
                                 &cxl_mem_rw_buffer.data[cache_idx][0],
                                 CXL_MEM_ACCESS_UNIT, attrs);
        cxl_mem_rw_buffer.page_num[cache_idx] = host_addr >> 6;
        cxl_mem_rw_buffer.last_access_time[cache_idx] =
            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        /* Bring the data from backend to the cache */
        cxl_remote_cxl_mem_read(d, host_addr,
                                &cxl_mem_rw_buffer.data[cache_idx][0],
                                CXL_MEM_ACCESS_UNIT, attrs);
    }
    return cache_idx;
}

MemTxResult cxl_remote_cxl_mem_write_with_cache(PCIDevice *d, hwaddr host_addr,
                                                uint64_t data, unsigned size,
                                                MemTxAttrs attrs)
{
    uint64_t cache_candidate = cxl_get_dest_cache(d, host_addr, attrs);
    memcpy(&cxl_mem_rw_buffer
                .data[cache_candidate][host_addr & CXL_MEM_ACCESS_OFFSET_MASK],
           &data, size);
    return MEMTX_OK;
}

MemTxResult cxl_remote_cxl_mem_write(PCIDevice *d, hwaddr host_addr,
                                     uint8_t *data, unsigned size,
                                     MemTxAttrs attrs)
{
    trace_cxl_root_cxl_cxl_mem_write(host_addr);

    CXLRootPort *crp = CXL_ROOT_PORT(d);

    uint16_t tag;

    if (!send_cxl_mem_mem_write(crp->socket_fd, host_addr, data, &tag)) {
        trace_cxl_root_debug_message("Failed to send CXL.mem MEM WR request");
        return MEMTX_OK;
    }

    cxl_mem_s2m_ndr_packet_t *cxl_packet =
        wait_for_cxl_mem_completion(crp->socket_fd, tag);
    release_packet_entry(tag);
    if (cxl_packet == NULL) {
        trace_cxl_root_debug_message("Failed to get CXL.mem MEM DATA response");
        return MEMTX_OK;
    }

    return MEMTX_OK;
}

static bool is_type0_config_request(PCIDevice *root_port, uint16_t bdf)
{
    uint8_t secondary_bus = root_port->config[PCI_SECONDARY_BUS];
    uint16_t bus = bdf >> 8;
    return bus == secondary_bus;
}

static bool is_valid_bdf(PCIDevice *d, uint16_t bdf)
{
    uint8_t secondary_bus = d->config[PCI_SECONDARY_BUS];
    uint8_t subordinate_bus = d->config[PCI_SUBORDINATE_BUS];
    uint16_t bus = bdf >> 8;
    return bus >= secondary_bus && bus <= subordinate_bus;
}

static void cxl_remote_device_check_device(CXLRootPort *crp, uint16_t bdf, uint32_t offset, uint32_t value, int size) {
    const uint8_t bus = bdf >> 8;
    const uint8_t device = (bdf >> 3) & 0x1F;
    const uint8_t function = bdf & 0x7;
    if (offset == PCI_VENDOR_ID) {
        if ((size == 4 && value != 0xFFFFFFFF) || (size == 2 && value != 0xFFFF)) {
            crp->remote_devices[bdf].found = true;
            trace_cxl_root_cxl_remote_found(bus, device, function);
        }
    }
}

static void cxl_remote_cxl_io_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                            unsigned size)
{
    remote_memory_region_t *region = opaque;
    CXLRootPort *crp = CXL_ROOT_PORT(region->root_port);
    const uint16_t bdf = region->bdf;
    const uint8_t bus = bdf >> 8;
    const uint8_t device = (bdf >> 3) & 0x1F;
    const uint8_t function = bdf & 0x7;
    addr += region->address;

    trace_cxl_root_cxl_io_mmio_write(bus, device, function, addr, size, val);
    uint16_t tag;

    if (!send_cxl_io_mem_write(crp->socket_fd, addr, val, size, &tag)) {
        trace_cxl_root_debug_message("Failed to send CXL.io MEM WR request");
        assert(0);
    }

    release_packet_entry(tag);
}

static uint64_t cxl_remote_cxl_io_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    remote_memory_region_t *region = opaque;
    CXLRootPort *crp = CXL_ROOT_PORT(region->root_port);
    const uint16_t bdf = region->bdf;
    const uint8_t bus = bdf >> 8;
    const uint8_t device = (bdf >> 3) & 0x1F;
    const uint8_t function = bdf & 0x7;
    addr += region->address;

    trace_cxl_root_cxl_io_mmio_read(bus, device, function, addr, size);

    uint16_t tag;
    if (!send_cxl_io_mem_read(crp->socket_fd, addr, size, &tag)) {
        trace_cxl_root_debug_message("Failed to send CXL.io MEM RD request");
        assert(0);
    }

    uint64_t val;
    size_t packet_size =
        wait_for_cxl_io_completion_data(crp->socket_fd, tag, &val);
    if (packet_size == 0) {
        release_packet_entry(tag);
        trace_cxl_root_debug_message("Failed to get CXL.io CPLD response");
        assert(0);
    }

    trace_cxl_root_cxl_io_mmio_cpld(bus, device, function, val);

    release_packet_entry(tag);
    
    return val;
}

const MemoryRegionOps remote_mr_ops = {
    .read = cxl_remote_cxl_io_mmio_read,
    .write = cxl_remote_cxl_io_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
};

static void cxl_remote_device_register_memory(CXLRootPort *crp, uint16_t bdf, uint8_t bar_index) {
    remote_memory_region_t *region = &crp->remote_devices[bdf].memory_regions[bar_index];
    char *name = g_strdup_printf("device-%02x-bar-%d", bdf, bar_index);
    memory_region_init_io(&region->mr, OBJECT(crp),
                                  &remote_mr_ops, region,
                                  name, region->size);

    PCIBridge *bridge = PCI_BRIDGE(crp);
    MemoryRegion *address_space = bridge->sec_bus.address_space_mem;
    memory_region_add_subregion_overlap(address_space, region->address, 
        &region->mr, 1);
}

static void cxl_remote_device_bar_update(CXLRootPort *crp, uint16_t bdf, uint32_t offset, uint32_t value, int size, bool is_write) {
    if (!crp->remote_devices[bdf].found) {
        return;
    }

    const bool type0 = crp->remote_devices[bdf].type0;
    const bool is_type0_bar = ranges_overlap(offset, size, PCI_BASE_ADDRESS_0, 24) && type0;
    const bool is_type1_bar = ranges_overlap(offset, size, PCI_BASE_ADDRESS_0, 8) && !type0;
    if (is_type0_bar) {
        trace_cxl_root_debug_message("Accessing Type 0 Device's Bar");
    }
    else if (is_type1_bar) {
        trace_cxl_root_debug_message("Accessing Type 1 Device's Bar");
    }
    else {
        return;
    }

    const uint8_t bus = bdf >> 8;
    const uint8_t device = (bdf >> 3) & 0x1F;
    const uint8_t function = bdf & 0x7;
    uint8_t bar_index = (offset - PCI_BASE_ADDRESS_0) / 4;
    trace_cxl_root_cxl_remote_bar_update(bus, device, function, bar_index);
    
    remote_memory_region_t *region = &crp->remote_devices[bdf].memory_regions[bar_index];
    const remote_memory_state_t state = region->state;
    if (is_write && state == REMOTE_MEMORY_UNINIT) {
        region->address = value;
        region->state = REMOTE_MEMORY_SIZE_DISCOVERY;
        trace_cxl_root_debug_message("Starting BAR size discovery");
    } else if (!is_write && state == REMOTE_MEMORY_SIZE_DISCOVERY) {
        const uint32_t size = (~(value & 0xFFFFFFF0)) + 1;
        region->size = size;
        trace_cxl_root_cxl_remote_bar_size(bus, device, function, bar_index, size);
        if (size > 0) {
            region->state = REMOTE_MEMORY_SIZE_SET;
        } else {
            region->state = REMOTE_MEMORY_UNINIT;
        }
    } else if (is_write && state == REMOTE_MEMORY_SIZE_SET && value != 0) {
        region->address = value;
        region->state = REMOTE_MEMORY_ADDRESS_SET;
        cxl_remote_device_register_memory(crp, bdf, bar_index);
        trace_cxl_root_cxl_remote_bar_update_addr(bus, device, function, bar_index, value);
    }
}

static void cxl_remote_device_update_header_type(CXLRootPort *crp, uint16_t bdf, uint32_t offset, uint32_t val, int size) {
    if (!crp->remote_devices[bdf].found) {
        return;
    }

    const uint8_t bus = bdf >> 8;
    const uint8_t device = (bdf >> 3) & 0x1F;
    const uint8_t function = bdf & 0x7;
    if (offset == PCI_HEADER_TYPE) {
        const bool type0 = (val & PCI_HEADER_TYPE_MASK) == PCI_HEADER_TYPE_NORMAL;
        crp->remote_devices[bdf].type0 = type0;
        if  (type0) {
            trace_cxl_root_cxl_remote_type0(bus, device, function);
        } else {
            trace_cxl_root_cxl_remote_type1(bus, device, function);
        }
    }
}

void cxl_remote_config_space_read(PCIDevice *d, uint16_t bdf, uint32_t offset,
                                  uint32_t *val, int size)
{
    if (!is_valid_bdf(d, bdf)) {
        trace_cxl_root_error_msg("Invalid BDF received");
        assert(0);
    }

    CXLRootPort *crp = CXL_ROOT_PORT(d);
    bool type0 = is_type0_config_request(d, bdf);
    uint16_t tag;
    const uint8_t bus = bdf >> 8;
    const uint8_t device = (bdf >> 3) & 0x1F;
    const uint8_t function = bdf & 0x7;

    uint32_t bit_offset = (offset % 4) * 8;
    uint32_t bit_mask = (1ULL << size * 8) - 1;

    if (type0 && (bdf & 0xFF) != 0) {
        *val = (0xFFFFFFFF >> bit_offset) & bit_mask;
        return;
    }

    if (type0) {
        trace_cxl_root_cxl_io_config_space_read0(bus, device, function, offset,
                                                 size);
    } else {
        trace_cxl_root_cxl_io_config_space_read1(bus, device, function, offset,
                                                 size);
    }

    if (!send_cxl_io_config_space_read(crp->socket_fd, bdf, offset, size, type0,
                                       &tag)) {
        trace_cxl_root_error_msg("Failed to send CXL.io CFG RD request");
        assert(0);
    }

    uint32_t value = 0;
    if (!wait_for_cxl_io_cfg_completion(crp->socket_fd, tag, &value)) {
        trace_cxl_root_error_msg("Failed to receive CXL.io CPL or CPLD packet");
        assert(0);
    }

    trace_cxl_root_cxl_io_config_cpld(bus, device, function, value);

    value = (value >> bit_offset) & bit_mask;
    *val = value;

    cxl_remote_device_check_device(crp, bdf, offset, *val, size);
    cxl_remote_device_update_header_type(crp, bdf, offset, *val, size);
    cxl_remote_device_bar_update(crp, bdf, offset, *val, size, false);

    release_packet_entry(tag);
}

void cxl_remote_config_space_write(PCIDevice *d, uint16_t bdf, uint32_t offset,
                                   uint32_t val, int size)
{
    if (!is_valid_bdf(d, bdf)) {
        trace_cxl_root_error_msg("Invalid BDF received");
        assert(0);
    }

    CXLRootPort *crp = CXL_ROOT_PORT(d);
    bool type0 = is_type0_config_request(d, bdf);
    uint16_t tag;
    const uint8_t bus = bdf >> 8;
    const uint8_t device = (bdf >> 3) & 0x1F;
    const uint8_t function = bdf & 0x7;

    if (type0 && (bdf & 0xFF) != 0) {
        return;
    }

    if (type0) {
        trace_cxl_root_cxl_io_config_space_write0(bus, device, function, offset,
                                                  size, val);
    } else {
        trace_cxl_root_cxl_io_config_space_write1(bus, device, function, offset,
                                                  size, val);
    }

    if (!send_cxl_io_config_space_write(crp->socket_fd, bdf, offset, val, size,
                                        type0, &tag)) {
        trace_cxl_root_error_msg("Failed to send CXL.io CFG WR request");
        assert(0);
    }

    if (!wait_for_cxl_io_cfg_completion(crp->socket_fd, tag, NULL)) {
        trace_cxl_root_error_msg("Failed to receive CXL.io CPL packet");
        assert(0);
    }

    cxl_remote_device_bar_update(crp, bdf, offset, val, size, true);

    release_packet_entry(tag);
}

/*
 * If two MSI vector are allocated, Advanced Error Interrupt Message Number
 * is 1. otherwise 0.
 * 17.12.5.10 RPERRSTS,  32:27 bit Advanced Error Interrupt Message Number.
 */
static uint8_t cxl_rp_aer_vector(const PCIDevice *d)
{
    switch (msi_nr_vectors_allocated(d)) {
    case 1:
        return 0;
    case 2:
        return 1;
    case 4:
    case 8:
    case 16:
    case 32:
    default:
        break;
    }
    abort();
    return 0;
}

static int cxl_rp_interrupts_init(PCIDevice *d, Error **errp)
{
    int rc;

    rc = msi_init(d, CXL_RP_MSI_OFFSET, CXL_RP_MSI_NR_VECTOR,
                  CXL_RP_MSI_SUPPORTED_FLAGS & PCI_MSI_FLAGS_64BIT,
                  CXL_RP_MSI_SUPPORTED_FLAGS & PCI_MSI_FLAGS_MASKBIT, errp);
    if (rc < 0) {
        assert(rc == -ENOTSUP);
    }

    return rc;
}

static void cxl_rp_interrupts_uninit(PCIDevice *d)
{
    msi_uninit(d);
}

static void latch_registers(CXLRootPort *crp)
{
    uint32_t *reg_state = crp->cxl_cstate.crb.cache_mem_registers;
    uint32_t *write_msk = crp->cxl_cstate.crb.cache_mem_regs_write_mask;

    cxl_component_register_init_common(reg_state, write_msk, CXL2_ROOT_PORT);
}

static void build_dvsecs(CXLComponentState *cxl)
{
    uint8_t *dvsec;

    dvsec = (uint8_t *)&(CXLDVSECPortExtensions) { 0 };
    cxl_component_create_dvsec(
        cxl, CXL2_ROOT_PORT, EXTENSIONS_PORT_DVSEC_LENGTH,
        EXTENSIONS_PORT_DVSEC, EXTENSIONS_PORT_DVSEC_REVID, dvsec);

    dvsec = (uint8_t *)&(CXLDVSECPortGPF) {
        .rsvd = 0,
        .phase1_ctrl = 1, /* 1μs timeout */
        .phase2_ctrl = 1, /* 1μs timeout */
    };
    cxl_component_create_dvsec(cxl, CXL2_ROOT_PORT, GPF_PORT_DVSEC_LENGTH,
                               GPF_PORT_DVSEC, GPF_PORT_DVSEC_REVID, dvsec);

    dvsec = (uint8_t *)&(CXLDVSECPortFlexBus) {
        .cap = 0x26, /* IO, Mem, non-MLD */
        .ctrl = 0x2,
        .status = 0x26, /* same */
        .rcvd_mod_ts_data_phase1 = 0xef,
    };
    cxl_component_create_dvsec(
        cxl, CXL2_ROOT_PORT, PCIE_FLEXBUS_PORT_DVSEC_LENGTH_2_0,
        PCIE_FLEXBUS_PORT_DVSEC, PCIE_FLEXBUS_PORT_DVSEC_REVID_2_0, dvsec);

    dvsec = (uint8_t *)&(CXLDVSECRegisterLocator) {
        .rsvd = 0,
        .reg0_base_lo = RBI_COMPONENT_REG | CXL_COMPONENT_REG_BAR_IDX,
        .reg0_base_hi = 0,
    };
    cxl_component_create_dvsec(cxl, CXL2_ROOT_PORT, REG_LOC_DVSEC_LENGTH,
                               REG_LOC_DVSEC, REG_LOC_DVSEC_REVID, dvsec);
}

static bool cxl_rp_init_socket_client(CXLRootPort *crp)
{
    crp->socket_fd = create_socket_client(crp->socket_host, crp->socket_port);
    if (crp->socket_fd < 0) {
        return false;
    }

    if (!send_sideband_connection_request(crp->socket_fd, crp->switch_port)) {
        trace_cxl_root_debug_message(
            "CXL Root Port: Failed to send connection request");
        return false;
    }

    base_sideband_packet_t *packet =
        wait_for_base_sideband_packet(crp->socket_fd);
    const uint16_t tag = 0;
    if (packet == NULL) {
        release_packet_entry(tag);
        trace_cxl_root_debug_message(
            "CXL Root Port: Failed to get connection response");
        return false;
    }

    if (packet->sideband_header.type != SIDEBAND_CONNECTION_ACCEPT) {
        release_packet_entry(tag);
        trace_cxl_root_debug_message(
            "CXL Root Port: Connection request was not accepted");
        return false;
    }
    release_packet_entry(tag);
    trace_cxl_root_debug_message(
        "CXL Root Port: Successfully connected to switch");

    return true;
}

static void cxl_rp_realize(DeviceState *dev, Error **errp)
{
    PCIDevice *pci_dev = PCI_DEVICE(dev);
    PCIERootPortClass *rpc = PCIE_ROOT_PORT_GET_CLASS(dev);
    CXLRootPort *crp = CXL_ROOT_PORT(dev);
    CXLComponentState *cxl_cstate = &crp->cxl_cstate;
    ComponentRegisters *cregs = &cxl_cstate->crb;
    MemoryRegion *component_bar = &cregs->component_registers;
    Error *local_err = NULL;

    trace_cxl_root_debug_message("Realizing CXLRootPort Class instance");

    rpc->parent_realize(dev, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    int rc =
        pci_bridge_qemu_reserve_cap_init(pci_dev, 0, crp->res_reserve, errp);
    if (rc < 0) {
        rpc->parent_class.exit(pci_dev);
        return;
    }

    if (!crp->res_reserve.io || crp->res_reserve.io == -1) {
        pci_word_test_and_clear_mask(pci_dev->wmask + PCI_COMMAND,
                                     PCI_COMMAND_IO);
        pci_dev->wmask[PCI_IO_BASE] = 0;
        pci_dev->wmask[PCI_IO_LIMIT] = 0;
    }

    cxl_cstate->dvsec_offset = CXL_ROOT_PORT_DVSEC_OFFSET;
    cxl_cstate->pdev = pci_dev;
    build_dvsecs(&crp->cxl_cstate);

    cxl_component_register_block_init(OBJECT(pci_dev), cxl_cstate,
                                      TYPE_CXL_ROOT_PORT);

    pci_register_bar(pci_dev, CXL_COMPONENT_REG_BAR_IDX,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                         PCI_BASE_ADDRESS_MEM_TYPE_64,
                     component_bar);

    if (!cxl_is_remote_root_port(pci_dev)) {
        return;
    }

    if (!cxl_rp_init_socket_client(crp)) {
        return;
    }

    for (uint32_t bdf = 0; bdf < 0x10000; ++bdf) {
        crp->remote_devices[bdf].found = false;
        crp->remote_devices[bdf].type0 = false;
        for (uint8_t bar_index = 0; bar_index < PCI_NUM_REGIONS; ++bar_index) {
            crp->remote_devices[bdf].memory_regions[bar_index].state = REMOTE_MEMORY_UNINIT;
            crp->remote_devices[bdf].memory_regions[bar_index].root_port = pci_dev;
            crp->remote_devices[bdf].memory_regions[bar_index].bdf = bdf;
        }
    }

    trace_cxl_root_debug_message("Realized CXLRootPort Class instance");
}

static void cxl_rp_reset_hold(Object *obj)
{
    PCIERootPortClass *rpc = PCIE_ROOT_PORT_GET_CLASS(obj);
    CXLRootPort *crp = CXL_ROOT_PORT(obj);

    if (rpc->parent_phases.hold) {
        rpc->parent_phases.hold(obj);
    }

    latch_registers(crp);
}

static Property gen_rp_props[] = {
    DEFINE_PROP_UINT32("bus-reserve", CXLRootPort, res_reserve.bus, -1),
    DEFINE_PROP_SIZE("io-reserve", CXLRootPort, res_reserve.io, -1),
    DEFINE_PROP_SIZE("mem-reserve", CXLRootPort, res_reserve.mem_non_pref, -1),
    DEFINE_PROP_SIZE("pref32-reserve", CXLRootPort, res_reserve.mem_pref_32,
                     -1),
    DEFINE_PROP_SIZE("pref64-reserve", CXLRootPort, res_reserve.mem_pref_64,
                     -1),
    DEFINE_PROP_STRING("socket-host", CXLRootPort, socket_host),
    DEFINE_PROP_UINT32("socket-port", CXLRootPort, socket_port, 8000),
    DEFINE_PROP_UINT32("switch-port", CXLRootPort, switch_port, 0),
    DEFINE_PROP_END_OF_LIST()
};

static void cxl_rp_dvsec_write_config(PCIDevice *dev, uint32_t addr,
                                      uint32_t val, int len)
{
    CXLRootPort *crp = CXL_ROOT_PORT(dev);

    if (range_contains(&crp->cxl_cstate.dvsecs[EXTENSIONS_PORT_DVSEC], addr)) {
        uint8_t *reg = &dev->config[addr];
        addr -= crp->cxl_cstate.dvsecs[EXTENSIONS_PORT_DVSEC].lob;
        if (addr == PORT_CONTROL_OFFSET) {
            if (pci_get_word(reg) & PORT_CONTROL_UNMASK_SBR) {
                /* unmask SBR */
                qemu_log_mask(LOG_UNIMP, "SBR mask control is not supported\n");
            }
            if (pci_get_word(reg) & PORT_CONTROL_ALT_MEMID_EN) {
                /* Alt Memory & ID Space Enable */
                qemu_log_mask(LOG_UNIMP,
                              "Alt Memory & ID space is not supported\n");
            }
        }
    }
}

static void cxl_rp_aer_vector_update(PCIDevice *d)
{
    PCIERootPortClass *rpc = PCIE_ROOT_PORT_GET_CLASS(d);

    if (rpc->aer_vector) {
        pcie_aer_root_set_vector(d, rpc->aer_vector(d));
    }
}

static void cxl_rp_write_config(PCIDevice *d, uint32_t address, uint32_t val,
                                int len)
{
    uint16_t slt_ctl, slt_sta;
    uint32_t root_cmd =
        pci_get_long(d->config + d->exp.aer_cap + PCI_ERR_ROOT_COMMAND);

    pcie_cap_slot_get(d, &slt_ctl, &slt_sta);
    pci_bridge_write_config(d, address, val, len);
    cxl_rp_aer_vector_update(d);
    pcie_cap_flr_write_config(d, address, val, len);
    pcie_cap_slot_write_config(d, slt_ctl, slt_sta, address, val, len);
    pcie_aer_write_config(d, address, val, len);
    pcie_aer_root_write_config(d, address, val, len, root_cmd);

    cxl_rp_dvsec_write_config(d, address, val, len);
}

static void cxl_root_port_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(oc);
    ResettableClass *rc = RESETTABLE_CLASS(oc);
    PCIERootPortClass *rpc = PCIE_ROOT_PORT_CLASS(oc);

    k->vendor_id = PCI_VENDOR_ID_INTEL;
    k->device_id = CXL_ROOT_PORT_DID;
    dc->desc = "CXL Root Port";
    k->revision = 0;
    device_class_set_props(dc, gen_rp_props);
    k->config_write = cxl_rp_write_config;

    device_class_set_parent_realize(dc, cxl_rp_realize, &rpc->parent_realize);
    resettable_class_set_parent_phases(rc, NULL, cxl_rp_reset_hold, NULL,
                                       &rpc->parent_phases);

    rpc->aer_offset = GEN_PCIE_ROOT_PORT_AER_OFFSET;
    rpc->acs_offset = GEN_PCIE_ROOT_PORT_ACS_OFFSET;
    rpc->aer_vector = cxl_rp_aer_vector;
    rpc->interrupts_init = cxl_rp_interrupts_init;
    rpc->interrupts_uninit = cxl_rp_interrupts_uninit;

    dc->hotpluggable = false;
}

static const TypeInfo cxl_root_port_info = {
    .name = TYPE_CXL_ROOT_PORT,
    .parent = TYPE_PCIE_ROOT_PORT,
    .instance_size = sizeof(CXLRootPort),
    .class_init = cxl_root_port_class_init,
    .interfaces = (InterfaceInfo[]) { { INTERFACE_CXL_DEVICE }, {} },
};

static void cxl_register(void)
{
    type_register_static(&cxl_root_port_info);
}

type_init(cxl_register);
