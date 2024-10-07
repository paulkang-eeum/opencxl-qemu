#!/bin/bash
cd ../build && ./qemu-system-x86_64 \
    --trace "pci_debug*" \
    --trace "pci_pxb_dev*" \
    --trace "cxl_root*" \
    --trace "pci_cfg_write" \
    --trace "pci_cfg_read" \
    --trace "cxl_socket_*" \
    --trace "cxl_opencxl_packet_*" \
	-m 8G -smp 4 \
	-machine type=q35,accel=kvm,cxl=on -nographic \
	-hda fedora_39.qcow2 \
	-cdrom seed.qcow2 \
	-D debug.log \
	-L /usr/local/share/qemu \
    -device pxb-cxl,bus_nr=1,bus=pcie.0,id=cxl.1 \
    -device cxl-rp,port=0,bus=cxl.1,id=root_port0,chassis=0,slot=2,socket-host=0.0.0.0 \
    -M "cxl-fmw.0.targets.0=cxl.1,cxl-fmw.0.size=512G" \
	-nic user,id=vmnic,hostfwd=tcp::2222-:22
