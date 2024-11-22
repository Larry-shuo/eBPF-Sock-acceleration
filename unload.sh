#!/bin/bash
set -x
# set -e
# Detach and unload the bpf_tcpip_bypass program
sudo bpftool prog detach pinned "/sys/fs/bpf/bpf_tcpip_bypass" msg_verdict pinned "/sys/fs/bpf/sock_ops_map"
sleep 1
sudo rm "/sys/fs/bpf/bpf_tcpip_bypass"
sleep 1

cgroup_path=/sys/fs/cgroup/kubepods.slice/
# Detach and unload the bpf_sockops_v4 program
sudo bpftool cgroup detach "$cgroup_path" sock_ops pinned "/sys/fs/bpf/bpf_sockops"
sleep 1
sudo rm "/sys/fs/bpf/bpf_sockops"
sleep 1

# Delete the map
sudo rm "/sys/fs/bpf/sock_ops_map"
