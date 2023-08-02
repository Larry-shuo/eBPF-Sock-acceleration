#!/bin/bash

# enable debug output for each executed command
# to disable: set +x
set -x

bash unload.sh

# exit if any command fails
set -e

# Mount the bpf filesystem when it not exist
bpf_mounted=$(mount | grep -c "sys/fs/bpf")

if [ $bpf_mounted -eq 0 ]; then
    sudo mount -t bpf bpf /sys/fs/bpf/
fi

# Compile the bpf_sockops program
clang -O2 -g -target bpf -c bpf_sockops.c -o bpf_sockops.o

# Load and attach the bpf_sockops program
sudo bpftool prog load bpf_sockops.o "/sys/fs/bpf/bpf_sockops"
# get the cgroup filesystem path
cgroup_path=$(mount | grep 'cgroup' | awk 'NR==1{print $3}' )
sudo bpftool cgroup attach "$cgroup_path" sock_ops pinned "/sys/fs/bpf/bpf_sockops"

# Extract the id of the sockhash map used by the bpf_sockops program
# This map is then pinned to the bpf virtual file system
MAP_ID=$(sudo bpftool prog show pinned "/sys/fs/bpf/bpf_sockops" | grep -o -E 'map_ids [0-9]+' | cut -d ' ' -f2-)
sudo bpftool map pin id $MAP_ID "/sys/fs/bpf/sock_ops_map"

# # Load and attach thetcpippf_sk_bypass program to the sock_ops_map
clang -O2 -g -Wall -target bpf  -c bpf_tcpip_bypass.c -o bpf_tcpip_bypass.o
sudo bpftool prog load bpf_tcpip_bypass.o "/sys/fs/bpf/bpf_tcpip_bypass" map name sock_ops_map pinned "/sys/fs/bpf/sock_ops_map"
sudo bpftool prog attach pinned "/sys/fs/bpf/bpf_tcpip_bypass" msg_verdict pinned "/sys/fs/bpf/sock_ops_map"
