#!/bin/bash

sudo apt install -y make gcc libssl-dev bc libelf-dev libcap-dev clang gcc-multilib llvm libncurses5-dev \
     pkg-config libmnl-dev bison flex graphviz iproute2 libbfd-dev


sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h