# Socket data redirection using eBPF

> This is BPF code that demonstrates how to bypass TCPIP for socket data without modifying the applications. This code is a companion to this [blog](https://cyral.com/blog/how-to-ebpf-accelerating-cloud-native) post. 

The goal of this project is to show how to setup an eBPF network acceleration using socket data redirection when the communicating apps are on the same host.


## Testing

A simple bash script `load.sh` is included that performs the following tasks:

1. Compiles the sockops BPF code, using LLVM Clang frontend, that updates the sockhash map
2. Uses bpftool to attach the above compiled code to the cgroup so that it gets invoked for all the socket operations such as connection established, etc. in the system.
3. Extracts the id of the sockhash map created by the above program and pins the map to the virtual filesystem so that it can be accessed by the second eBPF program 
4. Compiles the `tcpip_bypass` code that performs the socket data redirection bypassing the TCPIP stack
5. Uses bpftool to attach the above eBPF code to sockhash map 

After running the script you should be able to verify the eBPF program is loaded in the kernel.

### Verifying BPF programs are loaded in the kernel

You can list all the BPF programs loaded and their map ids:

```bash
#sudo bpftool prog show
...
22: sock_ops  name bpf_sockops  tag 171192957e2f27eb  gpl
        loaded_at 2023-08-02T14:01:09+0800  uid 0
        xlated 1224B  jited 717B  memlock 4096B  map_ids 1
        btf_id 118
26: sk_msg  name bpf_tcpip_bypas  tag ae65f988d4eefaaa  gpl
        loaded_at 2023-08-02T14:01:11+0800  uid 0
        xlated 640B  jited 400B  memlock 4096B  map_ids 1
        btf_id 124
```

You should be able to view the SOCKHASH map also pinned onto the filesystem:

```bash
#sudo bt map show id 1 -f
1: sockhash  name sock_ops_map  flags 0x0
        key 24B  value 4B  max_entries 65535  memlock 2097152B
        pinned /sys/fs/bpf/sock_ops_map


#sudo tree /sys/fs/bpf/
/sys/fs/bpf/
├── bpf_sockops
├── bpf_tcpip_bypass
└── sock_ops_map

0 directories, 3 files
```



### Verifying application programs are bypassing the TCPIP stack

#### Turn on tracing logs (if not enabled by default)
```bash
#echo 1 > /sys/kernel/debug/tracing/tracing_on
```

#### We can use a TCP listener spawned by SOCAT to mimic an echo server, and netcat to sent a TCP connection request.
```bash
sudo socat TCP4-LISTEN:1000,fork exec:cat
nc localhost 1000 # this should produce the trace in the kernel file trace_pipe
```

#### You can cat the kernel live streaming trace file, trace_pipe, in a shell to monitor the trace of the TCP communication through eBPF
```bash
#cat /sys/kernel/tracing/trace_pipe
nc-3732    	  [000] d...1  1693.775336: bpf_trace_printk: update sockmap: 127.0.0.1 -> 127.0.0.1
nc-3732    	  [000] dN..1  1693.775584: bpf_trace_printk: update sockmap: op=4(Passive connect), port 39164-->1000
nc-3732    	  [000] dNs11  1693.775649: bpf_trace_printk: update sockmap: 127.0.0.1 -> 127.0.0.1
nc-3732    	  [000] dNs11  1693.775651: bpf_trace_printk: update sockmap: op=5(Active connect), port 1000-->39164

nc-3732    	  [000] d...1  1704.570131: bpf_trace_printk: sock_msg_redirect by sockmap: 127.0.0.1 --> 127.0.0.1
nc-3732    	  [000] d...1  1704.570143: bpf_trace_printk: sock_msg_redirect by sockmap: 1000 --> 39164
socat-3733    [000] d...1  1704.570720: bpf_trace_printk: sock_msg_redirect by sockmap: 127.0.0.1 --> 127.0.0.1
socat-3733    [000] d...1  1704.570730: bpf_trace_printk: sock_msg_redirect by sockmap: 39164 --> 1000
nc-3732    	  [001] d...1  1706.056008: bpf_trace_printk: sock_msg_redirect by sockmap: 127.0.0.1 --> 127.0.0.1
nc-3732    	  [001] d...1  1706.056016: bpf_trace_printk: sock_msg_redirect by sockmap: 1000 --> 39164
socat-3733    [001] d...1  1706.056795: bpf_trace_printk: sock_msg_redirect by sockmap: 127.0.0.1 --> 127.0.0.1
socat-3733    [001] d...1  1706.056801: bpf_trace_printk: sock_msg_redirect by sockmap: 39164 --> 1000
```


## Cleanup

Running the `unload.sh` script detaches the eBPF programs from the hooks and unloads them from the kernel.

## Building

You can build on any Linux kernel with eBPF support. We have used Ubuntu Linux 22.04 with kernel 5.15.0-78-generic

## Ubuntu Linux

To prepare a Linux development environment for eBPF development, various packages and kernel headers need to be installed. Follow the following steps to prepare your development environment:
1. Prepare Ubuntu 22.04
2. Install the necessary tools
	```bash
	sudo apt-get install -y make gcc libssl-dev bc libelf-dev libcap-dev clang gcc-multilib llvm libncurses5-dev git pkg-config libmnl-dev bison flex graphviz iproute2
	```
3. Download the Linux kernel source
	1. You will need to update source URIs in /etc/apt/source.list
	2. Perform the following:
		```bash
		sudo apt-get update
		sudo apt-get source linux-image-$(uname -r)
		```
		If it fails to download the source, try:
		```bash
		sudo apt-get source linux-image-unsigned-$(uname -r)
		```
	3. More information on Ubuntu [wiki](https://wiki.ubuntu.com/Kernel/BuildYourOwnKernel)
4. Compile and install bpftool from source. It is not yet packaged as part of the standard distributions of Ubuntu. 
	```bash
	cd $kernel_src_dir/tools/bpf/bpftools
	make 
	make install.
	```
5. Dump the vmlinux into the directory sockredir 
	```bash
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > <program_path>/bpflet/sockredir/vmlinux.h
	```


6. You might also need to install libbfd-dev
