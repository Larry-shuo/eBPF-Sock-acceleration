#include "vmlinux.h"
#include "bpf_sockops.h"

char ____license[] SEC("license") = "GPL";
int _version SEC("version") = 1;

/*
 * extract the key identifying the socket source of the TCP event 
 */
static inline
void sk_extract_key(struct bpf_sock_ops *ops,
	struct sock_key *key)
{
	// keep ip and port in network byte order
	key->dip4 = ops->remote_ip4;
	key->sip4 = ops->local_ip4;
	key->family = 1;
	
	// local_port is in host byte order, and 
	// remote_port is in network byte order
	key->sport = (bpf_htonl(ops->local_port) >> 16);
	key->dport = FORCE_READ(ops->remote_port) >> 16;
}

static inline
void bpf_sockops_ipv4(struct bpf_sock_ops *skops)
{
	struct sock_key key = {};
	
	sk_extract_key(skops, &key);

	// if(key.sip4 != lo_ip && key.dip4 != lo_ip)
	// 	return;

	// if( ((key.sip4 << 16) >> 16) != podsubnet && ((key.dip4 << 16) >> 16) != podsubnet ){
	// 	return;
	// }
	
	// insert the source socket in the sock_ops_map
	int ret = sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
	
	printk("update sockmap: %pI4 -> %pI4",&key.sip4, &key.dip4);
	// if(skops->op == 4){
	// 	printk("update sockmap: op=%d(Passive connect), port %d-->%d\n",
	// 			skops->op, skops->local_port, bpf_ntohl(skops->remote_port));
	// }
	// else if(skops->op == 5){
	// 	printk("update sockmap: op=%d(Active connect), port %d-->%d\n",
	// 			skops->op, skops->local_port, bpf_ntohl(skops->remote_port));
	// }
	if (ret != 0) {
		printk("FAILED: sock_hash_update ret: %d\n", ret);
	}
}

SEC("sockops")
int bpf_sockops(struct bpf_sock_ops *skops)
{
	switch (skops->op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB://5
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB://4
		if (skops->family == 2) { //AF_INET
            bpf_sockops_ipv4(skops);
		}
        	break;
        default:
            break;
        }
	return 0;
}
