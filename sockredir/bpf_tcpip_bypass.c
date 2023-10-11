#include "vmlinux.h"
#include "bpf_sockops.h"

char ____license[] SEC("license") = "GPL";

/* extract the key that identifies the destination socket in the sock_ops_map */
static inline
void sk_msg_extract_key(struct sk_msg_md *msg,
	struct sock_key *key)
{
	key->sip4 = msg->remote_ip4;
	key->dip4 = msg->local_ip4;
	// printk("sip :%pi4, dip=%pi4",bpf_ntohl( key->sip4 ), bpf_ntohl(key->dip4));

	key->family = 1;

	key->dport = (bpf_htonl(msg->local_port) >> 16);
	key->sport = FORCE_READ(msg->remote_port) >> 16;
}


SEC("sk_msg")
int bpf_tcpip_bypass(struct sk_msg_md *msg)
{
    struct  sock_key key = {};
    sk_msg_extract_key(msg, &key);

	if(key.sip4 != lo_ip && key.dip4 != lo_ip){
		return SK_PASS;
	}
	
    u32 flag = msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);

	if(flag == SK_PASS){
		printk("sock_msg_redirect by sockmap: %pI4 --> %pI4", &key.sip4, &key.dip4);
		printk("sock_msg_redirect by sockmap: %d --> %d", bpf_ntohl(msg->remote_port), msg->local_port);
	}
	return SK_PASS;
}