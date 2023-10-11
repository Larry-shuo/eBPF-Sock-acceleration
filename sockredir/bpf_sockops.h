#include "vmlinux.h"
#include "bpf/bpf_helpers.h"

#define ___constant_swab32(x) ((__u32)(                         \
        (((__u32)(x) & (__u32)0x000000ffUL) << 24) |            \
        (((__u32)(x) & (__u32)0x0000ff00UL) <<  8) |            \
        (((__u32)(x) & (__u32)0x00ff0000UL) >>  8) |            \
        (((__u32)(x) & (__u32)0xff000000UL) >> 24)))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __bpf_ntohl(x)                 __builtin_bswap32(x)
# define __bpf_htonl(x)                 __builtin_bswap32(x)
# define __bpf_constant_ntohl(x)        ___constant_swab32(x)
# define __bpf_constant_htonl(x)        ___constant_swab32(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define __bpf_ntohl(x)                 (x)
# define __bpf_htonl(x)                 (x)
# define __bpf_constant_ntohl(x)        (x)
# define __bpf_constant_htonl(x)        (x)
#else
# error "Check the compiler's endian detection."
#endif

#define bpf_htonl(x)                            \
        (__builtin_constant_p(x) ?              \
         __bpf_constant_htonl(x) : __bpf_htonl(x))
#define bpf_ntohl(x)                            \
        (__builtin_constant_p(x) ?              \
         __bpf_constant_ntohl(x) : __bpf_ntohl(x))

#ifndef FORCE_READ
#define FORCE_READ(X) (*(volatile typeof(X)*)&X)
#endif

#ifndef BPF_FUNC
#define BPF_FUNC(NAME, ...) 	\
	(*NAME)(__VA_ARGS__) = (void *) BPF_FUNC_##NAME
#endif

#ifndef printk
# define printk(fmt, ...)                                      \
    ({                                                         \
        char ____fmt[] = fmt;                                  \
        trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#endif


/* ebpf helper function
 * The generated function is used for parameter verification
 * by the eBPF verifier
 */
static int BPF_FUNC(msg_redirect_hash, struct sk_msg_md *md,
			void *map, void *key, uint64_t flag);
static int BPF_FUNC(sock_hash_update, struct bpf_sock_ops *skops,
			void *map, void *key, uint64_t flags);
static void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);

// 127.0.0.1
static const uint32_t lo_ip = 127 + (1 << 24);

struct sock_key {
	uint32_t sip4;
	uint32_t dip4;
	uint8_t  family;
	uint8_t  pad1;
	uint16_t pad2;
	// this padding required for 64bit alignment
	// else ebpf kernel verifier rejects loading
	// of the program
	uint32_t pad3;
	uint32_t sport;
	uint32_t dport;
} __attribute__((packed));

/*
 * Map definition
 */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, struct sock_key);
	__type(value, int);
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
} sock_ops_map SEC(".maps");