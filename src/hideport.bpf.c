// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_RULES 128
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1
#define IPPROTO_ICMPV6 58

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

/* Rule flags */
#define RULE_FLAG_SRC_CIDR_IPV4   0x01
#define RULE_FLAG_DST_IP_EXACT    0x02
#define RULE_FLAG_DST_PORT_RANGE  0x04
#define RULE_FLAG_PROTO_TCP       0x08
#define RULE_FLAG_PROTO_UDP       0x10
#define RULE_FLAG_PROTO_ICMP      0x20
#define RULE_FLAG_DST_PORT_EXACT  0x40

/* IPv4 CIDR rule */
struct ipv4_cidr {
    __u32 network;      /* Network address in host byte order */
    __u32 mask;         /* Netmask in host byte order */
};

/* Port range */
struct port_range {
    __u16 start;
    __u16 end;
};

/* Whitelist rule */
struct whitelist_rule {
    __u32 flags;                       /* Rule flags */
    struct ipv4_cidr src_cidr;         /* Source CIDR (IPv4) */
    __u32 dst_ip;                      /* Destination IP (IPv4) */
    __u16 dst_port_start;              /* Destination port start or single port */
    __u16 dst_port_end;                /* Destination port end (for range) */
};

/* Map: rule index -> whitelist rule */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct whitelist_rule);
} whitelist_rules SEC(".maps");

/* Map: number of active rules */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} rule_count SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

static __always_inline int ipv4_in_cidr(struct ipv4_cidr *cidr, __u32 ip)
{
    /* Convert network byte order to host byte order for comparison */
    __u32 ip_host = bpf_ntohl(ip);
    return (ip_host & cidr->mask) == cidr->network;
}

static __always_inline int port_matches(struct whitelist_rule *rule, __u16 port)
{
    __u16 port_host = bpf_ntohs(port);
    
    if (rule->flags & RULE_FLAG_DST_PORT_RANGE) {
        return port_host >= rule->dst_port_start && port_host <= rule->dst_port_end;
    } else if (rule->flags & RULE_FLAG_DST_PORT_EXACT) {
        return port_host == rule->dst_port_start;
    }
    
    return 1;
}

static __always_inline int match_rule(struct whitelist_rule *rule,
                                      __u8 protocol,
                                      __u32 src_ip,
                                      __u32 dst_ip,
                                      __u16 dst_port)
{
    /* Check protocol */
    if (protocol == IPPROTO_TCP && !(rule->flags & RULE_FLAG_PROTO_TCP))
        return 0;
    
    if (protocol == IPPROTO_UDP && !(rule->flags & RULE_FLAG_PROTO_UDP))
        return 0;
    
    if (protocol == IPPROTO_ICMP && !(rule->flags & RULE_FLAG_PROTO_ICMP))
        return 0;
    
    /* Check source CIDR if required */
    if (rule->flags & RULE_FLAG_SRC_CIDR_IPV4) {
        if (!ipv4_in_cidr(&rule->src_cidr, src_ip))
            return 0;
    }
    
    /* Check destination IP if required */
    if (rule->flags & RULE_FLAG_DST_IP_EXACT) {
        if (dst_ip != rule->dst_ip)
            return 0;
    }
    
    /* Check destination port (skip for ICMP) */
    if (protocol != IPPROTO_ICMP) {
        if (!port_matches(rule, dst_port))
            return 0;
    }
    
    return 1;
}

static __always_inline int check_whitelist(
    __u8 protocol,
    __u32 src_ip,
    __u32 dst_ip,
    __u16 dst_port)
{
    __u32 zero = 0;
    __u32 *count_ptr = bpf_map_lookup_elem(&rule_count, &zero);
    
    if (!count_ptr || *count_ptr == 0)
        return 0;
    
    __u32 rule_count_val = *count_ptr;
    
    #pragma unroll
    for (__u32 i = 0; i < MAX_RULES && i < rule_count_val; i++) {
        struct whitelist_rule *rule = bpf_map_lookup_elem(&whitelist_rules, &i);
        if (!rule)
            continue;
        
        if (match_rule(rule, protocol, src_ip, dst_ip, dst_port))
            return 1;
    }
    
    return 0;
}

SEC("cgroup/connect4")
int whitelist_connect4(struct bpf_sock_addr *ctx)
{
    __u8 protocol = ctx->protocol;
    __u32 src_ip = ctx->sk->__sk_common.skc_rcv_saddr;
    __u32 dst_ip = ctx->user_ip4;
    __u16 dst_port = ctx->user_port;
    
    /* Only handle TCP and UDP */
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return 1;
    
    /* Check if connection is allowed by whitelist */
    if (!check_whitelist(protocol, src_ip, dst_ip, dst_port)) {
        /* Connection not allowed - redirect to port 1 (unreachable) */
        ctx->user_port = bpf_htons(1);
        return 1;
    }
    
    return 1;
}

SEC("cgroup/connect6")
int whitelist_connect6(struct bpf_sock_addr *ctx)
{
    __u8 protocol = ctx->protocol;
    
    /* Only handle TCP and UDP */
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return 1;
    
    /* IPv6 whitelist check would go here */
    /* For now, allow all IPv6 or implement IPv6 CIDR matching */
    
    return 1;
}

SEC("cgroup/sendmsg4")
int whitelist_sendmsg4(struct bpf_sock_addr *ctx)
{
    __u8 protocol = ctx->protocol;
    __u32 src_ip = ctx->sk->__sk_common.skc_rcv_saddr;
    __u32 dst_ip = ctx->user_ip4;
    __u16 dst_port = ctx->user_port;
    
    /* Handle UDP */
    if (protocol == IPPROTO_UDP) {
        if (!check_whitelist(protocol, src_ip, dst_ip, dst_port)) {
            return 0;  /* Drop packet */
        }
    }
    
    return 1;
}

SEC("cgroup/recvmsg4")
int whitelist_recvmsg4(struct bpf_sock_addr *ctx)
{
    /* Allow all inbound traffic for now */
    return 1;
}
