// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_RULES4 128
#define MAX_RULES6 64
#define MAX_UID_FLAGS 128

#define IPV4_LOOPBACK_PREFIX 0x7f000000U

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#define WL_UID_BYPASS 1
#define WL_UID_ONLY 2

/*
 * One IPv4 outbound whitelist entry.
 *
 *   dst_ip   network byte order; 0 means "any destination".
 *   proto    IPPROTO_TCP / IPPROTO_UDP; 0 means "any protocol".
 *   port_start / port_end   host byte order, inclusive range.
 */
struct rule4 {
    __u32 dst_ip;
    __u16 port_start;
    __u16 port_end;
    __u8 proto;
    __u8 pad[3];
};

/*
 * One IPv6 outbound whitelist entry.
 *
 *   dst_ipN / maskN   prefix address and mask, in the byte order the kernel
 *                     exposes user_ip6 (raw wire bytes interpreted by the
 *                     host).  Loader precomputes them from an a.b.c.d::/len
 *                     string so a single AND + compare works here.
 *   proto / ports     same meaning as struct rule4.
 */
struct rule6 {
    __u32 dst_ip0;
    __u32 mask0;
    __u32 dst_ip1;
    __u32 mask1;
    __u32 dst_ip2;
    __u32 mask2;
    __u32 dst_ip3;
    __u32 mask3;
    __u16 port_start;
    __u16 port_end;
    __u8 proto;
    __u8 pad[3];
};

/* Runtime knobs; single ARRAY entry keyed by 0. */
struct wl_config {
    __u8 default_allow; /* 0 = deny unmatched, 1 = allow unmatched */
    __u8 uid_mode;      /* 0 = filter all UIDs, 1 = filter only listed UIDs */
    __u8 allow_loopback; /* 1 = always allow 127.0.0.0/8 and ::1 */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES4);
    __type(key, __u32);
    __type(value, struct rule4);
} rules4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES6);
    __type(key, __u32);
    __type(value, struct rule6);
} rules6 SEC(".maps");

/*
 * UID flags:
 *   value & WL_UID_BYPASS -> this UID always passes the firewall.
 *   value & WL_UID_ONLY   -> this UID is explicitly subject to filtering
 *                            (meaningful only when config.uid_mode == 1).
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_UID_FLAGS);
    __type(key, __u32);
    __type(value, __u8);
} uid_flags SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct wl_config);
} wl_cfg SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

static __always_inline int default_allow(void)
{
    __u32 zero = 0;
    struct wl_config *c = bpf_map_lookup_elem(&wl_cfg, &zero);

    return (c && c->default_allow) ? 1 : 0;
}

static __always_inline int allow_loopback(void)
{
    __u32 zero = 0;
    struct wl_config *c = bpf_map_lookup_elem(&wl_cfg, &zero);

    return (c && c->allow_loopback) ? 1 : 0;
}

/*
 * Returns 1 when this UID should bypass the whitelist entirely,
 * 0 when it is subject to rule matching / default policy.
 */
static __always_inline int uid_policy(__u32 uid)
{
    __u32 zero = 0;
    struct wl_config *c = bpf_map_lookup_elem(&wl_cfg, &zero);
    __u8 *v = bpf_map_lookup_elem(&uid_flags, &uid);

    if (v) {
        if (*v & WL_UID_BYPASS)
            return 1;
        if (*v & WL_UID_ONLY)
            return 0;
    }

    if (c && c->uid_mode)
        return 1;

    return 0;
}

static __always_inline int is_ipv4_loopback(__u32 ip4)
{
    if (ip4 == 0)
        return 1;

    if ((ip4 & 0xff000000U) == IPV4_LOOPBACK_PREFIX)
        return 1;

    return (bpf_ntohl(ip4) & 0xff000000U) == IPV4_LOOPBACK_PREFIX;
}

static __always_inline int is_ipv6_loopback(__u32 ip0, __u32 ip1,
                                            __u32 ip2, __u32 ip3)
{
    if (ip0 != 0 || ip1 != 0 || ip2 != 0)
        return 0;

    return ip3 == 0 || ip3 == 1 || ip3 == bpf_htonl(1);
}

static __always_inline int match_rule4(__u32 dst, __u32 port_net, __u8 proto)
{
    __u16 port = (__u16)bpf_ntohs((__u16)port_net);

    for (__u32 idx = 0; idx < MAX_RULES4; idx++) {
        struct rule4 *r = bpf_map_lookup_elem(&rules4, &idx);

        if (!r)
            continue;
        if (r->port_start == 0 && r->port_end == 0)
            break;
        if (r->proto != 0 && r->proto != proto)
            continue;
        if (r->dst_ip != 0 && r->dst_ip != dst)
            continue;
        if (port < r->port_start || port > r->port_end)
            continue;
        return 1;
    }

    return 0;
}

static __always_inline int match_rule6(__u32 ip0, __u32 ip1, __u32 ip2,
                                       __u32 ip3, __u32 port_net, __u8 proto)
{
    __u16 port = (__u16)bpf_ntohs((__u16)port_net);

    for (__u32 idx = 0; idx < MAX_RULES6; idx++) {
        struct rule6 *r = bpf_map_lookup_elem(&rules6, &idx);

        if (!r)
            continue;
        if (r->port_start == 0 && r->port_end == 0)
            break;
        if (r->proto != 0 && r->proto != proto)
            continue;
        if ((ip0 & r->mask0) != r->dst_ip0)
            continue;
        if ((ip1 & r->mask1) != r->dst_ip1)
            continue;
        if ((ip2 & r->mask2) != r->dst_ip2)
            continue;
        if ((ip3 & r->mask3) != r->dst_ip3)
            continue;
        if (port < r->port_start || port > r->port_end)
            continue;
        return 1;
    }

    return 0;
}

SEC("cgroup/connect4")
int wl_connect4(struct bpf_sock_addr *ctx)
{
    __u32 uid = (__u32)bpf_get_current_uid_gid();
    __u32 dst = ctx->user_ip4;

    if (uid_policy(uid))
        return 1;

    if (allow_loopback() && is_ipv4_loopback(dst))
        return 1;

    if (match_rule4(dst, ctx->user_port, (__u8)ctx->protocol))
        return 1;

    return default_allow();
}

SEC("cgroup/connect6")
int wl_connect6(struct bpf_sock_addr *ctx)
{
    __u32 uid = (__u32)bpf_get_current_uid_gid();

    if (uid_policy(uid))
        return 1;

    if (allow_loopback() &&
        is_ipv6_loopback(ctx->user_ip6[0], ctx->user_ip6[1],
                         ctx->user_ip6[2], ctx->user_ip6[3]))
        return 1;

    if (match_rule6(ctx->user_ip6[0], ctx->user_ip6[1],
                    ctx->user_ip6[2], ctx->user_ip6[3],
                    ctx->user_port, (__u8)ctx->protocol))
        return 1;

    return default_allow();
}

SEC("cgroup/udp4_sendmsg")
int wl_udp4_sendmsg(struct bpf_sock_addr *ctx)
{
    __u32 uid = (__u32)bpf_get_current_uid_gid();
    __u32 dst = ctx->user_ip4;

    if (uid_policy(uid))
        return 1;

    if (allow_loopback() && is_ipv4_loopback(dst))
        return 1;

    if (match_rule4(dst, ctx->user_port, IPPROTO_UDP))
        return 1;

    return default_allow();
}

SEC("cgroup/udp6_sendmsg")
int wl_udp6_sendmsg(struct bpf_sock_addr *ctx)
{
    __u32 uid = (__u32)bpf_get_current_uid_gid();

    if (uid_policy(uid))
        return 1;

    if (allow_loopback() &&
        is_ipv6_loopback(ctx->user_ip6[0], ctx->user_ip6[1],
                         ctx->user_ip6[2], ctx->user_ip6[3]))
        return 1;

    if (match_rule6(ctx->user_ip6[0], ctx->user_ip6[1],
                    ctx->user_ip6[2], ctx->user_ip6[3],
                    ctx->user_port, IPPROTO_UDP))
        return 1;

    return default_allow();
}
