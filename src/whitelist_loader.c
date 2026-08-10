// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "whitelist.skel.h"

#define MAX_RULES4 128
#define MAX_RULES6 64
#define MAX_UID_FLAGS 128
#define CGROUP_PATH "/sys/fs/cgroup"
#define MAX_LINE 512

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

/* Must be byte-identical to the maps declared in whitelist.bpf.c. */
struct wl_rule4 {
    __u32 dst_ip;
    __u16 port_start;
    __u16 port_end;
    __u8 proto;
    __u8 pad[3];
};

struct wl_rule6 {
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

struct wl_config {
    __u8 default_allow;
    __u8 uid_mode;
    __u8 allow_loopback;
};

struct config {
    char conf_path[PATH_MAX];
    char pidfile[PATH_MAX];
    struct wl_config knobs;
    struct wl_rule4 rules4[MAX_RULES4];
    int rule4_count;
    struct wl_rule6 rules6[MAX_RULES6];
    int rule6_count;
    uint32_t bypass_uids[MAX_UID_FLAGS];
    int bypass_count;
    uint32_t only_uids[MAX_UID_FLAGS];
    int only_count;
};

static volatile sig_atomic_t exiting;
static volatile sig_atomic_t reload_requested;

static void sig_exit(int sig)
{
    (void)sig;
    exiting = 1;
}

static void sig_reload(int sig)
{
    (void)sig;
    reload_requested = 1;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [--conf FILE] [--pidfile FILE]\n"
            "\n"
            "Default-deny eBPF outbound whitelist firewall loader.\n"
            "\n"
            "Options:\n"
            "  --conf FILE     read whitelist rules from FILE (default: none, deny all)\n"
            "  --pidfile FILE  write the daemon PID here (default: /dev/netwhitelist_loader.pid)\n"
            "\n"
            "SIGHUP/SIGUSR1 re-reads FILE and updates the BPF maps at runtime.\n",
            argv0);
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim))
        return -errno;

    return 0;
}

static void trim(char *s)
{
    char *p = s;
    size_t len;

    while (*p && isspace((unsigned char)*p))
        p++;
    if (p != s)
        memmove(s, p, strlen(p) + 1);

    len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        s[--len] = '\0';
}

static void strip_quotes(char *s)
{
    size_t len = strlen(s);

    if (len >= 2 && s[0] == '"' && s[len - 1] == '"') {
        s[len - 1] = '\0';
        memmove(s, s + 1, len - 1);
    }
}

static int parse_u16(const char *text, uint16_t *out)
{
    char *end = NULL;
    long v;

    if (!text || !*text)
        return -EINVAL;

    errno = 0;
    v = strtol(text, &end, 10);
    if (errno || !end || *end != '\0' || v < 1 || v > 65535)
        return -EINVAL;

    *out = (uint16_t)v;
    return 0;
}

static uint8_t parse_proto(const char *text)
{
    if (!strcmp(text, "tcp"))
        return IPPROTO_TCP;
    if (!strcmp(text, "udp"))
        return IPPROTO_UDP;
    return 0;
}

static int split_fields(char *text, char *fields[], int max)
{
    int n = 0;
    char *save = NULL;
    char *tok = strtok_r(text, "|", &save);

    while (tok && n < max) {
        fields[n++] = tok;
        tok = strtok_r(NULL, "|", &save);
    }

    return n;
}

static int parse_ipv4(const char *text, uint32_t *out)
{
    struct in_addr addr;

    if (!strcmp(text, "*") || !*text) {
        *out = 0;
        return 0;
    }

    if (inet_pton(AF_INET, text, &addr) != 1)
        return -EINVAL;

    *out = addr.s_addr;
    return 0;
}

static int parse_ipv6_prefix(const char *text, uint32_t *dst, uint32_t *mask)
{
    char addr[INET6_ADDRSTRLEN];
    struct in6_addr a6;
    uint8_t m[16] = {0};
    const char *slash = strchr(text, '/');
    long plen;

    if (!slash)
        return -EINVAL;

    if ((size_t)(slash - text) >= sizeof(addr))
        return -EINVAL;
    memcpy(addr, text, slash - text);
    addr[slash - text] = '\0';

    if (inet_pton(AF_INET6, addr, &a6) != 1)
        return -EINVAL;

    errno = 0;
    plen = strtol(slash + 1, NULL, 10);
    if (errno || plen < 0 || plen > 128)
        return -EINVAL;

    for (int b = 0; b < plen; b++)
        m[b / 8] |= (uint8_t)(0x80 >> (b % 8));

    memcpy(dst, a6.s6_addr, 16);
    memcpy(mask, m, 16);
    return 0;
}

static int add_rule4(struct config *cfg, const char *proto, const char *dst,
                     const char *start, const char *end)
{
    struct wl_rule4 r = {};
    int err;

    if (cfg->rule4_count >= MAX_RULES4)
        return -E2BIG;

    r.proto = parse_proto(proto);
    err = parse_ipv4(dst, &r.dst_ip);
    if (err)
        return err;
    err = parse_u16(start, &r.port_start);
    if (err)
        return err;
    err = parse_u16(end, &r.port_end);
    if (err)
        return err;
    if (r.port_start > r.port_end)
        return -EINVAL;

    cfg->rules4[cfg->rule4_count++] = r;
    return 0;
}

static int add_rule6(struct config *cfg, const char *proto, const char *prefix,
                     const char *start, const char *end)
{
    struct wl_rule6 r = {};
    int err;

    if (cfg->rule6_count >= MAX_RULES6)
        return -E2BIG;

    r.proto = parse_proto(proto);
    err = parse_ipv6_prefix(prefix, &r.dst_ip0, &r.mask0);
    if (err)
        return err;
    err = parse_u16(start, &r.port_start);
    if (err)
        return err;
    err = parse_u16(end, &r.port_end);
    if (err)
        return err;
    if (r.port_start > r.port_end)
        return -EINVAL;

    cfg->rules6[cfg->rule6_count++] = r;
    return 0;
}

static int parse_uid_list(char *value, uint32_t *out, int max)
{
    char *save = NULL;
    char *tok;
    int n = 0;

    strip_quotes(value);
    trim(value);

    for (tok = strtok_r(value, " \t", &save);
         tok && n < max;
         tok = strtok_r(NULL, " \t", &save)) {
        char *end = NULL;
        unsigned long v;

        errno = 0;
        v = strtoul(tok, &end, 10);
        if (errno || !end || *end != '\0' || v > UINT32_MAX)
            continue;

        out[n++] = (uint32_t)v;
    }

    return n;
}

static void config_reset(struct config *cfg)
{
    cfg->knobs.default_allow = 0;
    cfg->knobs.uid_mode = 0;
    cfg->knobs.allow_loopback = 1;
    cfg->rule4_count = 0;
    cfg->rule6_count = 0;
    cfg->bypass_count = 0;
    cfg->only_count = 0;
}

static int parse_conf_line(struct config *cfg, char *line)
{
    char *eq;
    char *key;
    char *value;

    trim(line);
    if (!*line || line[0] == '#')
        return 0;

    eq = strchr(line, '=');
    if (!eq)
        return 0;

    *eq = '\0';
    key = line;
    value = eq + 1;
    trim(key);
    trim(value);

    if (!strcmp(key, "DEFAULT_ALLOW")) {
        cfg->knobs.default_allow = atoi(value) ? 1 : 0;
    } else if (!strcmp(key, "UID_MODE")) {
        cfg->knobs.uid_mode = atoi(value) ? 1 : 0;
    } else if (!strcmp(key, "ONLY_UIDS")) {
        cfg->only_count = parse_uid_list(value, cfg->only_uids, MAX_UID_FLAGS);
    } else if (!strcmp(key, "BYPASS_UIDS")) {
        cfg->bypass_count = parse_uid_list(value, cfg->bypass_uids, MAX_UID_FLAGS);
    } else if (!strcmp(key, "ALLOW_LOOPBACK")) {
        cfg->knobs.allow_loopback = atoi(value) ? 1 : 0;
    } else if (!strcmp(key, "RULE4")) {
        char *fields[4];
        int n;

        strip_quotes(value);
        n = split_fields(value, fields, 4);
        if (n != 4)
            return -EINVAL;

        if (add_rule4(cfg, fields[0], fields[1], fields[2], fields[3]))
            fprintf(stderr, "warning: skipping invalid RULE4: %s\n", value);
    } else if (!strcmp(key, "RULE6")) {
        char *fields[4];
        int n;

        strip_quotes(value);
        n = split_fields(value, fields, 4);
        if (n != 4)
            return -EINVAL;

        if (add_rule6(cfg, fields[0], fields[1], fields[2], fields[3]))
            fprintf(stderr, "warning: skipping invalid RULE6: %s\n", value);
    }
    /* ICMP4 / ICMP_ALLOW_ALL / SRC_NET4 / SRC_NET6 are handled by the shell side. */

    return 0;
}

static int load_config(struct config *cfg)
{
    FILE *fp;
    char line[MAX_LINE];
    int err = 0;

    if (!cfg->conf_path[0])
        return 0;

    fp = fopen(cfg->conf_path, "r");
    if (!fp)
        return -errno;

    while (fgets(line, sizeof(line), fp)) {
        if (parse_conf_line(cfg, line))
            err = -EINVAL;
    }

    fclose(fp);
    return err;
}

static int apply_uid_flags(struct wl_bpf *skel, const struct config *cfg)
{
    int fd = bpf_map__fd(skel->maps.uid_flags);
    __u32 key, next;
    int err;
    __u8 value;

    err = bpf_map_get_next_key(fd, NULL, &key);
    while (err == 0) {
        bpf_map_delete_elem(fd, &key);
        err = bpf_map_get_next_key(fd, &key, &next);
        key = next;
    }

    for (int i = 0; i < cfg->bypass_count; i++) {
        value = 1;
        key = cfg->bypass_uids[i];
        if (bpf_map_update_elem(fd, &key, &value, BPF_ANY))
            fprintf(stderr, "failed to add bypass uid %u: %s\n",
                    key, strerror(errno));
    }

    for (int i = 0; i < cfg->only_count; i++) {
        value = 2;
        key = cfg->only_uids[i];
        if (bpf_map_update_elem(fd, &key, &value, BPF_ANY))
            fprintf(stderr, "failed to add only uid %u: %s\n",
                    key, strerror(errno));
    }

    return 0;
}

static int apply_rules4(struct wl_bpf *skel, const struct config *cfg)
{
    int fd = bpf_map__fd(skel->maps.rules4);
    struct wl_rule4 zero = {};
    __u32 idx;

    for (idx = 0; idx < MAX_RULES4; idx++) {
        const struct wl_rule4 *val =
            idx < (__u32)cfg->rule4_count ? &cfg->rules4[idx] : &zero;

        if (bpf_map_update_elem(fd, &idx, val, BPF_ANY)) {
            fprintf(stderr, "failed to update rule4[%u]: %s\n",
                    idx, strerror(errno));
            return -errno;
        }
    }

    return 0;
}

static int apply_rules6(struct wl_bpf *skel, const struct config *cfg)
{
    int fd = bpf_map__fd(skel->maps.rules6);
    struct wl_rule6 zero = {};
    __u32 idx;

    for (idx = 0; idx < MAX_RULES6; idx++) {
        const struct wl_rule6 *val =
            idx < (__u32)cfg->rule6_count ? &cfg->rules6[idx] : &zero;

        if (bpf_map_update_elem(fd, &idx, val, BPF_ANY)) {
            fprintf(stderr, "failed to update rule6[%u]: %s\n",
                    idx, strerror(errno));
            return -errno;
        }
    }

    return 0;
}

static int apply_knobs(struct wl_bpf *skel, const struct config *cfg)
{
    int fd = bpf_map__fd(skel->maps.wl_cfg);
    __u32 key = 0;

    if (bpf_map_update_elem(fd, &key, &cfg->knobs, BPF_ANY)) {
        fprintf(stderr, "failed to update config map: %s\n", strerror(errno));
        return -errno;
    }

    return 0;
}

static int apply_config(struct wl_bpf *skel, const struct config *cfg)
{
    int err;

    err = apply_knobs(skel, cfg);
    if (err)
        return err;
    err = apply_rules4(skel, cfg);
    if (err)
        return err;
    err = apply_rules6(skel, cfg);
    if (err)
        return err;
    err = apply_uid_flags(skel, cfg);
    if (err)
        return err;

    return 0;
}

static int attach_cgroup_prog(struct bpf_program *prog, int cgroup_fd,
                              enum bpf_attach_type attach_type,
                              const char *name)
{
    int prog_fd = bpf_program__fd(prog);

    if (prog_fd < 0) {
        fprintf(stderr, "invalid %s program fd\n", name);
        return -EINVAL;
    }

    if (!bpf_prog_attach(prog_fd, cgroup_fd, attach_type, BPF_F_ALLOW_MULTI)) {
        fprintf(stderr, "attached %s to %s with allow-multi\n",
                name, CGROUP_PATH);
        return 0;
    }

    if (!bpf_prog_attach(prog_fd, cgroup_fd, attach_type, 0)) {
        fprintf(stderr, "attached %s to %s with legacy single attach\n",
                name, CGROUP_PATH);
        return 0;
    }

    fprintf(stderr, "attach %s to %s failed: %s\n",
            name, CGROUP_PATH, strerror(errno));
    return -errno;
}

static void detach_cgroup_prog(struct bpf_program *prog, int cgroup_fd,
                               enum bpf_attach_type attach_type,
                               const char *name)
{
    int prog_fd;

    if (cgroup_fd < 0)
        return;

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0)
        return;

    if (bpf_prog_detach2(prog_fd, cgroup_fd, attach_type)) {
        fprintf(stderr, "detach %s from %s failed: %s\n",
                name, CGROUP_PATH, strerror(errno));
    }
}

int main(int argc, char **argv)
{
    struct config cfg;
    struct wl_bpf *skel = NULL;
    int cgroup_fd = -1;
    int err;
    int do_load = 0;

    memset(&cfg, 0, sizeof(cfg));
    strcpy(cfg.pidfile, "/dev/netwhitelist_loader.pid");
    config_reset(&cfg);

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
            usage(argv[0]);
            return 0;
        }

        if (!strcmp(arg, "--conf")) {
            if (++i >= argc) {
                usage(argv[0]);
                return 2;
            }
            if (strlen(argv[i]) >= sizeof(cfg.conf_path)) {
                fprintf(stderr, "--conf path too long\n");
                return 2;
            }
            strcpy(cfg.conf_path, argv[i]);
            do_load = 1;
            continue;
        }

        if (!strncmp(arg, "--conf=", 7)) {
            if (strlen(arg + 7) >= sizeof(cfg.conf_path)) {
                fprintf(stderr, "--conf path too long\n");
                return 2;
            }
            strcpy(cfg.conf_path, arg + 7);
            do_load = 1;
            continue;
        }

        if (!strcmp(arg, "--pidfile")) {
            if (++i >= argc) {
                usage(argv[0]);
                return 2;
            }
            if (strlen(argv[i]) >= sizeof(cfg.pidfile)) {
                fprintf(stderr, "--pidfile path too long\n");
                return 2;
            }
            strcpy(cfg.pidfile, argv[i]);
            continue;
        }

        usage(argv[0]);
        return 2;
    }

    signal(SIGINT, sig_exit);
    signal(SIGTERM, sig_exit);
    signal(SIGUSR1, sig_reload);
    signal(SIGHUP, sig_reload);

    err = bump_memlock_rlimit();
    if (err)
        fprintf(stderr, "warning: failed to raise RLIMIT_MEMLOCK: %s\n",
                strerror(-err));

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = wl_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    err = wl_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    if (do_load) {
        err = load_config(&cfg);
        if (err) {
            fprintf(stderr, "failed to read config %s: %s\n",
                    cfg.conf_path, strerror(-err));
            goto cleanup;
        }
    }

    err = apply_config(skel, &cfg);
    if (err) {
        fprintf(stderr, "failed to apply config: %s\n", strerror(-err));
        goto cleanup;
    }

    cgroup_fd = open(CGROUP_PATH, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cgroup_fd < 0) {
        fprintf(stderr, "failed to open %s: %s\n",
                CGROUP_PATH, strerror(errno));
        err = -errno;
        goto cleanup;
    }

    if ((err = attach_cgroup_prog(skel->progs.wl_connect4, cgroup_fd,
                                  BPF_CGROUP_INET4_CONNECT, "connect4")))
        goto cleanup;
    if ((err = attach_cgroup_prog(skel->progs.wl_connect6, cgroup_fd,
                                  BPF_CGROUP_INET6_CONNECT, "connect6")))
        goto cleanup;
    if ((err = attach_cgroup_prog(skel->progs.wl_udp4_sendmsg, cgroup_fd,
                                  BPF_CGROUP_UDP4_SENDMSG, "udp4_sendmsg")))
        goto cleanup;
    if ((err = attach_cgroup_prog(skel->progs.wl_udp6_sendmsg, cgroup_fd,
                                  BPF_CGROUP_UDP6_SENDMSG, "udp6_sendmsg")))
        goto cleanup;

    {
        FILE *pf = fopen(cfg.pidfile, "w");

        if (pf) {
            fprintf(pf, "%d\n", (int)getpid());
            fclose(pf);
        } else {
            fprintf(stderr, "warning: cannot write pidfile %s: %s\n",
                    cfg.pidfile, strerror(errno));
        }
    }

    fprintf(stderr,
            "netwhitelist loaded: default=%s loopback=%s uid_mode=%s "
            "rules4=%d rules6=%d bypass_uids=%d only_uids=%d\n",
            cfg.knobs.default_allow ? "allow" : "deny",
            cfg.knobs.allow_loopback ? "allow" : "deny",
            cfg.knobs.uid_mode ? "only-listed" : "all",
            cfg.rule4_count, cfg.rule6_count,
            cfg.bypass_count, cfg.only_count);

    while (!exiting) {
        sleep(1);
        if (reload_requested) {
            reload_requested = 0;
            memset(&cfg.knobs, 0, sizeof(cfg.knobs));
            cfg.rule4_count = 0;
            cfg.rule6_count = 0;
            cfg.bypass_count = 0;
            cfg.only_count = 0;
            if (do_load) {
                err = load_config(&cfg);
                if (err)
                    fprintf(stderr, "reload: failed to read config: %s\n",
                            strerror(-err));
                else {
                    err = apply_config(skel, &cfg);
                    if (err)
                        fprintf(stderr, "reload: apply failed: %s\n",
                                strerror(-err));
                    else
                        fprintf(stderr,
                                "reload ok: default=%s rules4=%d rules6=%d "
                                "bypass=%d only=%d\n",
                                cfg.knobs.default_allow ? "allow" : "deny",
                                cfg.rule4_count, cfg.rule6_count,
                                cfg.bypass_count, cfg.only_count);
                }
            } else {
                err = apply_config(skel, &cfg);
                if (err)
                    fprintf(stderr, "reload: apply failed: %s\n",
                            strerror(-err));
            }
        }
    }

    err = 0;
    unlink(cfg.pidfile);

cleanup:
    if (cgroup_fd >= 0) {
        detach_cgroup_prog(skel->progs.wl_udp6_sendmsg, cgroup_fd,
                           BPF_CGROUP_UDP6_SENDMSG, "udp6_sendmsg");
        detach_cgroup_prog(skel->progs.wl_udp4_sendmsg, cgroup_fd,
                           BPF_CGROUP_UDP4_SENDMSG, "udp4_sendmsg");
        detach_cgroup_prog(skel->progs.wl_connect6, cgroup_fd,
                           BPF_CGROUP_INET6_CONNECT, "connect6");
        detach_cgroup_prog(skel->progs.wl_connect4, cgroup_fd,
                           BPF_CGROUP_INET4_CONNECT, "connect4");
        close(cgroup_fd);
    }
    wl_bpf__destroy(skel);
    return err;
}
