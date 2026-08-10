# User Instruction Memory

This file records user instructions, preferences, and teachings for reference in future interactions.

## Format

### User Instruction Entry
User instruction entries should follow this format:

[User Instruction Summary]
- Date: [YYYY-MM-DD]
- Context: [Mentioned scenario or time]
- Instructions:
  - [Content of user teaching or instruction, described line by line]

### Project Knowledge Entry
Entries discovered by the Agent during task execution should follow this format:

[Project Knowledge Summary]
- Date: [YYYY-MM-DD]
- Context: Discovered by Agent while performing [specific task description]
- Category: [Operations & Deployment|Build Methods|Testing Methods|Troubleshooting & Debugging|Workflow & Collaboration|Environment Configuration]
- Instructions:
  - [Specific knowledge points, described line by line]

## Deduplication Strategy
- Before adding a new entry, check for similar or identical instructions.
- If a duplicate is found, skip the new entry or merge it with the existing one.
- When merging, update the context or date information.
- This helps avoid redundant entries and keeps the memory file tidy.

## Entries

[Project Knowledge Summary]
- Date: 2026-08-10
- Context: Discovered by Agent while performing full rewrite to the NetWhitelist eBPF whitelist firewall module
- Category: Build Methods / Troubleshooting & Debugging / Environment Configuration
- Instructions:
  - Host-side verification build (no Android NDK needed): `clang -target bpf -D__TARGET_ARCH_arm64 -g -O2 -I src -I /usr/include -c src/whitelist.bpf.c -o /tmp/wl/wl.bpf.o`, then `bpftool gen skeleton /tmp/wl/wl.bpf.o > src/whitelist.skel.h`, then `gcc -O2 -Wall -Wextra -I src -I /usr/include -o /tmp/wl/wl_loader src/whitelist_loader.c -lbpf -lelf -lz`.
  - Host environment already has clang 14.0.6, bpftool 7.1.0, libbpf dev headers at `/usr/include/bpf/*`, and libbpf.so in `/usr/lib/x86_64-linux-gnu/`; compile tasks must run in a managed background terminal.
  - Kernel 6.1 `bpf_sock_addr` has NO `msg_dst_*` fields; use `user_ip4`/`user_ip6`/`user_port` (for cgroup connect/sendmsg hooks these carry the destination). The udp4/6_sendmsg hooks fire only on unconnected-socket sendto, where user_* is the per-message destination.
  - BPF map names must not collide with vmlinux.h types; `config` collided with `typedef struct config_s config` and was renamed to `wl_cfg`.
  - Never run `wl_loader` live on the host: it attaches default-deny programs to the root cgroup `/sys/fs/cgroup` and would cut host networking.
  - Offline config-parse test pattern: `#define main loader_real_main` + `#include "src/whitelist_loader.c"`, then call `load_config()` from a test main; build with `-I src -I /usr/include -lbpf -lelf -lz`.
  - 6.1 `bpf_map_get_next_key(fd, key, next_key)` takes 3 args (no size arg).
