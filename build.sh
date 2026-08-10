#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$ROOT/src"
OUT="$ROOT/system/bin"

ANDROID_API="${ANDROID_API:-26}"
ANDROID_NDK="${ANDROID_NDK:-${ANDROID_NDK_HOME:-}}"
LIBBPF_SRC="${LIBBPF_SRC:-}"
BPF_CC="${BPF_CC:-clang}"
BPFTOOL="${BPFTOOL:-${BPFOOL:-bpftool}}"
TARGET_CC="${TARGET_CC:-}"
VMLINUX_H="${VMLINUX_H:-$SRC/vmlinux.h}"
EXTRA_LDLIBS="${EXTRA_LDLIBS:-}"

if [[ -z "$ANDROID_NDK" ]]; then
    echo "Set ANDROID_NDK or ANDROID_NDK_HOME to your Android NDK path." >&2
    exit 1
fi

if [[ -z "$LIBBPF_SRC" ]]; then
    echo "Set LIBBPF_SRC to a libbpf checkout/build directory." >&2
    exit 1
fi

if [[ ! -f "$VMLINUX_H" ]]; then
    echo "Missing $VMLINUX_H. Generate it from the target device BTF first." >&2
    exit 1
fi

if [[ -z "$TARGET_CC" ]]; then
    HOST_TAG="linux-x86_64"
    case "$(uname -s)" in
        Darwin) HOST_TAG="darwin-x86_64" ;;
        MINGW*|MSYS*|CYGWIN*) HOST_TAG="windows-x86_64" ;;
    esac
    TARGET_CC="$ANDROID_NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin/aarch64-linux-android${ANDROID_API}-clang"
fi

LIBBPF_HEADERS="${LIBBPF_HEADERS:-}"
if [[ -z "$LIBBPF_HEADERS" ]]; then
    for candidate in \
        "$LIBBPF_SRC/include" \
        "$LIBBPF_SRC/src/root/usr/include" \
        "$LIBBPF_SRC/root/usr/include"; do
        if [[ -f "$candidate/bpf/bpf_core_read.h" ]]; then
            LIBBPF_HEADERS="$candidate"
            break
        fi
    done
fi

if [[ -z "$LIBBPF_HEADERS" || ! -f "$LIBBPF_HEADERS/bpf/bpf_core_read.h" ]]; then
    echo "Could not find libbpf headers." >&2
    echo "Set LIBBPF_HEADERS to a directory containing bpf/bpf_core_read.h." >&2
    echo "Current LIBBPF_SRC=$LIBBPF_SRC" >&2
    exit 1
fi

LIBBPF_LIBDIR="${LIBBPF_LIBDIR:-$LIBBPF_SRC/src}"

mkdir -p "$OUT"

"$BPF_CC" -target bpf -D__TARGET_ARCH_arm64 -g -O2 \
    -I"$SRC" \
    -I"$LIBBPF_HEADERS" \
    -c "$SRC/whitelist.bpf.c" \
    -o "$OUT/wl.bpf.o"

"$BPFTOOL" gen skeleton "$OUT/wl.bpf.o" > "$SRC/whitelist.skel.h"

"$TARGET_CC" -O2 -Wall -Wextra -static \
    -I"$SRC" \
    -I"$LIBBPF_HEADERS" \
    -L"$LIBBPF_LIBDIR" \
    -o "$OUT/wl_loader" \
    "$SRC/whitelist_loader.c" \
    -lbpf -lelf -lz $EXTRA_LDLIBS

chmod 0755 "$OUT/wl_loader" 2>/dev/null || \
    echo "Warning: could not chmod $OUT/wl_loader; this is normal on some /mnt/* WSL mounts."
echo "Built $OUT/wl_loader and $OUT/wl.bpf.o"
