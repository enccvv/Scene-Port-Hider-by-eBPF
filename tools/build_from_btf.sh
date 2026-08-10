#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_API="${ANDROID_API:-26}"
ANDROID_NDK="${ANDROID_NDK:-$HOME/android-ndk-r25c}"
NDK_ZIP="${NDK_ZIP:-$HOME/android-ndk-r25c-linux.zip}"
NDK_URL="${NDK_URL:-https://dl.google.com/android/repository/android-ndk-r25c-linux.zip}"
DEPS_DIR="${DEPS_DIR:-$HOME/netwhitelist-deps}"
PREFIX="${PREFIX:-$DEPS_DIR/android-arm64}"
BPFTOOL="${BPFTOOL:-}"

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || return 1
}

if [[ -z "$BPFTOOL" ]]; then
    if [[ -x /usr/local/sbin/bpftool ]]; then
        BPFTOOL=/usr/local/sbin/bpftool
    elif need_cmd bpftool; then
        BPFTOOL=bpftool
    else
        echo "Missing bpftool. Install it or set BPFTOOL=/path/to/bpftool." >&2
        exit 1
    fi
fi

if [[ ! -x "$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android${ANDROID_API}-clang" ]]; then
    echo "Android NDK not found at $ANDROID_NDK"
    echo "Downloading $NDK_URL"
    curl -fL --retry 3 "$NDK_URL" -o "$NDK_ZIP"
    unzip -q "$NDK_ZIP" -d "$HOME"
fi

btf_file=""
for candidate in "$ROOT/btf/vmlinux.btf" "$ROOT/vmlinux.btf"; do
    if [[ -f "$candidate" ]]; then
        btf_file="$candidate"
        break
    fi
done

if [[ -n "$btf_file" ]]; then
    btf_magic="$(xxd -p -l 4 "$btf_file")"
    if [[ "$btf_magic" != "9feb0100" ]]; then
        echo "Unexpected BTF magic in $btf_file: $btf_magic" >&2
        echo "Expected 9feb0100. The file may have been copied as text." >&2
        exit 1
    fi

    echo "==> Generating src/vmlinux.h from $btf_file"
    "$BPFTOOL" btf dump file "$btf_file" format c > "$ROOT/src/vmlinux.h"
elif [[ -f "$ROOT/src/vmlinux.h" ]]; then
    echo "==> Using existing src/vmlinux.h"
else
    cat >&2 <<EOF
Missing target kernel BTF.

Provide one of:
  btf/vmlinux.btf
  vmlinux.btf
  src/vmlinux.h

Recommended for GitHub Actions:
  1. Pull BTF locally:
       adb shell su -c 'cp /sys/kernel/btf/vmlinux /storage/emulated/0/Download/vmlinux.btf && chmod 0644 /storage/emulated/0/Download/vmlinux.btf'
       adb pull /storage/emulated/0/Download/vmlinux.btf ./btf/vmlinux.btf
       adb shell su -c 'rm -f /storage/emulated/0/Download/vmlinux.btf'
  2. Commit btf/vmlinux.btf to your fork.
  3. Run the build workflow.
EOF
    exit 1
fi

echo "==> Building netwhitelist module binaries"
export LIBBPF_SRC="$PREFIX"
export LIBBPF_HEADERS="$PREFIX/include"
export LIBBPF_LIBDIR="$PREFIX/lib"
export BPFTOOL
export EXTRA_LDLIBS="-Wl,-z,max-page-size=0x1000 -Wl,-z,common-page-size=0x1000"
bash "$ROOT/build.sh"

echo "==> Building netwhitelist module binaries"
export LIBBPF_SRC="$PREFIX"
export LIBBPF_HEADERS="$PREFIX/include"
export LIBBPF_LIBDIR="$PREFIX/lib"
export BPFTOOL
bash "$ROOT/build.sh"

echo "==> Packaging KernelSU module"
bash "$ROOT/package.sh"

echo "Built $ROOT/../netwhitelist_module.zip"
