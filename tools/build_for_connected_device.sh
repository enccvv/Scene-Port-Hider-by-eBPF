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
REMOTE_BTF="/storage/emulated/0/Download/vmlinux.btf"

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || return 1
}

missing=()
for cmd in adb curl unzip make git clang tar xxd zip; do
    need_cmd "$cmd" || missing+=("$cmd")
done

if ((${#missing[@]} > 0)); then
    cat >&2 <<EOF
Missing host tools: ${missing[*]}

On Ubuntu/WSL, install them with:
  sudo apt update
  sudo apt install -y android-tools-adb curl unzip make git clang llvm lld tar xxd zip pkg-config autoconf automake libtool bzip2 xz-utils
EOF
    exit 1
fi

if [[ -z "$BPFTOOL" ]]; then
    if [[ -x /usr/local/sbin/bpftool ]]; then
        BPFTOOL=/usr/local/sbin/bpftool
    elif need_cmd bpftool; then
        BPFTOOL=bpftool
    else
        cat >&2 <<EOF
Missing bpftool.

On Ubuntu/WSL, install it with:
  sudo apt update
  sudo apt install -y bpftool

Or set BPFTOOL=/path/to/bpftool.
EOF
        exit 1
    fi
fi

if [[ ! -x "$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android${ANDROID_API}-clang" ]]; then
    echo "Android NDK not found at $ANDROID_NDK"
    echo "Downloading $NDK_URL"
    curl -fL --retry 3 "$NDK_URL" -o "$NDK_ZIP"
    unzip -q "$NDK_ZIP" -d "$HOME"
fi

echo "==> Pulling target kernel BTF from connected device"
adb wait-for-device
adb shell su -c 'test -r /sys/kernel/btf/vmlinux'
adb shell su -c "cp /sys/kernel/btf/vmlinux '$REMOTE_BTF' && chmod 0644 '$REMOTE_BTF'"
adb pull "$REMOTE_BTF" "$ROOT/vmlinux.btf" >/dev/null
adb shell su -c "rm -f '$REMOTE_BTF'"

btf_magic="$(xxd -p -l 4 "$ROOT/vmlinux.btf")"
if [[ "$btf_magic" != "9feb0100" ]]; then
    echo "Unexpected BTF magic: $btf_magic" >&2
    echo "Do not use shell redirection for BTF; adb pull must preserve binary data." >&2
    exit 1
fi

echo "==> Generating src/vmlinux.h"
"$BPFTOOL" btf dump file "$ROOT/vmlinux.btf" format c > "$ROOT/src/vmlinux.h"

echo "==> Building Android arm64 dependencies"
export ANDROID_NDK
export ANDROID_API
export DEPS_DIR
export PREFIX
bash "$ROOT/build_deps_android.sh"

echo "==> Building netwhitelist module binaries"
export LIBBPF_SRC="$PREFIX"
export LIBBPF_HEADERS="$PREFIX/include"
export LIBBPF_LIBDIR="$PREFIX/lib"
export BPFTOOL
bash "$ROOT/build.sh"

echo "==> Packaging KernelSU module"
bash "$ROOT/package.sh"

cat <<EOF

Done:
  $ROOT/../netwhitelist_module.zip

Install this zip in KernelSU Manager, then reboot.
Logs on device:
  /data/adb/modules/netwhitelist/whitelist.log
EOF
