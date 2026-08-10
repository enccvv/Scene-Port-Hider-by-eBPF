#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZIP="${1:-$ROOT/../netwhitelist_module.zip}"

if [[ ! -f "$ROOT/system/bin/wl_loader" ]]; then
    echo "Missing executable: $ROOT/system/bin/wl_loader" >&2
    echo "Run ./build.sh first." >&2
    exit 1
fi

fingerprint="$ROOT/kernel_btf.sha256"
btf_source=""
for candidate in "$ROOT/btf/vmlinux.btf" "$ROOT/vmlinux.btf"; do
    if [[ -f "$candidate" ]]; then
        btf_source="$candidate"
        break
    fi
done

if [[ -n "$btf_source" ]]; then
    sha256sum "$btf_source" | awk '{print $1}' > "$fingerprint"
    echo "Wrote kernel BTF fingerprint from $btf_source"
elif [[ -f "$fingerprint" ]]; then
    rm -f "$fingerprint"
    echo "Removed stale kernel BTF fingerprint"
else
    echo "Warning: no vmlinux.btf found; package will not enforce kernel BTF match." >&2
fi

(
    cd "$ROOT"
    files=(
        module.prop
        whitelist.conf
        post-fs-data.sh
        service.sh
        whitelist_start.sh
        customize.sh
        uninstall.sh
        webui_ctl.sh
        webroot/index.html
        system/bin/wl_loader
        system/bin/whitelist.bpf.o
    )
    if [[ -f kernel_btf.sha256 ]]; then
        files+=(kernel_btf.sha256)
    fi

    rm -f "$ZIP"
    zip -r "$ZIP" "${files[@]}" -x '*/.git/*'
)

echo "Wrote $ZIP"
