#!/system/bin/sh

SKIPUNZIP=0

# ── abort fallback (in case the installer framework hasn't defined it) ──
if ! command -v abort >/dev/null 2>&1; then
    abort() {
        ui_print "$1" 2>/dev/null || echo "$1"
        [ -d "$MODPATH" ] && rm -rf "$MODPATH"
        exit 1
    }
fi

# ── SHA-256 helper ──
calc_sha256() {
    local file="$1"
    local line

    if command -v sha256sum >/dev/null 2>&1; then
        line="$(sha256sum "$file" 2>/dev/null)" || return 1
    elif command -v toybox >/dev/null 2>&1; then
        line="$(toybox sha256sum "$file" 2>/dev/null)" || return 1
    elif command -v busybox >/dev/null 2>&1; then
        line="$(busybox sha256sum "$file" 2>/dev/null)" || return 1
    else
        return 1
    fi

    echo "${line%% *}"
}

# ── Kernel BTF fingerprint verification (top-level, always runs) ──
ui_print "- Installing NetWhitelist eBPF Firewall"

expected_file="$MODPATH/kernel_btf.sha256"
tmp_expected="${TMPDIR:-/dev}/netwhitelist_kernel_btf.sha256"
current_btf="/sys/kernel/btf/vmlinux"

# Try extracting from the zip if the file wasn't unpacked to MODPATH
if [ ! -f "$expected_file" ] && [ -n "$ZIPFILE" ] && command -v unzip >/dev/null 2>&1; then
    if unzip -p "$ZIPFILE" kernel_btf.sha256 > "$tmp_expected" 2>/dev/null && [ -s "$tmp_expected" ]; then
        expected_file="$tmp_expected"
    fi
fi

if [ ! -f "$expected_file" ]; then
    abort "! No kernel BTF fingerprint (kernel_btf.sha256) found in module package. Rebuild the module with your device's BTF."
fi

read -r expected < "$expected_file"
if [ -z "$expected" ]; then
    abort "! Empty kernel BTF fingerprint in module package"
fi

if [ ! -r "$current_btf" ]; then
    abort "! Cannot read $current_btf on this device"
fi

actual="$(calc_sha256 "$current_btf")" || abort "! Failed to calculate current kernel BTF fingerprint"

ui_print "- Expected kernel BTF: $expected"
ui_print "- Current  kernel BTF: $actual"

if [ "$expected" != "$actual" ]; then
    abort "! Kernel BTF mismatch. This module was built for another kernel/device."
fi

ui_print "- Kernel BTF matched"
ui_print "- Edit whitelist.conf to change firewall rules"

# Remove leftovers from the previous Scene-port module.
rm -rf "$MODPATH/service.d" "$MODPATH/hideport_start.sh" "$MODPATH/hideport.conf" "$MODPATH/system/bin/hideport_loader"

# ── Permissions ──
set_permissions() {
    set_perm_recursive "$MODPATH" 0 0 0755 0644
    set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
    set_perm "$MODPATH/service.sh" 0 0 0755
    set_perm "$MODPATH/whitelist_start.sh" 0 0 0755
    set_perm "$MODPATH/system/bin/wl_loader" 0 0 0755
}
