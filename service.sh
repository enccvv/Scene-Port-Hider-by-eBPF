#!/system/bin/sh
MODDIR=${0%/*}

sh "$MODDIR/whitelist_start.sh" start late_boot >/dev/null 2>&1 &
