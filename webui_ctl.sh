#!/system/bin/sh
# Helper for the KsuWebUI configuration page. All operations are local.
# Usage:
#   webui_ctl.sh read               -> dump whitelist.conf
#   webui_ctl.sh write <base64>     -> atomically replace whitelist.conf and reload
#   webui_ctl.sh reload             -> send SIGUSR1 to the loader
#   webui_ctl.sh status             -> print one-line loader status
#   webui_ctl.sh tail               -> last log lines

MODDIR=${0%/*}
CONF="$MODDIR/whitelist.conf"
LOG="$MODDIR/whitelist.log"
PIDFILE="/dev/netwhitelist_loader.pid"

is_running() {
    [ -f "$PIDFILE" ] || return 1
    pid="$(cat "$PIDFILE" 2>/dev/null)"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

case "$1" in
    read)
        cat "$CONF" 2>/dev/null
        ;;
    write)
        if [ -z "$2" ]; then
            echo "usage: webui_ctl.sh write <base64>" >&2
            exit 2
        fi
        tmp="$CONF.tmp"
        if ! echo "$2" | base64 -d > "$tmp" 2>/dev/null; then
            echo "failed to decode payload" >&2
            exit 1
        fi
        mv "$tmp" "$CONF" 2>/dev/null || { rm -f "$tmp"; echo "failed to replace $CONF" >&2; exit 1; }
        chmod 644 "$CONF"
        exec "$0" reload
        ;;
    reload)
        if is_running; then
            kill -USR1 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null
            echo "reload signal sent"
        else
            sh "$MODDIR/whitelist_start.sh" start webui >/dev/null 2>&1
            echo "loader restarted"
        fi
        ;;
    status)
        if is_running; then
            echo "running pid=$(cat "$PIDFILE" 2>/dev/null)"
        else
            echo "stopped"
        fi
        ;;
    tail)
        tail -n 20 "$LOG" 2>/dev/null
        ;;
    *)
        echo "usage: webui_ctl.sh {read|write|reload|status|tail}" >&2
        exit 2
        ;;
esac
