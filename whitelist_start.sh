#!/system/bin/sh

MODDIR=${0%/*}
CONF="$MODDIR/whitelist.conf"
LOADER="$MODDIR/system/bin/wl_loader"
LOG="$MODDIR/whitelist.log"
PIDFILE="/dev/netwhitelist_loader.pid"
ICMP_PIDFILE="/dev/netwhitelist_icmp.pid"
LOCKDIR="/dev/netwhitelist_loader.lock"

log_msg() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$1] $2" >> "$LOG"
}

is_running() {
    [ -f "$PIDFILE" ] || return 1
    pid="$(cat "$PIDFILE" 2>/dev/null)"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

conf_key() {
    sed -n "s/^$1=//p" "$CONF" 2>/dev/null | tail -n 1
}

conf_keys() {
    sed -n "s/^$1=//p" "$CONF" 2>/dev/null
}

# ---------------------------------------------------------------------------
# ICMP (ping) rules. The eBPF cgroup hook cannot see ICMP, so ping whitelisting
# is enforced with iptables/ip6tables on the OUTPUT chain. echo-request to any
# other target is rejected by default; all other ICMP types (errors, NDP) pass.
# ---------------------------------------------------------------------------

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

apply_icmp_once() {
    local allow_all ip4 ip6 list

    allow_all="$(conf_key ICMP_ALLOW_ALL)"

    if ! has_cmd iptables; then
        log_msg icmp "iptables not found, skipping IPv4 ICMP rules"
        return 0
    fi

    if [ "$allow_all" = "1" ]; then
        iptables -D OUTPUT -p icmp -j ACCEPT 2>/dev/null
        iptables -I OUTPUT 1 -p icmp -j ACCEPT
        log_msg icmp "ICMP_ALLOW_ALL=1: all IPv4 ICMP accepted"
        return 0
    fi

    iptables -I OUTPUT 1 -p icmp --icmp-type echo-request -j REJECT
    for ip4 in $(conf_keys ICMP4); do
        iptables -I OUTPUT 1 -p icmp --icmp-type echo-request -d "$ip4" -j ACCEPT
    done
    log_msg icmp "IPv4 echo-request whitelist applied"
}

apply_icmp6_once() {
    local list

    if ! has_cmd ip6tables; then
        log_msg icmp6 "ip6tables not found, skipping IPv6 ICMP rules"
        return 0
    fi

    list="$(conf_keys ICMP6)"
    [ -n "$list" ] || return 0

    ip6tables -I OUTPUT 1 -p ipv6-icmp --icmpv6-type echo-request -j REJECT
    for ip6 in $list; do
        ip6tables -I OUTPUT 1 -p ipv6-icmp --icmpv6-type echo-request -d "$ip6" -j ACCEPT
    done
    log_msg icmp6 "IPv6 echo-request whitelist applied: $list"
}

icmp_rules_present() {
    local allow_all

    allow_all="$(conf_key ICMP_ALLOW_ALL)"
    [ "$allow_all" = "1" ] && return 0

    if has_cmd iptables; then
        iptables -C OUTPUT -p icmp --icmp-type echo-request -j REJECT >/dev/null 2>&1 || return 1
    fi
    if has_cmd ip6tables && [ -n "$(conf_keys ICMP6)" ]; then
        ip6tables -C OUTPUT -p ipv6-icmp --icmpv6-type echo-request -j REJECT >/dev/null 2>&1 || return 1
    fi
    return 0
}

icmp_daemon() {
    # Re-apply rules until the loader stops; netd/firewall may reset OUTPUT.
    while is_running; do
        if ! icmp_rules_present; then
            apply_icmp_once
            apply_icmp6_once
        fi
        sleep 5
    done
}

icmp_cleanup() {
    if has_cmd iptables; then
        while iptables -D OUTPUT -p icmp -j ACCEPT 2>/dev/null; do :; done
        while iptables -D OUTPUT -p icmp --icmp-type echo-request -j REJECT 2>/dev/null; do :; done
        for ip4 in $(conf_keys ICMP4); do
            while iptables -D OUTPUT -p icmp --icmp-type echo-request -d "$ip4" -j ACCEPT 2>/dev/null; do :; done
        done
    fi
    if has_cmd ip6tables; then
        while ip6tables -D OUTPUT -p ipv6-icmp --icmpv6-type echo-request -j REJECT 2>/dev/null; do :; done
        for ip6 in $(conf_keys ICMP6); do
            while ip6tables -D OUTPUT -p ipv6-icmp --icmpv6-type echo-request -d "$ip6" -j ACCEPT 2>/dev/null; do :; done
        done
    fi
}

# ---------------------------------------------------------------------------
# Loader control
# ---------------------------------------------------------------------------

start() {
    local ctx="$1"
    local lock_pid

    if is_running; then
        log_msg "$ctx" "wl_loader already running"
        return 0
    fi

    if [ ! -x "$LOADER" ]; then
        log_msg "$ctx" "missing executable: $LOADER"
        return 1
    fi

    if ! mkdir "$LOCKDIR" 2>/dev/null; then
        sleep 2
        if is_running; then
            log_msg "$ctx" "wl_loader already running"
            return 0
        fi
        log_msg "$ctx" "another start in progress"
        return 0
    fi

    log_msg "$ctx" "starting wl_loader with conf $CONF"
    "$LOADER" --conf "$CONF" --pidfile "$PIDFILE" >> "$LOG" 2>&1 &

    rmdir "$LOCKDIR" 2>/dev/null

    for i in 1 2 3 4 5 6 7 8 9 10; do
        is_running && break
        sleep 1
    done

    if is_running; then
        log_msg "$ctx" "wl_loader started"
        apply_icmp_once
        apply_icmp6_once
        (
            exec </dev/null
            while is_running; do
                if ! icmp_rules_present; then
                    apply_icmp_once
                    apply_icmp6_once
                fi
                sleep 5
            done
        ) >/dev/null 2>&1 &
        echo "$!" > "$ICMP_PIDFILE"
        return 0
    fi

    log_msg "$ctx" "wl_loader failed to start"
    return 1
}

stop() {
    local pid

    if is_running; then
        pid="$(cat "$PIDFILE" 2>/dev/null)"
        kill "$pid" 2>/dev/null
        for i in 1 2 3 4 5 6 7 8 9 10; do
            is_running || break
            sleep 1
        done
        kill -9 "$pid" 2>/dev/null
        log_msg stop "wl_loader stopped"
    fi

    rm -f "$PIDFILE"
    if [ -f "$ICMP_PIDFILE" ]; then
        kill "$(cat "$ICMP_PIDFILE" 2>/dev/null)" 2>/dev/null
        rm -f "$ICMP_PIDFILE"
    fi

    icmp_cleanup
    rmdir "$LOCKDIR" 2>/dev/null
}

reload() {
    local pid

    if is_running; then
        pid="$(cat "$PIDFILE" 2>/dev/null)"
        kill -USR1 "$pid" 2>/dev/null
        log_msg reload "sent USR1 to $pid"
        apply_icmp_once
        apply_icmp6_once
        return 0
    fi

    log_msg reload "not running, starting"
    start reload
}

status() {
    if is_running; then
        echo "running (pid $(cat "$PIDFILE" 2>/dev/null))"
        return 0
    fi
    echo "stopped"
    return 1
}

case "${1:-start}" in
    start)   start "${2:-manual}" ;;
    stop)    stop ;;
    reload)  reload ;;
    status)  status ;;
    *)       echo "usage: $0 {start|stop|reload|status}" >&2; exit 2 ;;
esac
