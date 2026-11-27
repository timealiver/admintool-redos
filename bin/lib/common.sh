#!/usr/bin/env bash

ADMINTOOL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_DIR="$ADMINTOOL_ROOT/logs"
CONF_FILE="$ADMINTOOL_ROOT/conf/thresholds.json"
ERR_LOG="$LOG_DIR/admintool.err"
PY_DIR="$ADMINTOOL_ROOT/py"

mkdir -p "$LOG_DIR"

ts() { date '+%F %T'; }

log_err() {
    echo "$(ts) | $(basename "$0") | ERROR | $*" >> "$ERR_LOG"
    echo "ERROR: $*" >&2
}

log_to() {
    local file="$1"; shift
    echo "$(ts) | $*" >> "$file"
}

require_cmds() {
    local missing=()
    local c
    for c in "$@"; do
        command -v "$c" >/dev/null 2>&1 || missing+=("$c")
    done
    if ((${#missing[@]})); then
        log_err "missing dependencies: ${missing[*]}"
        exit 3
    fi
}

conf_get() {
    local key="$1"
    local val
    val=$(jq -r --arg k "$key" '.[$k] // empty | if type == "array" then join(" ") else . end' "$CONF_FILE")
    if [[ -z "$val" ]]; then
        log_err "config key '$key' not found in $CONF_FILE"
        exit 3
    fi
    echo "$val"
}

status_name() {
    case "$1" in
        0) echo OK ;;
        1) echo WARN ;;
        2) echo CRIT ;;
        *) echo UNKNOWN ;;
    esac
}

level_for() {
    local value="$1" warn="$2" crit="$3"
    if (( value >= crit )); then
        return 2
    elif (( value >= warn )); then
        return 1
    fi
    return 0
}

valid_ipv4() {
    local ip="$1" octet
    local octets=()
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS=. read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        (( 10#$octet <= 255 )) || return 1
    done
    return 0
}
