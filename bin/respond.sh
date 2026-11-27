#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$(readlink -f "$0")")/lib/common.sh"

ACTIONS_LOG="$LOG_DIR/actions.log"
BLOCKED_LIST="$LOG_DIR/blocked_ips.txt"
LOGWATCH_JSON="$LOG_DIR/logwatch.json"
SECAUDIT_JSON="$LOG_DIR/secaudit.json"
BLOCK_TIMEOUT=10m
BACKEND=""
RESULT=0

action() {
    log_to "$ACTIONS_LOG" "$*"
    echo "$*"
}

choose_backend() {
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        echo firewalld
    elif command -v iptables >/dev/null 2>&1; then
        echo iptables
    else
        log_err "не найден ни firewalld, ни iptables"
        exit 3
    fi
}

rich_rule() {
    echo "rule family=ipv4 source address=$1 reject"
}

is_blocked() {
    case "$BACKEND" in
        firewalld) firewall-cmd --query-rich-rule="$(rich_rule "$1")" >/dev/null 2>&1 ;;
        iptables) iptables -C INPUT -s "$1" -j DROP >/dev/null 2>&1 ;;
    esac
}

block_ip() {
    case "$BACKEND" in
        firewalld) firewall-cmd --add-rich-rule="$(rich_rule "$1")" --timeout="$BLOCK_TIMEOUT" >/dev/null ;;
        iptables) iptables -A INPUT -s "$1" -j DROP ;;
    esac
}

unblock_ip() {
    case "$BACKEND" in
        firewalld) firewall-cmd --remove-rich-rule="$(rich_rule "$1")" >/dev/null ;;
        iptables) iptables -D INPUT -s "$1" -j DROP ;;
    esac
}

block_failed_ips() {
    if [[ ! -f "$LOGWATCH_JSON" ]]; then
        action "WARN | нет $LOGWATCH_JSON — сначала запустите logwatch.py, блокировка пропущена"
        RESULT=1
        return 0
    fi

    local limit ip count
    limit=$(conf_get failed_logins)

    while read -r ip count; do
        if ! valid_ipv4 "$ip"; then
            action "WARN | пропущен некорректный IP '$ip'"
            RESULT=1
            continue
        fi
        if is_blocked "$ip"; then
            action "SKIP | ip=$ip | уже заблокирован"
            continue
        fi
        block_ip "$ip"
        echo "$ip" >> "$BLOCKED_LIST"
        action "BLOCK | ip=$ip | неудачных входов $count > $limit | $BACKEND, на $BLOCK_TIMEOUT"
        RESULT=1
    done < <(jq -r --argjson limit "$limit" \
        '.top_failed_ips[] | select(.count > $limit) | "\(.ip) \(.count)"' "$LOGWATCH_JSON")
}

warn_unexpected_ports() {
    if [[ ! -f "$SECAUDIT_JSON" ]]; then
        action "WARN | нет $SECAUDIT_JSON — сначала запустите secaudit.py, проверка портов пропущена"
        RESULT=1
        return 0
    fi

    local port proto process
    while read -r port proto process; do
        action "WARN | неожиданный порт $port/$proto ($process) | рекомендация: проверить службу; если не нужна — остановить её и закрыть порт: firewall-cmd --permanent --remove-port=$port/$proto"
        RESULT=1
    done < <(jq -r '.ports.unexpected[] | "\(.port) \(.proto) \(.process)"' "$SECAUDIT_JSON")
}

save_top_processes_if_cpu_crit() {
    local last_log last_line out
    last_log=$(ls -t "$LOG_DIR"/health_*.log 2>/dev/null | head -n 1) || true
    [[ -n "$last_log" ]] || return 0

    last_line=$(tail -n 1 "$last_log")
    [[ "$last_line" == *"cpu=CRIT"* ]] || return 0

    if [[ ! -f "$PY_DIR/report.py" ]]; then
        action "WARN | CPU в CRIT, но py/report.py ещё нет — топ процессов не сохранён"
        RESULT=1
        return 0
    fi

    out="$LOG_DIR/top_processes_$(date +%F_%H-%M).json"
    python3 "$PY_DIR/report.py" --top-processes --out "$out"
    action "CPU | cpu=CRIT в $(basename "$last_log") | топ-5 процессов сохранён в $out"
    RESULT=1
}

unblock_all() {
    if [[ ! -f "$BLOCKED_LIST" ]]; then
        echo "Нечего снимать: $BLOCKED_LIST не существует"
        return 0
    fi

    local ip
    while read -r ip; do
        valid_ipv4 "$ip" || continue
        if is_blocked "$ip"; then
            unblock_ip "$ip"
            action "UNBLOCK | ip=$ip | снято вручную (--unblock-all)"
        else
            action "UNBLOCK | ip=$ip | правила уже нет (истёк таймаут)"
        fi
    done < <(sort -u "$BLOCKED_LIST")
    rm -f "$BLOCKED_LIST"
}

main() {
    require_cmds jq python3

    if [[ $EUID -ne 0 ]]; then
        log_err "нужен root (sudo): правила firewall меняет только root"
        exit 3
    fi

    BACKEND=$(choose_backend)

    case "${1:-}" in
        "") ;;
        --unblock-all)
            unblock_all
            exit 0
            ;;
        *)
            log_err "неизвестный аргумент '$1' (есть только --unblock-all)"
            exit 3
            ;;
    esac

    block_failed_ips
    warn_unexpected_ports
    save_top_processes_if_cpu_crit
    exit "$RESULT"
}

main "$@"
