#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$(readlink -f "$0")")/lib/common.sh"

require_cmds jq ping df free awk

CPU_WARN=$(conf_get cpu)
CPU_CRIT=$(conf_get cpu_crit)
MEM_WARN=$(conf_get mem)
MEM_CRIT=$(conf_get mem_crit)
DISK_WARN=$(conf_get disk)
DISK_CRIT=$(conf_get disk_crit)
LOSS_WARN=$(conf_get loss)
LOSS_CRIT=$(conf_get loss_crit)
PING_HOST=$(conf_get ping_host)
DISK_MOUNTS_RAW=$(conf_get disk_mounts)
read -r -a DISK_MOUNTS <<< "$DISK_MOUNTS_RAW"

CPU_VALUE=0
LOAD_VALUE=0
MEM_VALUE=0
DISK_VALUE=0
DISK_WORST=/
NET_VALUE=0

read_cpu_sample() {
    awk '/^cpu /{idle=$5+$6; total=0; for(i=2;i<=9;i++) total+=$i; print total, idle}' /proc/stat
}

check_cpu() {
    LOAD_VALUE=$(awk '{print $1}' /proc/loadavg)
    local t1 i1 t2 i2
    read -r t1 i1 < <(read_cpu_sample)
    sleep 1
    read -r t2 i2 < <(read_cpu_sample)
    local dt=$((t2 - t1)) di=$((i2 - i1))
    CPU_VALUE=$(( (100 * (dt - di) + dt / 2) / dt ))
    level_for "$CPU_VALUE" "$CPU_WARN" "$CPU_CRIT"
}

check_mem() {
    MEM_VALUE=$(free -m -w | awk '/^Mem:/{
        total=$2; free=$4; buffers=$6; cache=$7
        used=total-free
        printf "%d", ((used-buffers-cache)*100/total)+0.5
    }')
    level_for "$MEM_VALUE" "$MEM_WARN" "$MEM_CRIT"
}

check_disk() {
    local line mount pct
    DISK_VALUE=0
    while read -r line; do
        pct=$(awk '{gsub("%","",$5); print $5}' <<< "$line")
        mount=$(awk '{print $6}' <<< "$line")
        if (( pct > DISK_VALUE )); then
            DISK_VALUE=$pct
            DISK_WORST=$mount
        fi
    done < <(df -P "${DISK_MOUNTS[@]}" 2>/dev/null | tail -n +2 | sort -u)
    level_for "$DISK_VALUE" "$DISK_WARN" "$DISK_CRIT"
}

check_net() {
    local out
    out=$(ping -c 5 -W 2 "$PING_HOST" 2>&1 || true)
    NET_VALUE=$(grep -oE '[0-9]+(\.[0-9]+)?% packet loss' <<< "$out" | grep -oE '^[0-9]+' || echo 100)
    level_for "$NET_VALUE" "$LOSS_WARN" "$LOSS_CRIT"
}

main() {
    local rc_cpu=0 rc_mem=0 rc_disk=0 rc_net=0
    check_cpu || rc_cpu=$?
    check_mem || rc_mem=$?
    check_disk || rc_disk=$?
    check_net || rc_net=$?

    local line
    line="$(ts) | cpu=$(status_name $rc_cpu)(${CPU_VALUE}%) | load=${LOAD_VALUE} | mem=$(status_name $rc_mem)(${MEM_VALUE}%) | disk=$(status_name $rc_disk)(${DISK_VALUE}% ${DISK_WORST}) | net=$(status_name $rc_net)(${NET_VALUE}%)"

    local logfile="$LOG_DIR/health_$(date +%F_%H-%M).log"
    echo "$line" >> "$logfile"
    echo "$line"

    local worst=0 rc
    for rc in $rc_cpu $rc_mem $rc_disk $rc_net; do
        (( rc > worst )) && worst=$rc
    done
    exit "$worst"
}

main "$@"
