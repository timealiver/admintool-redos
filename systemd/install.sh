#!/usr/bin/env bash
set -euo pipefail

UNIT_DIR=/etc/systemd/system
SRC_DIR="$(dirname "$(readlink -f "$0")")"

if [[ $EUID -ne 0 ]]; then
    echo "Нужен root: sudo $0" >&2
    exit 3
fi

mkdir -p /var/log/admintool
cp "$SRC_DIR"/admintool-*.service "$SRC_DIR"/admintool-*.timer "$UNIT_DIR"/
systemctl daemon-reload
systemctl enable --now admintool-health.timer admintool-logs.timer admintool-report.timer
systemctl list-timers 'admintool-*' --no-pager
