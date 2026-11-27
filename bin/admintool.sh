#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$(readlink -f "$0")")/lib/common.sh"

MAIN_LOG="$LOG_DIR/admintool.log"
STEPS_ORDER="health logs audit respond report"
FORMAT=json

DO_HEALTH=0
DO_LOGS=0
DO_AUDIT=0
DO_RESPOND=0
DO_REPORT=0

usage() {
    cat <<EOF
Использование: admintool.sh [флаги]
  --health            мониторинг ресурсов (health.sh)
  --logs              разбор журналов (logwatch.py)
  --audit             аудит безопасности (secaudit.py)
  --respond           реагирование (respond.sh, нужен root)
  --report            сводный отчёт (report.py)
  --format json|html  формат отчёта для --report (по умолчанию json)
  --all               всё по порядку: health → logs → audit → respond → report
  --help              эта справка
Без флагов — интерактивное меню.
EOF
}

select_all() {
    DO_HEALTH=1
    DO_LOGS=1
    DO_AUDIT=1
    DO_RESPOND=1
    DO_REPORT=1
}

menu() {
    local choice
    PS3="Выберите действие: "
    select choice in health logs audit respond "report (html)" all exit; do
        case "$choice" in
            health) DO_HEALTH=1 ;;
            logs) DO_LOGS=1 ;;
            audit) DO_AUDIT=1 ;;
            respond) DO_RESPOND=1 ;;
            "report (html)") DO_REPORT=1; FORMAT=html ;;
            all) select_all ;;
            exit) exit 0 ;;
            *) echo "Нет такого пункта"; continue ;;
        esac
        break
    done
}

parse_args() {
    local opt
    while getopts ":h-:" opt; do
        case "$opt" in
            h) usage; exit 0 ;;
            -)
                case "$OPTARG" in
                    health) DO_HEALTH=1 ;;
                    logs) DO_LOGS=1 ;;
                    audit) DO_AUDIT=1 ;;
                    respond) DO_RESPOND=1 ;;
                    report) DO_REPORT=1 ;;
                    all) select_all ;;
                    format)
                        if (( OPTIND > $# )); then
                            log_err "после --format нужно значение: json или html"
                            exit 3
                        fi
                        FORMAT="${!OPTIND}"
                        OPTIND=$((OPTIND + 1))
                        ;;
                    format=*) FORMAT="${OPTARG#*=}" ;;
                    help) usage; exit 0 ;;
                    *) log_err "неизвестный флаг --$OPTARG"; usage; exit 3 ;;
                esac
                ;;
            *)
                log_err "неизвестный флаг -$OPTARG (используйте длинные флаги, см. --help)"
                exit 3
                ;;
        esac
    done

    if [[ "$FORMAT" != json && "$FORMAT" != html ]]; then
        log_err "неверный формат '$FORMAT': нужен json или html"
        exit 3
    fi
}

check_dependencies() {
    require_cmds python3 jq ping ss
    if ! command -v firewall-cmd >/dev/null 2>&1 && ! command -v iptables >/dev/null 2>&1; then
        log_err "missing dependencies: firewall-cmd или iptables"
        exit 3
    fi
}

step_command() {
    case "$1" in
        health) echo "$ADMINTOOL_ROOT/bin/health.sh" ;;
        logs) echo "python3 $PY_DIR/logwatch.py --source journal --since 24h --out $LOG_DIR/logwatch.json" ;;
        audit) echo "python3 $PY_DIR/secaudit.py --out $LOG_DIR/secaudit.json" ;;
        respond) echo "$ADMINTOOL_ROOT/bin/respond.sh" ;;
        report) echo "python3 $PY_DIR/report.py --format $FORMAT" ;;
    esac
}

step_selected() {
    case "$1" in
        health) (( DO_HEALTH )) ;;
        logs) (( DO_LOGS )) ;;
        audit) (( DO_AUDIT )) ;;
        respond) (( DO_RESPOND )) ;;
        report) (( DO_REPORT )) ;;
    esac
}

run_step() {
    local name="$1" start end duration rc=0 cmd
    read -r -a cmd <<< "$(step_command "$name")"

    echo "=== $name ==="
    start=$(date +%s%N)
    "${cmd[@]}" || rc=$?
    end=$(date +%s%N)
    duration=$(( (end - start) / 1000000 ))

    log_to "$MAIN_LOG" "step=$name | rc=$rc | $(status_name "$rc") | ${duration}ms"
    return "$rc"
}

main() {
    if (( $# == 0 )); then
        menu
    else
        parse_args "$@"
    fi
    check_dependencies

    local name rc worst=0 ran=0
    for name in $STEPS_ORDER; do
        step_selected "$name" || continue
        ran=1
        rc=0
        run_step "$name" || rc=$?

        if (( rc >= 3 )); then
            log_err "шаг $name завершился с ошибкой (код $rc), выполнение остановлено"
            log_to "$MAIN_LOG" "STOP | шаг $name, код $rc"
            exit 3
        fi
        if (( rc == 2 )); then
            log_to "$MAIN_LOG" "CRIT | шаг $name вернул CRIT, продолжаем"
        fi
        (( rc > worst )) && worst=$rc
    done

    if (( ! ran )); then
        usage
        exit 3
    fi
    log_to "$MAIN_LOG" "DONE | итоговый статус $(status_name "$worst")"
    exit "$worst"
}

main "$@"
