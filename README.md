# admintool

Комплексный проект по дисциплине «Операционная система Linux» (ИТМО): мониторинг, аудит безопасности и Bash/Python-автоматизация. Проверено на РЕД ОС 8.0.3 (aarch64), Python 3.11, jq 1.8, firewalld 2.3.

## Состав

| Файл | Язык | Назначение |
|---|---|---|
| `bin/admintool.sh` | Bash | главный сценарий: флаги, порядок шагов, коды возврата, журнал `logs/admintool.log` |
| `bin/health.sh` | Bash | CPU (`/proc/stat`), память (`free`), диски (`df -P`), потери пакетов (`ping`) |
| `bin/respond.sh` | Bash | блокировка IP в firewalld, предупреждения о портах, топ процессов при CPU CRIT, откат `--unblock-all` |
| `bin/lib/common.sh` | Bash | общие функции: журналирование, зависимости, чтение конфига, проверка IPv4 |
| `py/logwatch.py` | Python | разбор журнала: топ ошибок и IP с неудачными входами |
| `py/secaudit.py` | Python | учётные записи, SUID/SGID, права 777, файлы-сироты, открытые порты |
| `py/report.py` | Python | сводный отчёт HTML/JSON, `--top-processes` |
| `conf/thresholds.json` | JSON | пороги, общие для Bash и Python |
| `systemd/` | unit-файлы | три таймера и службы, `install.sh` |
| `py/tests/` | Python | 16 тестов на unittest |

Коды возврата всех модулей: 0 — OK, 1 — WARN, 2 — CRIT, 3 — ошибка самого инструмента.

## Установка на ВМ

```bash
cp -r admintool /opt/admintool
dnf install -y jq python3 firewalld iproute
systemctl enable --now firewalld
/opt/admintool/systemd/install.sh
```

## Запуск

```bash
cd /opt/admintool
./bin/admintool.sh --all --format html
./bin/admintool.sh --health
./bin/respond.sh --unblock-all
python3 -m unittest discover -s py/tests -v
```

Результаты — в `logs/`, вывод служб systemd — в `/var/log/admintool/systemd.log` и `journalctl -u admintool-*.service`.

Отчёт по работе — `report/`.
