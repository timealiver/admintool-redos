#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timedelta

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONF_FILE = os.path.join(ROOT_DIR, "conf", "thresholds.json")

ISO_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"\S*\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[^\s\[:]+)"
    r"(?:\[\d+\])?"
    r":\s*"
    r"(?P<text>.*)$"
)

SYSLOG_LINE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"
    r"\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[^\s\[:]+)"
    r"(?:\[\d+\])?"
    r":\s*"
    r"(?P<text>.*)$"
)

LEVEL = re.compile(
    r"^\s*[<\[]?(emerg|alert|crit|critical|err|error|warn|warning|notice|info|debug)[>\]:]",
    re.IGNORECASE,
)

ERROR_WORDS = re.compile(r"error|fail|denied|crit|panic", re.IGNORECASE)

IP = r"\d{1,3}(?:\.\d{1,3}){3}"

FAILED_LOGIN = [
    re.compile(r"Failed password for .* from (" + IP + r")"),
    re.compile(r"Invalid user .* from (" + IP + r")"),
]


class LogSourceError(Exception):
    pass


def parse_since(value):
    match = re.fullmatch(r"(\d+)([hd])", value)
    if not match:
        raise argparse.ArgumentTypeError(
            f"неверный формат: '{value}' (нужно число + h или d, например 24h, 7d)"
        )
    number = int(match.group(1))
    unit = match.group(2)
    if unit == "h":
        return timedelta(hours=number)
    return timedelta(days=number)


def parse_timestamp(raw, now):
    if "T" in raw:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S")
    ts = datetime.strptime(f"{now.year} {raw}", "%Y %b %d %H:%M:%S")
    if ts > now + timedelta(days=1):
        ts = ts.replace(year=now.year - 1)
    return ts


def parse_line(line, now):
    for pattern in (ISO_LINE, SYSLOG_LINE):
        match = pattern.match(line)
        if match:
            text = match.group("text")
            level = LEVEL.match(text)
            return {
                "time": parse_timestamp(match.group("ts"), now),
                "host": match.group("host"),
                "proc": match.group("proc"),
                "level": level.group(1).lower() if level else None,
                "text": text,
            }
    return None


def normalize(text):
    text = re.sub(r"\b" + IP + r"\b", "IP", text)
    text = re.sub(r"(?<!\w)/[\w.\-/]+", "PATH", text)
    text = re.sub(r"\d+", "N", text)
    return text


def find_failed_ip(text):
    for pattern in FAILED_LOGIN:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return None


def analyze(lines, since_dt, now, top):
    total = 0
    matched_errors = 0
    unparsed = 0
    errors = Counter()
    examples = {}
    failed_ips = Counter()

    for line in lines:
        if not line.strip():
            continue

        entry = parse_line(line, now)
        if entry is None:
            unparsed += 1
            total += 1
            continue

        if since_dt is not None and entry["time"] < since_dt:
            continue
        total += 1

        if ERROR_WORDS.search(entry["text"]):
            matched_errors += 1
            key = entry["proc"] + ": " + normalize(entry["text"])
            errors[key] += 1
            examples.setdefault(key, line)

        ip = find_failed_ip(entry["text"])
        if ip:
            failed_ips[ip] += 1

    return {
        "period": {
            "from": since_dt.isoformat(timespec="seconds") if since_dt else None,
            "to": now.isoformat(timespec="seconds"),
        },
        "counts": {
            "total": total,
            "matched_errors": matched_errors,
            "unparsed": unparsed,
        },
        "top_errors": [
            {"pattern": key, "count": count, "example": examples[key]}
            for key, count in errors.most_common(top)
        ],
        "top_failed_ips": [
            {"ip": ip, "count": count}
            for ip, count in failed_ips.most_common(top)
        ],
    }


def read_file(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    except FileNotFoundError:
        raise LogSourceError(f"файл не найден: {path}")
    except PermissionError:
        raise LogSourceError(f"нет прав на чтение: {path} (запустите через sudo)")
    except IsADirectoryError:
        raise LogSourceError(f"это каталог, а не файл: {path}")


def read_journal(since_dt):
    cmd = [
        "journalctl",
        "--since", since_dt.strftime("%Y-%m-%d %H:%M:%S"),
        "-o", "short-iso",
        "--no-pager",
    ]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            errors="replace",
        )
    except FileNotFoundError:
        raise LogSourceError("команда journalctl не найдена")
    if result.returncode != 0:
        raise LogSourceError(f"journalctl завершился с ошибкой: {result.stderr.strip()}")
    return result.stdout.splitlines()


def load_failed_logins_threshold():
    try:
        with open(CONF_FILE, encoding="utf-8") as f:
            return int(json.load(f)["failed_logins"])
    except (OSError, ValueError, KeyError) as e:
        raise LogSourceError(f"не удалось прочитать порог failed_logins из {CONF_FILE}: {e}")


def print_table(result, threshold):
    period = result["period"]
    counts = result["counts"]
    print(f"Период: {period['from']} — {period['to']}")
    print(f"Строк: {counts['total']}, ошибок: {counts['matched_errors']}, "
          f"не разобрано: {counts['unparsed']}")

    print()
    print("Топ ошибок:")
    if not result["top_errors"]:
        print("  (нет)")
    for item in result["top_errors"]:
        print(f"  {item['count']:>6}  {item['pattern']}")

    print()
    print(f"Топ IP по неудачным входам (порог блокировки: > {threshold}):")
    if not result["top_failed_ips"]:
        print("  (нет)")
    for item in result["top_failed_ips"]:
        mark = "  <-- выше порога" if item["count"] > threshold else ""
        print(f"  {item['count']:>6}  {item['ip']}{mark}")


def save_json(result, path):
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
    except OSError as e:
        raise LogSourceError(f"не удалось записать {path}: {e}")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Анализ журналов: топ ошибок и топ IP по неудачным входам"
    )
    parser.add_argument("--since", type=parse_since, default="24h",
                        help="за какой период смотреть: 24h, 7d, 2h (по умолчанию 24h)")
    parser.add_argument("--top", type=int, default=5,
                        help="сколько строк в топах (по умолчанию 5)")
    parser.add_argument("--source", choices=["file", "journal"], default="file",
                        help="откуда читать: file (файл из --log) или journal (journalctl)")
    parser.add_argument("--log", default="/var/log/messages",
                        help="путь к файлу журнала для --source file")
    parser.add_argument("--out", default="logs/logwatch.json",
                        help="куда сохранить JSON-отчёт")
    return parser


def main():
    args = build_parser().parse_args()
    now = datetime.now()
    since_dt = now - args.since

    try:
        threshold = load_failed_logins_threshold()
        if args.source == "journal":
            lines = read_journal(since_dt)
        else:
            lines = read_file(args.log)
        result = analyze(lines, since_dt, now, args.top)
        save_json(result, args.out)
    except LogSourceError as e:
        print(f"ОШИБКА: {e}", file=sys.stderr)
        return 2

    print_table(result, threshold)

    for item in result["top_failed_ips"]:
        if item["count"] > threshold:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
