#!/usr/bin/env python3
import argparse
import json
import os
import pprint
import re
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CA = os.path.join(ROOT_DIR, "conf", "russian_trusted_ca.pem")
OAUTH_URL = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth"
CHAT_URL = "https://gigachat.devices.sberbank.ru/api/v1/chat/completions"

MASTER_PROMPT = """Ты — преподаватель вуза. Ты пишешь текст лекции по Linux для студентов технической специальности.

СОДЕРЖАНИЕ
- Язык русский, академический, но понятный. Без воды, без обращений к читателю, без вопросов к читателю.
- Только проверенные факты. Если называешь команду или утилиту, описывай то, что она действительно делает.
- Никаких заглушек вида «здесь будет текст», «и т. д. по аналогии».

ФОРМАТ ОТВЕТА — СТРОГО ПОСТРОЧНЫЙ
Ответ состоит только из строк пяти видов. Каждая строка — ровно один элемент. Пустые строки допустимы и игнорируются.

1. Подзаголовок:  ## Текст подзаголовка
   - начинается ровно с «## » (два символа # и пробел), больше никаких #;
   - обычный регистр: заглавная только первая буква и имена собственные (Linux, SELinux, systemd пишется как есть);
   - не длиннее 8 слов, без точки в конце;
   - запрещены подзаголовки «Определения», «Заключение», «Выводы», «Итоги», «Введение», а также повтор названия раздела.

2. Определение:  ОПРЕДЕЛЕНИЕ: Термин — текст определения.
   - строка начинается ровно с «ОПРЕДЕЛЕНИЕ: »;
   - термин в обычном регистре (не заглавными буквами), затем пробел, длинное тире «—», пробел и одно-два предложения;
   - определение никогда не бывает подзаголовком и не стоит внутри абзаца.

3. Пункт маркированного списка:  - текст пункта
4. Пункт нумерованного списка:  1. текст пункта  (далее 2., 3. …)
   - в списке от 3 до 7 пунктов, каждый пункт — законченная мысль одной строкой.

5. Абзац: любая другая строка — один абзац из 2–6 предложений. Абзац не начинается с «#», «-», цифры с точкой или «ОПРЕДЕЛЕНИЕ».

ЗАПРЕЩЕНО
- блоки кода, тройные кавычки, примеры скриптов построчно, строки, начинающиеся с «#!», «$» или «#» внутри кода;
  команды упоминай только внутри абзаца или пункта списка, например: команда df -h показывает свободное место;
- Markdown-выделение (**, __, `), таблицы, эмодзи, неразрывные пробелы, ссылки;
- повтор названия раздела в начале ответа.

СТРУКТУРА РАЗДЕЛА
- первая строка — вводный абзац (без подзаголовка);
- затем 3–5 подразделов: подзаголовок, после него минимум два абзаца;
- в разделе не меньше двух определений и хотя бы один список;
- раздел заканчивается обычным абзацем, без подзаголовка «Заключение»."""

OUTLINE_SYSTEM = "Ты составляешь планы вузовских лекций. Отвечай только списком строк, без определений и пояснений."

OUTLINE_PROMPT = """Составь план лекции на тему «{topic}».
Ответ — только строки без пояснений:
первая строка — название лекции;
затем {sections} строк — короткие названия разделов (до 8 слов), по одному в строке, без номеров."""

SECTION_PROMPT = """Лекция на тему «{topic}». План лекции:
{outline}

Напиши полный текст раздела «{section}» объёмом около {words} слов.
Не затрагивай темы других разделов плана — они будут написаны отдельно.
Соблюдай формат ответа и структуру раздела из системных требований строго."""

CONTINUE_PROMPT = """Лекция на тему «{topic}», раздел «{section}».
Уже написаны подразделы: {subheadings}.

Последний абзац раздела:
{tail}

Допиши этот раздел ещё на {words} слов: 1–2 новых подраздела, которых нет в списке выше, с примерами команд Linux
внутри абзацев. Не повторяй уже написанное, не пиши вводный абзац, название раздела и «Заключение».
Соблюдай формат ответа из системных требований строго."""

TEMPLATE = '''# -*- coding: utf-8 -*-
try:
    from docx import Document
except ImportError:
    raise SystemExit('Установите python-docx: pip install python-docx')
from docx.shared import Pt, Cm, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
import os
import sys

FONT_NAME = 'Times New Roman'
FONT_SIZE = Pt(14)
HEADING_COLORS = {1: RGBColor(0x1A, 0x3A, 0x5C), 2: RGBColor(0x2C, 0x3E, 0x50)}

TITLE = __TITLE__

CONTENT = __CONTENT__


def set_font(run, size=FONT_SIZE, bold=None, underline=None, color=None):
    run.font.name = FONT_NAME
    run.font.size = size
    if bold is not None:
        run.bold = bold
    if underline is not None:
        run.underline = underline
    if color is not None:
        run.font.color.rgb = color
    r_fonts = run._element.get_or_add_rPr().get_or_add_rFonts()
    for attr in ('w:ascii', 'w:hAnsi', 'w:cs', 'w:eastAsia'):
        r_fonts.set(qn(attr), FONT_NAME)


def format_body(paragraph):
    fmt = paragraph.paragraph_format
    fmt.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    fmt.first_line_indent = Cm(1.25)
    fmt.line_spacing = 1.5
    fmt.space_after = Pt(8)


def add_title_line(doc, text):
    paragraph = doc.add_paragraph()
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    paragraph.paragraph_format.space_after = Pt(12)
    set_font(paragraph.add_run(text), size=Pt(16), bold=True, color=HEADING_COLORS[1])


def add_heading_custom(doc, text, level=1):
    heading = doc.add_heading(level=level)
    heading.paragraph_format.space_before = Pt(12)
    heading.paragraph_format.space_after = Pt(6)
    set_font(heading.add_run(text), size=Pt(16 if level == 1 else 14), bold=True, color=HEADING_COLORS[level])


def add_paragraph_custom(doc, text):
    paragraph = doc.add_paragraph()
    format_body(paragraph)
    set_font(paragraph.add_run(text))


def add_definition(doc, term, text):
    paragraph = doc.add_paragraph()
    format_body(paragraph)
    set_font(paragraph.add_run('Определение.'), bold=True, underline=True)
    set_font(paragraph.add_run(' ' + term + ' — ' + text))


def add_list_item(doc, text, numbered=False):
    paragraph = doc.add_paragraph(style='List Number' if numbered else 'List Bullet')
    paragraph.paragraph_format.line_spacing = 1.5
    paragraph.paragraph_format.space_after = Pt(4)
    set_font(paragraph.add_run(text))


def build_document():
    doc = Document()
    for section in doc.sections:
        section.top_margin = Cm(2)
        section.bottom_margin = Cm(2)
        section.left_margin = Cm(2)
        section.right_margin = Cm(2)
    normal = doc.styles['Normal']
    normal.font.name = FONT_NAME
    normal.font.size = FONT_SIZE
    normal.element.get_or_add_rPr().get_or_add_rFonts().set(qn('w:eastAsia'), FONT_NAME)

    add_title_line(doc, TITLE)
    for kind, *data in CONTENT:
        if kind == 'h1':
            add_heading_custom(doc, data[0], 1)
        elif kind == 'h2':
            add_heading_custom(doc, data[0], 2)
        elif kind == 'definition':
            add_definition(doc, data[0], data[1])
        elif kind == 'bullet':
            add_list_item(doc, data[0])
        elif kind == 'number':
            add_list_item(doc, data[0], numbered=True)
        else:
            add_paragraph_custom(doc, data[0])
    return doc


def main():
    run_dir = os.getcwd()
    doc = build_document()
    os.chdir(run_dir)
    doc.save('lekciya.docx')
    print('Создан файл: ' + os.path.join(run_dir, 'lekciya.docx'))


if __name__ == '__main__':
    main()
'''


class LLMError(Exception):
    pass


def ssl_context(ca_path):
    if not os.path.isfile(ca_path):
        raise LLMError(f"нет файла сертификатов {ca_path}")
    return ssl.create_default_context(cafile=ca_path)


def post(url, headers, body, context, attempts=4):
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, context=context, timeout=180) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code < 500 and e.code != 429:
                raise LLMError(f"{url}: HTTP {e.code} {e.read().decode('utf-8', 'replace')[:300]}")
            error = f"HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            error = str(getattr(e, "reason", e))
        if attempt < attempts:
            print(f"    сеть: {error}, повтор {attempt}/{attempts - 1}", file=sys.stderr)
            time.sleep(10 * attempt)
    raise LLMError(f"{url}: {error}")


def get_token(auth_key, scope, context):
    body = urllib.parse.urlencode({"scope": scope}).encode()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "RqUID": str(uuid.uuid4()),
        "Authorization": f"Basic {auth_key}",
    }
    return post(OAUTH_URL, headers, body, context)["access_token"]


def ask(token, model, user_prompt, context, max_tokens=4000, system=MASTER_PROMPT):
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.5,
        "max_tokens": max_tokens,
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }
    data = post(CHAT_URL, headers, json.dumps(payload).encode("utf-8"), context)
    return data["choices"][0]["message"]["content"]


def clean(text):
    text = text.replace(" ", " ").replace(" ", " ").replace(" ", " ")
    text = re.sub(r"\*\*|__|`", "", text)
    return re.sub(r"[ \t]+", " ", text).strip()


def parse_outline(text, sections):
    lines = [re.sub(r"^\s*(\d+[.)]|[-*#]+)\s*", "", clean(l)) for l in text.splitlines()]
    lines = [l.strip("«»\" .") for l in lines if l.strip()]
    lines = [l for l in lines if len(l) <= 100 and not re.match(r"^(ОПРЕДЕЛЕНИЕ|план)", l, re.IGNORECASE)]
    if len(lines) < 3:
        raise LLMError("модель вернула пустой план")
    return lines[0], lines[1:sections + 1]


FORBIDDEN_HEADINGS = {"определения", "определение", "заключение", "выводы", "вывод", "итоги", "введение"}
DEFINITION = re.compile(r"^ОПРЕДЕЛЕНИЕ\s*[:.]\s*(.+?)\s+[—–-]\s+(.+)$", re.IGNORECASE)


def fix_term(term):
    if re.fullmatch(r"[A-Z0-9_-]+", term):
        return term.lower()
    if term.isupper():
        return term[:1] + term[1:].lower()
    return term


def parse_section(text, title):
    blocks = [("h1", title)]
    plain_title = re.sub(r"^\d+\.\s*", "", title).lower()
    in_code = False
    for raw in text.splitlines():
        if raw.strip().startswith("```"):
            in_code = not in_code
            continue
        if in_code or raw.lstrip().startswith(("#!", "$ ")):
            continue
        line = clean(raw)
        if not line:
            continue
        bare = re.sub(r"^[#\s]+", "", line)
        definition = DEFINITION.match(bare)
        if definition:
            blocks.append(("definition", fix_term(definition.group(1).strip()), definition.group(2).strip()))
        elif line.startswith("#"):
            heading = bare.rstrip(".:")
            if not heading or heading.lower() in FORBIDDEN_HEADINGS or heading.lower() == plain_title:
                continue
            if heading.isupper():
                heading = heading[:1] + heading[1:].lower()
            blocks.append(("h2", heading))
        elif re.match(r"^[-*•]\s+", line):
            blocks.append(("bullet", re.sub(r"^[-*•]\s+", "", line)))
        elif re.match(r"^\d+[.)]\s+", line):
            blocks.append(("number", re.sub(r"^\d+[.)]\s+", "", line)))
        else:
            blocks.append(("paragraph", line))
    return [b for i, b in enumerate(blocks)
            if not (b[0] == "h2" and (i + 1 == len(blocks) or blocks[i + 1][0] in ("h1", "h2")))]


def fix_heading(text):
    text = re.sub(r"\blinux\b", "Linux", text, flags=re.IGNORECASE)
    return text[:1].upper() + text[1:]


def normalize(title, content):
    fixed = []
    section = ""
    for block in content:
        if block[0] == "paragraph" and not re.search(r"\w", block[1]):
            continue
        if block[0] == "h1":
            section = re.sub(r"^\d+\.\s*", "", block[1]).lower().strip(" .")
        if block[0] == "h2" and block[1].lower().strip(" .") == section:
            continue
        if block[0] in ("h1", "h2"):
            prefix = re.match(r"^\d+\.\s*", block[1])
            head = prefix.group(0) if prefix else ""
            fixed.append((block[0], head + fix_heading(block[1][len(head):])))
        else:
            fixed.append(tuple(block))
    return fix_heading(title), fixed


def render_script(title, content):
    return (TEMPLATE
            .replace("__TITLE__", repr(title))
            .replace("__CONTENT__", pprint.pformat(content, width=110)))


def count_words(content):
    return sum(len(" ".join(str(x) for x in block[1:]).split()) for block in content)


def check_script(path):
    with tempfile.TemporaryDirectory() as tmp:
        result = subprocess.run([sys.executable, path], cwd=tmp, capture_output=True, text=True)
        if result.returncode != 0:
            raise LLMError("сгенерированный скрипт упал: " + result.stderr.strip()[-500:])
        if not os.path.isfile(os.path.join(tmp, "lekciya.docx")):
            raise LLMError("сгенерированный скрипт не создал lekciya.docx в каталоге запуска")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Генерация generate_lekciya.py по теме через GigaChat и мастер-промпт"
    )
    parser.add_argument("topic", nargs="?", help="тема лекции")
    parser.add_argument("--out", default="generate_lekciya.py", help="куда записать скрипт")
    parser.add_argument("--sections", type=int, default=8, help="число разделов (по умолчанию 8)")
    parser.add_argument("--words", type=int, default=650, help="слов на раздел (по умолчанию 650)")
    parser.add_argument("--model", default=os.environ.get("GIGACHAT_MODEL", "GigaChat"),
                        help="модель GigaChat (по умолчанию GigaChat или $GIGACHAT_MODEL)")
    parser.add_argument("--json", help="сохранить сгенерированное содержание в JSON")
    parser.add_argument("--from-json", help="собрать скрипт из ранее сохранённого JSON, без запросов к модели")
    return parser


def generate(args):
    auth_key = os.environ.get("GIGACHAT_AUTH_KEY")
    if not auth_key:
        print("ОШИБКА: задайте ключ авторизации в переменной окружения GIGACHAT_AUTH_KEY", file=sys.stderr)
        return None, None
    scope = os.environ.get("GIGACHAT_SCOPE", "GIGACHAT_API_PERS")
    ca_path = os.environ.get("GIGACHAT_CA_BUNDLE", DEFAULT_CA)

    try:
        context = ssl_context(ca_path)
        token = get_token(auth_key, scope, context)
        print(f"Токен получен, модель {args.model}. Составляю план…")
        title, sections = parse_outline(
            ask(token, args.model, OUTLINE_PROMPT.format(topic=args.topic, sections=args.sections), context, 800,
                system=OUTLINE_SYSTEM),
            args.sections,
        )
        outline = "\n".join(f"{n}. {s}" for n, s in enumerate(sections, 1))
        print(f"Лекция «{title}», разделов: {len(sections)}")
        content = []
        for number, section in enumerate(sections, 1):
            heading = f"{number}. {section}"
            text = ask(token, args.model,
                       SECTION_PROMPT.format(topic=args.topic, outline=outline, section=section, words=args.words),
                       context)
            for _ in range(2):
                if len(text.split()) >= args.words * 0.85:
                    break
                parsed = parse_section(text, heading)
                subheadings = ", ".join(f"«{b[1]}»" for b in parsed if b[0] == "h2") or "нет"
                tail = next((b[1] for b in reversed(parsed) if b[0] == "paragraph"), "")
                text += "\n" + ask(token, args.model,
                                   CONTINUE_PROMPT.format(topic=args.topic, section=section, subheadings=subheadings,
                                                          tail=tail, words=args.words - len(text.split())),
                                   context)
            content.extend(parse_section(text, heading))
            print(f"  {heading}: {len(text.split())} слов, всего {count_words(content)}")
    except LLMError as e:
        print(f"ОШИБКА: {e}", file=sys.stderr)
        return None, None
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"title": title, "content": content}, f, ensure_ascii=False, indent=2)
    return title, content


def main():
    args = build_parser().parse_args()
    if args.from_json:
        with open(args.from_json, encoding="utf-8") as f:
            data = json.load(f)
        title, content = data["title"], data["content"]
    elif args.topic:
        title, content = generate(args)
        if title is None:
            return 2
    else:
        print("ОШИБКА: укажите тему или --from-json", file=sys.stderr)
        return 2

    title, content = normalize(title, content)

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(render_script(title, content))
    try:
        check_script(os.path.abspath(args.out))
    except LLMError as e:
        print(f"ОШИБКА: {e}", file=sys.stderr)
        return 3

    words = count_words(content)
    definitions = sum(1 for block in content if block[0] == "definition")
    print(f"Готово: {args.out}, слов {words}, определений {definitions}")
    if words < 4500:
        print("ВНИМАНИЕ: меньше 4500 слов — увеличьте --words или --sections", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
