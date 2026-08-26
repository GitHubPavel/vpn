#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_winner.py

Берёт лучший рабочий конфиг из results.csv (файл уже отсортирован
proxy_tester.py: рабочие и быстрые — первыми) и сохраняет его ПОЛНУЮ
ссылку (vless://..., vmess://... и т.д.) в отдельный текстовый файл.

Файл делается специально маленьким и в корне репозитория, чтобы его можно
было забрать одной строкой без авторизации — просто GET-запросом на
https://raw.githubusercontent.com/<user>/<repo>/<branch>/winner.txt
(например, из iOS Shortcut) и сразу подставить в
v2box://install-config?url=<urlencode(содержимое файла)>

Победителем считается первая строка, где:
  - хотя бы один из Claude/ChatGPT ответил "OK..." или Gemini — "вероятно OK";
  - повторная проверка (recheck) не показала "не подтверждён".
Если подходящих конфигов нет — файл не создаётся (и предыдущий не трогаем,
чтобы не затирать последний известный рабочий вариант).
"""

import csv
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "results.csv"
out_path = sys.argv[2] if len(sys.argv) > 2 else "winner.txt"


def is_ok(row):
    claude_ok = str(row.get("claude", "")).startswith("OK")
    chatgpt_ok = str(row.get("chatgpt", "")).startswith("OK")
    gemini_ok = row.get("gemini") == "вероятно OK"
    return claude_ok or chatgpt_ok or gemini_ok


def recheck_alive(row):
    return row.get("recheck") != "не подтверждён (умер за это время)"


def main():
    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    winner = None
    for r in rows:
        if r.get("full_uri") and is_ok(r) and recheck_alive(r):
            winner = r
            break

    if winner is None:
        print("Рабочих конфигов не найдено — winner.txt не обновлён.")
        return

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(winner["full_uri"].strip() + "\n")

    print(f"Победитель: {winner.get('name') or '(без имени)'} -> {out_path}")
    print(winner["full_uri"])


if __name__ == "__main__":
    main()
