#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Читает results.csv (уже отсортированный proxy_tester.py) и печатает
markdown-таблицу в stdout — используется для вывода в сводку прогона
GitHub Actions ($GITHUB_STEP_SUMMARY), чтобы результат был виден сразу
на странице прогона без скачивания файла.
"""

import csv
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "results.csv"
top_n = int(sys.argv[2]) if len(sys.argv) > 2 else 50

with open(path, encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

print(f"### Результаты проверки — {len(rows)} конфигов (топ {min(top_n, len(rows))}, рабочие и быстрые — вверху)\n")
print("| Имя | IP | Репутация IP | Claude | ChatGPT | Gemini |")
print("|---|---|---|---|---|---|")

for r in rows[:top_n]:
    name = (r.get("name") or "—")[:40].replace("|", "/")
    ip = r.get("external_ip") or "—"
    reputation = r.get("ip_reputation") or "—"
    claude = r.get("claude") or r.get("error") or "—"
    chatgpt = r.get("chatgpt") or "—"
    gemini = r.get("gemini") or "—"
    print(f"| {name} | {ip} | {reputation} | {claude} | {chatgpt} | {gemini} |")
