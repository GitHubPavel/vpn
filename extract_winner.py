#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_winner.py

Берёт TOP_N лучших рабочих конфигов из results.csv (файл уже отсортирован
proxy_tester.py: рабочие и быстрые — первыми) и сохраняет:

  - winners.txt      — их полные ссылки (vless://... и т.д.), по одной в
                        строке — для справки/отладки;
  - winners_sub.txt  — те же ссылки, склеенные и закодированные в base64 —
                        это стандартный формат v2ray-подписки (тот же, что
                        использует v2rayNG/V2Box). Файл можно скормить
                        напрямую в
                        v2box://install-sub?url=<urlencode(raw-ссылка-на-этот-файл)>&name=Top5
                        и V2Box сам подтянет и распакует все ссылки внутри.

Кандидат считается рабочим, если:
  - хотя бы один из Claude/ChatGPT ответил "OK..." или Gemini — "вероятно OK";
  - повторная проверка (recheck) не показала "не подтверждён".
"""

import base64
import csv
import sys

TOP_N = 10

path = sys.argv[1] if len(sys.argv) > 1 else "results.csv"
out_list_path = sys.argv[2] if len(sys.argv) > 2 else "winners.txt"
out_sub_path = sys.argv[3] if len(sys.argv) > 3 else "winners_sub.txt"


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

    winners = []
    for r in rows:
        if r.get("full_uri") and is_ok(r) and recheck_alive(r):
            winners.append(r)
        if len(winners) >= TOP_N:
            break

    if not winners:
        print("Рабочих конфигов не найдено — файлы не обновлены.")
        return

    uris = [w["full_uri"].strip() for w in winners]

    with open(out_list_path, "w", encoding="utf-8") as f:
        f.write("\n".join(uris) + "\n")

    sub_content = "\n".join(uris)
    b64 = base64.b64encode(sub_content.encode("utf-8")).decode("ascii")
    with open(out_sub_path, "w", encoding="utf-8") as f:
        f.write(b64)

    print(f"Топ-{len(winners)} сохранены в {out_list_path} и {out_sub_path}:")
    for w in winners:
        print(f"  - {w.get('name') or '(без имени)'}")


if __name__ == "__main__":
    main()
