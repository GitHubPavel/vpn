#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
proxy_tester.py

Проверяет список VLESS / Shadowsocks (SS) / Trojan ссылок:
для каждой конфигурации поднимает локальный SOCKS5-прокси через xray-core
и делает реальные HTTP-запросы к целевым сайтам, чтобы понять, работает ли
конфигурация на самом деле, а не только пингуется.

Требования:
  1. Скачать xray-core (ядро, на котором работает V2Box) для Windows:
     https://github.com/XTLS/Xray-core/releases  -> файл Xray-windows-64.zip
     Распаковать, взять xray.exe.
  2. pip install requests[socks] playwright
     playwright install chromium
  3. Список конфигов можно взять двумя способами:
     а) файлом configs.txt (по одной ссылке vless://.../ss://.../trojan:// на строку)
     б) напрямую по ссылке подписки через --sub-url (тот же URL, что и в V2Box
        в настройках группы подписки) — тогда список всегда свежий, руками
        обновлять не нужно.

Проверка идёт в три шага:
  1. Быстрый HTTP-запрос — отсеивает мёртвые серверы (без браузера).
  2. Проверка репутации внешнего IP через proxycheck.io (бесплатно, без ключа) —
     помечен ли IP как VPN/датацентр. Именно по этому признаку Google обычно
     блокирует Gemini (независимо от страны и без входа в аккаунт мы не можем
     поймать реальную блокировку иначе — она срабатывает только у залогиненного
     пользователя при отправке сообщения).
  3. Для живых серверов — реальный Chromium через прокси для claude.ai и
     chat.openai.com: проверка итогового отрендеренного текста страницы на
     фразы блокировки (это ловится надёжно даже анонимно, без входа).

Запуск (файл):
  python proxy_tester.py configs.txt --xray "C:\\path\\to\\xray.exe"

Запуск (по ссылке подписки):
  python proxy_tester.py --sub-url "https://.../sub" --xray "C:\\path\\to\\xray.exe"

Результат: results.csv с колонками — статус по каждому конфигу, внешний IP,
репутация IP (чистый / VPN-датацентр), реальная доступность claude.ai и
chat.openai.com (OK / BLOCKED / TIMEOUT / FAIL), эвристика по Gemini.
"""

import argparse
import base64
import csv
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import urllib.parse as up

try:
    import requests
except ImportError:
    print("Нужен пакет requests с поддержкой socks: pip install requests[socks]")
    sys.exit(1)

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("Нужен пакет playwright: pip install playwright && playwright install chromium")
    sys.exit(1)

DEFAULT_TARGETS = {
    "ip_check": "https://api.ipify.org?format=json",
    "claude": "https://claude.ai",
    "chatgpt": "https://chat.openai.com",
}

# gemini.google.com проверяется отдельно, через репутацию IP (см. IP_REPUTATION_URL) —
# блокировка по стране у Gemini срабатывает только у залогиненного аккаунта при
# отправке сообщения, поэтому анонимная проверка браузером её не ловит и вводит
# в заблуждение (показывает "доступно", хотя реально нет).
IP_REPUTATION_URL = "http://proxycheck.io/v2/{ip}?vpn=1&asn=1&risk=1"

# Проверенные фразы, которыми claude.ai / chat.openai.com сообщают о региональной
# блокировке (собраны из официальных страниц/документации). Проверка идёт по
# итоговому отрендеренному тексту страницы (после JS), а не только по коду
# HTTP-ответа.
BLOCK_PHRASES = {
    "claude": [
        "only available in certain regions",
        "app unavailable",
        "not available in your region",
        "not available in your country",
    ],
    "chatgpt": [
        "not available in your country",
        "is not available in your country",
    ],
}

PAGE_LOAD_TIMEOUT_MS = 12000   # таймаут навигации в браузере
POST_LOAD_WAIT_MS = 1500       # доп. ожидание, чтобы JS успел отрисовать блок-страницу

TIMEOUT = 5          # сек. на быструю первичную HTTP-проверку (ip_check)
STARTUP_WAIT = 1.2   # сек. на старт xray перед тестами


def find_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def b64_fix(s):
    """Добавляет недостающий padding для base64."""
    return s + "=" * (-len(s) % 4)


def parse_vless(uri):
    # vless://uuid@host:port?params#remark
    parsed = up.urlparse(uri)
    uuid = parsed.username
    host = parsed.hostname
    port = parsed.port
    q = dict(up.parse_qsl(parsed.query))
    network = q.get("type", "tcp")
    security = q.get("security", "none")
    flow = q.get("flow", "")

    stream = {"network": network, "security": security}

    if security == "tls":
        stream["tlsSettings"] = {
            "serverName": q.get("sni", host),
            "allowInsecure": False,
            "fingerprint": q.get("fp", "chrome"),
        }
        if q.get("alpn"):
            stream["tlsSettings"]["alpn"] = q["alpn"].split(",")
    elif security == "reality":
        stream["realitySettings"] = {
            "serverName": q.get("sni", host),
            "fingerprint": q.get("fp", "chrome"),
            "publicKey": q.get("pbk", ""),
            "shortId": q.get("sid", ""),
            "spiderX": q.get("spx", ""),
        }

    if network == "ws":
        stream["wsSettings"] = {
            "path": q.get("path", "/"),
            "headers": {"Host": q.get("host", host)},
        }
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": q.get("serviceName", "")}

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{"id": uuid, "encryption": "none", "flow": flow}],
            }]
        },
        "streamSettings": stream,
    }
    return outbound


def parse_ss(uri):
    # Вариант 1: ss://BASE64(method:password)@host:port#remark
    # Вариант 2 (старый): ss://BASE64(method:password@host:port)#remark
    body = uri[len("ss://"):]
    body = body.split("#")[0]

    if "@" in body:
        userinfo, hostport = body.split("@", 1)
        try:
            userinfo = base64.urlsafe_b64decode(b64_fix(userinfo)).decode()
        except Exception:
            try:
                userinfo = base64.b64decode(b64_fix(userinfo)).decode()
            except Exception:
                pass
        method, password = userinfo.split(":", 1)
        host, port = hostport.rsplit(":", 1)
        port = int(port)
    else:
        decoded = base64.urlsafe_b64decode(b64_fix(body)).decode()
        creds, hostport = decoded.split("@", 1)
        method, password = creds.split(":", 1)
        host, port = hostport.rsplit(":", 1)
        port = int(port)

    outbound = {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": host,
                "port": port,
                "method": method,
                "password": password,
            }]
        },
    }
    return outbound


def parse_trojan(uri):
    parsed = up.urlparse(uri)
    password = parsed.username
    host = parsed.hostname
    port = parsed.port
    q = dict(up.parse_qsl(parsed.query))
    outbound = {
        "protocol": "trojan",
        "settings": {
            "servers": [{"address": host, "port": port, "password": password}]
        },
        "streamSettings": {
            "network": q.get("type", "tcp"),
            "security": "tls",
            "tlsSettings": {
                "serverName": q.get("sni", host),
                "allowInsecure": False,
            },
        },
    }
    return outbound


def fetch_subscription(url):
    """
    Скачивает содержимое подписки (как это делает V2Box) и возвращает список
    строк-конфигов. Поддерживает как обычный текст (по ссылке на строку),
    так и весь блок, закодированный целиком в base64 (стандартный формат
    подписок V2rayNG/Shadowrocket/V2Box).
    """
    r = requests.get(url, timeout=20)
    r.raise_for_status()
    text = r.text.strip()

    known_schemes = ("vless://", "ss://", "trojan://", "vmess://")

    if any(scheme in text for scheme in known_schemes):
        raw = text
    else:
        try:
            raw = base64.b64decode(b64_fix(text)).decode("utf-8", errors="ignore")
        except Exception:
            raw = text

    lines = [l.strip() for l in raw.splitlines() if l.strip()]
    return lines


def parse_uri(uri):
    uri = uri.strip()
    if not uri:
        return None
    if uri.startswith("vless://"):
        return parse_vless(uri)
    if uri.startswith("ss://"):
        return parse_ss(uri)
    if uri.startswith("trojan://"):
        return parse_trojan(uri)
    return None  # неподдерживаемый протокол (vmess и др. можно добавить позже)


def build_config(outbound, socks_port):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": False},
        }],
        "outbounds": [outbound],
    }


_ip_reputation_cache = {}
_ip_reputation_lock = threading.Lock()


def check_ip_reputation(ip):
    """
    Проверяет через proxycheck.io: помечен ли IP как VPN/датацентр, в какой
    стране он реально находится по базе Google/proxycheck (а не по названию
    из подписки, которое может быть неверным для wireless/мобильных IP), и
    risk-score по истории злоупотреблений. Результат кэшируется по IP.
    """
    empty = {"is_proxy": False, "country": "", "risk": None, "summary": "unknown"}
    if not ip:
        return empty

    with _ip_reputation_lock:
        if ip in _ip_reputation_cache:
            return _ip_reputation_cache[ip]

    try:
        r = requests.get(IP_REPUTATION_URL.format(ip=ip), timeout=8)
        data = r.json()
        info = data.get(ip, {})
        is_proxy = info.get("proxy") == "yes"
        ip_type = info.get("type", "") or ""
        country = info.get("country", "") or ""
        risk = info.get("risk")
        try:
            risk = int(risk) if risk is not None else None
        except (TypeError, ValueError):
            risk = None

        label = f"VPN/датацентр ({ip_type})" if is_proxy else (f"чистый ({ip_type})" if ip_type else "чистый")
        if country:
            label += f", {country}"
        if risk is not None:
            label += f", risk {risk}"

        result = {"is_proxy": is_proxy, "country": country, "risk": risk, "summary": label}
    except Exception:
        result = empty

    with _ip_reputation_lock:
        _ip_reputation_cache[ip] = result
    return result


def normalize_country(s):
    s = (s or "").strip().lower()
    if s.startswith("the "):
        s = s[4:]
    return s


def has_flag_emoji(name):
    """Проверяет, начинается ли имя с флага-эмодзи (два Regional Indicator Symbol подряд)."""
    if not name or len(name) < 2:
        return False
    cp0, cp1 = ord(name[0]), ord(name[1])
    return 0x1F1E6 <= cp0 <= 0x1F1FF and 0x1F1E6 <= cp1 <= 0x1F1FF


def extract_label_country(name):
    """
    Достаёт название страны из имени конфига (например '🇸🇪 Sweden — #267' -> 'Sweden').
    Возвращает пустую строку, если в имени нет явного флага — чтобы не путать
    страну с произвольным текстом вроде '@FarazV2ray'.
    """
    if not has_flag_emoji(name):
        return ""
    m = re.search(r"([A-Za-z][A-Za-z .]+)", name or "")
    return m.group(1).strip() if m else ""


def extract_name(uri):
    """Достаёт человекочитаемое имя (remark) из ссылки — то же, что видно в V2Box."""
    frag = up.urlparse(uri).fragment
    if frag:
        try:
            return up.unquote(frag)
        except Exception:
            return frag
    return ""


_thread_local = threading.local()
_all_browsers = []
_browsers_lock = threading.Lock()


def get_browser():
    """
    Возвращает Chromium-браузер для текущего потока, создавая его один раз
    на поток (а не на каждый конфиг) — так дороже всего (запуск Chromium)
    происходит один раз, а не сотни раз.
    """
    if not hasattr(_thread_local, "browser"):
        _thread_local.pw = sync_playwright().start()
        _thread_local.browser = _thread_local.pw.chromium.launch(headless=True)
        with _browsers_lock:
            _all_browsers.append((_thread_local.pw, _thread_local.browser))
    return _thread_local.browser


def shutdown_browsers():
    """Закрывает все Chromium-браузеры, поднятые потоками, и останавливает Playwright."""
    with _browsers_lock:
        for pw, browser in _all_browsers:
            try:
                browser.close()
            except Exception:
                pass
            try:
                pw.stop()
            except Exception:
                pass
        _all_browsers.clear()


def check_service(browser, socks_port, url, block_phrases):
    """
    Открывает url через реальный Chromium (с прокси через xray) и проверяет
    итоговый ОТРЕНДЕРЕННЫЙ текст страницы на фразы блокировки — это ловит
    и блокировки на уровне сети, и блокировки, которые сайт показывает уже
    после загрузки через JS (как всплывающее окно у Gemini).
    """
    t0 = time.time()
    context = None
    try:
        context = browser.new_context(
            proxy={"server": f"socks5://127.0.0.1:{socks_port}"},
            ignore_https_errors=True,
        )
        page = context.new_page()
        resp = page.goto(url, timeout=PAGE_LOAD_TIMEOUT_MS, wait_until="domcontentloaded")
        page.wait_for_timeout(POST_LOAD_WAIT_MS)

        status = resp.status if resp else "?"
        try:
            body_text = page.inner_text("body").lower()
        except Exception:
            body_text = ""

        dt = round(time.time() - t0, 2)

        if any(phrase in body_text for phrase in block_phrases):
            return f"BLOCKED {status} ({dt}s)"
        return f"OK {status} ({dt}s)"

    except Exception as e:
        dt = round(time.time() - t0, 2)
        err_name = type(e).__name__
        if "Timeout" in err_name:
            return "TIMEOUT"
        return f"FAIL ({err_name})"
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass


def test_one(uri, xray_path, targets):
    result = {"uri": uri[:70], "_full_uri": uri, "name": extract_name(uri), "error": ""}
    outbound = None
    try:
        outbound = parse_uri(uri)
    except Exception as e:
        result["error"] = f"parse error: {e}"
        return result

    if outbound is None:
        result["error"] = "unsupported protocol"
        return result

    port = find_free_port()
    cfg = build_config(outbound, port)

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        cfg_path = f.name

    proc = None
    try:
        proc = subprocess.Popen(
            [xray_path, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(STARTUP_WAIT)

        if proc.poll() is not None:
            result["error"] = "xray не запустился (проверьте конфиг/параметры)"
            return result

        proxies = {
            "http": f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}",
        }

        # Шаг 1: быстрая проверка базовой доступности (без браузера) —
        # если сервер вообще не отвечает, нет смысла тратить время на Chromium.
        t0 = time.time()
        try:
            r = requests.get(DEFAULT_TARGETS["ip_check"], proxies=proxies, timeout=TIMEOUT)
            dt = round(time.time() - t0, 2)
            result["ip_check"] = f"OK {r.status_code} ({dt}s)"
            try:
                result["external_ip"] = r.json().get("ip", "")
            except Exception:
                result["external_ip"] = ""
        except requests.exceptions.Timeout:
            result["ip_check"] = "TIMEOUT"
        except Exception as e:
            result["ip_check"] = f"FAIL ({type(e).__name__})"

        if not str(result["ip_check"]).startswith("OK"):
            for name in targets:
                if name != "ip_check":
                    result[name] = "SKIP"
            result["ip_reputation"] = "SKIP"
            result["gemini"] = "SKIP"
            return result

        # Шаг 2: репутация IP (для Gemini — блокировка по стране у него ловится
        # только у залогиненного аккаунта, поэтому вместо анонимной проверки
        # смотрим репутацию самого IP: не VPN/датацентр ли это, не завышен ли
        # risk-score, и совпадает ли реальная страна с той, что заявлена в
        # названии конфига — у мобильных/wireless IP геолокация часто врёт).
        reputation = check_ip_reputation(result.get("external_ip", ""))
        summary = reputation["summary"]

        label_country = normalize_country(extract_label_country(result.get("name", "")))
        real_country = normalize_country(reputation.get("country", ""))
        country_mismatch = bool(label_country and real_country and label_country not in real_country and real_country not in label_country)
        if country_mismatch:
            summary += f" [метка: {result.get('name', '').strip()!r} ≠ реальная страна]"

        result["ip_reputation"] = summary

        risk = reputation.get("risk")
        looks_clean = (
            not reputation["is_proxy"]
            and not country_mismatch
            and (risk is None or risk < 50)
        )
        result["gemini"] = "вероятно OK" if looks_clean else "вероятно BLOCKED"

        # Шаг 3: сервер живой — проверяем реальную доступность сервисов через браузер.
        browser = get_browser()
        for name, url in targets.items():
            if name == "ip_check":
                continue
            result[name] = check_service(browser, port, url, BLOCK_PHRASES.get(name, []))

    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        try:
            os.remove(cfg_path)
        except OSError:
            pass

    return result


def _latency(value):
    """Извлекает число секунд из строки вида 'OK 200 (0.81s)'. Возвращает inf, если не удалось."""
    if not value:
        return float("inf")
    m = re.search(r"\(([\d.]+)s\)", value)
    return float(m.group(1)) if m else float("inf")


def sort_key(row):
    claude_ok = str(row.get("claude", "")).startswith("OK")
    chatgpt_ok = str(row.get("chatgpt", "")).startswith("OK")
    gemini_ok = str(row.get("gemini", "")) == "вероятно OK"
    ip_ok = str(row.get("ip_check", "")).startswith("OK")

    ok_count = sum([claude_ok, chatgpt_ok, gemini_ok])

    if ok_count == 3:
        rank = 0
    elif ok_count > 0:
        rank = 1
    elif ip_ok:
        rank = 2
    else:
        rank = 3

    avg_latency = min(
        _latency(row.get("claude", "")),
        _latency(row.get("chatgpt", "")),
    )
    return (rank, -ok_count, avg_latency)


def main():
    ap = argparse.ArgumentParser(description="Тестирование списка VPN-конфигов через xray-core")
    ap.add_argument("configs_file", nargs="?", help="Файл со списком ссылок (по одной на строку)")
    ap.add_argument("--sub-url", help="Ссылка на подписку — конфиги будут скачаны напрямую (без файла)")
    ap.add_argument("--xray", required=True, help="Путь к xray.exe / xray")
    ap.add_argument("--out", default="results.csv", help="Файл с результатами")
    ap.add_argument("--workers", type=int, default=10, help="Сколько конфигов проверять параллельно (по умолчанию 10 — каждый поток держит свой Chromium)")
    ap.add_argument("--recheck", type=int, default=20, help="Сколько лучших кандидатов перепроверять повторно перед выдачей результата (по умолчанию 20, 0 — отключить)")
    args = ap.parse_args()

    if not os.path.isfile(args.xray):
        print(f"Не найден xray по пути: {args.xray}")
        sys.exit(1)

    if args.sub_url:
        print("Скачиваю подписку...")
        lines = fetch_subscription(args.sub_url)
    elif args.configs_file:
        with open(args.configs_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    else:
        print("Нужно указать либо configs_file, либо --sub-url")
        sys.exit(1)

    print(f"Найдено конфигов: {len(lines)}. Проверяю параллельно ({args.workers} потоков)...")
    rows = []
    done_count = [0]
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(test_one, uri, args.xray, DEFAULT_TARGETS): uri for uri in lines}
        for fut in as_completed(futures):
            res = fut.result()
            rows.append(res)
            with lock:
                done_count[0] += 1
                print(f"[{done_count[0]}/{len(lines)}] готово")

    shutdown_browsers()

    rows.sort(key=sort_key)

    # Повторная проверка топ-кандидатов: у бесплатных публичных серверов часто
    # ограничение на число одновременных подключений, и сервер, ответивший
    # секунду назад, может уже быть занят другими пользователями этого же
    # источника. Перепроверяем лучшие результаты второй раз, чтобы в топе
    # оказались только те, кто выжил дважды подряд.
    recheck_n = min(args.recheck, len(rows))
    candidates = [r for r in rows[:recheck_n * 3] if sort_key(r)[0] <= 1][:recheck_n]

    if candidates:
        print(f"\nПовторно проверяю топ-{len(candidates)} кандидатов (двойное подтверждение)...")
        by_uri = {r["_full_uri"]: r for r in candidates}

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(test_one, uri, args.xray, DEFAULT_TARGETS): uri for uri in by_uri}
            for fut in as_completed(futures):
                uri = futures[fut]
                second = fut.result()
                first = by_uri[uri]
                still_ok = sort_key(second)[0] <= 1
                first["recheck"] = "подтверждён" if still_ok else "не подтверждён (умер за это время)"

        shutdown_browsers()

    for r in rows:
        r.setdefault("recheck", "не проверялся повторно")

    def final_key(row):
        recheck_rank = 0 if row.get("recheck") == "подтверждён" else (1 if row.get("recheck", "").startswith("не проверялся") else 2)
        return (recheck_rank,) + sort_key(row)

    rows.sort(key=final_key)

    fieldnames = ["name", "uri", "external_ip", "ip_check", "ip_reputation", "claude", "chatgpt", "gemini", "recheck", "error"]
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in fieldnames})

    print(f"\nГотово. Результаты в {args.out} (отсортированы: рабочие и быстрые — вверху)")





if __name__ == "__main__":
    main()
