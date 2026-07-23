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
  2. pip install requests[socks]
  3. Список конфигов можно взять двумя способами:
     а) файлом configs.txt (по одной ссылке vless://.../ss://.../trojan:// на строку)
     б) напрямую по ссылке подписки через --sub-url (тот же URL, что и в V2Box
        в настройках группы подписки) — тогда список всегда свежий, руками
        обновлять не нужно.

Запуск (файл):
  python proxy_tester.py configs.txt --xray "C:\\path\\to\\xray.exe"

Запуск (по ссылке подписки):
  python proxy_tester.py --sub-url "https://.../sub" --xray "C:\\path\\to\\xray.exe"

Результат: results.csv с колонками — статус по каждому конфигу,
внешний IP через прокси, доступность claude.ai и chat.openai.com, задержка.
"""

import argparse
import base64
import csv
import json
import os
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

DEFAULT_TARGETS = {
    "ip_check": "https://api.ipify.org?format=json",
    "claude": "https://claude.ai",
    "chatgpt": "https://chat.openai.com",
}

TIMEOUT = 7          # сек. на каждый HTTP-запрос через прокси
STARTUP_WAIT = 1.5   # сек. на старт xray перед тестами


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


def test_one(uri, xray_path, targets):
    result = {"uri": uri[:70], "error": ""}
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

        for name, url in targets.items():
            t0 = time.time()
            try:
                r = requests.get(url, proxies=proxies, timeout=TIMEOUT)
                dt = round(time.time() - t0, 2)
                result[name] = f"OK {r.status_code} ({dt}s)"
                if name == "ip_check":
                    try:
                        result["external_ip"] = r.json().get("ip", "")
                    except Exception:
                        result["external_ip"] = ""
            except requests.exceptions.Timeout:
                result[name] = "TIMEOUT"
            except Exception as e:
                result[name] = f"FAIL ({type(e).__name__})"

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


def main():
    ap = argparse.ArgumentParser(description="Тестирование списка VPN-конфигов через xray-core")
    ap.add_argument("configs_file", nargs="?", help="Файл со списком ссылок (по одной на строку)")
    ap.add_argument("--sub-url", help="Ссылка на подписку — конфиги будут скачаны напрямую (без файла)")
    ap.add_argument("--xray", required=True, help="Путь к xray.exe / xray")
    ap.add_argument("--out", default="results.csv", help="Файл с результатами")
    ap.add_argument("--workers", type=int, default=12, help="Сколько конфигов проверять параллельно (по умолчанию 12)")
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

    fieldnames = ["uri", "external_ip", "ip_check", "claude", "chatgpt", "error"]
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in fieldnames})

    print(f"\nГотово. Результаты в {args.out}")


if __name__ == "__main__":
    main()
