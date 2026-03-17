import os
import re
import json
import time
import socket
import psutil
import ipaddress
import subprocess
import platform
import ctypes
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from flask import Flask, Response, jsonify, render_template_string, request, stream_with_context
import nmap

app = Flask(__name__)

MAX_HOSTS_PER_SUBNET = 4096
NMAP_SCAN_ARGUMENTS = "-sn -R -T4 --host-timeout 10s"
IGNORED_IFACE_PARTS = ("docker", "vboxnet", "vmnet", "br-", "loopback", "lo")
ALIASES_FILE = "device_aliases.json"


def is_admin() -> bool:
    system = platform.system()
    try:
        if system == "Windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def safe_run_command(command: str) -> str:
    return subprocess.check_output(
        command,
        shell=True,
        text=True,
        stderr=subprocess.DEVNULL,
        encoding="utf-8",
        errors="ignore",
    ).strip()


def normalize_mac(mac: str) -> str:
    if not mac:
        return ""
    mac = mac.strip().upper().replace("-", ":")
    parts = mac.split(":")
    if len(parts) == 6:
        try:
            return ":".join(f"{int(p, 16):02X}" for p in parts)
        except ValueError:
            return mac
    return mac


def get_default_gateway() -> Optional[str]:
    system = platform.system()

    try:
        if system == "Windows":
            output = safe_run_command("route print -4")
            for line in output.splitlines():
                line = line.strip()
                if not line or "On-link" in line:
                    continue
                if re.match(r"^0\.0\.0\.0\s+0\.0\.0\.0\s+\d+\.\d+\.\d+\.\d+", line):
                    parts = line.split()
                    if len(parts) >= 3:
                        gateway = parts[2]
                        try:
                            ipaddress.ip_address(gateway)
                            return gateway
                        except ValueError:
                            continue

        elif system == "Linux":
            commands = ["ip route show default", "route -n"]
            for cmd in commands:
                try:
                    output = safe_run_command(cmd)
                except Exception:
                    continue

                for line in output.splitlines():
                    line = line.strip()

                    if line.startswith("default via "):
                        parts = line.split()
                        if len(parts) >= 3:
                            gateway = parts[2]
                            try:
                                ipaddress.ip_address(gateway)
                                return gateway
                            except ValueError:
                                pass

                    if re.match(r"^0\.0\.0\.0\s+\d+\.\d+\.\d+\.\d+", line):
                        parts = line.split()
                        if len(parts) >= 2:
                            gateway = parts[1]
                            try:
                                ipaddress.ip_address(gateway)
                                return gateway
                            except ValueError:
                                pass

        elif system == "Darwin":
            commands = ["route -n get default", "netstat -rn"]
            for cmd in commands:
                try:
                    output = safe_run_command(cmd)
                except Exception:
                    continue

                for line in output.splitlines():
                    line = line.strip()

                    if line.lower().startswith("gateway:"):
                        gateway = line.split(":", 1)[1].strip()
                        try:
                            ipaddress.ip_address(gateway)
                            return gateway
                        except ValueError:
                            pass

                    if line.startswith("default "):
                        parts = line.split()
                        if len(parts) >= 2:
                            gateway = parts[1]
                            try:
                                ipaddress.ip_address(gateway)
                                return gateway
                            except ValueError:
                                pass
    except Exception:
        pass

    return None


def get_nmap_scanner() -> nmap.PortScanner:
    try:
        nm = nmap.PortScanner()
        _ = nm.nmap_version()
        return nm
    except Exception as exc:
        raise RuntimeError(
            "nmap не найден или недоступен. Установите nmap и добавьте его в PATH."
        ) from exc


def is_ignored_interface(iface_name: str) -> bool:
    lowered = iface_name.lower()
    return any(part in lowered for part in IGNORED_IFACE_PARTS)


def get_mac_for_ip(target_ip: str) -> str:
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            has_target_ip = any(
                addr.family == socket.AF_INET and addr.address == target_ip
                for addr in addrs
            )
            if not has_target_ip:
                continue

            for addr in addrs:
                if getattr(psutil, "AF_LINK", None) is not None and addr.family == psutil.AF_LINK:
                    return normalize_mac(addr.address or "N/A")

                if isinstance(addr.address, str) and re.match(
                    r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$", addr.address
                ):
                    return normalize_mac(addr.address)
    except Exception:
        pass
    return "N/A"


def resolve_hostname(ip: str, primary: Optional[str] = None) -> str:
    if primary and primary.strip() and primary.strip().lower() != "unknown":
        return primary.strip()

    try:
        host, _, _ = socket.gethostbyaddr(ip)
        if host:
            return host
    except Exception:
        pass

    return "Неизвестно"


def get_all_networks() -> Tuple[List[Dict], List[str]]:
    networks: List[Dict] = []
    local_ips: List[str] = []
    seen_subnets = set()

    default_gw = get_default_gateway()

    for iface, addrs in psutil.net_if_addrs().items():
        if is_ignored_interface(iface):
            continue

        stats = psutil.net_if_stats().get(iface)
        if not stats or not stats.isup:
            continue

        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue
            if not addr.address or addr.address.startswith(("127.", "169.254.")):
                continue
            if not addr.netmask:
                continue

            try:
                net = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
            except Exception:
                continue

            subnet_str = str(net)
            if subnet_str in seen_subnets:
                if addr.address not in local_ips:
                    local_ips.append(addr.address)
                continue

            seen_subnets.add(subnet_str)
            if addr.address not in local_ips:
                local_ips.append(addr.address)

            gateway = None
            gateway_guessed = False

            if default_gw:
                try:
                    gw_ip = ipaddress.ip_address(default_gw)
                    if gw_ip in net:
                        gateway = default_gw
                except ValueError:
                    gateway = None

            if gateway is None:
                try:
                    gateway = str(net.network_address + 1)
                    gateway_guessed = True
                except Exception:
                    gateway = "Неизвестно"
                    gateway_guessed = True

            networks.append(
                {
                    "iface": iface,
                    "subnet": subnet_str,
                    "gateway": gateway,
                    "gateway_guessed": gateway_guessed,
                    "local_ip": addr.address,
                }
            )

    return networks, sorted(set(local_ips), key=lambda ip: ipaddress.ip_address(ip))


def guess_device(hostname: str, vendor: str, ip: str, gateway_ips: List[str]) -> Tuple[str, str]:
    hn = (hostname or "").lower()
    vd = (vendor or "").lower()

    if ip in gateway_ips:
        return "🔌 Шлюз / роутер", "gateway"

    if any(x in vd for x in ["tp-link", "d-link", "asus", "mikrotik", "cisco", "ubiquiti", "huawei"]):
        return "🔌 Сетевое оборудование", "network"

    if any(x in vd for x in ["hp", "brother", "epson", "canon", "kyocera", "xerox", "lexmark"]):
        return "🖨️ Принтер", "printer"

    if any(x in hn for x in ["iphone", "ipad", "macbook", "imac", "apple-tv"]):
        return "🍎 Apple устройство", "apple"

    if "apple" in vd:
        return "🍎 Apple устройство", "apple"

    if any(x in hn for x in ["yandex", "alice", "yndx", "станция", "station"]):
        return "🎙️ Яндекс.Станция", "yandex"

    if any(x in hn for x in ["sber", "salute", "салют"]):
        return "📺 Sber устройство", "sber"

    if "tv" in hn or any(x in vd for x in ["lg", "samsung", "sony", "philips", "tcl", "hisense", "shiyuan"]):
        return "📺 Телевизор / медиаприставка", "tv"

    if any(x in hn for x in ["pc", "desktop", "laptop", "notebook"]) or any(
        x in vd for x in ["lenovo", "dell", "asus", "acer", "msi", "intel"]
    ):
        return "💻 Компьютер / ноутбук", "computer"

    if any(x in hn for x in ["phone", "mobile", "android"]):
        return "📱 Телефон", "phone"

    return "❓ Неизвестное устройство", "unknown"


def load_aliases() -> Dict[str, Dict[str, str]]:
    if not os.path.exists(ALIASES_FILE):
        return {}

    try:
        with open(ALIASES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        devices = data.get("devices", {})
        result = {}
        for mac, meta in devices.items():
            nmac = normalize_mac(mac)
            if not nmac:
                continue
            if isinstance(meta, dict):
                result[nmac] = {
                    "name": str(meta.get("name", "")).strip(),
                    "comment": str(meta.get("comment", "")).strip(),
                }
            else:
                result[nmac] = {
                    "name": str(meta).strip(),
                    "comment": "",
                }
        return result
    except Exception:
        return {}


def save_aliases(devices_mapping: Dict[str, Dict[str, str]]) -> None:
    payload = {
        "version": 1,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "devices": devices_mapping,
    }
    with open(ALIASES_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def build_display_name(dev: Dict) -> str:
    user_name = (dev.get("user_name") or "").strip()
    hostname = (dev.get("hostname") or "").strip()
    vendor = (dev.get("vendor") or "").strip()
    ip = dev.get("ip", "")
    last_octet = ip.split(".")[-1] if "." in ip else ip

    if user_name:
        return user_name

    if hostname and hostname != "Неизвестно":
        return hostname

    if vendor and vendor != "Неизвестно":
        short_vendor = vendor
        replacements = {
            "Technologies": "",
            "Technology": "",
            "Company Limited": "",
            "Co., Ltd.": "",
            "Services AG": "",
            "Limited": "",
        }
        for old, new in replacements.items():
            short_vendor = short_vendor.replace(old, new)

        short_vendor = " ".join(short_vendor.split()).strip(" ,.-")
        if len(short_vendor) > 18:
            short_vendor = short_vendor[:18] + "…"
        return f"{short_vendor} • .{last_octet}"

    return f"Устройство • .{last_octet}"


def apply_aliases_to_device(dev: Dict, aliases: Dict[str, Dict[str, str]]) -> Dict:
    mac = normalize_mac(dev.get("mac", ""))
    alias = aliases.get(mac, {}) if mac and mac != "N/A" else {}

    dev["mac"] = mac if mac else dev.get("mac", "N/A")
    dev["user_name"] = alias.get("name", "")
    dev["comment"] = alias.get("comment", "")
    dev["display_name"] = build_display_name(dev)
    return dev


def sse_message(payload: Dict) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/aliases", methods=["GET"])
def get_aliases():
    return jsonify({
        "ok": True,
        "file": ALIASES_FILE,
        "aliases": load_aliases(),
    })


@app.route("/api/aliases/save", methods=["POST"])
def save_aliases_api():
    payload = request.get_json(silent=True) or {}
    devices = payload.get("devices", {})

    normalized = {}
    for mac, meta in devices.items():
        nmac = normalize_mac(mac)
        if not nmac or nmac == "N/A":
            continue

        if isinstance(meta, dict):
            name = str(meta.get("name", "")).strip()
            comment = str(meta.get("comment", "")).strip()
        else:
            name = str(meta).strip()
            comment = ""

        if not name and not comment:
            continue

        normalized[nmac] = {
            "name": name,
            "comment": comment,
        }

    save_aliases(normalized)
    return jsonify({"ok": True, "file": ALIASES_FILE, "count": len(normalized)})


@app.route("/api/scan/stream")
def scan_stream():
    @stream_with_context
    def generate():
        start_time = time.time()
        aliases = load_aliases()

        yield sse_message({"type": "start", "message": "Начинаем сканирование..."})
        yield sse_message({
            "type": "log",
            "message": f"Загружено пользовательских алиасов: {len(aliases)}"
        })

        admin = is_admin()
        if not admin:
            yield sse_message(
                {
                    "type": "warning",
                    "message": (
                        "Скрипт запущен без прав администратора. "
                        "Некоторые MAC-адреса и данные устройств могут быть недоступны."
                    ),
                }
            )

        try:
            nm = get_nmap_scanner()
        except RuntimeError as exc:
            yield sse_message({"type": "error", "message": str(exc)})
            return

        networks, local_ips = get_all_networks()
        if not networks:
            yield sse_message(
                {
                    "type": "error",
                    "message": "Не найдено активных IPv4-сетей.",
                }
            )
            return

        yield sse_message({"type": "log", "message": f"Найдено активных подсетей: {len(networks)}"})

        scannable_networks = []
        for net in networks:
            try:
                net_obj = ipaddress.ip_network(net["subnet"], strict=False)
                net["host_count"] = max(0, net_obj.num_addresses - 2)

                if net_obj.num_addresses > MAX_HOSTS_PER_SUBNET:
                    yield sse_message(
                        {
                            "type": "warning",
                            "message": (
                                f"Подсеть {net['subnet']} слишком большая "
                                f"({net_obj.num_addresses} адресов) — пропускаю."
                            ),
                        }
                    )
                    continue

                scannable_networks.append(net)
            except Exception:
                yield sse_message(
                    {
                        "type": "warning",
                        "message": f"Не удалось обработать подсеть {net.get('subnet', '<?>')}, пропускаю.",
                    }
                )

        if not scannable_networks:
            yield sse_message({"type": "error", "message": "Нет подходящих подсетей для сканирования."})
            return

        all_devices: List[Dict] = []
        gateway_ips = [n["gateway"] for n in scannable_networks if n.get("gateway") and n["gateway"] != "Неизвестно"]

        total_networks = len(scannable_networks)

        for idx, net in enumerate(scannable_networks, start=1):
            subnet = net["subnet"]
            gateway = net["gateway"]
            gateway_note = " (предположен)" if net.get("gateway_guessed") else ""

            yield sse_message({
                "type": "log",
                "message": f"Сканирую подсеть {subnet}, шлюз {gateway}{gateway_note}..."
            })

            try:
                nm.scan(hosts=subnet, arguments=NMAP_SCAN_ARGUMENTS)
            except Exception as exc:
                yield sse_message({"type": "warning", "message": f"Ошибка при сканировании {subnet}: {exc}"})
                progress = int((idx / total_networks) * 100)
                yield sse_message({
                    "type": "progress",
                    "percent": progress,
                    "message": f"Подсеть {idx}/{total_networks} завершена с ошибкой.",
                })
                continue

            devices_in_subnet = []

            for host in nm.all_hosts():
                try:
                    if nm[host].state() != "up":
                        continue

                    addresses = nm[host].get("addresses", {})
                    mac = normalize_mac(addresses.get("mac", "N/A"))

                    if mac == "N/A" and host in local_ips:
                        mac = get_mac_for_ip(host)

                    vendor_map = nm[host].get("vendor", {}) or {}
                    vendor = vendor_map.get(mac, "Неизвестно") if mac != "N/A" else "Неизвестно"

                    if host in local_ips and vendor == "Неизвестно":
                        vendor = "Локальный компьютер"

                    nmap_hostname = ""
                    hostnames = nm[host].get("hostnames", [])
                    if hostnames:
                        nmap_hostname = hostnames[0].get("name", "") or ""

                    hostname = resolve_hostname(host, nmap_hostname)
                    dev_type, category = guess_device(hostname, vendor, host, gateway_ips)

                    if host in local_ips:
                        category = "self"
                        if hostname and hostname != "Неизвестно":
                            dev_type = "💻 Компьютер / ноутбук"

                    dev = {
                        "ip": host,
                        "hostname": hostname,
                        "mac": mac,
                        "vendor": vendor,
                        "type": dev_type,
                        "category": category,
                        "subnet": subnet,
                    }

                    dev = apply_aliases_to_device(dev, aliases)
                    devices_in_subnet.append(dev)
                    all_devices.append(dev)

                except Exception:
                    continue

            progress = int((idx / total_networks) * 100)
            yield sse_message({
                "type": "progress",
                "percent": progress,
                "message": f"Подсеть {idx}/{total_networks} обработана, найдено устройств: {len(devices_in_subnet)}"
            })

        this_pc_name = socket.gethostname() or "Этот компьютер"

        for lip in local_ips:
            if any(d["ip"] == lip for d in all_devices):
                continue

            local_mac = get_mac_for_ip(lip)
            dev = {
                "ip": lip,
                "hostname": this_pc_name,
                "mac": local_mac,
                "vendor": "Локальный компьютер",
                "type": "💻 Этот компьютер",
                "category": "self",
                "subnet": "Local",
            }
            dev = apply_aliases_to_device(dev, aliases)
            all_devices.append(dev)

        unique_devices = {}
        for dev in all_devices:
            ip = dev.get("ip")
            if ip in {"127.0.0.1", "::1", None, ""}:
                continue
            unique_devices[ip] = dev

        sorted_devices = sorted(unique_devices.values(), key=lambda x: ipaddress.ip_address(x["ip"]))

        duration = round(time.time() - start_time, 1)

        note_parts = ["Имена устройств: nmap reverse DNS + socket.gethostbyaddr + пользовательский mapping по MAC."]
        if not admin:
            note_parts.append("Для более полного определения MAC-адресов лучше запускать от имени администратора.")
        if any(net.get("gateway_guessed") for net in scannable_networks):
            note_parts.append("Часть шлюзов определена эвристически как network+1.")

        yield sse_message({
            "type": "result",
            "devices": sorted_devices,
            "networks": scannable_networks,
            "admin": admin,
            "note": " ".join(note_parts),
            "duration": duration,
            "aliases_file": ALIASES_FILE,
        })

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Карта локальной сети v10.0</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://unpkg.com/vis-network@9.1.2/standalone/umd/vis-network.min.js"></script>
    <style>
        :root {
            --bg: #f5f7fb;
            --panel: #ffffff;
            --panel-2: #fbfcfe;
            --text: #172033;
            --muted: #6b7280;
            --line: #e5e7eb;
            --line-soft: #eef2f7;
            --shadow: 0 10px 30px rgba(15, 23, 42, 0.08);

            --primary: #2563eb;
            --primary-soft: #dbeafe;

            --success: #10b981;
            --success-soft: #d1fae5;

            --danger: #ef4444;
            --danger-soft: #fee2e2;

            --warning: #f59e0b;
            --warning-soft: #fef3c7;

            --info: #06b6d4;
            --info-soft: #cffafe;

            --violet: #8b5cf6;
            --violet-soft: #ede9fe;

            --slate: #94a3b8;
            --slate-soft: #e2e8f0;

            --radius: 18px;
            --radius-sm: 12px;
        }

        * {
            box-sizing: border-box;
        }

        body {
            background:
                radial-gradient(circle at top left, rgba(37, 99, 235, 0.06), transparent 24%),
                radial-gradient(circle at top right, rgba(139, 92, 246, 0.06), transparent 22%),
                var(--bg);
            color: var(--text);
            font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }

        .container {
            max-width: 1320px;
        }

        h1, h4 {
            color: var(--text);
            font-weight: 750;
            letter-spacing: -0.02em;
        }

        #info {
            border: 1px solid transparent;
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            background: var(--panel);
            color: var(--text);
            padding: 16px 18px;
        }

        .alert-info {
            background: linear-gradient(180deg, #eff6ff 0%, #ffffff 100%);
            border-color: #bfdbfe !important;
        }

        .alert-warning {
            background: linear-gradient(180deg, #fff7ed 0%, #ffffff 100%);
            border-color: #fed7aa !important;
        }

        .alert-danger {
            background: linear-gradient(180deg, #fef2f2 0%, #ffffff 100%);
            border-color: #fecaca !important;
        }

        .alert-success {
            background: linear-gradient(180deg, #ecfdf5 0%, #ffffff 100%);
            border-color: #bbf7d0 !important;
        }

        .action-row {
            gap: 10px;
            flex-wrap: wrap;
        }

        .btn {
            border-radius: 14px;
            font-weight: 600;
            padding: 11px 16px;
            box-shadow: none !important;
        }

        .btn-lg {
            padding: 14px 18px;
            font-size: 1rem;
        }

        .btn-success {
            background: linear-gradient(135deg, #16a34a 0%, #10b981 100%);
            border: none;
        }

        .btn-outline-secondary,
        .btn-outline-primary,
        .btn-outline-dark {
            background: rgba(255,255,255,0.9);
            border-width: 1px;
        }

        .progress {
            height: 14px !important;
            border-radius: 999px;
            background: #eaf0f8;
            overflow: hidden;
            border: 1px solid #dde6f2;
        }

        .progress-bar {
            border-radius: 999px;
            background: linear-gradient(90deg, #2563eb 0%, #06b6d4 100%);
        }

        #progress-message {
            color: var(--muted);
            font-size: 0.95rem;
        }

        #log-area {
            background: #0f172a;
            color: #d1fae5;
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            height: 180px;
            overflow-y: auto;
            padding: 14px 16px;
            border-radius: var(--radius);
            font-size: 0.88rem;
            white-space: pre-wrap;
            box-shadow: var(--shadow);
            border: 1px solid rgba(255,255,255,0.04);
        }

        .log-entry {
            margin: 3px 0;
            color: #c7f9cc;
        }

        #network-vis {
            height: 680px;
            border: 1px solid var(--line);
            background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
            border-radius: 24px;
            box-shadow: var(--shadow);
        }

        .table-wrap {
            overflow-x: auto;
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 24px;
            box-shadow: var(--shadow);
            padding: 8px;
        }

        #devices-table {
            margin-bottom: 0;
            vertical-align: middle;
            --bs-table-bg: transparent;
        }

        #devices-table thead th {
            position: sticky;
            top: 0;
            z-index: 1;
            background: #f8fafc;
            color: #334155;
            border-bottom: 1px solid var(--line);
            font-size: 0.84rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.03em;
            padding: 16px 12px;
            white-space: nowrap;
        }

        #devices-table tbody tr {
            transition: background 0.15s ease, transform 0.15s ease;
        }

        #devices-table tbody tr:hover {
            background: #f8fbff;
        }

        #devices-table td {
            border-color: var(--line-soft);
            padding: 14px 12px;
            color: var(--text);
            vertical-align: middle;
        }

        #devices-table tbody tr:last-child td {
            border-bottom: none;
        }

        .display-name-cell {
            font-weight: 700;
            color: #0f172a;
        }

        .ip-cell {
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            color: #334155;
            font-size: 0.95rem;
            white-space: nowrap;
        }

        .mac-cell {
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            color: #334155;
            white-space: nowrap;
        }

        .vendor-cell,
        .hostname-cell {
            color: #475569;
        }

        .badge-soft {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            border-radius: 999px;
            padding: 7px 10px;
            font-size: 0.85rem;
            font-weight: 650;
            line-height: 1.2;
            border: 1px solid transparent;
        }

        .badge-gateway { background: var(--danger-soft); color: #b91c1c; border-color: #fecaca; }
        .badge-network { background: #ede9fe; color: #6d28d9; border-color: #ddd6fe; }
        .badge-printer { background: var(--warning-soft); color: #b45309; border-color: #fde68a; }
        .badge-apple { background: var(--info-soft); color: #0f766e; border-color: #a5f3fc; }
        .badge-yandex { background: #fff7ed; color: #c2410c; border-color: #fdba74; }
        .badge-sber { background: #ecfccb; color: #3f6212; border-color: #bef264; }
        .badge-tv { background: var(--violet-soft); color: #6d28d9; border-color: #ddd6fe; }
        .badge-computer { background: var(--success-soft); color: #047857; border-color: #a7f3d0; }
        .badge-phone { background: var(--primary-soft); color: #1d4ed8; border-color: #bfdbfe; }
        .badge-self { background: #dcfce7; color: #166534; border-color: #bbf7d0; }
        .badge-unknown { background: var(--slate-soft); color: #475569; border-color: #cbd5e1; }

        .form-control,
        .form-control-sm {
            border-radius: 12px;
            border: 1px solid #dbe2ea;
            background: #ffffff;
            color: var(--text);
            min-height: 40px;
            box-shadow: none;
        }

        .form-control:focus,
        .form-control-sm:focus {
            border-color: #93c5fd;
            box-shadow: 0 0 0 4px rgba(37, 99, 235, 0.10);
        }

        .alias-input {
            min-width: 180px;
            font-weight: 600;
        }

        .comment-input {
            min-width: 200px;
            color: #475569;
        }

        textarea#mapping-output {
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            min-height: 220px;
            background: #fbfdff;
            border-radius: 18px;
            border: 1px solid var(--line);
            box-shadow: var(--shadow);
            padding: 14px 16px;
        }

        .small-muted {
            font-size: 0.92rem;
            color: var(--muted);
            margin-top: 8px;
        }

        .card-like-title {
            margin-bottom: 14px;
        }

        @media (max-width: 768px) {
            #network-vis {
                height: 520px;
                border-radius: 18px;
            }

            .table-wrap {
                border-radius: 18px;
                padding: 4px;
            }

            #devices-table td,
            #devices-table th {
                padding: 10px 8px;
            }
        }
    </style>
</head>
<body class="p-3 p-md-4">
<div class="container">
    <h1 class="mb-4 text-center">🗺️ Карта локальной сети v10.0</h1>

    <div id="info" class="alert alert-info">
        Нажмите кнопку для сканирования локальной сети
    </div>

    <div class="d-flex action-row mb-3">
        <button id="scan-btn" class="btn btn-success btn-lg flex-grow-1">🚀 СКАНИРОВАТЬ СЕТЬ</button>
        <button id="copy-template-btn" class="btn btn-outline-secondary">📋 Скопировать шаблон MAC→имя</button>
        <button id="copy-mapping-btn" class="btn btn-outline-primary">📋 Скопировать текущий mapping</button>
        <button id="save-mapping-btn" class="btn btn-outline-dark">💾 Сохранить mapping рядом</button>
    </div>

    <div id="progress-container" class="mb-3 d-none">
        <div class="progress">
            <div id="progress-bar"
                 class="progress-bar progress-bar-striped progress-bar-animated"
                 role="progressbar"
                 style="width: 0%;">0%</div>
        </div>
        <div id="progress-message" class="mt-2 text-muted"></div>
    </div>

    <div id="log-area" class="mb-3 d-none"></div>

    <div id="loading" class="text-center d-none mb-3">
        <div class="spinner-border text-primary"></div>
        <p class="mt-2 mb-0">Сканирование выполняется...</p>
    </div>

    <div id="network-vis" class="d-none mb-4"></div>

    <div class="mb-4">
        <label for="mapping-output" class="form-label"><strong>Сводный mapping JSON</strong></label>
        <textarea id="mapping-output" class="form-control" placeholder="После сканирования здесь можно получить и отредактировать JSON mapping."></textarea>
        <div class="small-muted">
            Этот JSON можно скопировать и сохранить рядом с приложением как <span style="font-family: ui-monospace, monospace;">device_aliases.json</span>.
        </div>
    </div>

    <h4 class="mt-4 d-none card-like-title" id="devices-title">Найденные устройства</h4>
    <div class="table-wrap">
        <table class="table align-middle d-none" id="devices-table">
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Имя на графе</th>
                    <th>Пользовательское имя</th>
                    <th>Комментарий</th>
                    <th>Исходное имя</th>
                    <th>Тип</th>
                    <th>Производитель</th>
                    <th>MAC</th>
                    <th>Подсеть</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>
</div>

<script>
let visNetwork = null;
let eventSource = null;
let lastScanData = null;

const els = {
    btn: document.getElementById('scan-btn'),
    copyTemplateBtn: document.getElementById('copy-template-btn'),
    copyMappingBtn: document.getElementById('copy-mapping-btn'),
    saveMappingBtn: document.getElementById('save-mapping-btn'),
    loading: document.getElementById('loading'),
    info: document.getElementById('info'),
    progressContainer: document.getElementById('progress-container'),
    progressBar: document.getElementById('progress-bar'),
    progressMessage: document.getElementById('progress-message'),
    logArea: document.getElementById('log-area'),
    networkVis: document.getElementById('network-vis'),
    devicesTitle: document.getElementById('devices-title'),
    devicesTable: document.getElementById('devices-table'),
    mappingOutput: document.getElementById('mapping-output')
};

function escapeHtml(value) {
    return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
}

function addLog(message) {
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.textContent = '> ' + message;
    els.logArea.appendChild(entry);
    els.logArea.scrollTop = els.logArea.scrollHeight;
}

function resetUIBeforeScan() {
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }

    if (visNetwork) {
        visNetwork.destroy();
        visNetwork = null;
    }

    els.networkVis.classList.add('d-none');
    els.devicesTitle.classList.add('d-none');
    els.devicesTable.classList.add('d-none');
    els.logArea.classList.remove('d-none');
    els.logArea.innerHTML = '';

    els.btn.disabled = true;
    els.loading.classList.remove('d-none');

    els.info.className = 'alert alert-info';
    els.info.innerHTML = 'Сканирование запущено...';

    els.progressContainer.classList.remove('d-none');
    els.progressBar.style.width = '0%';
    els.progressBar.textContent = '0%';
    els.progressMessage.textContent = '';
}

function restoreUIAfterFinish() {
    els.btn.disabled = false;
    els.loading.classList.add('d-none');
    els.progressContainer.classList.add('d-none');
}

function setProgress(percent, message) {
    const p = Math.max(0, Math.min(100, Number(percent) || 0));
    els.progressBar.style.width = p + '%';
    els.progressBar.textContent = p + '%';
    els.progressMessage.textContent = message || '';
}

function createCell(text, className = '') {
    const td = document.createElement('td');
    if (className) td.className = className;
    td.textContent = text ?? '';
    return td;
}

function makeTypeBadge(type, category) {
    const span = document.createElement('span');
    span.className = `badge-soft badge-${category || 'unknown'}`;
    span.textContent = type || 'Неизвестно';
    return span;
}

function getDevicesFromTable() {
    const rows = Array.from(els.devicesTable.querySelectorAll('tbody tr'));
    return rows.map(row => {
        return {
            ip: row.dataset.ip || '',
            mac: row.dataset.mac || '',
            hostname: row.dataset.hostname || '',
            vendor: row.dataset.vendor || '',
            type: row.dataset.type || '',
            category: row.dataset.category || '',
            subnet: row.dataset.subnet || '',
            user_name: row.querySelector('.alias-input')?.value?.trim() || '',
            comment: row.querySelector('.comment-input')?.value?.trim() || '',
            display_name: row.querySelector('.display-name-cell')?.textContent?.trim() || ''
        };
    });
}

function buildMappingJsonFromCurrentState() {
    const devices = getDevicesFromTable();
    const result = {
        version: 1,
        updated_at: new Date().toISOString(),
        devices: {}
    };

    for (const dev of devices) {
        const mac = (dev.mac || '').trim().toUpperCase();
        if (!mac || mac === 'N/A') continue;

        if (dev.user_name || dev.comment) {
            result.devices[mac] = {
                name: dev.user_name || '',
                comment: dev.comment || ''
            };
        }
    }

    return result;
}

function buildTemplateJsonFromCurrentDevices() {
    const devices = getDevicesFromTable();
    const result = {
        version: 1,
        updated_at: new Date().toISOString(),
        devices: {}
    };

    for (const dev of devices) {
        const mac = (dev.mac || '').trim().toUpperCase();
        if (!mac || mac === 'N/A') continue;

        result.devices[mac] = {
            name: dev.user_name || '',
            comment: dev.comment || `IP ${dev.ip}; ${dev.vendor || dev.hostname || dev.type || ''}`.trim()
        };
    }

    return result;
}

async function copyText(text) {
    await navigator.clipboard.writeText(text);
}

function recomputeDisplayName(dev) {
    const userName = (dev.user_name || '').trim();
    const hostname = (dev.hostname || '').trim();
    const vendor = (dev.vendor || '').trim();
    const ip = dev.ip || '';
    const lastOctet = ip.includes('.') ? ip.split('.').pop() : ip;

    if (userName) return userName;
    if (hostname && hostname !== 'Неизвестно') return hostname;
    if (vendor && vendor !== 'Неизвестно') return `${vendor} • .${lastOctet}`;
    return `Устройство • .${lastOctet}`;
}

function refreshDisplayNamesInTable() {
    const rows = Array.from(els.devicesTable.querySelectorAll('tbody tr'));
    for (const row of rows) {
        const dev = {
            ip: row.dataset.ip || '',
            hostname: row.dataset.hostname || '',
            vendor: row.dataset.vendor || '',
            user_name: row.querySelector('.alias-input')?.value?.trim() || ''
        };
        row.querySelector('.display-name-cell').textContent = recomputeDisplayName(dev);
    }
    refreshMappingOutput();
    redrawGraphFromTable();
}

function refreshMappingOutput() {
    const mapping = buildMappingJsonFromCurrentState();
    els.mappingOutput.value = JSON.stringify(mapping, null, 2);
}

async function saveMappingToServer() {
    const mapping = buildMappingJsonFromCurrentState();

    const resp = await fetch('/api/aliases/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(mapping)
    });

    const data = await resp.json();
    if (!data.ok) throw new Error('Не удалось сохранить mapping');

    els.info.className = 'alert alert-success';
    els.info.textContent = `Mapping сохранен: ${data.file}, записей: ${data.count}`;
    addLog(`Mapping сохранен в ${data.file}, записей: ${data.count}`);
}

function redrawGraphFromTable() {
    const devices = getDevicesFromTable();
    const networks = lastScanData?.networks || [];
    renderGraph(networks, devices);
}

function renderGraph(networks, devices) {
    const nodes = new vis.DataSet();
    const edges = new vis.DataSet();

    networks.forEach((net) => {
        const netId = 'net_' + net.subnet;
        const guessed = net.gateway_guessed ? ' (предп.)' : '';
        nodes.add({
            id: netId,
            label: `🌐 ${net.subnet}\\nШлюз: ${net.gateway}${guessed}`,
            color: {
                background: '#2563eb',
                border: '#1d4ed8',
                highlight: { background: '#3b82f6', border: '#1d4ed8' },
                hover: { background: '#3b82f6', border: '#1d4ed8' }
            },
            shape: 'ellipse',
            size: 38,
            font: {
                color: '#ffffff',
                size: 19,
                face: 'Inter, Segoe UI, sans-serif',
                bold: true
            },
            borderWidth: 2,
            shadow: {
                enabled: true,
                color: 'rgba(37,99,235,0.25)',
                size: 18,
                x: 0,
                y: 6
            },
            title: `Подсеть: ${net.subnet}\\nИнтерфейс: ${net.iface || 'N/A'}`
        });
    });

    const colorByCategory = {
        gateway: '#ef4444',
        network: '#8b5cf6',
        printer: '#f59e0b',
        apple: '#06b6d4',
        yandex: '#f97316',
        sber: '#84cc16',
        tv: '#8b5cf6',
        computer: '#10b981',
        phone: '#3b82f6',
        self: '#059669',
        unknown: '#94a3b8'
    };

    devices.forEach((dev) => {
        const nodeId = dev.ip;
        const displayName = recomputeDisplayName(dev);
        const baseColor = colorByCategory[dev.category] || '#94a3b8';

        nodes.add({
            id: nodeId,
            label: `${displayName}\\n${dev.ip}`,
            title:
                `Пользовательское имя: ${dev.user_name || '-'}\\n` +
                `Исходное имя: ${dev.hostname || '-'}\\n` +
                `Тип: ${dev.type || '-'}\\n` +
                `Производитель: ${dev.vendor || '-'}\\n` +
                `MAC: ${dev.mac || '-'}\\n` +
                `Комментарий: ${dev.comment || '-'}\\n` +
                `Подсеть: ${dev.subnet || '-'}`,
            color: {
                background: baseColor,
                border: baseColor,
                highlight: { background: baseColor, border: baseColor },
                hover: { background: baseColor, border: baseColor }
            },
            shape: dev.category === 'gateway' ? 'circle' : 'box',
            borderWidth: 1.5,
            font: {
                color: '#ffffff',
                size: 17,
                face: 'Inter, Segoe UI, sans-serif'
            },
            margin: {
                top: 12,
                bottom: 12,
                left: 16,
                right: 16
            },
            shadow: {
                enabled: true,
                color: 'rgba(15,23,42,0.14)',
                size: 12,
                x: 0,
                y: 4
            }
        });

        if (dev.subnet !== 'Local') {
            const netId = 'net_' + dev.subnet;
            if (nodes.get(netId)) {
                edges.add({ from: netId, to: nodeId });
            }
        } else if (networks.length > 0) {
            edges.add({ from: 'net_' + networks[0].subnet, to: nodeId, dashes: true });
        }
    });

    if (visNetwork) {
        visNetwork.destroy();
    }

    visNetwork = new vis.Network(
        els.networkVis,
        { nodes, edges },
        {
            layout: {
                improvedLayout: true
            },
            physics: {
                enabled: true,
                stabilization: {
                    enabled: true,
                    iterations: 250,
                    updateInterval: 25
                },
                barnesHut: {
                    gravitationalConstant: -5000,
                    centralGravity: 0.2,
                    springLength: 145,
                    springConstant: 0.04,
                    damping: 0.09,
                    avoidOverlap: 0.7
                }
            },
            interaction: {
                hover: true,
                navigationButtons: true,
                keyboard: true
            },
            edges: {
                color: {
                    color: '#cbd5e1',
                    highlight: '#93c5fd',
                    hover: '#60a5fa'
                },
                width: 1.5,
                smooth: {
                    enabled: true,
                    type: 'dynamic'
                }
            },
            nodes: {
                shapeProperties: {
                    borderRadius: 14
                }
            }
        }
    );

    els.networkVis.classList.remove('d-none');
}

function renderResult(data) {
    lastScanData = data;

    const networks = Array.isArray(data.networks) ? data.networks : [];
    const devices = Array.isArray(data.devices) ? data.devices : [];
    const duration = data.duration ?? '?';

    els.info.className = 'alert alert-success';
    els.info.innerHTML =
        `Найдено сетей: <strong>${networks.length}</strong><br>` +
        `Устройств: <strong>${devices.length}</strong><br>` +
        `Время: <strong>${escapeHtml(duration)} сек</strong><br>` +
        `Файл алиасов: <strong>${escapeHtml(data.aliases_file || 'device_aliases.json')}</strong><br>` +
        `<small>${escapeHtml(data.note || '')}</small>`;

    renderGraph(networks, devices);

    const tbody = els.devicesTable.querySelector('tbody');
    tbody.innerHTML = '';

    devices.forEach((dev) => {
        const row = document.createElement('tr');
        row.dataset.ip = dev.ip || '';
        row.dataset.mac = dev.mac || '';
        row.dataset.hostname = dev.hostname || '';
        row.dataset.vendor = dev.vendor || '';
        row.dataset.type = dev.type || '';
        row.dataset.category = dev.category || '';
        row.dataset.subnet = dev.subnet || '';

        row.appendChild(createCell(dev.ip, 'ip-cell'));

        const displayCell = document.createElement('td');
        displayCell.className = 'display-name-cell';
        displayCell.textContent = dev.display_name || '';
        row.appendChild(displayCell);

        const aliasTd = document.createElement('td');
        const aliasInput = document.createElement('input');
        aliasInput.type = 'text';
        aliasInput.className = 'form-control form-control-sm alias-input';
        aliasInput.value = dev.user_name || '';
        aliasInput.placeholder = 'Например: Айфон Ивана';
        aliasInput.addEventListener('input', refreshDisplayNamesInTable);
        aliasTd.appendChild(aliasInput);
        row.appendChild(aliasTd);

        const commentTd = document.createElement('td');
        const commentInput = document.createElement('input');
        commentInput.type = 'text';
        commentInput.className = 'form-control form-control-sm comment-input';
        commentInput.value = dev.comment || '';
        commentInput.placeholder = 'Комментарий';
        commentInput.addEventListener('input', refreshMappingOutput);
        commentTd.appendChild(commentInput);
        row.appendChild(commentTd);

        row.appendChild(createCell(dev.hostname || '', 'hostname-cell'));

        const typeTd = document.createElement('td');
        typeTd.appendChild(makeTypeBadge(dev.type, dev.category));
        row.appendChild(typeTd);

        row.appendChild(createCell(dev.vendor || '', 'vendor-cell'));
        row.appendChild(createCell(dev.mac || '', 'mac-cell'));
        row.appendChild(createCell(dev.subnet || '', 'ip-cell'));

        tbody.appendChild(row);
    });

    els.devicesTitle.classList.remove('d-none');
    els.devicesTable.classList.remove('d-none');
    refreshMappingOutput();
    restoreUIAfterFinish();
}

function handleError(message) {
    addLog('Ошибка: ' + message);
    els.info.className = 'alert alert-danger';
    els.info.innerHTML = 'Ошибка: ' + escapeHtml(message).replaceAll('\\n', '<br>');
    restoreUIAfterFinish();
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }
}

els.btn.addEventListener('click', () => {
    resetUIBeforeScan();
    addLog('Запуск сканирования...');

    eventSource = new EventSource('/api/scan/stream');

    eventSource.onmessage = function(event) {
        let data = null;

        try {
            data = JSON.parse(event.data);
        } catch {
            addLog('Получен некорректный ответ от сервера');
            return;
        }

        switch (data.type) {
            case 'start':
                addLog(data.message || 'Старт');
                break;
            case 'warning':
                addLog('Предупреждение: ' + (data.message || ''));
                els.info.className = 'alert alert-warning';
                els.info.textContent = data.message || 'Предупреждение';
                break;
            case 'log':
                addLog(data.message || '');
                break;
            case 'progress':
                setProgress(data.percent, data.message || '');
                addLog(data.message || '');
                break;
            case 'result':
                addLog('Сканирование завершено');
                if (eventSource) {
                    eventSource.close();
                    eventSource = null;
                }
                renderResult(data);
                break;
            case 'error':
                handleError(data.message || 'Неизвестная ошибка');
                break;
            default:
                addLog('Неизвестное сообщение: ' + JSON.stringify(data));
        }
    };

    eventSource.onerror = function() {
        if (!eventSource) return;
        addLog('Соединение SSE потеряно или закрыто');
        els.info.className = 'alert alert-warning';
        els.info.textContent = 'Соединение с сервером было закрыто. Если результата нет — попробуйте снова.';
        restoreUIAfterFinish();
        eventSource.close();
        eventSource = null;
    };
});

els.copyTemplateBtn.addEventListener('click', async () => {
    const payload = buildTemplateJsonFromCurrentDevices();
    const text = JSON.stringify(payload, null, 2);
    els.mappingOutput.value = text;
    await copyText(text);
    addLog('Шаблон MAC→имя скопирован в буфер обмена');
});

els.copyMappingBtn.addEventListener('click', async () => {
    const payload = buildMappingJsonFromCurrentState();
    const text = JSON.stringify(payload, null, 2);
    els.mappingOutput.value = text;
    await copyText(text);
    addLog('Текущий mapping скопирован в буфер обмена');
});

els.saveMappingBtn.addEventListener('click', async () => {
    try {
        await saveMappingToServer();
    } catch (e) {
        handleError(e.message || 'Не удалось сохранить mapping');
    }
});
</script>
</body>
</html>
"""


if __name__ == "__main__":
    print("🚀 Запуск сервера...")
    if not is_admin():
        print("⚠️ Рекомендуется запуск от имени администратора/root для более полного сканирования.")
    else:
        print("✅ Повышенные права обнаружены.")

    print(f"Файл пользовательских имен: {ALIASES_FILE}")
    print("Откройте в браузере: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)