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
from typing import Dict, List, Optional, Tuple

from flask import Flask, Response, render_template_string, stream_with_context
import nmap

app = Flask(__name__)

MAX_HOSTS_PER_SUBNET = 4096
NMAP_SCAN_ARGUMENTS = "-sn -R -T4 --host-timeout 10s"
IGNORED_IFACE_PARTS = ("docker", "vboxnet", "vmnet", "br-", "loopback", "lo")


def is_admin() -> bool:
    """Проверка повышенных привилегий."""
    system = platform.system()
    try:
        if system == "Windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def safe_run_command(command: str) -> str:
    """Безопасный запуск shell-команды с возвратом текста."""
    return subprocess.check_output(
        command,
        shell=True,
        text=True,
        stderr=subprocess.DEVNULL,
        encoding="utf-8",
        errors="ignore",
    ).strip()


def get_default_gateway() -> Optional[str]:
    """
    Возвращает IP шлюза по умолчанию.
    Это лучший-effort: если не удалось определить, возвращает None.
    """
    system = platform.system()

    try:
        if system == "Windows":
            output = safe_run_command("route print -4")

            # Ищем строку таблицы маршрутизации с default route:
            # 0.0.0.0    0.0.0.0    <gateway>    ...
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
            commands = [
                "ip route show default",
                "route -n",
            ]
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

                    # fallback для route -n
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
            commands = [
                "route -n get default",
                "netstat -rn",
            ]
            for cmd in commands:
                try:
                    output = safe_run_command(cmd)
                except Exception:
                    continue

                for line in output.splitlines():
                    line = line.strip()

                    # route -n get default -> gateway: 192.168.1.1
                    if line.lower().startswith("gateway:"):
                        gateway = line.split(":", 1)[1].strip()
                        try:
                            ipaddress.ip_address(gateway)
                            return gateway
                        except ValueError:
                            pass

                    # netstat -rn -> default 192.168.1.1 ...
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
    """
    Проверяет доступность nmap и возвращает инициализированный сканер.
    Бросает RuntimeError, если nmap недоступен.
    """
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
    """
    Возвращает MAC интерфейса, на котором висит target_ip.
    """
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            has_target_ip = any(
                addr.family == socket.AF_INET and addr.address == target_ip
                for addr in addrs
            )
            if not has_target_ip:
                continue

            for addr in addrs:
                # Windows/Linux/macOS могут давать AF_LINK по-разному
                if getattr(psutil, "AF_LINK", None) is not None and addr.family == psutil.AF_LINK:
                    return addr.address or "N/A"

                # Иногда MAC может приходить строкой в другом family — берем только похожие значения
                if isinstance(addr.address, str) and re.match(
                    r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$", addr.address
                ):
                    return addr.address
    except Exception:
        pass
    return "N/A"


def resolve_hostname(ip: str, primary: Optional[str] = None) -> str:
    """
    Возвращает hostname. Если primary уже осмысленный — использует его.
    """
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
    """
    Возвращает список активных IPv4-подсетей и список локальных IPv4-адресов.
    """
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
                # Fallback — только как предположение
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
    """
    Возвращает (label, category)
    category используется на фронтенде для цвета/стиля.
    """
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

    if any(x in hn for x in ["yandex", "alice", "yndx", "станция", "station"]):
        return "🎙️ Яндекс.Станция", "yandex"

    if any(x in hn for x in ["sber", "salute", "салют"]):
        return "📺 Sber устройство", "sber"

    if "tv" in hn or any(x in vd for x in ["lg", "samsung", "sony", "philips", "tcl", "hisense"]):
        return "📺 Телевизор / медиаприставка", "tv"

    if any(x in hn for x in ["pc", "desktop", "laptop", "notebook"]) or any(
        x in vd for x in ["lenovo", "dell", "asus", "acer", "msi", "intel"]
    ):
        return "💻 Компьютер / ноутбук", "computer"

    if any(x in hn for x in ["phone", "mobile", "android"]):
        return "📱 Телефон", "phone"

    return "❓ Неизвестное устройство", "unknown"


def sse_message(payload: Dict) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/scan/stream")
def scan_stream():
    @stream_with_context
    def generate():
        start_time = time.time()
        yield sse_message({"type": "start", "message": "Начинаем сканирование..."})

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
                    "message": "Не найдено активных IPv4-сетей (кроме localhost/служебных интерфейсов).",
                }
            )
            return

        yield sse_message(
            {
                "type": "log",
                "message": f"Найдено активных подсетей: {len(networks)}",
            }
        )

        scannable_networks = []
        for net in networks:
            try:
                net_obj = ipaddress.ip_network(net["subnet"], strict=False)
                host_count = max(0, net_obj.num_addresses - 2) if net_obj.version == 4 else net_obj.num_addresses
                net["host_count"] = host_count

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
            yield sse_message(
                {
                    "type": "error",
                    "message": "Нет подходящих подсетей для сканирования.",
                }
            )
            return

        all_devices: List[Dict] = []
        gateway_ips = [n["gateway"] for n in scannable_networks if n.get("gateway") and n["gateway"] != "Неизвестно"]

        total_networks = len(scannable_networks)

        for idx, net in enumerate(scannable_networks, start=1):
            subnet = net["subnet"]
            gateway = net["gateway"]
            gateway_note = " (предположен)" if net.get("gateway_guessed") else ""

            yield sse_message(
                {
                    "type": "log",
                    "message": f"Сканирую подсеть {subnet}, шлюз {gateway}{gateway_note}...",
                }
            )

            try:
                nm.scan(hosts=subnet, arguments=NMAP_SCAN_ARGUMENTS)
            except Exception as exc:
                yield sse_message(
                    {
                        "type": "warning",
                        "message": f"Ошибка при сканировании {subnet}: {exc}",
                    }
                )
                progress = int((idx / total_networks) * 100)
                yield sse_message(
                    {
                        "type": "progress",
                        "percent": progress,
                        "message": f"Подсеть {idx}/{total_networks} завершена с ошибкой.",
                    }
                )
                continue

            devices_in_subnet = []

            for host in nm.all_hosts():
                try:
                    if nm[host].state() != "up":
                        continue

                    addresses = nm[host].get("addresses", {})
                    mac = addresses.get("mac", "N/A")
                    vendor_map = nm[host].get("vendor", {}) or {}
                    vendor = vendor_map.get(mac, "Неизвестно") if mac != "N/A" else "Неизвестно"

                    nmap_hostname = ""
                    hostnames = nm[host].get("hostnames", [])
                    if hostnames:
                        nmap_hostname = hostnames[0].get("name", "") or ""

                    hostname = resolve_hostname(host, nmap_hostname)
                    dev_type, category = guess_device(hostname, vendor, host, gateway_ips)

                    dev = {
                        "ip": host,
                        "hostname": hostname,
                        "mac": mac,
                        "vendor": vendor,
                        "type": dev_type,
                        "category": category,
                        "subnet": subnet,
                    }

                    devices_in_subnet.append(dev)
                    all_devices.append(dev)
                except Exception:
                    continue

            progress = int((idx / total_networks) * 100)
            yield sse_message(
                {
                    "type": "progress",
                    "percent": progress,
                    "message": (
                        f"Подсеть {idx}/{total_networks} обработана, "
                        f"найдено устройств: {len(devices_in_subnet)}"
                    ),
                }
            )

        # Добавляем локальный компьютер, если nmap его не вернул
        this_pc_name = socket.gethostname() or "Этот компьютер"

        for lip in local_ips:
            if any(d["ip"] == lip for d in all_devices):
                continue

            local_mac = get_mac_for_ip(lip)
            all_devices.append(
                {
                    "ip": lip,
                    "hostname": this_pc_name,
                    "mac": local_mac,
                    "vendor": "Локальный компьютер",
                    "type": "💻 Этот компьютер",
                    "category": "self",
                    "subnet": "Local",
                }
            )

        # Удаляем дубли и localhost
        unique_devices = {}
        for dev in all_devices:
            ip = dev.get("ip")
            if ip in {"127.0.0.1", "::1", None, ""}:
                continue
            unique_devices[ip] = dev

        sorted_devices = sorted(
            unique_devices.values(),
            key=lambda x: ipaddress.ip_address(x["ip"])
        )

        duration = round(time.time() - start_time, 1)

        note_parts = [
            "Имена устройств: nmap reverse DNS + socket.gethostbyaddr.",
        ]
        if not admin:
            note_parts.append(
                "Для максимально полного сбора MAC-адресов и сетевых данных запустите терминал от имени администратора."
            )
        if any(net.get("gateway_guessed") for net in scannable_networks):
            note_parts.append(
                "Часть шлюзов определена эвристически как network+1, это может быть неточно."
            )

        yield sse_message(
            {
                "type": "result",
                "devices": sorted_devices,
                "networks": scannable_networks,
                "admin": admin,
                "note": " ".join(note_parts),
                "duration": duration,
            }
        )

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
    <title>Карта локальной сети v8.0</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://unpkg.com/vis-network@9.1.2/standalone/umd/vis-network.min.js"></script>
    <style>
        body { background: #f8f9fa; }
        #network-vis { height: 650px; border: 1px solid #ddd; background: white; border-radius: 8px; }
        #log-area {
            background: #1e1e1e;
            color: #8cff8c;
            font-family: Consolas, monospace;
            height: 180px;
            overflow-y: auto;
            padding: 10px;
            border-radius: 8px;
            font-size: 0.9rem;
            white-space: pre-wrap;
        }
        .log-entry { margin: 2px 0; }
        .small-note { font-size: 0.9rem; color: #666; }
        .table-wrap { overflow-x: auto; }
    </style>
</head>
<body class="p-3 p-md-4">
<div class="container">
    <h1 class="mb-4 text-center">🗺️ Карта локальной сети v8.0</h1>

    <div id="info" class="alert alert-info">
        Нажмите кнопку для сканирования локальной сети
    </div>

    <button id="scan-btn" class="btn btn-success btn-lg w-100 mb-3">
        🚀 СКАНИРОВАТЬ СЕТЬ
    </button>

    <div id="progress-container" class="mb-3 d-none">
        <div class="progress" style="height: 26px;">
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

    <h4 class="mt-4 d-none" id="devices-title">Найденные устройства</h4>
    <div class="table-wrap">
        <table class="table table-striped align-middle d-none" id="devices-table">
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Имя</th>
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

const els = {
    btn: document.getElementById('scan-btn'),
    loading: document.getElementById('loading'),
    info: document.getElementById('info'),
    progressContainer: document.getElementById('progress-container'),
    progressBar: document.getElementById('progress-bar'),
    progressMessage: document.getElementById('progress-message'),
    logArea: document.getElementById('log-area'),
    networkVis: document.getElementById('network-vis'),
    devicesTitle: document.getElementById('devices-title'),
    devicesTable: document.getElementById('devices-table')
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

function createCell(text, strong = false) {
    const td = document.createElement('td');
    if (strong) {
        const el = document.createElement('strong');
        el.textContent = text ?? '';
        td.appendChild(el);
    } else {
        td.textContent = text ?? '';
    }
    return td;
}

function renderResult(data) {
    const networks = Array.isArray(data.networks) ? data.networks : [];
    const devices = Array.isArray(data.devices) ? data.devices : [];
    const duration = data.duration ?? '?';

    els.info.className = 'alert alert-success';
    els.info.innerHTML =
        `Найдено сетей: <strong>${networks.length}</strong><br>` +
        `Устройств: <strong>${devices.length}</strong><br>` +
        `Время: <strong>${escapeHtml(duration)} сек</strong><br>` +
        `<small>${escapeHtml(data.note || '')}</small>`;

    const nodes = new vis.DataSet();
    const edges = new vis.DataSet();

    networks.forEach((net) => {
        const gwId = 'gw_' + net.subnet;
        const guessed = net.gateway_guessed ? ' (предположен)' : '';
        nodes.add({
            id: gwId,
            label: `🔌 Шлюз\\n${net.gateway}${guessed}`,
            color: '#dc3545',
            shape: 'circle',
            size: 34,
            title: `Подсеть: ${net.subnet}\\nИнтерфейс: ${net.iface || 'N/A'}`
        });
    });

    devices.forEach((dev) => {
        const nodeId = dev.ip;
        const colorByCategory = {
            gateway: '#dc3545',
            network: '#6f42c1',
            printer: '#fd7e14',
            apple: '#0dcaf0',
            yandex: '#f59f00',
            sber: '#6610f2',
            tv: '#20c997',
            computer: '#198754',
            phone: '#0d6efd',
            self: '#198754',
            unknown: '#6c757d'
        };

        nodes.add({
            id: nodeId,
            label: `${dev.hostname}\\n${dev.ip}`,
            title:
                `Тип: ${dev.type}\\n` +
                `Производитель: ${dev.vendor}\\n` +
                `MAC: ${dev.mac}\\n` +
                `Подсеть: ${dev.subnet}`,
            color: colorByCategory[dev.category] || '#198754',
            shape: dev.category === 'gateway' ? 'circle' : 'box'
        });

        if (dev.subnet !== 'Local') {
            const gwId = 'gw_' + dev.subnet;
            if (nodes.get(gwId)) {
                edges.add({ from: gwId, to: nodeId });
            }
        } else if (networks.length > 0) {
            edges.add({ from: 'gw_' + networks[0].subnet, to: nodeId, dashes: true });
        }
    });

    if (visNetwork) {
        visNetwork.destroy();
    }

    visNetwork = new vis.Network(
        els.networkVis,
        { nodes, edges },
        {
            autoResize: true,
            physics: {
                enabled: true,
                stabilization: { iterations: 200 }
            },
            interaction: {
                hover: true,
                navigationButtons: true,
                keyboard: true
            },
            nodes: {
                font: { multi: false }
            }
        }
    );

    const tbody = els.devicesTable.querySelector('tbody');
    tbody.innerHTML = '';

    devices.forEach((dev) => {
        const row = document.createElement('tr');
        row.appendChild(createCell(dev.ip));
        row.appendChild(createCell(dev.hostname, true));
        row.appendChild(createCell(dev.type));
        row.appendChild(createCell(dev.vendor));
        row.appendChild(createCell(dev.mac));
        row.appendChild(createCell(dev.subnet));
        tbody.appendChild(row);
    });

    els.networkVis.classList.remove('d-none');
    els.devicesTitle.classList.remove('d-none');
    els.devicesTable.classList.remove('d-none');

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
        } catch (e) {
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
        // Если соединение уже штатно закрыли после result — просто выходим
        if (!eventSource) {
            return;
        }

        addLog('Соединение SSE потеряно или закрыто');
        els.info.className = 'alert alert-warning';
        els.info.textContent = 'Соединение с сервером было закрыто. Если результата нет — попробуйте запустить сканирование снова.';
        restoreUIAfterFinish();

        eventSource.close();
        eventSource = null;
    };
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

    print("Откройте в браузере: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)