import socket
import psutil
import ipaddress
import json
import subprocess
import platform
import ctypes
from flask import Flask, jsonify, render_template_string, Response
import nmap

app = Flask(__name__)

def is_admin():
    """Проверка, запущен ли процесс с правами администратора (Windows)"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        # На Linux/macOS можно проверить через os.geteuid() == 0
        return False

def get_default_gateway():
    """Возвращает IP шлюза по умолчанию (кроссплатформенно)"""
    try:
        if platform.system() == 'Windows':
            output = subprocess.check_output('route print -4', shell=True, text=True)
            for line in output.splitlines():
                if '0.0.0.0' in line and 'On-link' not in line:
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] != 'On-link':
                        return parts[2]
        else:  # Linux / Mac
            output = subprocess.check_output('ip route | grep default', shell=True, text=True)
            return output.split()[2]
    except:
        return None

def get_all_networks():
    networks = []
    local_ips = []
    seen = set()
    ignore_ifaces = ('docker', 'vboxnet', 'vmnet', 'br-', 'lo')
    for iface, addrs in psutil.net_if_addrs().items():
        if any(ign in iface.lower() for ign in ignore_ifaces):
            continue
        stats = psutil.net_if_stats().get(iface)
        if stats and stats.isup:
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith(('127.', '169.254.')):
                    if not addr.netmask:
                        continue
                    try:
                        net = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                        subnet_str = str(net)
                        if subnet_str not in seen:
                            seen.add(subnet_str)
                            gw = get_default_gateway()
                            if not gw or ipaddress.ip_address(gw) not in net:
                                gw = str(net.network_address + 1)
                            networks.append({'subnet': subnet_str, 'gateway': gw})
                            local_ips.append(addr.address)
                    except Exception:
                        pass
    return networks, list(set(local_ips))

def guess_device_type(hostname, vendor, ip, gateway_ips):
    hn = (hostname or '').lower()
    vm = (vendor or '').lower()

    if ip in gateway_ips:
        return '🔌 Шлюз / Роутер'

    if any(x in vm for x in ['tp-link', 'd-link', 'asus', 'mikrotik', 'cisco', 'router']):
        return '🔌 Сетевое оборудование'
    if any(x in vm for x in ['hp', 'brother', 'epson', 'canon', 'kyocera', 'xerox']):
        return '🖨️ Принтер'
    if any(x in hn for x in ['iphone', 'ipad', 'macbook', 'imac']):
        return '🍎 Apple устройство'
    if any(x in hn for x in ['yandex', 'alice', 'mini']):
        return '🎙️ Яндекс.Станция'
    if any(x in hn for x in ['sber', 'salute']):
        return '📺 Sber устройство'
    if 'tv' in hn or 'lg' in vm or 'samsung' in vm:
        return '📺 Телевизор'
    if 'pc' in hn or 'desktop' in hn or 'laptop' in hn:
        return '💻 Компьютер/Ноутбук'
    if 'phone' in hn or 'mobile' in hn:
        return '📱 Телефон'

    return '❓ Неизвестное устройство'

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/scan/stream')
def scan_stream():
    def generate():
        yield "data: {}\n\n".format(json.dumps({'type': 'start', 'message': 'Начинаем сканирование...'}))

        # Проверяем права администратора
        admin = is_admin()
        if not admin:
            yield "data: {}\n\n".format(json.dumps({
                'type': 'warning',
                'message': '⚠️ Внимание: скрипт запущен без прав администратора. Некоторые MAC-адреса могут быть недоступны, сканирование может быть неполным.'
            }))

        # Проверка наличия nmap
        try:
            nmap.nmap.PortScanner().__class__
        except Exception:
            yield "data: {}\n\n".format(json.dumps({'type': 'error', 'message': 'nmap не найден. Установите nmap и добавьте в PATH'}))
            return

        networks, local_ips = get_all_networks()
        if not networks:
            yield "data: {}\n\n".format(json.dumps({'type': 'error', 'message': 'Нет активных сетей (кроме localhost)'}))
            return

        total_networks = len(networks)
        yield "data: {}\n\n".format(json.dumps({'type': 'log', 'message': f'Найдено подсетей: {total_networks}'}))

        all_devices = []
        gateway_ips = [net['gateway'] for net in networks]
        nm = nmap.PortScanner()

        for idx, net in enumerate(networks, 1):
            yield "data: {}\n\n".format(json.dumps({
                'type': 'log',
                'message': f'🔍 Сканирую подсеть {net["subnet"]} (шлюз {net["gateway"]})...'
            }))

            nm.scan(
                hosts=net['subnet'],
                arguments='-sn -R -T4 --host-timeout 10s'
            )

            devices_in_subnet = []
            for host in nm.all_hosts():
                if nm[host].state() != 'up':
                    continue

                hostname = nm[host].hostname() or 'Неизвестно'
                mac = nm[host]['addresses'].get('mac', 'N/A')
                vendor = nm[host].get('vendor', {}).get(mac, 'Неизвестно') if mac != 'N/A' else 'Неизвестно'

                if hostname == 'Неизвестно':
                    try:
                        hostname = socket.gethostbyaddr(host)[0]
                    except:
                        pass

                dev_type = guess_device_type(hostname, vendor, host, gateway_ips)

                dev = {
                    'ip': host,
                    'hostname': hostname,
                    'mac': mac,
                    'vendor': vendor,
                    'type': dev_type,
                    'subnet': net['subnet']
                }
                devices_in_subnet.append(dev)
                all_devices.append(dev)

            progress = int((idx / total_networks) * 100)
            yield "data: {}\n\n".format(json.dumps({
                'type': 'progress',
                'percent': progress,
                'message': f'✅ Подсеть {idx}/{total_networks} обработана, найдено {len(devices_in_subnet)} устройств'
            }))

        # Добавляем локальный компьютер
        this_pc_name = socket.gethostname()
        for lip in local_ips:
            if any(d['ip'] == lip for d in all_devices):
                continue
            local_mac = 'N/A'
            try:
                for iface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.address == lip and addr.family == psutil.AF_LINK:
                            local_mac = addr.address
                            break
            except:
                pass
            all_devices.append({
                'ip': lip,
                'hostname': this_pc_name,
                'mac': local_mac,
                'vendor': 'Локальный компьютер',
                'type': '💻 Этот компьютер',
                'subnet': 'Local'
            })

        # Убираем дубли, сортируем
        unique = {d['ip']: d for d in all_devices if d['ip'] not in ['127.0.0.1', '::1']}
        sorted_devices = sorted(unique.values(), key=lambda x: tuple(map(int, x['ip'].split('.'))))

        # Формируем заметку о правах
        note = "Имена из DHCP + socket.gethostbyaddr."
        if not admin:
            note += " ⚠️ Запустите от имени администратора для полного сканирования (MAC-адреса и точные данные)."

        yield "data: {}\n\n".format(json.dumps({
            'type': 'result',
            'devices': sorted_devices,
            'networks': networks,
            'admin': admin,
            'note': note
        }))

    return Response(generate(), mimetype='text/event-stream')

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Карта локальной сети v7.2</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://unpkg.com/vis-network@9.1.2/standalone/umd/vis-network.min.js"></script>
    <style>
        body { background: #f8f9fa; }
        #network-vis { height: 650px; border: 1px solid #ddd; background: white; }
        #log-area { background: #2d2d2d; color: #0f0; font-family: monospace; height: 150px; overflow-y: scroll; padding: 10px; border-radius: 5px; font-size: 0.9rem; }
        .log-entry { margin: 2px 0; }
    </style>
</head>
<body class="p-4">
<div class="container">
    <h1 class="mb-4 text-center">🗺️ Карта локальной сети v7.2 (с проверкой прав)</h1>
    <div id="info" class="alert alert-info">Нажмите кнопку для сканирования</div>
    <button id="scan-btn" class="btn btn-success btn-lg w-100 mb-3">🚀 СКАНИРОВАТЬ СЕТЬ</button>

    <div id="progress-container" class="mb-3 d-none">
        <div class="progress" style="height: 25px;">
            <div id="progress-bar" class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" style="width: 0%;">0%</div>
        </div>
        <div id="progress-message" class="mt-1 text-muted"></div>
    </div>

    <div id="log-area" class="mb-3 d-none"></div>

    <div id="loading" class="text-center d-none">
        <div class="spinner-border text-primary"></div>
        <p>Сканирование... (может занять до 30 сек)</p>
    </div>

    <div id="network-vis" class="d-none"></div>

    <h4 class="mt-5 d-none" id="devices-title">Найденные устройства</h4>
    <table class="table table-striped d-none" id="devices-table">
        <thead><tr>
            <th>IP</th><th>Имя</th><th>Тип</th><th>Производитель</th><th>MAC</th><th>Подсеть</th>
        </tr></thead>
        <tbody></tbody>
    </table>
</div>

<script>
let visNetwork = null;
let eventSource = null;

document.getElementById('scan-btn').addEventListener('click', async () => {
    // Закрываем предыдущее соединение если есть
    if (eventSource) {
        eventSource.close();
    }

    const btn = document.getElementById('scan-btn');
    const loading = document.getElementById('loading');
    const info = document.getElementById('info');
    const progressContainer = document.getElementById('progress-container');
    const progressBar = document.getElementById('progress-bar');
    const progressMessage = document.getElementById('progress-message');
    const logArea = document.getElementById('log-area');
    const networkVis = document.getElementById('network-vis');
    const devicesTitle = document.getElementById('devices-title');
    const devicesTable = document.getElementById('devices-table');

    // Скрываем предыдущие результаты
    networkVis.classList.add('d-none');
    devicesTitle.classList.add('d-none');
    devicesTable.classList.add('d-none');
    logArea.classList.remove('d-none');
    logArea.innerHTML = '';

    btn.disabled = true;
    loading.classList.remove('d-none');
    info.className = 'alert alert-info';
    info.innerHTML = 'Сканирование запущено...';
    progressContainer.classList.remove('d-none');
    progressBar.style.width = '0%';
    progressBar.textContent = '0%';
    progressMessage.textContent = '';

    // Подключаемся к SSE
    eventSource = new EventSource('/api/scan/stream');

    eventSource.onmessage = function(event) {
        const data = JSON.parse(event.data);
        console.log('SSE:', data);

        switch (data.type) {
            case 'start':
                addLog('🚀 ' + data.message);
                break;
            case 'warning':
                addLog('⚠️ ' + data.message);
                info.className = 'alert alert-warning';
                info.innerHTML = data.message;
                break;
            case 'log':
                addLog('📌 ' + data.message);
                break;
            case 'progress':
                progressBar.style.width = data.percent + '%';
                progressBar.textContent = data.percent + '%';
                progressMessage.textContent = data.message;
                addLog('📊 ' + data.message);
                break;
            case 'result':
                addLog('✅ Сканирование завершено!');
                eventSource.close();
                renderResult(data);
                break;
            case 'error':
                addLog('❌ Ошибка: ' + data.message);
                info.className = 'alert alert-danger';
                info.innerHTML = 'Ошибка: ' + data.message.replace(/\\n/g, '<br>');
                eventSource.close();
                btn.disabled = false;
                loading.classList.add('d-none');
                progressContainer.classList.add('d-none');
                break;
            default:
                addLog('ℹ️ ' + JSON.stringify(data));
        }
    };

    eventSource.onerror = function() {
        addLog('⚠️ Соединение потеряно или закрыто');
    };
});

function addLog(message) {
    const logArea = document.getElementById('log-area');
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.textContent = '> ' + message;
    logArea.appendChild(entry);
    logArea.scrollTop = logArea.scrollHeight;
}

function renderResult(data) {
    const btn = document.getElementById('scan-btn');
    const loading = document.getElementById('loading');
    const info = document.getElementById('info');
    const progressContainer = document.getElementById('progress-container');
    const networkVis = document.getElementById('network-vis');
    const devicesTitle = document.getElementById('devices-title');
    const devicesTable = document.getElementById('devices-table');

    info.className = 'alert alert-success';
    info.innerHTML = `Найдено сетей: <strong>${data.networks.length}</strong><br>` +
                     `Устройств: <strong>${data.devices.length}</strong><br>` +
                     `<small>${data.note || ''}</small>`;

    // Строим граф
    const nodes = new vis.DataSet();
    const edges = new vis.DataSet();

    // Добавляем шлюзы
    data.networks.forEach((net, idx) => {
        nodes.add({
            id: 'gw_' + net.subnet,
            label: `🔌 Шлюз\\n${net.gateway}`,
            color: '#dc3545',
            shape: 'circle',
            size: 35,
            title: `Подсеть: ${net.subnet}`
        });
    });

    // Добавляем устройства
    data.devices.forEach(dev => {
        const nodeId = dev.ip;
        nodes.add({
            id: nodeId,
            label: `${dev.hostname}\\n${dev.ip}`,
            title: `Тип: ${dev.type}\\nПроизв.: ${dev.vendor}\\nMAC: ${dev.mac}\\nПодсеть: ${dev.subnet}`,
            color: dev.type.includes('iPhone') ? '#0dcaf0' :
                   dev.type.includes('Sber') ? '#6610f2' :
                   dev.type.includes('Яндекс') ? '#fd7e14' :
                   dev.type.includes('Шлюз') ? '#dc3545' : '#198754',
            shape: 'box'
        });

        if (dev.subnet !== 'Local') {
            const gwId = 'gw_' + dev.subnet;
            edges.add({ from: gwId, to: nodeId });
        } else {
            if (data.networks.length > 0) {
                edges.add({ from: 'gw_' + data.networks[0].subnet, to: nodeId, dashes: true });
            }
        }
    });

    const container = document.getElementById('network-vis');
    if (visNetwork) visNetwork.destroy();
    visNetwork = new vis.Network(container, { nodes, edges }, { physics: { enabled: true } });

    // Заполняем таблицу
    const tbody = devicesTable.querySelector('tbody');
    tbody.innerHTML = '';
    data.devices.forEach(dev => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${dev.ip}</td>
            <td><strong>${dev.hostname}</strong></td>
            <td>${dev.type}</td>
            <td>${dev.vendor}</td>
            <td>${dev.mac}</td>
            <td>${dev.subnet}</td>
        `;
        tbody.appendChild(row);
    });

    // Показываем элементы
    networkVis.classList.remove('d-none');
    devicesTitle.classList.remove('d-none');
    devicesTable.classList.remove('d-none');
    btn.disabled = false;
    loading.classList.add('d-none');
    progressContainer.classList.add('d-none');
}
</script>
</body>
</html>
"""

if __name__ == '__main__':
    print("🚀 Запуск сервера...")
    if not is_admin():
        print("⚠️  ВНИМАНИЕ: Запустите PowerShell/терминал ОТ ИМЕНИ АДМИНИСТРАТОРА для полной функциональности!")
    else:
        print("✅ Права администратора есть, сканирование будет работать полностью.")
    print("Открой: http://127.0.0.1:5000")
    app.run(debug=True, threaded=True)