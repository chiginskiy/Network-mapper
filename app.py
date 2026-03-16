import socket
import psutil
import ipaddress
from flask import Flask, jsonify, render_template_string
import nmap
import subprocess
import platform

app = Flask(__name__)

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
    # Игнорируем интерфейсы виртуальных машин/контейнеров по имени
    ignore_ifaces = ('docker', 'vboxnet', 'vmnet', 'br-', 'lo')
    for iface, addrs in psutil.net_if_addrs().items():
        if any(ign in iface.lower() for ign in ignore_ifaces):
            continue
        stats = psutil.net_if_stats().get(iface)
        if stats and stats.isup:
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith(('127.', '169.254.')):
                    if not addr.netmask:  # нет маски — пропускаем
                        continue
                    try:
                        net = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                        subnet_str = str(net)
                        if subnet_str not in seen:
                            seen.add(subnet_str)
                            # Используем реальный шлюз, если не удалось — берём .1
                            gw = get_default_gateway()
                            if not gw or ipaddress.ip_address(gw) not in net:
                                gw = str(net.network_address + 1)
                            networks.append({'subnet': subnet_str, 'gateway': gw})
                            local_ips.append(addr.address)
                    except Exception:
                        pass
    return networks, list(set(local_ips))

def guess_device_type(hostname, vendor, ip, gateway_ips):
    """Определяет тип устройства по эвристикам"""
    hn = (hostname or '').lower()
    vm = (vendor or '').lower()

    if ip in gateway_ips:
        return '🔌 Шлюз / Роутер'

    # Типовые вендоры
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
    return render_string_template(HTML_TEMPLATE)

@app.route('/api/scan')
def scan():
    try:
        # Проверяем доступность nmap
        try:
            nmap.nmap.PortScanner().__class__
        except Exception:
            return jsonify({'error': 'nmap не найден. Установите nmap и добавьте в PATH'}), 500

        networks, local_ips = get_all_networks()
        if not networks:
            return jsonify({'error': 'Нет активных сетей (кроме localhost)'}), 500

        # Собираем IP всех шлюзов для определения типа
        gateway_ips = [net['gateway'] for net in networks]

        all_devices = []
        nm = nmap.PortScanner()

        for net in networks:
            # Сканируем без принудительного DNS-сервера (используем системный)
            # Увеличиваем таймаут до 10 секунд на хост
            nm.scan(
                hosts=net['subnet'],
                arguments='-sn -R -T4 --host-timeout 10s'
            )

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

                all_devices.append({
                    'ip': host,
                    'hostname': hostname,
                    'mac': mac,
                    'vendor': vendor,
                    'type': dev_type,
                    'subnet': net['subnet']
                })

        # Добавляем локальный компьютер (текущий хост)
        this_pc_name = socket.gethostname()
        for lip in local_ips:
            if any(d['ip'] == lip for d in all_devices):
                continue
            # Пытаемся получить MAC для локального IP
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

        # Удаляем дубликаты и сортируем
        unique = {d['ip']: d for d in all_devices if d['ip'] not in ['127.0.0.1', '::1']}
        sorted_devices = sorted(unique.values(), key=lambda x: tuple(map(int, x['ip'].split('.'))))

        return jsonify({
            'devices': sorted_devices,
            'networks': networks,
            'note': 'Имена из DHCP + socket.gethostbyaddr. Запускай от имени администратора!'
        })

    except Exception as e:
        import traceback
        return jsonify({'error': str(e) + '\n\n' + traceback.format_exc()}), 500

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Карта локальной сети v7.0</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://unpkg.com/vis-network@9.1.2/standalone/umd/vis-network.min.js"></script>
    <style>
        body { background: #f8f9fa; }
        #network-vis { height: 650px; border: 1px solid #ddd; background: white; }
    </style>
</head>
<body class="p-4">
<div class="container">
    <h1 class="mb-4 text-center">🗺️ Карта локальной сети v7.0</h1>
    <div id="info" class="alert alert-info"></div>
    <button id="scan-btn" class="btn btn-success btn-lg w-100 mb-3">🚀 СКАНИРОВАТЬ СЕТЬ</button>
    <div id="loading" class="text-center d-none">
        <div class="spinner-border text-primary"></div>
        <p>Сканирование... (до 30 сек)</p>
    </div>
    <div id="network-vis"></div>

    <h4 class="mt-5">Найденные устройства</h4>
    <table class="table table-striped" id="devices-table">
        <thead><tr>
            <th>IP</th><th>Имя</th><th>Тип</th><th>Производитель</th><th>MAC</th><th>Подсеть</th>
        </tr></thead>
        <tbody></tbody>
    </table>
</div>

<script>
let visNetwork = null;

document.getElementById('scan-btn').addEventListener('click', async () => {
    const btn = document.getElementById('scan-btn');
    const loading = document.getElementById('loading');
    const info = document.getElementById('info');

    btn.disabled = true;
    loading.classList.remove('d-none');
    info.className = 'alert alert-info';
    info.innerHTML = 'Сканирование...';

    try {
        const res = await fetch('/api/scan');
        if (!res.ok) {
            const errData = await res.json();
            throw new Error(errData.error || 'Сервер вернул ошибку');
        }
        const data = await res.json();

        info.innerHTML = `Найдено сетей: <strong>${data.networks.length}</strong><br>` +
                         `<small>${data.note || ''}</small>`;

        const nodes = new vis.DataSet();
        const edges = new vis.DataSet();

        // Добавляем узлы-шлюзы для каждой подсети
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

            // Соединяем устройство с соответствующим шлюзом
            if (dev.subnet !== 'Local') {
                const gwId = 'gw_' + dev.subnet;
                edges.add({ from: gwId, to: nodeId });
            } else {
                // Для локального устройства можно соединить с первым шлюзом или оставить без связи
                if (data.networks.length > 0) {
                    edges.add({ from: 'gw_' + data.networks[0].subnet, to: nodeId, dashes: true });
                }
            }
        });

        const tbody = document.querySelector('#devices-table tbody');
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

        const container = document.getElementById('network-vis');
        if (visNetwork) visNetwork.destroy();
        visNetwork = new vis.Network(container, { nodes, edges }, { physics: { enabled: true } });

    } catch (err) {
        info.className = 'alert alert-danger';
        info.innerHTML = `❌ Ошибка: ${err.message.replace(/\\n/g, '<br>')}<br><br>` +
                         `Убедись, что:<br>• Запущен от имени администратора<br>• nmap установлен и в PATH<br>• python-nmap установлен`;
    } finally {
        btn.disabled = false;
        loading.classList.add('d-none');
    }
});
</script>
</body>
</html>
"""

def render_string_template(template):
    """Просто возвращает шаблон (вспомогательная функция)"""
    return render_template_string(template)

if __name__ == '__main__':
    print("🚀 Запуск сервера...")
    print("Открой: http://127.0.0.1:5000")
    print("ВАЖНО: Запусти PowerShell/терминал ОТ ИМЕНИ АДМИНИСТРАТОРА!")
    app.run(debug=True)