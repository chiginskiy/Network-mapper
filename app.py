import socket
import psutil
import ipaddress
from flask import Flask, jsonify, render_template_string
import nmap

app = Flask(__name__)

def get_all_networks():
    """Только реальные сети, Docker скрываем"""
    networks = []
    local_ips = []
    seen = set()
    for iface, addrs in psutil.net_if_addrs().items():
        if iface in psutil.net_if_stats() and psutil.net_if_stats()[iface].isup:
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith(('127.', '169.254.')):
                    try:
                        net = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                        subnet_str = str(net)
                        if subnet_str not in seen and not subnet_str.startswith('172.19.'):
                            seen.add(subnet_str)
                            gw = str(ipaddress.ip_network(subnet_str).network_address + 1)
                            networks.append({
                                'subnet': subnet_str,
                                'gateway': gw
                            })
                            local_ips.append(addr.address)
                    except:
                        pass
    return networks, list(set(local_ips))

def guess_device_type(hostname: str, vendor: str, osmatch: str, ip: str) -> str:
    """Определение типа только по реальным данным из сети"""
    hn = hostname.lower()
    vm = vendor.lower()
    om = osmatch.lower()

    if 'pc10' in hn or 'windows' in om:
        return '💻 Компьютер (Этот ПК)'
    if 'iphone' in hn or 'apple' in vm:
        return '📱 iPhone'
    if 'salute' in hn or 'sber' in hn:
        return '📺 Salute TV'
    if 'yandex' in hn or 'mini' in hn:
        return '🎙️ Яндекс Станция'
    if 'tv' in hn:
        return '📺 Телевизор'
    if any(x in vm for x in ['hp', 'brother', 'epson', 'canon']) or any(x in hn for x in ['print', 'printer']):
        return '🖨️ Принтер'
    if ip.endswith('.1') or 'router' in hn or 'tp-link' in vm.lower():
        return '🔌 Роутер'
    if 'linux' in om:
        return '💻 Linux устройство'
    return '❓ Неизвестное устройство'

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/scan')
def scan():
    try:
        networks, local_ips = get_all_networks()
        if not networks:
            return jsonify({'error': 'Нет активных сетей'}), 500

        all_devices = []
        nm = nmap.PortScanner()

        for net in networks:
            # Надёжный и быстрый скан без зависаний
            nm.scan(hosts=net['subnet'], arguments='-sn -R -T4 --host-timeout 3s')

            for host in nm.all_hosts():
                if nm[host].state() != 'up':
                    continue
                hostname = nm[host].hostname() or 'Неизвестно'
                mac = nm[host]['addresses'].get('mac', 'N/A')
                vendor = nm[host].get('vendor', {}).get(mac, 'Неизвестно') if mac != 'N/A' else 'Неизвестно'
                osmatch = nm[host].get('osmatch', [{}])[0].get('name', 'Неизвестно') if nm[host].get('osmatch') else 'Неизвестно'

                dev_type = guess_device_type(hostname, vendor, osmatch, host)

                all_devices.append({
                    'ip': host,
                    'hostname': hostname,
                    'mac': mac,
                    'vendor': vendor,
                    'os': osmatch,
                    'type': dev_type,
                    'subnet': net['subnet']
                })

        # Добавляем Этот ПК, если его нет в списке
        for lip in local_ips:
            if any(d['ip'] == lip for d in all_devices):
                continue
            all_devices.append({
                'ip': lip,
                'hostname': socket.gethostname() + ' (Этот ПК)',
                'mac': 'Local',
                'vendor': 'Local',
                'os': 'Ваша ОС',
                'type': '💻 Компьютер (Этот ПК)',
                'subnet': 'Local'
            })

        # Убираем дубли и сортируем по IP
        unique = {d['ip']: d for d in all_devices if d['ip'] not in ['127.0.0.1', '::1']}
        sorted_devices = sorted(unique.values(), key=lambda x: tuple(int(p) for p in x['ip'].split('.')))

        return jsonify({
            'devices': sorted_devices,
            'networks': networks,
            'note': 'Docker-подсеть скрыта. Имена взяты из DHCP роутера.'
        })

    except Exception as e:
        import traceback
        error_msg = str(e) + "\n\n" + traceback.format_exc()
        return jsonify({'error': error_msg}), 500

# ====================== HTML + JS ======================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Карта локальной сети v5.1</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://unpkg.com/vis-network@9.1.2/standalone/umd/vis-network.min.js"></script>
    <style>
        body { background: #f8f9fa; }
        #network-vis { height: 650px; border: 1px solid #ddd; background: white; }
    </style>
</head>
<body class="p-4">
<div class="container">
    <h1 class="mb-4 text-center">🗺️ Карта локальной сети v5.1</h1>
    <div id="info" class="alert alert-info"></div>
    <button id="scan-btn" class="btn btn-success btn-lg w-100 mb-3">🚀 СКАНИРОВАТЬ СЕТЬ (одна кнопка)</button>
    <div id="loading" class="text-center d-none"><div class="spinner-border text-primary"></div><p>Сканирование... (3–8 сек)</p></div>
    <div id="network-vis"></div>

    <h4 class="mt-5">Найденные устройства</h4>
    <table class="table table-striped" id="devices-table">
        <thead><tr><th>IP</th><th>Имя (из роутера)</th><th>Тип</th><th>Производитель</th><th>MAC</th></tr></thead>
        <tbody></tbody>
    </table>
</div>

<script>
let visNetwork;

document.getElementById('scan-btn').addEventListener('click', async () => {
    const btn = document.getElementById('scan-btn');
    const loading = document.getElementById('loading');
    const info = document.getElementById('info');
    btn.disabled = true;
    loading.classList.remove('d-none');
    info.className = 'alert alert-info';
    info.innerHTML = 'Идёт сканирование...';

    try {
        const res = await fetch('/api/scan');
        if (!res.ok) {
            const errData = await res.json();
            throw new Error(errData.error || 'Ошибка сервера');
        }
        const data = await res.json();

        info.innerHTML = `Сеть: <strong>${data.networks[0]?.subnet || '—'}</strong><br>` +
                         `Роутер: <strong>${data.networks[0]?.gateway || '—'}</strong><br>` +
                         `<small class="text-muted">${data.note || ''}</small>`;

        const nodes = new vis.DataSet();
        const edges = new vis.DataSet();
        const routerId = 'router';
        if (data.networks[0]) {
            nodes.add({ id: routerId, label: `🔌 Роутер\\n${data.networks[0].gateway}`, color: '#dc3545', shape: 'circle', size: 40 });
        }

        const tbody = document.querySelector('#devices-table tbody');
        tbody.innerHTML = '';

        data.devices.forEach(dev => {
            const nodeId = dev.ip;
            nodes.add({
                id: nodeId,
                label: `${dev.hostname}\\n${dev.ip}`,
                title: `Тип: ${dev.type}\\nПроизводитель: ${dev.vendor}\\nMAC: ${dev.mac}\\n\\nОткрыть веб-интерфейс → http://${dev.ip}`,
                color: dev.type.includes('iPhone') ? '#0dcaf0' : dev.type.includes('Salute') ? '#6610f2' : dev.type.includes('Яндекс') ? '#fd7e14' : '#198754',
                shape: 'box'
            });
            if (data.networks[0]) {
                edges.add({ from: routerId, to: nodeId });
            }

            const row = document.createElement('tr');
            row.innerHTML = `<td>${dev.ip}</td><td><strong>${dev.hostname}</strong></td><td>${dev.type}</td><td>${dev.vendor}</td><td>${dev.mac}</td>`;
            tbody.appendChild(row);
        });

        const container = document.getElementById('network-vis');
        if (visNetwork) visNetwork.destroy();
        visNetwork = new vis.Network(container, { nodes, edges }, { physics: { enabled: true } });

    } catch (err) {
        info.className = 'alert alert-danger';
        info.innerHTML = `❌ Ошибка:<br><pre style="font-size:0.9em; white-space:pre-wrap;">${err.message}</pre><br>` +
                         `Проверьте:<br>• nmap установлен и добавлен в PATH<br>• Запуск от имени администратора<br>• Python-пакет python-nmap установлен`;
    } finally {
        btn.disabled = false;
        loading.classList.add('d-none');
    }
});
</script>
</body>
</html>
"""

if __name__ == '__main__':
    print("🚀 Запуск сервера...")
    print("Откройте в браузере: http://127.0.0.1:5000")
    print("ВАЖНО: запустите от имени администратора!")
    app.run(debug=True)