import socket
import psutil
import ipaddress
from flask import Flask, jsonify, render_template_string
import nmap

app = Flask(__name__)

def get_all_networks():
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
                                'mask': str(addr.netmask),
                                'interface': iface,
                                'gateway': gw
                            })
                            local_ips.append(addr.address)
                    except:
                        pass
    return networks, list(set(local_ips))

def guess_device_type(hostname: str, osmatch: str, vendor: str, mac: str, ip: str) -> str:
    hn = hostname.lower()
    om = osmatch.lower()
    vm = vendor.lower()
    m = mac.upper().replace(':', '').replace('-', '')

    if 'pc10' in hn or ip == '192.168.0.160':
        return '💻 PC10 (Этот компьютер)'
    if m.startswith('1C2FA2') or 'salute' in hn:
        return '📺 Salute TV (Sber)'
    if m.startswith('B8876E') or 'yandex' in hn or 'mini' in hn:
        return '🎙️ Яндекс Станция Мини 2'
    if any(m.startswith(p) for p in ['24D0DF', 'FA0240', 'AAC10E']) or 'apple' in vm:
        if 'se' in hn or 'chigins' in hn:
            return '📱 iPhone SE 2'
        return '📱 iPhone'
    if ip.endswith('.1') or 'router' in hn:
        return '🔌 Роутер TP-Link'
    if any(x in vm for x in ['hp', 'brother', 'epson', 'canon']) or any(x in hn for x in ['print', 'printer']):
        return '🖨️ Принтер'
    if 'windows' in om:
        return '💻 Windows ПК'
    return '❓ Устройство'

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/scan')
def scan():
    networks, local_ips = get_all_networks()
    all_devices = []
    nm = nmap.PortScanner()

    for net in networks:
        gw = net['gateway']
        args = f'-sn -R --dns-servers {gw} -O --osscan-guess -T4 --host-timeout 4s'
        try:
            nm.scan(hosts=net['subnet'], arguments=args)
        except:
            args = f'-sn -R --dns-servers {gw} -T4 --host-timeout 4s'
            nm.scan(hosts=net['subnet'], arguments=args)

        for host in nm.all_hosts():
            if nm[host].state() != 'up':
                continue
            hostname = nm[host].hostname() or 'Неизвестно'
            mac = nm[host]['addresses'].get('mac', 'N/A')
            vendor = nm[host].get('vendor', {}).get(mac, 'Неизвестно') if mac != 'N/A' else 'Неизвестно'
            osmatch = nm[host].get('osmatch', [{}])[0].get('name', 'Неизвестно') if nm[host].get('osmatch') else 'Неизвестно'

            dev_type = guess_device_type(hostname, osmatch, vendor, mac, host)

            all_devices.append({
                'ip': host,
                'hostname': hostname,
                'mac': mac,
                'vendor': vendor,
                'os': osmatch,
                'type': dev_type,
                'subnet': net['subnet']
            })

    # Добавляем Этот ПК
    for lip in local_ips:
        if any(d['ip'] == lip for d in all_devices):
            continue
        all_devices.append({
            'ip': lip,
            'hostname': socket.gethostname() + ' (PC10)',
            'mac': 'Local',
            'vendor': 'Local',
            'os': 'Ваша ОС',
            'type': '💻 PC10 (Этот компьютер)',
            'subnet': 'Local'
        })

    unique = {d['ip']: d for d in all_devices if d['ip'] not in ['127.0.0.1', '::1']}
    sorted_devices = sorted(unique.values(), key=lambda x: tuple(int(p) for p in x['ip'].split('.')))

    return jsonify({
        'devices': sorted_devices,
        'networks': networks,
        'local_ips': local_ips,
        'note': 'Docker-подсеть 172.19.0.0/28 скрыта — это внутренние контейнеры вашего ПК'
    })

# ====================== HTML ======================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Карта локальной сети v4 — теперь всё понятно</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://unpkg.com/vis-network@9.1.2/standalone/umd/vis-network.min.js"></script>
    <style>body { background: #f8f9fa; } #network-vis { height: 650px; border: 1px solid #ddd; background: white; }</style>
</head>
<body class="p-4">
<div class="container">
    <h1 class="mb-4 text-center">🗺️ Карта локальной сети — теперь всё понятно!</h1>
    <div id="network-info" class="alert alert-success"></div>
    <button id="scan-btn" class="btn btn-success btn-lg w-100 mb-3">🚀 СКАНИРОВАТЬ СЕТЬ (одна кнопка)</button>
    <div id="loading" class="text-center d-none"><div class="spinner-border text-primary"></div><p>Сканирование... (3–8 сек)</p></div>
    <div id="network-vis"></div>

    <h4 class="mt-5">Найденные устройства</h4>
    <table class="table table-striped" id="devices-table">
        <thead><tr><th>IP</th><th>Имя (из роутера)</th><th>Тип</th><th>Производитель</th><th>OS</th><th>MAC</th></tr></thead>
        <tbody></tbody>
    </table>
</div>

<script>
let visNetwork;
document.getElementById('scan-btn').addEventListener('click', async () => {
    const btn = document.getElementById('scan-btn');
    const loading = document.getElementById('loading');
    btn.disabled = true; loading.classList.remove('d-none');

    const res = await fetch('/api/scan');
    const data = await res.json();

    document.getElementById('network-info').innerHTML = 
        `Реальная сеть: <strong>${data.networks[0].subnet}</strong><br>` +
        `Роутер: <strong>${data.networks[0].gateway}</strong><br>` +
        `<small class="text-muted">${data.note}</small>`;

    const nodes = new vis.DataSet();
    const edges = new vis.DataSet();
    const rId = 'router';
    nodes.add({id: rId, label: `🔌 TP-Link\\n${data.networks[0].gateway}`, color: '#dc3545', shape: 'circle', size: 40});

    const tbody = document.querySelector('#devices-table tbody');
    tbody.innerHTML = '';

    data.devices.forEach(dev => {
        const nodeId = dev.ip;
        nodes.add({
            id: nodeId,
            label: `${dev.hostname}\\n${dev.ip}`,
            title: `Тип: ${dev.type}\\nПроизводитель: ${dev.vendor}\\nOS: ${dev.os}\\nMAC: ${dev.mac}\\n\\nОткрыть веб-интерфейс: http://${dev.ip}`,
            color: dev.type.includes('iPhone') ? '#0dcaf0' : dev.type.includes('Salute') ? '#6610f2' : dev.type.includes('Яндекс') ? '#fd7e14' : '#198754',
            shape: 'box'
        });
        edges.add({from: rId, to: nodeId});

        const row = document.createElement('tr');
        row.innerHTML = `<td>${dev.ip}</td><td><strong>${dev.hostname}</strong></td><td>${dev.type}</td><td>${dev.vendor}</td><td>${dev.os}</td><td>${dev.mac}</td>`;
        tbody.appendChild(row);
    });

    const container = document.getElementById('network-vis');
    visNetwork = new vis.Network(container, {nodes, edges}, {physics: {enabled: true}});
    
    btn.disabled = false; loading.classList.add('d-none');
});
</script>
</body>
</html>
"""

if __name__ == '__main__':
    print("🚀 Запуск... Открой http://127.0.0.1:5000\n(Запусти от имени администратора!)")
    app.run(debug=True)