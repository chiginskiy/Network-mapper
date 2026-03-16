import socket
import psutil
import ipaddress
from flask import Flask, jsonify, render_template_string
import nmap

app = Flask(__name__)

def get_all_networks():
    """Находим ВСЕ активные подсети + шлюзы"""
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
                        if subnet_str not in seen:
                            seen.add(subnet_str)
                            network_obj = ipaddress.ip_network(subnet_str)
                            gw = str(network_obj.network_address + 1)
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

def guess_device_type(hostname: str, osmatch: str, vendor: str, ip: str) -> str:
    hn = hostname.lower()
    om = osmatch.lower()
    vm = vendor.lower()

    # Приоритет — OS-детекция
    if 'windows' in om or 'microsoft' in om:
        return '💻 Windows ПК'
    if any(x in om for x in ['linux', 'ubuntu', 'debian']):
        return '💻 Linux'
    if 'android' in om:
        return '📱 Android устройство'

    # Потом по имени и производителю
    if any(x in hn for x in ['iphone', 'ipad', 'ipod']) or 'apple' in vm:
        return '📱 iOS устройство'
    if any(x in hn for x in ['macbook', 'imac', 'macmini']):
        return '💻 Mac'
    if any(x in hn for x in ['printer', 'print', 'hp', 'brother', 'epson', 'canon']) or any(x in vm for x in ['hp', 'brother', 'epson', 'canon']):
        return '🖨️ Принтер'
    if any(x in hn for x in ['tv', 'smarttv', 'lg', 'samsung tv']):
        return '📺 Смарт TV'
    if ip.endswith('.1') or 'router' in hn or 'gateway' in hn:
        return '🔌 Роутер/Шлюз'
    return '❓ Неизвестное устройство'

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/scan')
def scan():
    networks, local_ips = get_all_networks()
    if not networks:
        return jsonify({'error': 'Нет активных сетевых интерфейсов'}), 500

    all_devices = []
    nm = nmap.PortScanner()

    for net in networks:
        scanned = False
        for args in [
            '-sn -R -O --osscan-guess --max-os-tries=2 -T4 --host-timeout 4s',   # с OS (нужны права админа)
            '-sn -R -T4 --host-timeout 4s'                                       # fallback без OS
        ]:
            try:
                nm.scan(hosts=net['subnet'], arguments=args)
                scanned = True
                break
            except:
                continue
        if not scanned:
            continue

        for host in nm.all_hosts():
            if nm[host].state() != 'up':
                continue
            hostname = nm[host].hostname() or 'Неизвестно'
            mac = nm[host]['addresses'].get('mac', 'N/A')
            vendor = nm[host].get('vendor', {}).get(mac, 'Неизвестно') if mac != 'N/A' else 'Неизвестно'
            osmatch_list = nm[host].get('osmatch', [])
            osmatch = osmatch_list[0].get('name', 'Неизвестно') if osmatch_list else 'Неизвестно'

            dev_type = guess_device_type(hostname, osmatch, vendor, host)

            all_devices.append({
                'ip': host,
                'hostname': hostname,
                'mac': mac,
                'vendor': vendor,
                'os': osmatch,
                'type': dev_type,
                'subnet': net['subnet']
            })

    # Добавляем "Этот ПК"
    for lip in local_ips:
        if any(d['ip'] == lip for d in all_devices):
            continue
        all_devices.append({
            'ip': lip,
            'hostname': socket.gethostname() + ' (Этот ПК)',
            'mac': 'Local',
            'vendor': 'Local',
            'os': 'Ваша ОС',
            'type': '💻 Этот компьютер',
            'subnet': 'Local'
        })

    # Убираем дубли и сортируем по IP
    unique = {d['ip']: d for d in all_devices if d['ip'] not in ['127.0.0.1', '::1']}
    sorted_devices = sorted(unique.values(), key=lambda x: tuple(int(p) for p in x['ip'].split('.')))

    return jsonify({
        'devices': sorted_devices,
        'networks': networks,
        'local_ips': local_ips
    })

# ====================== HTML + JS ======================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Карта локальной сети v3 — с правами админа</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://unpkg.com/vis-network@9.1.2/standalone/umd/vis-network.min.js"></script>
    <style>
        body { background: #f8f9fa; }
        #network-vis { height: 650px; border: 1px solid #ddd; background: white; }
        .device-table th { background: #0d6efd; color: white; }
    </style>
</head>
<body class="p-4">
<div class="container">
    <h1 class="mb-4 text-center">🗺️ Карта локальной сети (с OS и типами устройств)</h1>
    
    <div id="network-info" class="alert alert-info"></div>
    
    <button id="scan-btn" class="btn btn-success btn-lg w-100 mb-3">
        🚀 СКАНИРОВАТЬ ВСЕ ПОДСЕТИ (одна кнопка)
    </button>
    
    <div id="loading" class="text-center d-none">
        <div class="spinner-border text-primary"></div>
        <p>Сканирование... (5–12 сек с OS-детекцией)</p>
    </div>

    <div id="network-vis"></div>

    <h4 class="mt-5">Найденные устройства</h4>
    <table class="table table-striped device-table" id="devices-table">
        <thead><tr>
            <th>IP</th><th>Имя</th><th>Тип</th><th>Производитель</th><th>OS</th><th>MAC</th><th>Подсеть</th>
        </tr></thead>
        <tbody></tbody>
    </table>
</div>

<script>
let visNetwork;

function getNodeColor(type) {
    if (type.includes('📱')) return '#0dcaf0';
    if (type.includes('💻')) return '#198754';
    if (type.includes('🖨️')) return '#fd7e14';
    if (type.includes('📺')) return '#6610f2';
    if (type.includes('Этот компьютер')) return '#0d6efd';
    return '#6c757d';
}

document.getElementById('scan-btn').addEventListener('click', async () => {
    const btn = document.getElementById('scan-btn');
    const loading = document.getElementById('loading');
    btn.disabled = true;
    loading.classList.remove('d-none');

    try {
        const res = await fetch('/api/scan');
        const data = await res.json();

        if (data.error) { alert('Ошибка: ' + data.error); return; }

        let infoHTML = `Подсетей найдено: <strong>${data.networks.length}</strong><br>`;
        data.networks.forEach(n => {
            infoHTML += `• ${n.subnet} (GW: ${n.gateway})<br>`;
        });
        infoHTML += `Ваши IP: ${data.local_ips.join(', ')}`;
        document.getElementById('network-info').innerHTML = infoHTML;

        const nodes = new vis.DataSet();
        const edges = new vis.DataSet();
        const routerMap = {};

        data.networks.forEach(net => {
            const rId = 'router_' + net.subnet.replace(/[^a-z0-9]/gi, '_');
            nodes.add({
                id: rId,
                label: `🔌 Роутер\\n${net.subnet}\\n${net.gateway}`,
                color: '#dc3545',
                font: { size: 16, color: '#fff' },
                shape: 'circle',
                size: 40
            });
            routerMap[net.subnet] = rId;
        });

        const tbody = document.querySelector('#devices-table tbody');
        tbody.innerHTML = '';

        data.devices.forEach(dev => {
            const nodeId = 'dev_' + dev.ip.replace(/[^a-z0-9]/gi, '_');
            const color = getNodeColor(dev.type);

            nodes.add({
                id: nodeId,
                label: `${dev.hostname}\\n${dev.ip}`,
                title: `Тип: ${dev.type}\\nПроизв.: ${dev.vendor}\\nOS: ${dev.os}\\nMAC: ${dev.mac}`,
                color: color,
                shape: 'box',
                font: { size: 13 }
            });

            let rId = routerMap[dev.subnet] || Object.values(routerMap)[0];
            if (rId) edges.add({ from: rId, to: nodeId, arrows: 'to' });

            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${dev.ip}</td>
                <td>${dev.hostname}</td>
                <td>${dev.type}</td>
                <td>${dev.vendor}</td>
                <td>${dev.os}</td>
                <td>${dev.mac}</td>
                <td>${dev.subnet}</td>
            `;
            tbody.appendChild(row);
        });

        const container = document.getElementById('network-vis');
        const options = { physics: { enabled: true }, layout: { improvedLayout: true } };

        if (visNetwork) visNetwork.destroy();
        visNetwork = new vis.Network(container, { nodes, edges }, options);

    } catch (err) {
        alert('Ошибка: ' + err);
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
    print("🚀 Запуск сервера...\nВАЖНО: Запустите от имени АДМИНИСТРАТОРА / sudo\nдля детекции OS и производителей!\nОткрывайте: http://127.0.0.1:5000")
    app.run(debug=True)