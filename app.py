import socket
import psutil
import ipaddress
from flask import Flask, jsonify, render_template_string
import nmap

app = Flask(__name__)

def get_network_info():
    """Автоматически находим активный интерфейс и подсеть"""
    for iface, addrs in psutil.net_if_addrs().items():
        if iface in psutil.net_if_stats() and psutil.net_if_stats()[iface].isup:
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith(('127.', '0.0.0.0')):
                    if addr.netmask:
                        net = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                        return {
                            'local_ip': addr.address,
                            'subnet': str(net),
                            'mask': addr.netmask,
                            'interface': iface
                        }
    raise Exception("Не удалось определить сеть. Подключитесь к Wi-Fi/Ethernet.")

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/scan')
def scan():
    try:
        info = get_network_info()
        nm = nmap.PortScanner()
        # Быстрый пинг-скан + разрешение имён
        nm.scan(hosts=info['subnet'], arguments='-sn -R -T4 --host-timeout 2s')

        devices = []
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                hostname = nm[host].hostname() or 'Неизвестно'
                mac = nm[host]['addresses'].get('mac', 'N/A')
                devices.append({'ip': host, 'hostname': hostname, 'mac': mac})

        # Добавляем наш компьютер, если nmap его пропустил
        local_hostname = socket.gethostname()
        if info['local_ip'] not in [d['ip'] for d in devices]:
            devices.append({'ip': info['local_ip'], 'hostname': local_hostname + ' (Этот ПК)', 'mac': 'Local'})

        return jsonify({
            'devices': devices,
            'network_info': info
        })
    except Exception as e:
        error_msg = str(e)
        if "nmap" in error_msg.lower():
            error_msg = "nmap не найден! Установите его и добавьте в PATH."
        return jsonify({'error': error_msg}), 500

# ====================== HTML + JS (один файл) ======================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Карта локальной сети — одна кнопка</title>
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
    <h1 class="mb-4 text-center">🗺️ Карта локальной сети</h1>
    
    <div id="network-info" class="alert alert-info text-center"></div>
    
    <button id="scan-btn" class="btn btn-success btn-lg w-100 mb-3">
        🚀 СКАНИРОВАТЬ СЕТЬ (одна кнопка)
    </button>
    
    <div id="loading" class="text-center d-none">
        <div class="spinner-border text-primary" role="status"></div>
        <p>Сканирование... (обычно 3–8 секунд)</p>
    </div>

    <div id="network-vis"></div>

    <h4 class="mt-5">Найденные устройства</h4>
    <table class="table table-striped device-table" id="devices-table">
        <thead><tr><th>IP</th><th>Имя компьютера</th><th>MAC</th></tr></thead>
        <tbody></tbody>
    </table>
</div>

<script>
let visNetwork;

document.getElementById('scan-btn').addEventListener('click', async () => {
    const btn = document.getElementById('scan-btn');
    const loading = document.getElementById('loading');
    btn.disabled = true;
    loading.classList.remove('d-none');

    try {
        const res = await fetch('/api/scan');
        const data = await res.json();

        if (data.error) {
            alert('Ошибка: ' + data.error);
            return;
        }

        // Информация о сети
        const ni = data.network_info;
        document.getElementById('network-info').innerHTML = 
            `Подсеть: <strong>${ni.subnet}</strong> | Маска: <strong>${ni.mask}</strong> | 
             Ваш IP: <strong>${ni.local_ip}</strong> | Интерфейс: ${ni.interface}`;

        // Визуализация
        const nodes = new vis.DataSet();
        const edges = new vis.DataSet();

        // Центральный шлюз
        nodes.add({
            id: 'router',
            label: 'Шлюз\\n(Router)',
            color: '#dc3545',
            font: { size: 18, color: '#fff' },
            shape: 'circle',
            size: 35
        });

        const tbody = document.querySelector('#devices-table tbody');
        tbody.innerHTML = '';

        data.devices.forEach((dev, i) => {
            const nodeId = i + 1;
            const isLocal = dev.ip === ni.local_ip;
            
            nodes.add({
                id: nodeId,
                label: `${dev.hostname}\\n${dev.ip}`,
                title: `MAC: ${dev.mac}`,
                color: isLocal ? '#0d6efd' : '#198754',
                font: { size: 14 },
                shape: 'box'
            });

            edges.add({ from: 'router', to: nodeId, arrows: 'to' });

            // Таблица
            const row = document.createElement('tr');
            row.innerHTML = `<td>${dev.ip}</td><td>${dev.hostname}</td><td>${dev.mac}</td>`;
            tbody.appendChild(row);
        });

        const container = document.getElementById('network-vis');
        const options = {
            nodes: { font: { multi: true } },
            physics: { enabled: true, stabilization: { iterations: 100 } },
            layout: { improvedLayout: true }
        };

        if (visNetwork) visNetwork.destroy();
        visNetwork = new vis.Network(container, { nodes, edges }, options);

    } catch (err) {
        alert('Ошибка соединения: ' + err);
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
    print("Запуск сервера... Откройте http://127.0.0.1:5000")
    app.run(debug=True)