from flask import Flask, render_template_string, jsonify
import sqlite3
import os
from database import get_db_connection

app = Flask(__name__)

# --- EMBEDDED DARK THEME DASHBOARD ---
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IDS Control Centre</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: { extend: { colors: { darkbg: '#0f172a', cardbg: '#1e293b', primary: '#0ea5e9', alert: '#ef4444', safe: '#10b981' } } }
        }
    </script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="bg-darkbg text-gray-200 font-sans min-h-screen flex">
    
    <aside class="w-64 bg-cardbg border-r border-gray-700 flex flex-col">
        <div class="p-6">
            <h1 class="text-xl font-bold text-primary flex items-center">
                <span class="w-3 h-3 rounded-full bg-safe animate-pulse mr-2"></span>
                IDS Control Centre
            </h1>
        </div>
        <nav class="flex-1 px-4 space-y-2">
            <a href="/" class="block px-4 py-2 rounded bg-primary/10 text-primary font-medium">Dashboard Overview</a>
            <a href="/dataset" class="block px-4 py-2 rounded hover:bg-gray-700 transition">Dataset Management</a>
            <a href="#" class="block px-4 py-2 rounded hover:bg-gray-700 transition">Model Training</a>
            <a href="#" class="block px-4 py-2 rounded hover:bg-gray-700 transition">Real-Time Detection</a>
        </nav>
    </aside>

    <main class="flex-1 p-8 overflow-y-auto">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg">
                <h3 class="text-sm text-gray-400">Total Flows Processed</h3>
                <p class="text-3xl font-bold mt-2 text-white">124,592</p>
            </div>
            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg">
                <h3 class="text-sm text-gray-400">Attacks Detected</h3>
                <p class="text-3xl font-bold mt-2 text-alert">{{ total_attacks }}</p>
            </div>
            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg">
                <h3 class="text-sm text-gray-400">Ensemble Accuracy</h3>
                <p class="text-3xl font-bold mt-2 text-primary">99.75%</p>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg">
                <h2 class="text-lg font-semibold mb-4 border-b border-gray-700 pb-2">Live Network Traffic</h2>
                <canvas id="trafficChart" height="200"></canvas>
            </div>
            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg">
                <h2 class="text-lg font-semibold mb-4 border-b border-gray-700 pb-2">Attack Distribution</h2>
                <canvas id="attackChart" height="200"></canvas>
            </div>
        </div>
    </main>

    <script>
        const trafficCtx = document.getElementById('trafficChart').getContext('2d');
        new Chart(trafficCtx, {
            type: 'line',
            data: { labels: ['10m', '8m', '6m', '4m', '2m', 'Now'], datasets: [{ label: 'Normal Traffic', data: [12, 19, 15, 25, 22, 30], borderColor: '#10b981', backgroundColor: 'rgba(16, 185, 129, 0.1)', fill: true, tension: 0.4 }] },
            options: { responsive: true, maintainAspectRatio: false, color: '#9ca3af' }
        });

        const attackCtx = document.getElementById('attackChart').getContext('2d');
        new Chart(attackCtx, {
            type: 'bar',
            data: { labels: ['DDoS', 'PortScan', 'Botnet'], datasets: [{ label: 'Detected', data: [2541, 1205, 145], backgroundColor: ['#ef4444', '#f59e0b', '#8b5cf6'] }] },
            options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, color: '#9ca3af' }
        });
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    try:
        conn = get_db_connection()
        attack_count_query = conn.execute("SELECT COUNT(*) FROM alerts WHERE attack_type != 'Benign'").fetchone()
        total_attacks = attack_count_query[0] if attack_count_query else 0
        conn.close()
    except Exception as e:
        total_attacks = 0

    return render_template_string(DASHBOARD_HTML, total_attacks=total_attacks)

@app.route('/dataset', methods=['GET'])
def dataset_management():
    return jsonify({"status": "Dataset subsystem ready."})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)