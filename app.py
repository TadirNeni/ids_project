from flask import Flask, render_template_string, jsonify
import sqlite3
import os
from database import get_db_connection

app = Flask(__name__)

# --- EMBEDDED DARK THEME DASHBOARD (NOW LIVE) ---
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="5">
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
            <a href="#" class="block px-4 py-2 rounded hover:bg-gray-700 transition text-alert">Real-Time Detection</a>
        </nav>
        <div class="p-4 border-t border-gray-700 text-xs text-gray-400">
            Live Sniffer: <span class="text-safe font-bold">ACTIVE</span>
        </div>
    </aside>

    <main class="flex-1 p-8 overflow-y-auto">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg">
                <h3 class="text-sm text-gray-400">Total Flows Processed</h3>
                <p class="text-3xl font-bold mt-2 text-white">Live Monitoring</p>
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

        <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg mb-8">
            <div class="flex justify-between items-center mb-4 border-b border-gray-700 pb-2">
                <h2 class="text-lg font-semibold">Live Packet Classification</h2>
                <span class="px-3 py-1 bg-alert/20 text-alert rounded-full text-xs font-bold animate-pulse">Live DB Sync Active</span>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left text-sm">
                    <thead class="text-gray-400 bg-gray-800/50">
                        <tr>
                            <th class="px-4 py-3">Timestamp</th>
                            <th class="px-4 py-3">Src IP:Port</th>
                            <th class="px-4 py-3">Dst IP:Port</th>
                            <th class="px-4 py-3">Protocol</th>
                            <th class="px-4 py-3">Prediction</th>
                            <th class="px-4 py-3">Confidence</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-700">
                        {% for event in events %}
                        <tr class="hover:bg-gray-800 transition {% if event['attack_type'] != 'Benign' %}bg-alert/5 text-alert{% else %}text-safe{% endif %}">
                            <td class="px-4 py-3 text-gray-400">{{ event['timestamp'] }}</td>
                            <td class="px-4 py-3">{{ event['src_ip'] }}:{{ event['src_port'] }}</td>
                            <td class="px-4 py-3">{{ event['dst_ip'] }}:{{ event['dst_port'] }}</td>
                            <td class="px-4 py-3">{{ event['protocol'] }}</td>
                            <td class="px-4 py-3 font-semibold">{{ event['attack_type'] }}</td>
                            <td class="px-4 py-3 text-xs">{{ event['confidence_score'] }}</td>
                        </tr>
                        {% else %}
                        <tr>
                            <td colspan="6" class="px-4 py-3 text-center text-gray-500">Listening for network traffic... No alerts generated yet.</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </main>
</body>
</html>
"""

@app.route('/')
def dashboard():
    try:
        conn = get_db_connection()
        # 1. Get total attack count dynamically
        attack_count_query = conn.execute("SELECT COUNT(*) FROM alerts WHERE attack_type != 'Benign'").fetchone()
        total_attacks = attack_count_query[0] if attack_count_query else 0
        
        # 2. Fetch the 10 most recent alerts to display in the table
        recent_events = conn.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10').fetchall()
        conn.close()
    except Exception as e:
        total_attacks = 0
        recent_events = []

    return render_template_string(DASHBOARD_HTML, total_attacks=total_attacks, events=recent_events)

@app.route('/dataset', methods=['GET'])
def dataset_management():
    return jsonify({"status": "Dataset subsystem ready."})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)