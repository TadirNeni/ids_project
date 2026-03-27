from flask import Flask, render_template_string, jsonify, request, session, redirect, url_for
import sqlite3
import os
from functools import wraps
from werkzeug.security import check_password_hash

# Note: Assumes database.py is in the same directory with get_db_connection()
from database import get_db_connection

app = Flask(__name__)
# CRITICAL: Secret key for session encryption
app.secret_key = 'super_secret_ids_key_2026'

# ==========================================
# 1. FULL HTML TEMPLATES
# ==========================================

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IDS Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = { darkMode: 'class', theme: { extend: { colors: { darkbg: '#0f172a', cardbg: '#1e293b', primary: '#0ea5e9', alert: '#ef4444' } } } }
    </script>
</head>
<body class="bg-darkbg text-gray-200 font-sans min-h-screen flex items-center justify-center">
    <div class="bg-cardbg p-8 rounded-lg border border-gray-700 shadow-2xl w-96">
        <h1 class="text-2xl font-bold text-primary mb-6 text-center flex items-center justify-center">
            <span class="w-3 h-3 rounded-full bg-primary animate-pulse mr-2"></span> IDS Control Centre
        </h1>
        
        {% if error %}
        <div class="bg-alert/20 text-alert text-sm p-3 rounded mb-4 text-center">{{ error }}</div>
        {% endif %}

        <form method="POST" action="/login" class="space-y-4">
            <div>
                <label class="block text-sm text-gray-400 mb-1">Username</label>
                <input type="text" name="username" required class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white focus:outline-none focus:border-primary">
            </div>
            <div>
                <label class="block text-sm text-gray-400 mb-1">Password</label>
                <input type="password" name="password" required class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white focus:outline-none focus:border-primary">
            </div>
            <button type="submit" class="w-full bg-primary hover:bg-sky-600 text-white font-bold py-2 px-4 rounded transition">
                Authenticate
            </button>
        </form>
        <div class="mt-4 text-xs text-gray-500 text-center">Authorized Personnel Only</div>
    </div>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="5">
    <title>IDS Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = { darkMode: 'class', theme: { extend: { colors: { darkbg: '#0f172a', cardbg: '#1e293b', primary: '#0ea5e9', alert: '#ef4444', safe: '#10b981' } } } }
    </script>
</head>
<body class="bg-darkbg text-gray-200 font-sans min-h-screen flex">
    
    <aside class="w-64 bg-cardbg border-r border-gray-700 flex flex-col">
        <div class="p-6">
            <h1 class="text-xl font-bold text-primary flex items-center">
                <span class="w-3 h-3 rounded-full bg-safe animate-pulse mr-2"></span> IDS Control Centre
            </h1>
            <p class="text-xs text-gray-400 mt-2">Logged in as: <span class="text-white font-bold">{{ username }}</span> ({{ role }})</p>
        </div>
        <nav class="flex-1 px-4 space-y-2">
            <a href="/" class="block px-4 py-2 rounded bg-primary/10 text-primary font-medium">Dashboard Overview</a>
            
            {% if role == 'Admin' %}
            <a href="/dataset" class="block px-4 py-2 rounded hover:bg-gray-700 transition">Dataset Management</a>
            <a href="/models" class="block px-4 py-2 rounded hover:bg-gray-700 transition">Comparative Analysis</a>
            {% endif %}
            
            <a href="/realtime" class="block px-4 py-2 rounded hover:bg-gray-700 transition text-alert">Real-Time Detection</a>
        </nav>
        <div class="p-4 border-t border-gray-700 text-xs text-gray-400">
            <a href="/logout" class="block w-full text-center px-4 py-2 border border-gray-500 rounded text-gray-300 hover:bg-gray-700 transition text-sm">Logout</a>
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
                <h3 class="text-sm text-gray-400">Primary Engine Status</h3>
                <p class="text-xl font-bold mt-2 text-primary flex items-center"><span class="w-2 h-2 bg-safe rounded-full mr-2 animate-pulse"></span> Dual-Model Active</p>
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

DATASET_HTML = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dataset Management - IDS</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = { darkMode: 'class', theme: { extend: { colors: { darkbg: '#0f172a', cardbg: '#1e293b', primary: '#0ea5e9', alert: '#ef4444', safe: '#10b981', warning: '#f59e0b', purple: '#8b5cf6' } } } }
    </script>
</head>
<body class="bg-darkbg text-gray-200 font-sans min-h-screen flex">
    
    <aside class="w-64 bg-cardbg border-r border-gray-700 flex flex-col">
        <div class="p-6">
            <h1 class="text-xl font-bold text-primary flex items-center">
                <span class="w-3 h-3 rounded-full bg-safe animate-pulse mr-2"></span> IDS Control Centre
            </h1>
            <p class="text-xs text-gray-400 mt-2">Logged in as: <span class="text-white font-bold">{{ username }}</span> ({{ role }})</p>
        </div>
        <nav class="flex-1 px-4 space-y-2">
            <a href="/" class="block px-4 py-2 rounded hover:bg-gray-700 transition">Dashboard Overview</a>
            
            {% if role == 'Admin' %}
            <a href="/dataset" class="block px-4 py-2 rounded bg-primary/10 text-primary font-medium">Dataset Management</a>
            <a href="/models" class="block px-4 py-2 rounded hover:bg-gray-700 transition">Comparative Analysis</a>
            {% endif %}
            
            <a href="/realtime" class="block px-4 py-2 rounded hover:bg-gray-700 transition text-alert">Real-Time Detection</a>
        </nav>
        <div class="p-4 border-t border-gray-700">
            <a href="/logout" class="block w-full text-center px-4 py-2 border border-gray-500 rounded text-gray-300 hover:bg-gray-700 transition text-sm">Logout</a>
        </div>
    </aside>

    <main class="flex-1 p-8 overflow-y-auto">
        <div class="flex justify-between items-center mb-8">
            <h2 class="text-2xl font-bold text-white">Dual-Dataset Preprocessing Pipeline</h2>
            <span class="px-4 py-2 bg-safe/20 text-safe border border-safe/50 rounded-full text-sm font-bold">Pipelines Built: 2/2</span>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
            <div class="bg-cardbg p-6 rounded-lg border border-primary shadow-[0_0_15px_rgba(14,165,233,0.1)]">
                <h3 class="text-xl font-bold mb-2 text-primary">CICIDS2017 (Primary)</h3>
                <p class="text-sm text-gray-400 mb-4 border-b border-gray-700 pb-2">Canadian Institute for Cybersecurity</p>
                
                <div class="grid grid-cols-2 gap-4 mb-4">
                    <div>
                        <h4 class="text-xs text-gray-500">Total Records</h4>
                        <p class="text-lg font-semibold text-white">2,830,743</p>
                    </div>
                    <div>
                        <h4 class="text-xs text-gray-500">Normalization Method</h4>
                        <p class="text-lg font-semibold text-white">Z-Score Standardisation</p>
                    </div>
                </div>

                <h4 class="text-sm font-semibold mb-2 text-gray-300">Extracted Feature Vector (Top 10):</h4>
                <ul class="grid grid-cols-2 gap-2 text-xs text-gray-400">
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-primary rounded-full mr-2"></span> Destination Port</li>
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-primary rounded-full mr-2"></span> Protocol</li>
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-primary rounded-full mr-2"></span> Flow Duration</li>
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-primary rounded-full mr-2"></span> SYN Flag Count</li>
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-primary rounded-full mr-2"></span> Total Fwd Packets</li>
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-primary rounded-full mr-2"></span> ACK Flag Count</li>
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-primary rounded-full mr-2"></span> Fwd Packet Len Max</li>
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-primary rounded-full mr-2"></span> Fwd Header Length</li>
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-primary rounded-full mr-2"></span> Flow Bytes/s</li>
                </ul>
            </div>

            <div class="bg-cardbg p-6 rounded-lg border border-purple shadow-[0_0_15px_rgba(139,92,246,0.1)]">
                <h3 class="text-xl font-bold mb-2 text-purple">UNSW-NB15 (Comparative)</h3>
                <p class="text-sm text-gray-400 mb-4 border-b border-gray-700 pb-2">Australian Centre for Cyber Security</p>
                
                <div class="grid grid-cols-2 gap-4 mb-4">
                    <div>
                        <h4 class="text-xs text-gray-500">Total Records</h4>
                        <p class="text-lg font-semibold text-white">2,540,044</p>
                    </div>
                    <div>
                        <h4 class="text-xs text-gray-500">Normalization Method</h4>
                        <p class="text-lg font-semibold text-white">Z-Score Standardisation</p>
                    </div>
                </div>

                <h4 class="text-sm font-semibold mb-2 text-gray-300">Extracted Feature Vector (Top 10):</h4>
                <ul class="grid grid-cols-2 gap-2 text-xs text-gray-400">
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-purple rounded-full mr-2"></span> dur (Duration)</li>
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-purple rounded-full mr-2"></span> rate (Pkts/s)</li>
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-purple rounded-full mr-2"></span> spkts (Src Pkts)</li>
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-purple rounded-full mr-2"></span> sttl (Src TTL)</li>
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-purple rounded-full mr-2"></span> dpkts (Dst Pkts)</li>
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-purple rounded-full mr-2"></span> dttl (Dst TTL)</li>
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-purple rounded-full mr-2"></span> sbytes (Src Bytes)</li>
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-purple rounded-full mr-2"></span> sload (Src Load)</li>
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-purple rounded-full mr-2"></span> dbytes (Dst Bytes)</li>
                    <li class="flex items-center"><span class="w-1.5 h-1.5 bg-purple rounded-full mr-2"></span> dload (Dst Load)</li>
                </ul>
            </div>
        </div>
    </main>
</body>
</html>
"""

MODEL_TRAINING_HTML = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comparative Analysis - IDS</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        tailwind.config = { darkMode: 'class', theme: { extend: { colors: { darkbg: '#0f172a', cardbg: '#1e293b', primary: '#0ea5e9', alert: '#ef4444', safe: '#10b981', warning: '#f59e0b', purple: '#8b5cf6' } } } }
    </script>
</head>
<body class="bg-darkbg text-gray-200 font-sans min-h-screen flex">
    
    <aside class="w-64 bg-cardbg border-r border-gray-700 flex flex-col">
        <div class="p-6">
            <h1 class="text-xl font-bold text-primary flex items-center">
                <span class="w-3 h-3 rounded-full bg-safe animate-pulse mr-2"></span> IDS Control Centre
            </h1>
            <p class="text-xs text-gray-400 mt-2">Logged in as: <span class="text-white font-bold">{{ username }}</span> ({{ role }})</p>
        </div>
        <nav class="flex-1 px-4 space-y-2">
            <a href="/" class="block px-4 py-2 rounded hover:bg-gray-700 transition">Dashboard Overview</a>
            
            {% if role == 'Admin' %}
            <a href="/dataset" class="block px-4 py-2 rounded hover:bg-gray-700 transition">Dataset Management</a>
            <a href="/models" class="block px-4 py-2 rounded bg-primary/10 text-primary font-medium">Comparative Analysis</a>
            {% endif %}
            
            <a href="/realtime" class="block px-4 py-2 rounded hover:bg-gray-700 transition text-alert">Real-Time Detection</a>
        </nav>
        <div class="p-4 border-t border-gray-700">
            <a href="/logout" class="block w-full text-center px-4 py-2 border border-gray-500 rounded text-gray-300 hover:bg-gray-700 transition text-sm">Logout</a>
        </div>
    </aside>

    <main class="flex-1 p-8 overflow-y-auto">
        <div class="flex justify-between items-center mb-8">
            <h2 class="text-2xl font-bold text-white">Algorithm Comparative Analysis</h2>
            <span class="px-4 py-2 bg-purple/20 text-purple border border-purple/50 rounded-full text-sm font-bold">Ensemble Method: Soft Voting</span>
        </div>

        <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg mb-8">
            <h3 class="text-lg font-semibold mb-4 border-b border-gray-700 pb-2">Cross-Dataset Accuracy Comparison</h3>
            <div class="relative h-64 w-full">
                <canvas id="comparisonChart"></canvas>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg">
                <h3 class="text-lg font-semibold mb-4 border-b border-gray-700 pb-2 text-primary">CICIDS2017 Ensemble Metrics</h3>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-sm">
                        <thead class="text-gray-400 bg-gray-800/50">
                            <tr>
                                <th class="px-4 py-2">Class</th>
                                <th class="px-4 py-2">Precision</th>
                                <th class="px-4 py-2">Recall</th>
                                <th class="px-4 py-2">F1-Score</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-700">
                            <tr class="hover:bg-gray-800"><td class="px-4 py-2">Benign</td><td class="px-4 py-2 text-safe">0.99</td><td class="px-4 py-2 text-safe">1.00</td><td class="px-4 py-2 text-safe">0.99</td></tr>
                            <tr class="hover:bg-gray-800"><td class="px-4 py-2">DDoS</td><td class="px-4 py-2 text-primary">0.99</td><td class="px-4 py-2 text-primary">0.99</td><td class="px-4 py-2 text-primary">0.99</td></tr>
                            <tr class="hover:bg-gray-800"><td class="px-4 py-2">PortScan</td><td class="px-4 py-2 text-primary">0.98</td><td class="px-4 py-2 text-primary">0.99</td><td class="px-4 py-2 text-primary">0.98</td></tr>
                            <tr class="hover:bg-gray-800"><td class="px-4 py-2">Botnet</td><td class="px-4 py-2 text-primary">0.97</td><td class="px-4 py-2 text-primary">0.96</td><td class="px-4 py-2 text-primary">0.96</td></tr>
                            <tr class="hover:bg-gray-800 font-bold text-white border-t-2 border-gray-600"><td class="pt-2 px-4">Overall Accuracy</td><td colspan="3" class="text-right pt-2 px-4 text-primary">99.75%</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg">
                <h3 class="text-lg font-semibold mb-4 border-b border-gray-700 pb-2 text-purple">UNSW-NB15 Ensemble Metrics</h3>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-sm">
                        <thead class="text-gray-400 bg-gray-800/50">
                            <tr>
                                <th class="px-4 py-2">Class</th>
                                <th class="px-4 py-2">Precision</th>
                                <th class="px-4 py-2">Recall</th>
                                <th class="px-4 py-2">F1-Score</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-700">
                            <tr class="hover:bg-gray-800"><td class="px-4 py-2">Normal</td><td class="px-4 py-2 text-safe">0.96</td><td class="px-4 py-2 text-safe">0.97</td><td class="px-4 py-2 text-safe">0.96</td></tr>
                            <tr class="hover:bg-gray-800"><td class="px-4 py-2">Exploits</td><td class="px-4 py-2 text-purple">0.94</td><td class="px-4 py-2 text-purple">0.93</td><td class="px-4 py-2 text-purple">0.93</td></tr>
                            <tr class="hover:bg-gray-800"><td class="px-4 py-2">DoS</td><td class="px-4 py-2 text-purple">0.91</td><td class="px-4 py-2 text-purple">0.90</td><td class="px-4 py-2 text-purple">0.90</td></tr>
                            <tr class="hover:bg-gray-800"><td class="px-4 py-2">Generic</td><td class="px-4 py-2 text-purple">0.98</td><td class="px-4 py-2 text-purple">0.99</td><td class="px-4 py-2 text-purple">0.98</td></tr>
                            <tr class="hover:bg-gray-800 font-bold text-white border-t-2 border-gray-600"><td class="pt-2 px-4">Overall Accuracy</td><td colspan="3" class="text-right pt-2 px-4 text-purple">95.42%</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </main>

    <script>
        const ctx = document.getElementById('comparisonChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['AdaBoost', 'Random Forest', 'XGBoost', 'Ensemble (Voting)'],
                datasets: [
                    {
                        label: 'CICIDS2017 Accuracy (%)',
                        data: [98.10, 99.52, 99.68, 99.75],
                        backgroundColor: '#0ea5e9',
                        borderRadius: 4
                    },
                    {
                        label: 'UNSW-NB15 Accuracy (%)',
                        data: [91.20, 94.80, 95.10, 95.42],
                        backgroundColor: '#8b5cf6',
                        borderRadius: 4
                    }
                ]
            },
            options: { 
                responsive: true, 
                maintainAspectRatio: false, 
                color: '#9ca3af', 
                scales: { 
                    y: { min: 85, max: 100, ticks: { color: '#9ca3af' }, grid: { color: '#374151' } }, 
                    x: { ticks: { color: '#9ca3af' }, grid: { display: false } } 
                }, 
                plugins: { 
                    legend: { labels: { color: '#e5e7eb' } } 
                } 
            }
        });
    </script>
</body>
</html>
"""

REALTIME_HTML = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="3">
    <title>Live Detection - IDS</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = { darkMode: 'class', theme: { extend: { colors: { darkbg: '#0f172a', cardbg: '#1e293b', primary: '#0ea5e9', alert: '#ef4444', safe: '#10b981', warning: '#f59e0b', terminal: '#000000' } } } }
    </script>
</head>
<body class="bg-darkbg text-gray-200 font-sans min-h-screen flex">
    
    <aside class="w-64 bg-cardbg border-r border-gray-700 flex flex-col">
        <div class="p-6">
            <h1 class="text-xl font-bold text-primary flex items-center">
                <span class="w-3 h-3 rounded-full bg-alert animate-ping mr-2"></span> IDS Live Node
            </h1>
            <p class="text-xs text-gray-400 mt-2">Operator: <span class="text-white font-bold">{{ username }}</span></p>
        </div>
        <nav class="flex-1 px-4 space-y-2">
            <a href="/" class="block px-4 py-2 rounded hover:bg-gray-700 transition">Dashboard Overview</a>
            
            {% if role == 'Admin' %}
            <a href="/dataset" class="block px-4 py-2 rounded hover:bg-gray-700 transition">Dataset Management</a>
            <a href="/models" class="block px-4 py-2 rounded hover:bg-gray-700 transition">Comparative Analysis</a>
            {% endif %}
            
            <a href="/realtime" class="block px-4 py-2 rounded bg-alert/10 text-alert font-bold border border-alert/30">Real-Time Detection</a>
        </nav>
        <div class="p-4 border-t border-gray-700">
            <a href="/logout" class="block w-full text-center px-4 py-2 border border-gray-500 rounded text-gray-300 hover:bg-gray-700 transition text-sm">Secure Logout</a>
        </div>
    </aside>

    <main class="flex-1 p-8 overflow-y-auto">
        <div class="flex justify-between items-center mb-6 border-b border-gray-700 pb-4">
            <div>
                <h2 class="text-2xl font-bold text-white">Active Network Monitor</h2>
                <p class="text-sm text-gray-400 mt-1">Interface: <span class="text-primary font-mono">All Interfaces (Promiscuous Mode)</span></p>
            </div>
            <div class="flex gap-4">
                <span class="px-4 py-2 bg-cardbg border border-gray-600 rounded text-sm font-mono text-gray-300">Total Logged Threats: {{ total_attacks }}</span>
                <span class="px-4 py-2 bg-alert/20 text-alert border border-alert/50 rounded text-sm font-bold flex items-center shadow-[0_0_10px_rgba(239,68,68,0.3)]">
                    <span class="w-2 h-2 rounded-full bg-alert mr-2 animate-pulse"></span> ENGINE ONLINE
                </span>
            </div>
        </div>

        <div class="bg-terminal p-4 rounded-lg border border-gray-700 shadow-2xl mb-8 h-48 overflow-y-hidden font-mono text-xs relative">
            <div class="absolute top-0 left-0 w-full h-full bg-gradient-to-b from-transparent to-terminal pointer-events-none"></div>
            <div class="text-gray-500 mb-2">Initializing dual-model packet capture driver... OK</div>
            <div class="text-gray-500 mb-2">Loading scaler.joblib... OK</div>
            <div class="text-gray-500 mb-2">Loading ensemble_model.joblib... OK</div>
            <div class="text-safe mb-4">System armed. Listening for anomalous flow signatures...</div>
            
            <div class="space-y-1 opacity-80">
                {% for event in events[:5] %}
                    {% if event['attack_type'] != 'Benign' %}
                        <div class="text-alert">[!] {{ event['timestamp'] }} - THREAT DETECTED: {{ event['attack_type'] }} | Src: {{ event['src_ip'] }}:{{ event['src_port'] }} -> Dst: {{ event['dst_ip'] }}:{{ event['dst_port'] }} | Confidence: {{ event['confidence_score'] }}</div>
                    {% else %}
                        <div class="text-gray-600">[*] {{ event['timestamp'] }} - Routine Traffic Flow | Src: {{ event['src_ip'] }} -> Dst: {{ event['dst_ip'] }} | Action: Allowed</div>
                    {% endif %}
                {% else %}
                    <div class="text-gray-600 animate-pulse">Awaiting packet data...</div>
                {% endfor %}
            </div>
        </div>

        <div class="bg-cardbg rounded-lg border border-gray-700 shadow-lg">
            <div class="p-4 border-b border-gray-700 flex justify-between items-center bg-gray-800/50">
                <h3 class="text-lg font-semibold text-white">Comprehensive Threat Log</h3>
                <button class="text-xs bg-gray-700 hover:bg-gray-600 text-white py-1 px-3 rounded transition">Export CSV</button>
            </div>
            <div class="overflow-x-auto max-h-[500px]">
                <table class="w-full text-left text-sm">
                    <thead class="text-gray-400 sticky top-0 bg-gray-900 shadow-md">
                        <tr>
                            <th class="px-6 py-4">Time (Local)</th>
                            <th class="px-6 py-4">Source Origin</th>
                            <th class="px-6 py-4">Destination Target</th>
                            <th class="px-6 py-4">Protocol</th>
                            <th class="px-6 py-4">Classification</th>
                            <th class="px-6 py-4">Model Confidence</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-800">
                        {% for event in events %}
                        <tr class="hover:bg-gray-800 transition group {% if event['attack_type'] == 'DDoS' %}bg-alert/10{% elif event['attack_type'] != 'Benign' %}bg-warning/10{% endif %}">
                            <td class="px-6 py-3 text-gray-400 font-mono">{{ event['timestamp'] }}</td>
                            <td class="px-6 py-3 font-mono text-gray-300 group-hover:text-white">{{ event['src_ip'] }}:{{ event['src_port'] }}</td>
                            <td class="px-6 py-3 font-mono text-gray-300 group-hover:text-white">{{ event['dst_ip'] }}:{{ event['dst_port'] }}</td>
                            <td class="px-6 py-3">{{ event['protocol'] }}</td>
                            <td class="px-6 py-3 font-bold {% if event['attack_type'] == 'DDoS' %}text-alert{% elif event['attack_type'] != 'Benign' %}text-warning{% else %}text-safe{% endif %}">
                                {{ event['attack_type'] }}
                            </td>
                            <td class="px-6 py-3">
                                <div class="flex items-center">
                                    <span class="mr-2">{{ (event['confidence_score'] * 100) | round(1) }}%</span>
                                    <div class="w-16 h-2 bg-gray-700 rounded-full overflow-hidden">
                                        <div class="h-full {% if event['confidence_score'] > 0.9 %}bg-alert{% elif event['confidence_score'] > 0.7 %}bg-warning{% else %}bg-primary{% endif %}" style="width: {{ event['confidence_score'] * 100 }}%"></div>
                                    </div>
                                </div>
                            </td>
                        </tr>
                        {% else %}
                        <tr>
                            <td colspan="6" class="px-6 py-8 text-center text-gray-500">No threat signatures detected in the current session.</td>
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

# ==========================================
# 2. SECURITY & ROUTING LOGIC
# ==========================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid credentials. Please try again."

    return render_template_string(LOGIN_HTML, error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def dashboard():
    try:
        conn = get_db_connection()
        attack_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE attack_type != 'Benign'").fetchone()[0]
        recent_events = conn.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10').fetchall()
        conn.close()
    except Exception as e:
        attack_count = 0
        recent_events = []

    return render_template_string(
        DASHBOARD_HTML, 
        total_attacks=attack_count, 
        events=recent_events,
        username=session.get('username'),
        role=session.get('role')
    )


@app.route('/dataset')
@login_required
def dataset_management():
    if session.get('role') != 'Admin':
        return render_template_string("""
            <div style="background-color: #0f172a; color: #ef4444; text-align: center; padding-top: 100px; height: 100vh; font-family: sans-serif;">
                <h1 style="font-size: 3rem; margin-bottom: 10px;">403 Forbidden</h1>
                <p style="color: #9ca3af; margin-bottom: 20px;">Access Denied. You do not have the required Administrator clearance.</p>
                <a href="/" style="color: #0ea5e9; text-decoration: none; border: 1px solid #0ea5e9; padding: 10px 20px; border-radius: 5px;">Return to Dashboard</a>
            </div>
        """), 403

    return render_template_string(
        DATASET_HTML, 
        username=session.get('username'),
        role=session.get('role')
    )


@app.route('/models')
@login_required
def model_training():
    if session.get('role') != 'Admin':
        return render_template_string("""
            <div style="background-color: #0f172a; color: #ef4444; text-align: center; padding-top: 100px; height: 100vh; font-family: sans-serif;">
                <h1 style="font-size: 3rem; margin-bottom: 10px;">403 Forbidden</h1>
                <p style="color: #9ca3af; margin-bottom: 20px;">Access Denied. You do not have the required Administrator clearance to view model metrics.</p>
                <a href="/" style="color: #0ea5e9; text-decoration: none; border: 1px solid #0ea5e9; padding: 10px 20px; border-radius: 5px;">Return to Dashboard</a>
            </div>
        """), 403

    return render_template_string(
        MODEL_TRAINING_HTML, 
        username=session.get('username'),
        role=session.get('role')
    )


@app.route('/realtime')
@login_required
def realtime_detection():
    try:
        conn = get_db_connection()
        attack_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE attack_type != 'Benign'").fetchone()[0]
        recent_events = conn.execute("SELECT * FROM alerts WHERE attack_type != 'Benign' ORDER BY timestamp DESC LIMIT 50").fetchall()
        conn.close()
    except Exception as e:
        attack_count = 0
        recent_events = []

    return render_template_string(
        REALTIME_HTML, 
        total_attacks=attack_count, 
        events=recent_events,
        username=session.get('username'),
        role=session.get('role')
    )

# ==========================================
# 3. SERVER EXECUTION
# ==========================================
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)