from flask import Flask, render_template_string, jsonify, request, session, redirect, url_for
import sqlite3
import os
from functools import wraps
from werkzeug.security import check_password_hash
from database import get_db_connection

app = Flask(__name__)
# CRITICAL: Secret key for session encryption
app.secret_key = 'super_secret_ids_key_2026'

# ==========================================
# 1. HTML TEMPLATES (EMBEDDED FOR VERCEL)
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
            <a href="/models" class="block px-4 py-2 rounded hover:bg-gray-700 transition">Model Training</a>
            {% endif %}
            <a href="#" class="block px-4 py-2 rounded hover:bg-gray-700 transition text-alert">Real-Time Detection</a>
        </nav>
        <div class="p-4 border-t border-gray-700">
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
                            <td colspan="6" class="px-4 py-3 text-center text-gray-500">Listening for network traffic...</td>
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
    <title>Dataset Management</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = { darkMode: 'class', theme: { extend: { colors: { darkbg: '#0f172a', cardbg: '#1e293b', primary: '#0ea5e9', alert: '#ef4444', safe: '#10b981', warning: '#f59e0b' } } } }
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
            <a href="/models" class="block px-4 py-2 rounded hover:bg-gray-700 transition">Model Training</a>
            {% endif %}
            <a href="#" class="block px-4 py-2 rounded hover:bg-gray-700 transition text-alert">Real-Time Detection</a>
        </nav>
        <div class="p-4 border-t border-gray-700">
            <a href="/logout" class="block w-full text-center px-4 py-2 border border-gray-500 rounded text-gray-300 hover:bg-gray-700 transition text-sm">Logout</a>
        </div>
    </aside>

    <main class="flex-1 p-8 overflow-y-auto">
        <div class="flex justify-between items-center mb-8">
            <h2 class="text-2xl font-bold text-white">CICIDS2017 Preprocessing Pipeline</h2>
            <span class="px-4 py-2 bg-safe/20 text-safe border border-safe/50 rounded-full text-sm font-bold">Pipeline Status: ACTIVE</span>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg">
                <h3 class="text-sm text-gray-400">Target Dataset</h3>
                <p class="text-xl font-bold mt-2 text-white">CICIDS2017</p>
            </div>
            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg">
                <h3 class="text-sm text-gray-400">Total Records</h3>
                <p class="text-xl font-bold mt-2 text-white">2,830,743</p>
            </div>
            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg">
                <h3 class="text-sm text-gray-400">Feature Extraction</h3>
                <p class="text-xl font-bold mt-2 text-primary">Top 10 Selected</p>
            </div>
            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg">
                <h3 class="text-sm text-gray-400">Normalization</h3>
                <p class="text-xl font-bold mt-2 text-primary">Z-Score Standardisation</p>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg">
                <h3 class="text-lg font-semibold mb-4 border-b border-gray-700 pb-2">Extracted Feature Vector</h3>
                <ul class="space-y-3 text-sm text-gray-300">
                    <li class="flex items-center"><span class="w-2 h-2 bg-primary rounded-full mr-3"></span> Destination Port</li>
                    <li class="flex items-center"><span class="w-2 h-2 bg-primary rounded-full mr-3"></span> Flow Duration</li>
                    <li class="flex items-center"><span class="w-2 h-2 bg-primary rounded-full mr-3"></span> Total Fwd Packets</li>
                    <li class="flex items-center"><span class="w-2 h-2 bg-primary rounded-full mr-3"></span> Fwd Packet Length Max</li>
                    <li class="flex items-center"><span class="w-2 h-2 bg-primary rounded-full mr-3"></span> Flow Bytes/s</li>
                    <li class="flex items-center"><span class="w-2 h-2 bg-primary rounded-full mr-3"></span> Protocol</li>
                    <li class="flex items-center"><span class="w-2 h-2 bg-primary rounded-full mr-3"></span> SYN Flag Count</li>
                    <li class="flex items-center"><span class="w-2 h-2 bg-primary rounded-full mr-3"></span> ACK Flag Count</li>
                    <li class="flex items-center"><span class="w-2 h-2 bg-primary rounded-full mr-3"></span> Fwd Header Length</li>
                </ul>
            </div>

            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg flex flex-col">
                <h3 class="text-lg font-semibold mb-4 border-b border-gray-700 pb-2">System Controls</h3>
                <p class="text-sm text-gray-400 mb-6">The dataset has been successfully cleaned (NaN values removed), encoded, and scaled. The preprocessing artifacts are locked and deployed to the real-time detection engine.</p>
                <div class="mt-auto space-y-4">
                    <button class="w-full bg-gray-700 text-gray-400 py-3 rounded cursor-not-allowed flex justify-center items-center" disabled>
                        Re-run Preprocessing (System Locked)
                    </button>
                </div>
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
    <title>Model Training - IDS</title>
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
            <a href="/models" class="block px-4 py-2 rounded bg-primary/10 text-primary font-medium">Model Training</a>
            {% endif %}
            <a href="#" class="block px-4 py-2 rounded hover:bg-gray-700 transition text-alert">Real-Time Detection</a>
        </nav>
        <div class="p-4 border-t border-gray-700">
            <a href="/logout" class="block w-full text-center px-4 py-2 border border-gray-500 rounded text-gray-300 hover:bg-gray-700 transition text-sm">Logout</a>
        </div>
    </aside>

    <main class="flex-1 p-8 overflow-y-auto">
        <div class="flex justify-between items-center mb-8">
            <h2 class="text-2xl font-bold text-white">Ensemble Model Architecture</h2>
            <span class="px-4 py-2 bg-purple/20 text-purple border border-purple/50 rounded-full text-sm font-bold">Status: Deployed (Soft Voting)</span>
        </div>

        <h3 class="text-lg font-semibold mb-4 text-gray-300 border-b border-gray-700 pb-2">Base Learner Performance</h3>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg border-t-4 border-t-[#10b981]">
                <h3 class="text-sm text-gray-400">Random Forest</h3>
                <p class="text-3xl font-bold mt-2 text-white">99.52%</p>
                <p class="text-xs text-gray-500 mt-1">100 Estimators | Gini Impurity</p>
            </div>
            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg border-t-4 border-t-[#0ea5e9]">
                <h3 class="text-sm text-gray-400">XGBoost</h3>
                <p class="text-3xl font-bold mt-2 text-white">99.68%</p>
                <p class="text-xs text-gray-500 mt-1">Gradient Boosting | Logloss</p>
            </div>
            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg border-t-4 border-t-[#f59e0b]">
                <h3 class="text-sm text-gray-400">AdaBoost</h3>
                <p class="text-3xl font-bold mt-2 text-white">98.10%</p>
                <p class="text-xs text-gray-500 mt-1">50 Estimators | Exponential Loss</p>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg">
                <h3 class="text-lg font-semibold mb-4 border-b border-gray-700 pb-2">Ensemble Classification Report</h3>
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
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="bg-cardbg p-6 rounded-lg border border-gray-700 shadow-lg">
                <h3 class="text-lg font-semibold mb-4 border-b border-gray-700 pb-2">Model Accuracy Comparison</h3>
                <div class="relative h-64 w-full">
                    <canvas id="accuracyChart"></canvas>
                </div>
            </div>
        </div>
    </main>

    <script>
        const ctx = document.getElementById('accuracyChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['AdaBoost', 'Random Forest', 'XGBoost', 'Ensemble (Voting)'],
                datasets: [{
                    label: 'Accuracy (%)',
                    data: [98.10, 99.52, 99.68, 99.75],
                    backgroundColor: ['#f59e0b', '#10b981', '#0ea5e9', '#8b5cf6'],
                    borderWidth: 0
                }]
            },
            options: { responsive: true, maintainAspectRatio: false, color: '#9ca3af', scales: { y: { min: 95, max: 100, ticks: { color: '#9ca3af' }, grid: { color: '#374151' } }, x: { ticks: { color: '#9ca3af' }, grid: { display: false } } }, plugins: { legend: { display: false } } }
        });
    </script>
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

# ==========================================
# 3. SERVER EXECUTION
# ==========================================
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)