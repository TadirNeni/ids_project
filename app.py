from flask import Flask, render_template_string, jsonify, request, session, redirect, url_for
import sqlite3
import os
from functools import wraps
from werkzeug.security import check_password_hash
from database import get_db_connection

app = Flask(__name__)
# CRITICAL: A secret key is required to encrypt session cookies
app.secret_key = 'super_secret_ids_key_2026'

# --- EMBEDDED LOGIN TEMPLATE ---
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
        <div class="mt-4 text-xs text-gray-500 text-center">
            Authorized Personnel Only
        </div>
    </div>
</body>
</html>
"""

# --- EMBEDDED DASHBOARD TEMPLATE ---
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
            <a href="#" class="block px-4 py-2 rounded hover:bg-gray-700 transition">Dataset Management</a>
            <a href="#" class="block px-4 py-2 rounded hover:bg-gray-700 transition">Model Training</a>
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

# --- SECURITY DECORATORS ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- ROUTES ---
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)