import sqlite3
import os

# Absolute pathing for Vercel
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "ids_database.db")

def init_db():
    """Initializes the SQLite database and creates Chapter 4 tables."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Alerts Table (Section 4.3.2)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            attack_type TEXT,
            confidence_score REAL,
            status TEXT DEFAULT 'NEW'
        )
    ''')

    # System Log Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            level TEXT,
            message TEXT
        )
    ''')

    # Inject one fake attack so the dashboard isn't empty on preview
    cursor.execute('''
        INSERT INTO alerts (timestamp, src_ip, dst_ip, protocol, attack_type, confidence_score)
        SELECT '2026-03-24 14:05:00', '192.168.1.50', '10.0.0.5', 'TCP', 'DDoS', 0.98
        WHERE NOT EXISTS (SELECT 1 FROM alerts WHERE attack_type='DDoS')
    ''')

    conn.commit()
    conn.close()
    print(f"[+] Database built successfully at: {DB_NAME}")

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row 
    return conn

if __name__ == "__main__":
    init_db()