import sqlite3
from datetime import datetime
import os

# Ensure we hit the exact same database Vercel and your app are looking at
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "ids_database.db")

def fire_missile():
    print("[*] Launching simulated inbound DDoS attack...")
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Injecting a critical DDoS alert (99% confidence)
    cursor.execute('''
        INSERT INTO alerts (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, attack_type, confidence_score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, '198.51.100.42', '10.0.0.5', 4444, 80, 'TCP', 'DDoS', 0.99))
    
    conn.commit()
    conn.close()
    
    print("[+] BOOM! Malicious packet injected into the database.")
    print("[!] Keep your eyes on your web dashboard. It will refresh in < 5 seconds!")

if __name__ == "__main__":
    fire_missile()