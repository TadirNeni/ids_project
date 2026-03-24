import os
import time
import sqlite3
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP

# Absolute paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "ids_database.db")
MODEL_PATH = os.path.join(BASE_DIR, "models", "ensemble_model.joblib")
SCALER_PATH = os.path.join(BASE_DIR, "models", "scaler.joblib")
ENCODER_PATH = os.path.join(BASE_DIR, "models", "label_encoder.joblib")

class RealTimeIDS:
    def __init__(self):
        print("[*] Initializing Real-Time Detection Subsystem...")
        
        # 1. Load the trained artifacts
        try:
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.label_encoder = joblib.load(ENCODER_PATH)
            print("[+] Ensemble Model and Preprocessing Artifacts loaded.")
        except FileNotFoundError:
            print("[-] Error: Model files not found. Run train_ensemble.py first.")
            exit()

        # 2. Setup Flow Tracking (Approximation for real-time feature extraction)
        self.flow_tracker = {}
        
        # The exact Top 10 features your model expects
        self.feature_columns = [
            'Destination Port', 'Flow Duration', 'Total Fwd Packets', 
            'Fwd Packet Length Max', 'Flow Bytes/s', 'Protocol', 
            'SYN Flag Count', 'ACK Flag Count', 'Fwd Header Length'
        ]

    def extract_features(self, packet):
        """Translates a raw Scapy packet into the Top 10 feature vector."""
        if not IP in packet:
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_length = len(packet)
        current_time = time.time()

        # Default transport layer values
        src_port, dst_port = 0, 0
        syn_flag, ack_flag = 0, 0
        header_length = 20 # Standard IP header

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            syn_flag = 1 if 'S' in flags else 0
            ack_flag = 1 if 'A' in flags else 0
            header_length += packet[TCP].dataofs * 4
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            header_length += 8

        # --- Flow Tracking Logic ---
        flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        
        if flow_key not in self.flow_tracker:
            self.flow_tracker[flow_key] = {
                'start_time': current_time,
                'fwd_packets': 1,
                'max_packet_len': packet_length,
                'total_bytes': packet_length
            }
        else:
            flow = self.flow_tracker[flow_key]
            flow['fwd_packets'] += 1
            flow['max_packet_len'] = max(flow['max_packet_len'], packet_length)
            flow['total_bytes'] += packet_length

        # Calculate dynamic flow features
        flow_duration_sec = current_time - self.flow_tracker[flow_key]['start_time']
        flow_duration_micro = max(flow_duration_sec * 1_000_000, 1) # Prevent division by zero
        flow_bytes_per_sec = (self.flow_tracker[flow_key]['total_bytes'] / flow_duration_micro) * 1_000_000

        # Construct the raw feature array
        raw_features = np.array([[
            dst_port,
            flow_duration_micro,
            self.flow_tracker[flow_key]['fwd_packets'],
            self.flow_tracker[flow_key]['max_packet_len'],
            flow_bytes_per_sec,
            protocol,
            syn_flag,
            ack_flag,
            header_length
        ]])

        return raw_features, src_ip, dst_ip, src_port, dst_port, protocol

    def process_packet(self, packet):
        """Callback function executed for every packet sniffed."""
        extracted_data = self.extract_features(packet)
        if not extracted_data:
            return

        raw_features, src_ip, dst_ip, src_port, dst_port, protocol = extracted_data

        # 3. Preprocess the features (Scale)
        raw_df = pd.DataFrame(raw_features, columns=self.feature_columns)
        scaled_array = self.scaler.transform(raw_df)
        
        # --- THE FIX: Convert back to DataFrame so the model sees the feature names ---
        scaled_df = pd.DataFrame(scaled_array, columns=self.feature_columns)

        # 4. Predict using Ensemble (using scaled_df now)
        prediction_encoded = self.model.predict(scaled_df)[0]
        prediction_label = self.label_encoder.inverse_transform([prediction_encoded])[0]
        
        # Get confidence score (max probability across soft voting)
        probabilities = self.model.predict_proba(scaled_df)[0]
        confidence = round(max(probabilities), 2)

        # 5. Alert Generation Logic
        if prediction_label != 'Benign' and confidence > 0.70:
            self.log_alert(src_ip, dst_ip, src_port, dst_port, protocol, prediction_label, confidence)
            print(f"[!] THREAT DETECTED: {prediction_label} from {src_ip} (Confidence: {confidence})")

    def log_alert(self, src_ip, dst_ip, src_port, dst_port, protocol, attack_type, confidence):
        """Writes the attack to the SQLite database."""
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute('''
            INSERT INTO alerts (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, attack_type, confidence_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, src_ip, dst_ip, src_port, dst_port, str(protocol), attack_type, confidence))
        
        conn.commit()
        conn.close()

    def start_sniffing(self, packet_count=0):
        """Starts the Scapy sniffer."""
        print("[*] Starting network interface sniffing... (Press Ctrl+C to stop)")
        # Sniff on all interfaces. packet_count=0 means sniff infinitely.
        sniff(prn=self.process_packet, store=False, count=packet_count)


if __name__ == "__main__":
    ids = RealTimeIDS()
    # To test locally, you can set packet_count to 100 to just grab 100 packets and stop.
    ids.start_sniffing(packet_count=0)