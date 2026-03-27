import pandas as pd
import numpy as np
import os
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder

class UNSWManager:
    def __init__(self, file_path='UNSW_NB15_sample.csv'):
        self.file_path = file_path
        # Top 10 Features specific to the UNSW-NB15 dataset architecture
        self.selected_features = [
            'dur',          # Record total duration
            'spkts',        # Source to destination packet count
            'dpkts',        # Destination to source packet count
            'sbytes',       # Source to destination transaction bytes
            'dbytes',       # Destination to source transaction bytes
            'rate',         # Packets per second
            'sttl',         # Source to destination time to live value
            'dttl',         # Destination to source time to live value
            'sload',        # Source bits per second
            'dload'         # Destination bits per second
        ]
        self.target_column = 'attack_cat' # UNSW uses 'attack_cat' instead of 'Label'
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()

    def load_data(self):
        print(f"[*] Loading UNSW-NB15 dataset from {self.file_path}...")
        try:
            self.df = pd.read_csv(self.file_path)
        except FileNotFoundError:
            print(f"[-] Dataset not found. Generating mock UNSW-NB15 data...")
            self._generate_mock_data()

    def clean_data(self):
        self.df.replace([np.inf, -np.inf], np.nan, inplace=True)
        self.df.dropna(inplace=True)

    def select_features(self):
        available_columns = [col for col in self.selected_features if col in self.df.columns]
        available_columns.append(self.target_column)
        self.df = self.df[available_columns]

    def encode_and_scale(self):
        # Encode the attack categories (Normal, Fuzzers, Analysis, Backdoors, DoS, Exploits...)
        self.df[self.target_column] = self.label_encoder.fit_transform(self.df[self.target_column].astype(str))
        
        X = self.df.drop(columns=[self.target_column])
        y = self.df[self.target_column]

        X_scaled = self.scaler.fit_transform(X)
        self.X_processed = pd.DataFrame(X_scaled, columns=X.columns)
        self.y_processed = y
        
        # Notice we are saving these with a specific 'unsw_' prefix so they don't overwrite CICIDS
        os.makedirs('models', exist_ok=True)
        joblib.dump(self.scaler, 'models/unsw_scaler.joblib')
        joblib.dump(self.label_encoder, 'models/unsw_encoder.joblib')

    def preprocess(self):
        print("\n--- Starting UNSW-NB15 Preprocessing ---")
        self.load_data()
        self.clean_data()
        self.select_features()
        self.encode_and_scale()
        print("--- UNSW-NB15 Pipeline Finished ---\n")
        return self.X_processed, self.y_processed

    def _generate_mock_data(self):
        np.random.seed(99)
        mock_data = {
            'dur': np.random.uniform(0.001, 10.0, 1000),
            'spkts': np.random.randint(1, 50, 1000),
            'dpkts': np.random.randint(0, 50, 1000),
            'sbytes': np.random.randint(100, 5000, 1000),
            'dbytes': np.random.randint(0, 5000, 1000),
            'rate': np.random.uniform(10.0, 100000.0, 1000),
            'sttl': np.random.choice([31, 62, 254], 1000),
            'dttl': np.random.choice([29, 60, 252], 1000),
            'sload': np.random.uniform(1000.0, 1000000.0, 1000),
            'dload': np.random.uniform(0.0, 1000000.0, 1000),
            'attack_cat': np.random.choice(['Normal', 'Exploits', 'DoS', 'Generic'], 1000, p=[0.7, 0.1, 0.1, 0.1])
        }
        self.df = pd.DataFrame(mock_data)
        self.df.to_csv(self.file_path, index=False)