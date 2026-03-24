import pandas as pd
import numpy as np
import os
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder

class DatasetManager:
    def __init__(self, file_path='CICIDS2017_sample.csv'):
        self.file_path = file_path
        # The Top 10 features exactly as specified in Chapter 4.3.7
        self.selected_features = [
            'Destination Port', 
            'Flow Duration', 
            'Total Fwd Packets', 
            'Fwd Packet Length Max', 
            'Flow Bytes/s', 
            'Protocol', 
            'SYN Flag Count', 
            'ACK Flag Count', 
            'Fwd Header Length'
        ]
        self.target_column = 'Label'
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()

    def load_data(self):
        """Loads the dataset from the CSV file."""
        print(f"[*] Loading dataset from {self.file_path}...")
        try:
            self.df = pd.read_csv(self.file_path)
            print(f"[+] Dataset loaded successfully. Shape: {self.df.shape}")
        except FileNotFoundError:
            print(f"[-] Error: Dataset file '{self.file_path}' not found.")
            # Generate a mock dataset for testing if the real one is missing
            self._generate_mock_data()

    def clean_data(self):
        """Cleans missing values and infinite values (Section 4.2)."""
        print("[*] Cleaning missing and infinite values...")
        # Replace infinite values with NaN
        self.df.replace([np.inf, -np.inf], np.nan, inplace=True)
        # Drop rows with NaN values
        initial_rows = len(self.df)
        self.df.dropna(inplace=True)
        dropped_rows = initial_rows - len(self.df)
        print(f"[+] Cleaning complete. Dropped {dropped_rows} invalid rows.")

    def select_features(self):
        """Filters the dataset to keep only the Top 10 discriminatory features."""
        print("[*] Performing feature selection (Top 10 features)...")
        # Ensure the columns exist before selecting
        available_columns = [col for col in self.selected_features if col in self.df.columns]
        available_columns.append(self.target_column)
        
        self.df = self.df[available_columns]
        print(f"[+] Feature selection complete. Current shape: {self.df.shape}")

    def encode_and_scale(self):
        """Encodes categorical labels and normalises numerical attributes."""
        print("[*] Encoding labels and normalising features (Standardisation)...")
        
        # 1. Encode the target label (e.g., 'Benign' -> 0, 'DDoS' -> 1)
        self.df[self.target_column] = self.label_encoder.fit_transform(self.df[self.target_column])
        
        # 2. Separate features (X) and target (y)
        X = self.df.drop(columns=[self.target_column])
        y = self.df[self.target_column]

        # 3. Normalise numerical features using Z-score formulation
        X_scaled = self.scaler.fit_transform(X)
        
        # Convert back to DataFrame for easier handling
        self.X_processed = pd.DataFrame(X_scaled, columns=X.columns)
        self.y_processed = y
        
        # Save the scaler and encoder so the Real-Time Sniffer can use them later
        os.makedirs('models', exist_ok=True)
        joblib.dump(self.scaler, 'models/scaler.joblib')
        joblib.dump(self.label_encoder, 'models/label_encoder.joblib')
        
        print("[+] Encoding and scaling complete. Artifacts saved to 'models/' directory.")

    def preprocess(self):
        """Orchestrates the entire data preparation pipeline."""
        print("\n--- Starting Dataset Preprocessing Pipeline ---")
        self.load_data()
        self.clean_data()
        self.select_features()
        self.encode_and_scale()
        print("--- Preprocessing Pipeline Finished Successfully ---\n")
        
        return self.X_processed, self.y_processed

    def _generate_mock_data(self):
        """Helper function: Generates fake data so you can test the script immediately."""
        print("[*] Generating a mock CICIDS2017 dataset for testing purposes...")
        np.random.seed(42)
        mock_data = {
            'Destination Port': np.random.choice([80, 443, 22, 21, 53], 1000),
            'Flow Duration': np.random.randint(100, 100000, 1000),
            'Total Fwd Packets': np.random.randint(1, 50, 1000),
            'Fwd Packet Length Max': np.random.uniform(50.0, 1500.0, 1000),
            'Flow Bytes/s': np.random.uniform(100.0, 5000.0, 1000),
            'Protocol': np.random.choice([6, 17], 1000),
            'SYN Flag Count': np.random.randint(0, 5, 1000),
            'ACK Flag Count': np.random.randint(0, 10, 1000),
            'Fwd Header Length': np.random.randint(20, 100, 1000),
            'Label': np.random.choice(['Benign', 'DDoS', 'PortScan', 'Botnet'], 1000, p=[0.7, 0.1, 0.1, 0.1])
        }
        self.df = pd.DataFrame(mock_data)
        self.df.to_csv(self.file_path, index=False)
        print(f"[+] Mock dataset '{self.file_path}' created successfully.\n")


# === Testing the Subsystem ===
if __name__ == "__main__":
    # Initialize the manager
    manager = DatasetManager()
    
    # Run the pipeline
    X_train, y_train = manager.preprocess()
    
    # Display the final output to verify it worked
    print("Preview of preprocessed features (X):")
    print(X_train.head())
    print("\nPreview of encoded labels (y):")
    print(y_train.head())