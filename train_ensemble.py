import joblib
import os
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier, VotingClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from sklearn.model_selection import train_test_split

# Import BOTH data preprocessing pipelines
from cicids2017 import DatasetManager as CICIDSManager
from unsw_nb15 import UNSWManager

class UniversalTrainer:
    def __init__(self):
        print("\n[*] Initializing Base Classifiers (Section 4.5.3.4)...")
        # Define the base learners exactly as specified in your methodology
        self.rf = RandomForestClassifier(n_estimators=100, random_state=42)
        self.xgb = XGBClassifier(use_label_encoder=False, eval_metric='mlogloss', random_state=42)
        self.ada = AdaBoostClassifier(n_estimators=50, random_state=42)

    def get_fresh_ensemble(self):
        """Creates a fresh Ensemble using Soft Voting (Section 4.3.3)"""
        return VotingClassifier(
            estimators=[('rf', self.rf), ('xgb', self.xgb), ('ada', self.ada)],
            voting='soft'
        )

    def train_and_evaluate(self, X, y, dataset_name, model_filename):
        """Handles the complete training and evaluation lifecycle for a specific dataset."""
        print(f"\n{'='*50}")
        print(f"--- Processing Target: {dataset_name} ---")
        print(f"{'='*50}")
        
        # 1. Split into 80% training and 20% testing
        print(f"[*] Splitting {dataset_name} dataset into training and testing sets...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        print(f"[+] Training set size: {X_train.shape[0]} records")
        print(f"[+] Testing set size:  {X_test.shape[0]} records")

        # 2. Get a fresh, untrained model
        ensemble = self.get_fresh_ensemble()

        # 3. Train the model
        print(f"\n[*] Training the Ensemble Model on {dataset_name}...")
        print("[!] This might take a minute depending on your CPU...")
        ensemble.fit(X_train, y_train)
        print("[+] Training Complete!")

        # 4. Evaluate the model
        print(f"\n[*] Evaluating Model Performance on Test Set ({dataset_name})...")
        y_pred = ensemble.predict(X_test)
        
        # Calculate core metrics
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        rec = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        
        print("-" * 40)
        print(f"Overall Accuracy : {acc * 100:.2f}%")
        print(f"Precision        : {prec:.2f}")
        print(f"Recall           : {rec:.2f}")
        print(f"F1-Score         : {f1:.2f}")
        print("-" * 40)
        
        print("\nDetailed Classification Report:")
        print(classification_report(y_test, y_pred, zero_division=0))

        # 5. Persist the trained model to disk
        os.makedirs('models', exist_ok=True)
        model_path = f'models/{model_filename}.joblib'
        joblib.dump(ensemble, model_path)
        print(f"\n[+] {dataset_name} Model successfully saved to: {model_path}")


if __name__ == "__main__":
    print("=== Multi-Dataset Model Training Subsystem Initiated ===")
    
    trainer = UniversalTrainer()
    
    # ---------------------------------------------------------
    # DATASET 1: CICIDS2017
    # ---------------------------------------------------------
    cic_manager = CICIDSManager()
    X_cic, y_cic = cic_manager.preprocess()
    trainer.train_and_evaluate(X_cic, y_cic, dataset_name="CICIDS2017", model_filename="ensemble_model")
    
    # ---------------------------------------------------------
    # DATASET 2: UNSW-NB15
    # ---------------------------------------------------------
    unsw_manager = UNSWManager()
    X_unsw, y_unsw = unsw_manager.preprocess()
    trainer.train_and_evaluate(X_unsw, y_unsw, dataset_name="UNSW-NB15", model_filename="unsw_ensemble_model")
    
    print("\n=== System Ready: All Brains Trained Successfully ===")