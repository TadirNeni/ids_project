import joblib
import os
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier, VotingClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from sklearn.model_selection import train_test_split

# Import the data preprocessing pipeline we built earlier
from cicids2017 import DatasetManager

class ModelTrainer:
    def __init__(self):
        print("[*] Initializing Base Classifiers...")
        # Define the base learners (Section 4.5.3.4)
        self.rf = RandomForestClassifier(n_estimators=100, random_state=42)
        self.xgb = XGBClassifier(use_label_encoder=False, eval_metric='mlogloss', random_state=42)
        self.ada = AdaBoostClassifier(n_estimators=50, random_state=42)
        
        # Define the Ensemble using Soft Voting (Section 4.3.3)
        self.ensemble = VotingClassifier(
            estimators=[('rf', self.rf), ('xgb', self.xgb), ('ada', self.ada)],
            voting='soft'
        )

    def load_and_prep_data(self):
        """Pulls the preprocessed data from our cicids2017 script."""
        manager = DatasetManager()
        X, y = manager.preprocess()
        
        # Split into 80% training and 20% testing
        print("[*] Splitting dataset into training and testing sets...")
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        print(f"[+] Training set size: {self.X_train.shape[0]} records")
        print(f"[+] Testing set size: {self.X_test.shape[0]} records")

    def train_model(self):
        """Trains the ensemble model on the processed dataset."""
        print("\n[*] Training the Ensemble Model (Random Forest + XGBoost + AdaBoost)...")
        print("[!] This might take a minute depending on your CPU...")
        self.ensemble.fit(self.X_train, self.y_train)
        print("[+] Training Complete!")

    def evaluate_model(self):
        """Evaluates model performance metrics (Section 4.2 & 4.5.3.4)."""
        print("\n[*] Evaluating Model Performance on Test Set...")
        y_pred = self.ensemble.predict(self.X_test)
        
        # Calculate core metrics
        acc = accuracy_score(self.y_test, y_pred)
        # Using 'weighted' to account for multiclass (Benign vs multiple attack types)
        prec = precision_score(self.y_test, y_pred, average='weighted', zero_division=0)
        rec = recall_score(self.y_test, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(self.y_test, y_pred, average='weighted', zero_division=0)
        
        print("-" * 40)
        print(f"Overall Accuracy : {acc * 100:.2f}%")
        print(f"Precision        : {prec:.2f}")
        print(f"Recall           : {rec:.2f}")
        print(f"F1-Score         : {f1:.2f}")
        print("-" * 40)
        
        print("\nDetailed Classification Report:")
        print(classification_report(self.y_test, y_pred, zero_division=0))

    def save_model(self):
        """Persists the trained model to disk (Section 4.2)."""
        os.makedirs('models', exist_ok=True)
        model_path = 'models/ensemble_model.joblib'
        joblib.dump(self.ensemble, model_path)
        print(f"\n[+] Model successfully saved to: {model_path}")


if __name__ == "__main__":
    print("=== Model Training Subsystem Initiated ===")
    trainer = ModelTrainer()
    trainer.load_and_prep_data()
    trainer.train_model()
    trainer.evaluate_model()
    trainer.save_model()
    print("=== System Ready for Real-Time Detection ===")