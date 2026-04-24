# 🛡️ Ensemble Machine Learning IDS

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-lightgrey.svg)
![Machine Learning](https://img.shields.io/badge/Machine%20Learning-Scikit--Learn-orange.svg)
![Tailwind](https://img.shields.io/badge/Tailwind_CSS-38B2AC?logo=tailwind-css&logoColor=white)

An advanced, lightweight Intrusion Detection System (IDS) dashboard powered by Ensemble Machine Learning. Designed to analyze network traffic patterns, classify threats in real-time, and provide an interactive Security Operations Center (SOC) interface for incident responders.

## 🎯 The Problem & Solution
Traditional rule-based IDS often struggle with zero-day attacks and generate high false-positive rates. Sentinel solves this by leveraging an **Ensemble Machine Learning** approach (combining AdaBoost, Random Forest, and XGBoost via Soft Voting). This allows the system to identify complex anomalous flow signatures across networks with high precision, currently achieving a **99.75% overall accuracy** on the CICIDS2017 dataset.

## ✨ Key Features
* Real-Time Threat Monitoring: Live simulated packet classification with visual confidence scoring and alert generation.
* Role-Based Access Control (RBAC): Secure authentication system separating 'Operator' live-monitoring views from 'Administrator' model-tuning and forensic views.
* Dual-Model Architecture: Pipeline evaluated against both CICIDS2017 and UNSW-NB15 datasets to prove cross-environment reliability.
* Forensic Logging & Export: Secure SQLite database storage of threat signatures with a one-click CSV export function for incident response documentation.
* Modern SOC Interface: A responsive, dark-mode dashboard built with Tailwind CSS and Chart.js for data visualization.

## 📸 System Previews

*(Note: Create an `assets` folder in your repository, upload your screenshots there, and replace the filenames below)*

### Dashboard Overview
> Displays live metrics, system status, and immediate threat alerts.
> 
> `<img src="assets/dashboard.png" alt="Dashboard View" width="800">`

### Comparative Analysis (Admin Only)
> Visualizes model performance metrics ($F_1$-score, Precision, Recall) across different ML algorithms.
> 
> `<img src="assets/metrics.png" alt="Model Metrics" width="800">`

### Active Network Monitor
> Real-time terminal interface logging incoming traffic and detecting anomalous flow signatures.
> 
> `<img src="assets/realtime.png" alt="Live Detection" width="800">`

## 🛠️ Technical Stack
* Backend: Python, Flask, SQLite3
* Machine Learning: Scikit-Learn, Pandas, NumPy, Joblib
* Frontend: HTML5, Tailwind CSS, Chart.js
* Environment: Local Development (VS Code)

## 🚀 Quick Start (Local Development)

1. Clone the repository:
   ```bash
   git clone https://github.com/YourUsername/Sentinel-IDS.git
   cd Sentinel-IDS
   ```

2. Set up a virtual environment (Recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Initialize the database and launch the Flask server:
   ```bash
   python app.py
   ```

5. Access the application:
   Open your web browser and navigate to `http://127.0.0.1:5000`

## 🔐 Default Credentials
To access the dashboard, use the following local testing credentials:
* **Administrator Access:** `admin` / `admin123`
* **Operator Access:** `operator` / `operator123`

*(Ensure you update these credentials in `database.py` before any public deployment)*

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
