# AI Intrusion Detection System with Granular Neural Network (GrNN)

An advanced AI-powered Network Intrusion Detection System (NIDS) integrating traditional machine learning with a **Granular Neural Network (GrNN)** architecture to pinpoint slow-and-low, multi-stage, and complex network attacks across multiple granular scales (Micro, Meso, Macro).

---

## 🌟 Key Features

1. **Granular Neural Network (GrNN) Analysis**:
   - **Micro-Granule**: Focuses on fine-grained packet-level attributes (lengths, TCP flags, header lengths).
   - **Meso-Granule**: Inspects flow-level attributes (flow duration, bytes/packets per second, bulk rates).
   - **Macro-Granule**: Evaluates long-term temporal patterns (inter-arrival times, idle times, active windows).
   - **Adaptive Attention Fusion ($\alpha$-weights)**: Learns which granular scale dominates for each specific attack.

2. **Ablation Study**:
   - Interactive breakdown evaluating detection capability when individual granules (Micro, Meso, or Macro) are disabled.

3. **Per-Attack Granule Fingerprints**:
   - Radar charts visualizing average granular contribution profiles across various attack categories (DDoS, Botnet, Port Scan, Brute Force, Web Attacks).

4. **Interactive Web Dashboard**:
   - Built with Django and Chart.js featuring dark/pink UI aesthetics.
   - Flow-by-flow comparison between flat-ML (Traditional) and multi-granule (GrNN) detections.
   - Real-time simulation and CSV dataset batch upload/analysis.

---

## 🛠️ Tech Stack

- **Backend**: Python 3, Django, Flask (Real-time microservice)
- **Machine Learning & Deep Learning**: PyTorch, Scikit-learn, XGBoost, Pandas, NumPy, Joblib
- **Frontend**: HTML5, CSS3, JavaScript, Chart.js

---

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/vivekshitole24-byte/AI-Intrusion-Detection-System-GrNN.git
cd AI-Intrusion-Detection-System-GrNN
```

### 2. Set up virtual environment & dependencies
```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Run the Django Server
```bash
cd ids_web
python manage.py migrate
python manage.py runserver 8000
```
Open [http://127.0.0.1:8000/](http://127.0.0.1:8000/) in your browser.

### 4. (Optional) Run the Real-Time Flask Service
```bash
cd ids_web/machine_learning
python flask_app.py
```
Runs at [http://127.0.0.1:5000/](http://127.0.0.1:5000/) to stream live simulated attack telemetry into the dashboard.

---

## 📊 Dataset Reference
Designed and evaluated with the **CICIDS2017** benchmark dataset.
