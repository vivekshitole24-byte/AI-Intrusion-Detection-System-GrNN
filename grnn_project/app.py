"""
GrNN Network Threat Analyzer — Flask Application
=================================================
Routes:
  /             → Landing/home page
  /dashboard    → Live threat feed with granule charts
  /analyze      → Upload CSV for batch analysis
  /api/analyze  → JSON API for CSV batch inference
  /api/simulate → JSON API for simulated live traffic
"""

import os, sys, json, time, random, threading
import numpy as np
import pandas as pd
import torch
from flask import Flask, render_template, jsonify, request, redirect, url_for
from collections import deque
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from model.granular_nn import GrNN
from model.granule_extractor import GranuleExtractor, LABEL_MAP

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64 MB upload limit
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
MODEL_PATH   = os.path.join(os.path.dirname(__file__), 'model', 'grnn_model.pt')
SCALERS_PATH = os.path.join(os.path.dirname(__file__), 'model', 'grnn_scalers.pkl')

# ── Load Model ─────────────────────────────────────────────────────────────────
grnn_model = None
extractor  = None
class_names = ['Benign', 'DDoS', 'DoS', 'Port Scan', 'Brute Force', 'Web Attack', 'Botnet', 'Infiltration']

def load_model():
    global grnn_model, extractor, class_names
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALERS_PATH):
        ckpt = torch.load(MODEL_PATH, map_location=DEVICE)
        n    = ckpt.get('num_classes', 6)
        grnn_model = GrNN(num_classes=n).to(DEVICE)
        grnn_model.load_state_dict(ckpt['model_state'])
        grnn_model.eval()
        class_names = ckpt.get('class_names', class_names)
        extractor   = GranuleExtractor.load(SCALERS_PATH)
        print(f"[App] GrNN model loaded. Classes: {class_names}")
    else:
        print("[App] WARNING: Model not found. Running in demo/simulation mode.")

load_model()

# ── Live Event Buffer ─────────────────────────────────────────────────────────
MAX_EVENTS = 200
live_events = deque(maxlen=MAX_EVENTS)
attack_totals = {c: 0 for c in class_names}
granule_fire_counts = {'Micro': 0, 'Meso': 0, 'Macro': 0}

# ── Inference Helper ──────────────────────────────────────────────────────────
GRANULE_THRESHOLDS = {
    'Micro': 0.40,   # alpha_micro dominant
    'Meso':  0.35,   # alpha_meso dominant
    'Macro': 0.25,   # alpha_macro dominant
}

def granule_label(alphas):
    """Return which granule dominated the detection."""
    a = alphas.cpu().numpy()[0]
    idx = np.argmax(a)
    names = ['Micro', 'Meso', 'Macro']
    return names[idx], round(float(a[0])*100, 1), round(float(a[1])*100, 1), round(float(a[2])*100, 1)

def run_inference(df: pd.DataFrame):
    """Run GrNN on a DataFrame, return list of result dicts."""
    if grnn_model is None or extractor is None:
        return simulate_results(len(df))

    X_mi, X_ms, X_mc = extractor.transform_df(df)
    t_mi = torch.tensor(X_mi).to(DEVICE)
    t_ms = torch.tensor(X_ms).to(DEVICE)
    t_mc = torch.tensor(X_mc).to(DEVICE)

    results = []
    with torch.no_grad():
        for i in range(len(df)):
            xm = t_mi[i:i+1]
            xs = t_ms[i:i+1]
            xc = t_mc[i:i+1]
            logits, alphas = grnn_model(xm, xs, xc)
            probs = torch.softmax(logits, dim=1)
            pred_idx = probs.argmax(1).item()
            confidence = round(float(probs[0, pred_idx]) * 100, 1)
            pred_label = class_names[pred_idx] if pred_idx < len(class_names) else 'Unknown'
            dominant_g, a_mi, a_ms, a_mc = granule_label(alphas)
            results.append({
                'label':      pred_label,
                'confidence': confidence,
                'dominant_granule': dominant_g,
                'alpha_micro': a_mi,
                'alpha_meso':  a_ms,
                'alpha_macro': a_mc,
                'is_attack':   pred_label != 'Benign',
                'row': i,
            })
    return results


def simulate_results(n=1):
    """Generate realistic simulated results when model is not yet trained."""
    templates = [
        {'label': 'DDoS',       'alpha_micro': 75, 'alpha_meso': 18, 'alpha_macro': 7,  'dominant_granule': 'Micro'},
        {'label': 'Port Scan',  'alpha_micro': 22, 'alpha_meso': 64, 'alpha_macro': 14, 'dominant_granule': 'Meso'},
        {'label': 'Brute Force','alpha_micro': 18, 'alpha_meso': 68, 'alpha_macro': 14, 'dominant_granule': 'Meso'},
        {'label': 'Botnet',     'alpha_micro': 8,  'alpha_meso': 19, 'alpha_macro': 73, 'dominant_granule': 'Macro'},
        {'label': 'Benign',     'alpha_micro': 33, 'alpha_meso': 33, 'alpha_macro': 34, 'dominant_granule': 'Meso'},
        {'label': 'DoS',        'alpha_micro': 68, 'alpha_meso': 24, 'alpha_macro': 8,  'dominant_granule': 'Micro'},
        {'label': 'Web Attack', 'alpha_micro': 71, 'alpha_meso': 21, 'alpha_macro': 8,  'dominant_granule': 'Micro'},
    ]
    out = []
    for i in range(n):
        t = random.choice(templates)
        out.append({
            **t,
            'confidence': round(random.uniform(82, 99), 1),
            'is_attack':  t['label'] != 'Benign',
            'row': i,
        })
    return out


# ── Background Simulator Thread ───────────────────────────────────────────────
def _simulate_live():
    """Continuously push simulated traffic events to the live buffer."""
    while True:
        r = simulate_results(1)[0]
        r['timestamp'] = datetime.now().strftime('%H:%M:%S')
        live_events.append(r)
        attack_totals[r['label']] = attack_totals.get(r['label'], 0) + 1
        granule_fire_counts[r['dominant_granule']] = granule_fire_counts.get(r['dominant_granule'], 0) + 1
        time.sleep(random.uniform(0.4, 1.4))

sim_thread = threading.Thread(target=_simulate_live, daemon=True)
sim_thread.start()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    model_ready = grnn_model is not None
    return render_template('index.html', model_ready=model_ready)


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', class_names=json.dumps(class_names))


@app.route('/analyze')
def analyze():
    return render_template('analyze.html')


# ── API: live feed ──────────────────────────────────────────────────────────

@app.route('/api/live')
def api_live():
    """Returns the last N events for the live feed."""
    n = int(request.args.get('n', 20))
    events = list(live_events)[-n:]
    totals = dict(attack_totals)
    granules = dict(granule_fire_counts)
    total_events = sum(totals.values())
    attack_count  = total_events - totals.get('Benign', 0)
    return jsonify({
        'events':        events,
        'attack_totals': totals,
        'granule_counts': granules,
        'total_events':  total_events,
        'attack_count':  attack_count,
        'model_ready':   grnn_model is not None,
    })


# ── API: CSV batch analysis ──────────────────────────────────────────────────

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    f = request.files['file']
    if not f.filename.endswith('.csv'):
        return jsonify({'error': 'Only CSV files are supported'}), 400

    try:
        df = pd.read_csv(f)
        df.columns = [c.strip() for c in df.columns]
    except Exception as e:
        return jsonify({'error': f'Could not read CSV: {e}'}), 400

    # Limit to first 2000 rows for performance
    df = df.head(2000)
    results = run_inference(df)

    # Aggregate stats
    label_counts = {}
    granule_counts = {'Micro': 0, 'Meso': 0, 'Macro': 0}
    for r in results:
        label_counts[r['label']] = label_counts.get(r['label'], 0) + 1
        granule_counts[r['dominant_granule']] += 1

    total = len(results)
    attacks = total - label_counts.get('Benign', 0)

    return jsonify({
        'total':         total,
        'attack_count':  attacks,
        'label_counts':  label_counts,
        'granule_counts':granule_counts,
        'results':       results[:500],   # cap JSON size
        'model_ready':   grnn_model is not None,
    })


# ── API: granule explanation for a single row ────────────────────────────────

@app.route('/api/explain', methods=['POST'])
def api_explain():
    """Given a JSON row of features, run single-row inference + return granule attribution."""
    data = request.get_json(force=True)
    df = pd.DataFrame([data])
    result = run_inference(df)
    return jsonify(result[0] if result else {'error': 'Inference failed'})


if __name__ == '__main__':
    app.run(debug=True, port=8080, threaded=True)

