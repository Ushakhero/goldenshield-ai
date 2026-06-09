"""
GoldenShield AI - Advanced Nigerian Fintech Fraud Detection Platform
Nigeria-specific fraud patterns, CBN compliance, WhatsApp alerts,
Explainable AI, BVN fraud detection, and Flutterwave/Paystack integration.
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading, time, random, json
from datetime import datetime
from modules.gs_scanner import GoldenShieldScanner
from modules.gs_threats import NigerianThreatDB
from modules.gs_explainer import FraudExplainer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'goldenshield-ng-2026'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

scanner = GoldenShieldScanner()
threat_db = NigerianThreatDB()
explainer = FraudExplainer()

@app.route('/')
def index():
    return render_template('goldenshield.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    result = scanner.analyze_transaction(data)
    explanation = explainer.explain(result, data)
    result['explanation'] = explanation
    return jsonify(result)

@app.route('/api/batch', methods=['POST'])
def batch():
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'No file uploaded'}), 400
    import pandas as pd, io
    df = pd.read_csv(io.BytesIO(file.read()))
    results = scanner.batch_analyze(df)
    return jsonify(results)

@app.route('/api/nigeria-threats', methods=['GET'])
def nigeria_threats():
    return jsonify(threat_db.get_active_threats())

@app.route('/api/cbn-report', methods=['GET'])
def cbn_report():
    return jsonify(scanner.generate_cbn_report())

@app.route('/api/network-graph', methods=['GET'])
def network_graph():
    return jsonify(scanner.get_fraud_network())

@app.route('/api/dashboard', methods=['GET'])
def dashboard():
    return jsonify({
        'score': scanner.get_risk_score(),
        'nigeria_threats': threat_db.get_active_threats(),
        'stats': scanner.get_stats(),
        'recent': scanner.get_recent_transactions(),
        'cbn_status': scanner.get_cbn_compliance()
    })

@socketio.on('connect')
def on_connect():
    emit('connected', {'status': 'GoldenShield AI active — Monitoring Nigerian transactions'})

@socketio.on('start_monitoring')
def start_monitoring():
    def push_alerts():
        while True:
            alert = threat_db.simulate_nigerian_threat()
            if alert:
                socketio.emit('fraud_alert', alert)
            time.sleep(random.uniform(10, 25))
    t = threading.Thread(target=push_alerts, daemon=True)
    t.start()
    emit('monitoring_started', {'message': 'Real-time Nigerian fraud monitoring active'})

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5002, allow_unsafe_werkzeug=True)
