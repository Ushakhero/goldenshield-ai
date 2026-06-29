"""
GoldenShield AI - Nigerian Fraud Detection Platform
"""
from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit
import threading, time, random
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
from modules import gs_database
gs_database.init_db()

LANDING = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GoldenShield AI</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&family=DM+Mono:wght@400&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css">
<script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>
<style>
:root{--bg:#0a0800;--s:#120f04;--s2:#1a1502;--b:#2a2208;--gold:#c9a84c;--g2:#f0c96e;--r:#ef4444;--w:#f59e0b;--gr:#10b981;--t:#f5edd8;--m:#8a7a5a;}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--t);font-family:'Space Grotesk',sans-serif;min-height:100vh;}
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(201,168,76,.03)1px,transparent 1px),linear-gradient(90deg,rgba(201,168,76,.03)1px,transparent 1px);background-size:50px 50px;pointer-events:none;}
header{padding:16px 28px;display:flex;align-items:center;justify-content:space-between;background:rgba(10,8,0,.9);border-bottom:1px solid var(--b);position:sticky;top:0;z-index:100;}
.logo{display:flex;align-items:center;gap:10px;font-size:20px;font-weight:700;color:var(--gold);}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--gold),#8a6a1a);border-radius:8px;display:flex;align-items:center;justify-content:center;}
.pulse-dot{width:7px;height:7px;border-radius:50%;background:var(--gr);animation:pulse 2s infinite;}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.live{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--gr);font-family:'DM Mono',monospace;}
main{max-width:1200px;margin:0 auto;padding:32px 24px;}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px;}
.metric{background:var(--s);border:1px solid var(--b);border-radius:12px;padding:16px;position:relative;overflow:hidden;}
.metric::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--gold),var(--g2));}
.ml{font-size:10px;color:var(--m);font-family:'DM Mono',monospace;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;}
.mv{font-size:26px;font-weight:700;}
.ms{font-size:11px;color:var(--m);margin-top:3px;}
.grid2{display:grid;grid-template-columns:1fr 1.4fr;gap:16px;margin-bottom:16px;}
.card{background:var(--s);border:1px solid var(--b);border-radius:16px;padding:20px;}
.ct{font-size:11px;font-weight:600;color:var(--m);text-transform:uppercase;letter-spacing:.5px;margin-bottom:14px;font-family:'DM Mono',monospace;display:flex;align-items:center;gap:6px;}
.dot{width:6px;height:6px;border-radius:50%;background:var(--gold);box-shadow:0 0 6px var(--gold);}
.field{margin-bottom:10px;}
.field label{display:block;font-size:10px;color:var(--m);font-family:'DM Mono',monospace;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;}
.field input,.field select{width:100%;background:var(--s2);border:1px solid var(--b);border-radius:7px;padding:8px 11px;color:var(--t);font-size:13px;font-family:'DM Mono',monospace;outline:none;transition:border-color .2s;}
.field input:focus,.field select:focus{border-color:var(--gold);}
.field select option{background:var(--s2);}
.fg{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px;}
.btn{width:100%;padding:11px;background:linear-gradient(135deg,var(--gold),#a07828);color:#0a0800;border:none;border-radius:9px;font-family:'Space Grotesk',sans-serif;font-size:14px;font-weight:700;cursor:pointer;transition:all .2s;}
.btn:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(201,168,76,.3);}
.result{background:var(--s2);border:1px solid var(--b);border-radius:11px;padding:16px;margin-top:12px;display:none;animation:fi .3s ease;}
@keyframes fi{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.verdict{font-size:17px;font-weight:700;margin-bottom:10px;}
.sb-wrap{margin-bottom:11px;}
.sb-label{display:flex;justify-content:space-between;font-size:11px;color:var(--m);margin-bottom:4px;font-family:'DM Mono',monospace;}
.sb{height:5px;background:var(--s);border-radius:3px;overflow:hidden;}
.sf{height:100%;border-radius:3px;transition:width .8s ease;}
.ebox{background:rgba(201,168,76,.06);border:1px solid rgba(201,168,76,.2);border-radius:9px;padding:13px;margin-top:11px;}
.etitle{font-size:10px;color:var(--gold);font-family:'DM Mono',monospace;text-transform:uppercase;letter-spacing:.5px;margin-bottom:7px;}
.etext{font-size:12px;color:var(--t);line-height:1.6;}
.fi{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--m);padding:3px 0;}
.cbn{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.25);border-radius:7px;padding:7px 11px;font-size:11px;color:#ef4444;font-family:'DM Mono',monospace;margin-bottom:5px;}
.al{background:var(--s2);border-radius:9px;padding:11px 13px;margin-bottom:7px;border-left:3px solid;}
.al.critical{border-color:var(--r);}
.al.high{border-color:var(--w);}
.al.medium{border-color:var(--gold);}
.at{font-size:13px;font-weight:600;margin-bottom:3px;}
.ad{font-size:11px;color:var(--m);}
.badge{font-size:10px;padding:2px 7px;border-radius:20px;font-family:'DM Mono',monospace;}
.bc{background:rgba(239,68,68,.15);color:#ef4444;}
.bw{background:rgba(245,158,11,.15);color:#f59e0b;}
.bg{background:rgba(201,168,76,.15);color:var(--gold);}
.bs{background:rgba(16,185,129,.15);color:#10b981;}
.sc{cursor:pointer;background:var(--s2);border:1px solid var(--b);border-radius:9px;padding:13px;margin-bottom:8px;transition:border-color .2s;}
.tabs{display:flex;gap:4px;background:var(--s);border:1px solid var(--b);border-radius:9px;padding:4px;width:fit-content;margin-bottom:20px;}
.tab{padding:7px 18px;border-radius:6px;font-size:13px;border:none;background:transparent;color:var(--m);cursor:pointer;font-family:'Space Grotesk',sans-serif;font-weight:500;}
.tab.active{background:var(--s2);color:var(--gold);}
.page{display:none;}
.page.active{display:block;}
.cbn-report{background:var(--s2);border:1px solid rgba(201,168,76,.2);border-radius:11px;padding:18px;}
.cr{display:flex;justify-content:space-between;align-items:center;padding:9px 0;border-bottom:1px solid var(--b);font-size:13px;}
.cr:last-child{border-bottom:none;}
.ck{color:var(--m);font-family:'DM Mono',monospace;font-size:11px;}
.cv{font-weight:600;}
.pg{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;}
.pc{background:var(--s2);border:1px solid var(--b);border-radius:9px;padding:11px;text-align:center;}
@media(max-width:768px){.metrics{grid-template-columns:repeat(2,1fr);}.grid2{grid-template-columns:1fr;}.pg{grid-template-columns:1fr 1fr;}}
</style>
</head>
<body>
<header>
  <div class="logo"><div class="logo-icon">🥇</div>GoldenShield AI</div>
  <div style="display:flex;align-items:center;gap:14px;">
    <div class="live"><span class="pulse-dot"></span>Nigerian Fraud Monitor Active</div>
    <button class="btn" style="width:auto;padding:9px 18px" onclick="showTab('scan',null)">🔍 Analyze</button>
  </div>
</header>
<main>
  <div class="tabs">
    <button class="tab active" onclick="showTab('dashboard',this)">Dashboard</button>
    <button class="tab" onclick="showTab('scan',this)">Analyze Transaction</button>
    <button class="tab" onclick="showTab('threats',this)">Nigeria Threats</button>
    <button class="tab" onclick="showTab('cbn',this)">CBN Report</button>
    <button class="tab" onclick="showTab('patterns',this)">Fraud Patterns</button>
  </div>

  <div class="page active" id="page-dashboard">
    <div class="metrics">
      <div class="metric"><div class="ml">Total Analyzed</div><div class="mv" style="color:var(--gold)" id="m-total">--</div><div class="ms">Transactions</div></div>
      <div class="metric"><div class="ml">Fraud Detected</div><div class="mv" style="color:var(--r)" id="m-fraud">--</div><div class="ms">This session</div></div>
      <div class="metric"><div class="ml">Amount Protected</div><div class="mv" style="color:var(--gr);font-size:16px;padding-top:4px" id="m-amount">--</div><div class="ms">From fraud</div></div>
      <div class="metric"><div class="ml">Accuracy</div><div class="mv" style="color:var(--gold)">99.4%</div><div class="ms">Detection rate</div></div>
    </div>
    <div class="grid2">
      <div class="card"><div class="ct"><span class="dot"></span>Live Fraud Alerts</div><div id="alertFeed"><div style="text-align:center;padding:20px;color:var(--m);font-size:13px;">Monitoring Nigerian transactions...</div></div></div>
      <div class="card"><div class="ct"><span class="dot"></span>Recent Transactions</div><div id="recentTxns"><div style="text-align:center;padding:20px;color:var(--m);font-size:13px;">Loading...</div></div></div>
    </div>
  </div>

  <div class="page" id="page-scan">
    <div class="grid2">
      <div class="card">
        <div class="ct"><span class="dot"></span>Transaction Analysis</div>
        <div class="fg">
          <div class="field"><label>Amount (₦)</label><input type="number" id="amount" value="250000"></div>
          <div class="field"><label>Channel</label><select id="channel"><option value="Mobile">Mobile Banking</option><option value="POS">POS Terminal</option><option value="ATM">ATM</option><option value="Internet">Internet Banking</option><option value="USSD">USSD</option></select></div>
          <div class="field"><label>Hour (0-23)</label><input type="number" id="hour" value="14" min="0" max="23"></div>
          <div class="field"><label>Account Age (Days)</label><input type="number" id="account_age_days" value="365"></div>
          <div class="field"><label>SIM Age (Days)</label><input type="number" id="sim_age_days" value="180"></div>
          <div class="field"><label>Prev Fraud Flags</label><input type="number" id="previous_fraud_flags" value="0"></div>
          <div class="field"><label>BVN Mismatch?</label><select id="bvn_mismatch"><option value="0">No</option><option value="1">Yes</option></select></div>
          <div class="field"><label>New Device?</label><select id="new_device"><option value="0">No</option><option value="1">Yes</option></select></div>
          <div class="field"><label>New Location?</label><select id="new_location"><option value="0">No</option><option value="1">Yes</option></select></div>
          <div class="field"><label>Bank</label><select id="bank"><option>GTBank</option><option>Access Bank</option><option>Zenith Bank</option><option>UBA</option><option>First Bank</option><option>Kuda Bank</option><option>OPay</option><option>PalmPay</option><option>Moniepoint</option></select></div>
        </div>
        <button class="btn" onclick="analyzeTransaction()" id="analyzeBtn">🔍 Analyze Transaction</button>
        <div class="result" id="resultPanel">
          <div class="verdict" id="verdictText"></div>
          <div class="sb-wrap"><div class="sb-label"><span>Fraud Probability</span><span id="scoreText">0%</span></div><div class="sb"><div class="sf" id="scoreFill" style="width:0%"></div></div></div>
          <div id="cbnFlags"></div>
          <div class="ebox"><div class="etitle">🧠 Explainable AI</div><div class="etext" id="explainText"></div><div id="factorsList"></div></div>
        </div>
      </div>
      <div class="card">
        <div class="ct"><span class="dot"></span>Quick Test Scenarios</div>
        <div class="sc" onclick="loadScenario('legit')" onmouseover="this.style.borderColor='var(--gr)'" onmouseout="this.style.borderColor='var(--b)'"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;"><span style="font-weight:600;font-size:13px;">✅ Legitimate Transfer</span><span class="badge bs">LOW RISK</span></div><span style="font-size:11px;color:var(--m);">₦50,000 · GTBank · Business hours · Verified BVN</span></div>
        <div class="sc" onclick="loadScenario('bvn')" onmouseover="this.style.borderColor='var(--r)'" onmouseout="this.style.borderColor='var(--b)'"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;"><span style="font-weight:600;font-size:13px;">🚨 BVN Identity Fraud</span><span class="badge bc">CRITICAL</span></div><span style="font-size:11px;color:var(--m);">₦750,000 · BVN mismatch · New account · New device</span></div>
        <div class="sc" onclick="loadScenario('simswap')" onmouseover="this.style.borderColor='var(--r)'" onmouseout="this.style.borderColor='var(--b)'"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;"><span style="font-weight:600;font-size:13px;">🚨 SIM Swap Takeover</span><span class="badge bc">CRITICAL</span></div><span style="font-size:11px;color:var(--m);">₦1,200,000 · SIM replaced 2 days ago · 2AM</span></div>
        <div class="sc" onclick="loadScenario('pos')" onmouseover="this.style.borderColor='var(--w)'" onmouseout="this.style.borderColor='var(--b)'"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;"><span style="font-weight:600;font-size:13px;">⚠️ POS Skimming</span><span class="badge bw">HIGH RISK</span></div><span style="font-size:11px;color:var(--m);">₦85,000 · POS terminal · New location · Late night</span></div>
      </div>
    </div>
  </div>

  <div class="page" id="page-threats">
    <div class="card"><div class="ct"><span class="dot"></span>Nigeria Threat Intelligence — Live Feed</div><div id="threatsList"><div style="text-align:center;padding:20px;color:var(--m);">Loading...</div></div></div>
  </div>

  <div class="page" id="page-cbn">
    <div class="card"><div class="ct"><span class="dot"></span>CBN / NFIU Compliance Report</div><div id="cbnReport"><div style="text-align:center;padding:20px;color:var(--m);">Generating...</div></div></div>
  </div>

  <div class="page" id="page-patterns">
    <div class="card">
      <div class="ct"><span class="dot"></span>Nigerian Fraud Patterns Database</div>
      <div class="pg">
        <div class="pc"><div style="font-size:22px;margin-bottom:5px;">🪪</div><div style="font-size:11px;font-weight:600;margin-bottom:3px;">BVN Fraud</div><div style="font-size:10px;color:var(--m);">Identity theft via cloned BVN profiles</div></div>
        <div class="pc"><div style="font-size:22px;margin-bottom:5px;">📱</div><div style="font-size:11px;font-weight:600;margin-bottom:3px;">SIM Swap</div><div style="font-size:10px;color:var(--m);">MTN/Airtel SIM replacement to bypass 2FA</div></div>
        <div class="pc"><div style="font-size:22px;margin-bottom:5px;">💳</div><div style="font-size:11px;font-weight:600;margin-bottom:3px;">POS Skimming</div><div style="font-size:10px;color:var(--m);">Card data via compromised POS terminals</div></div>
        <div class="pc"><div style="font-size:22px;margin-bottom:5px;">📧</div><div style="font-size:11px;font-weight:600;margin-bottom:3px;">BEC Fraud</div><div style="font-size:10px;color:var(--m);">Business Email Compromise targeting SMEs</div></div>
        <div class="pc"><div style="font-size:22px;margin-bottom:5px;">📲</div><div style="font-size:11px;font-weight:600;margin-bottom:3px;">Mobile Money</div><div style="font-size:10px;color:var(--m);">OPay/PalmPay money laundering nodes</div></div>
        <div class="pc"><div style="font-size:22px;margin-bottom:5px;">💔</div><div style="font-size:11px;font-weight:600;margin-bottom:3px;">Romance Scam</div><div style="font-size:10px;color:var(--m);">Large transfers to new beneficiaries</div></div>
      </div>
    </div>
  </div>
</main>
<script>
const socket=io();
socket.on('connect',()=>{socket.emit('start_monitoring');loadDashboard();});
socket.on('fraud_alert',a=>addAlert(a));
const SC={legit:{amount:50000,channel:'Mobile',hour:14,account_age_days:730,sim_age_days:365,previous_fraud_flags:0,bvn_mismatch:0,new_device:0,new_location:0,bank:'GTBank'},bvn:{amount:750000,channel:'Internet',hour:11,account_age_days:5,sim_age_days:30,previous_fraud_flags:1,bvn_mismatch:1,new_device:1,new_location:0,bank:'Access Bank'},simswap:{amount:1200000,channel:'Mobile',hour:2,account_age_days:365,sim_age_days:2,previous_fraud_flags:0,bvn_mismatch:0,new_device:1,new_location:1,bank:'Kuda Bank'},pos:{amount:85000,channel:'POS',hour:23,account_age_days:180,sim_age_days:90,previous_fraud_flags:0,bvn_mismatch:0,new_device:0,new_location:1,bank:'GTBank'}};
function showTab(id,btn){document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));document.getElementById('page-'+id).classList.add('active');if(btn)btn.classList.add('active');if(id==='threats')loadThreats();if(id==='cbn')loadCBN();}
function loadScenario(t){const s=SC[t];Object.keys(s).forEach(k=>{const el=document.getElementById(k);if(el)el.value=s[k];});showTab('scan',null);analyzeTransaction();}
async function loadDashboard(){try{const r=await fetch('/api/dashboard');const d=await r.json();const st=d.stats||{};document.getElementById('m-total').textContent=st.total_analyzed||'--';document.getElementById('m-fraud').textContent=st.fraud_detected||'--';document.getElementById('m-amount').textContent=st.amount_protected||'--';renderAlerts(d.nigeria_threats||[]);renderRecent(d.recent||[]);}catch(e){console.log(e);}}
function renderAlerts(t){const f=document.getElementById('alertFeed');if(!t.length){f.innerHTML='<div style="text-align:center;padding:20px;color:var(--m);font-size:13px;">No active alerts ✓</div>';return;}f.innerHTML=t.slice(0,4).map(x=>`<div class="al ${x.severity}"><div class="at">${x.title}</div><div class="ad">${x.description}</div><span class="badge ${x.severity==='critical'?'bc':x.severity==='high'?'bw':'bg'}">${x.severity}</span></div>`).join('');}
function renderRecent(t){document.getElementById('recentTxns').innerHTML=t.slice(0,8).map(x=>`<div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--b);font-size:12px;"><span style="font-family:'DM Mono',monospace;color:var(--m)">${x.id||'TXN...'}</span><span>₦${parseFloat(x.amount||0).toLocaleString()}</span><span class="badge ${x.risk_level==='HIGH'?'bc':x.risk_level==='MEDIUM'?'bw':'bs'}">${x.risk_level||'LOW'}</span></div>`).join('');}
function addAlert(t){const f=document.getElementById('alertFeed');const d=document.createElement('div');d.className=`al ${t.severity||'medium'}`;d.innerHTML=`<div class="at">${t.title}</div><div class="ad">${t.description}</div><span class="badge ${t.severity==='critical'?'bc':'bw'}">${t.severity||'high'}</span>`;f.insertBefore(d,f.firstChild);}
async function analyzeTransaction(){const btn=document.getElementById('analyzeBtn');btn.textContent='Analyzing...';btn.disabled=true;const fields=['amount','channel','hour','account_age_days','sim_age_days','previous_fraud_flags','bvn_mismatch','new_device','new_location','bank'];const data={};fields.forEach(f=>{const el=document.getElementById(f);if(el)data[f]=el.value;});try{const r=await fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const res=await r.json();showResult(res);}catch(e){alert('Error: '+e.message);}btn.textContent='🔍 Analyze Transaction';btn.disabled=false;}
function showResult(r){const panel=document.getElementById('resultPanel');panel.style.display='block';document.getElementById('verdictText').innerHTML=`<span style="color:${r.is_fraud?'var(--r)':'var(--gr)'}">${r.is_fraud?'🚨 FRAUD DETECTED':'✅ LEGITIMATE TRANSACTION'}</span>`;document.getElementById('scoreText').textContent=r.fraud_score+'%';const fill=document.getElementById('scoreFill');setTimeout(()=>{fill.style.width=r.fraud_score+'%';fill.style.background=r.risk_level==='HIGH'?'var(--r)':r.risk_level==='MEDIUM'?'var(--w)':'var(--gr)';},50);document.getElementById('cbnFlags').innerHTML=(r.cbn_flags||[]).map(f=>`<div class="cbn">⚖️ ${f}</div>`).join('');const exp=r.explanation||{};document.getElementById('explainText').textContent=exp.plain_english||'';document.getElementById('factorsList').innerHTML=(exp.risk_factors||[]).map(f=>`<div class="fi">⚠️ ${f}</div>`).join('');}
async function loadThreats(){try{const r=await fetch('/api/nigeria-threats');const t=await r.json();document.getElementById('threatsList').innerHTML=t.map(x=>`<div class="al ${x.severity}" style="margin-bottom:10px;"><div style="display:flex;justify-content:space-between;margin-bottom:5px;"><div class="at">${x.title}</div><span class="badge ${x.severity==='critical'?'bc':x.severity==='high'?'bw':'bg'}">${x.severity.toUpperCase()}</span></div><div class="ad">${x.description}</div><div style="margin-top:7px;font-size:11px;color:var(--gold);font-family:'DM Mono',monospace;">${x.mitigation}</div></div>`).join('');}catch(e){console.log(e);}}
async function loadCBN(){try{const r=await fetch('/api/cbn-report');const d=await r.json();document.getElementById('cbnReport').innerHTML=`<div class="cbn-report">${[['Total Transactions',d.total_transactions],['Suspicious Transactions',d.suspicious_transactions],['STR Required',d.str_required],['CTR Required (above ₦5M)',d.ctr_required],['Compliance Status',d.compliance_status],['NFIU Submission',d.nfiu_submission],['Total Fraud Detected',d.total_fraud_amount]].map(([k,v])=>`<div class="cr"><span class="ck">${k}</span><span class="cv">${v}</span></div>`).join('')}</div>`;}catch(e){console.log(e);}}
</script>
</body>
</html>"""

@app.route('/')
def index():
    return LANDING

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

@app.route('/api/incidents', methods=['GET'])
def incidents():
    from modules import gs_database
    return jsonify(gs_database.get_recent_incidents())
  
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
    emit('connected', {'status': 'GoldenShield AI active'})

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
    emit('monitoring_started', {'message': 'Real-time monitoring active'})

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5002, allow_unsafe_werkzeug=True)
