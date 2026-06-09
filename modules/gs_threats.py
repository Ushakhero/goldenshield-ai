"""GoldenShield AI - Nigerian Threat Intelligence Database"""
import random
from datetime import datetime

NIGERIAN_THREATS = [
    {'id': 'bvn_001', 'title': 'BVN Identity Fraud Wave', 'severity': 'critical',
     'description': 'Coordinated BVN cloning attack detected across 3 banks in Lagos',
     'affected_banks': ['GTBank', 'Access Bank', 'Zenith Bank'],
     'mitigation': 'Verify BVN biometrics before approving transactions above ₦50,000'},
    {'id': 'sim_001', 'title': 'SIM Swap Campaign Active', 'severity': 'critical',
     'description': 'MTN and Airtel SIM swaps spiking — 47 cases in last 24hrs',
     'affected_banks': ['Kuda Bank', 'OPay', 'PalmPay'],
     'mitigation': 'Enforce 24hr cooling period for accounts with recent SIM changes'},
    {'id': 'pos_001', 'title': 'POS Skimming Ring Detected', 'severity': 'high',
     'description': 'Skimming devices found on 12 POS terminals in Ikeja, Lagos',
     'affected_banks': ['All banks'],
     'mitigation': 'Block cards used at flagged terminals; issue replacement cards'},
    {'id': 'bec_001', 'title': 'BEC Fraud Targeting SMEs', 'severity': 'high',
     'description': 'Business Email Compromise targeting Abuja-based SMEs — ₦180M lost',
     'affected_banks': ['First Bank', 'UBA'],
     'mitigation': 'Implement dual approval for vendor payment changes above ₦500,000'},
    {'id': 'mob_001', 'title': 'Mobile Money Mule Network', 'severity': 'medium',
     'description': 'OPay/PalmPay accounts used as layering nodes — 23 accounts flagged',
     'affected_banks': ['OPay', 'PalmPay', 'Moniepoint'],
     'mitigation': 'Flag accounts receiving 10+ inflows per day from unrelated sources'},
]


class NigerianThreatDB:
    def __init__(self):
        self.active_threats = NIGERIAN_THREATS.copy()

    def get_active_threats(self):
        return self.active_threats

    def simulate_nigerian_threat(self):
        if random.random() < 0.35:
            threat = random.choice(NIGERIAN_THREATS).copy()
            threat['timestamp'] = datetime.now().isoformat()
            threat['live'] = True
            return threat
        return None
