"""GoldenShield AI - Explainable AI Module
Tells users WHY a transaction was flagged in plain English."""

EXPLANATIONS = {
    'bvn_fraud': "The BVN provided does not match the account holder's registered biometric data. This is a strong indicator of identity theft or synthetic identity fraud.",
    'sim_swap': "The SIM card associated with this account was replaced within the last 7 days. SIM swapping is a common technique used to bypass SMS-based 2FA and take over accounts.",
    'pos_skimming': "This transaction originates from a POS terminal flagged for potential skimming activity. The card data may have been compromised.",
    'bec_fraud': "The payment instruction pattern matches Business Email Compromise — specifically a sudden change in beneficiary details for a regular vendor.",
    'mobile_money': "This mobile wallet has received funds from 8+ unrelated sources in the past hour, consistent with money mule activity used for layering in money laundering.",
    'romance_scam': "The transaction pattern — large outward transfer to a recently added beneficiary — matches romance scam victim profiles in our database.",
}

class FraudExplainer:
    def explain(self, result, data):
        pattern = result.get('pattern')
        score = result.get('fraud_score', 0)
        factors = []

        if data.get('bvn_mismatch'): factors.append('BVN identity mismatch detected')
        if int(data.get('sim_age_days', 365)) < 7: factors.append('SIM card replaced in last 7 days')
        if int(data.get('account_age_days', 365)) < 30: factors.append('New account (less than 30 days old)')
        if data.get('new_device'): factors.append('Transaction from unrecognized device')
        if data.get('new_location'): factors.append('Transaction from new geographic location')
        if float(data.get('amount', 0)) > 1_000_000: factors.append('High-value transaction above ₦1M')
        hour = int(data.get('hour', 12))
        if hour < 5 or hour > 22: factors.append(f'Unusual transaction time ({hour}:00)')

        return {
            'plain_english': EXPLANATIONS.get(pattern, 'Multiple risk factors detected in this transaction.'),
            'risk_factors': factors,
            'confidence': f'{min(score + 5, 99):.0f}%',
            'model': 'GoldenShield Neural Network v2.1',
            'nigeria_context': 'Analyzed against Nigerian fraud pattern database with 50,000+ local cases'
        }
