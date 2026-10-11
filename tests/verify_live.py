import requests
import json

BASE_URL = 'http://127.0.0.1:5000'

# 1. Health check
h = requests.get(f'{BASE_URL}/api/health')
print('Health check:', h.status_code, h.json().get('status'))

# 2. Risk configuration endpoint
cfg = requests.get(f'{BASE_URL}/api/risk-scoring/config')
print('Config endpoint:', cfg.status_code)

# 3. Upload & scan sample with multiple algorithms (RSA, AES-128, DES, MD5)
code = """
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, DES

# Master RSA key for session exchange
key = RSA.generate(2048)

# AES-128 and legacy DES encryption
cipher_aes = AES.new(b'0123456789abcdef', AES.MODE_GCM)
cipher_des = DES.new(b'12345678', DES.MODE_ECB)

# User password hash
pwd_hash = hashlib.md5(b'secret_password').hexdigest()
"""

files = {'files': ('payment_processor.py', code.encode('utf-8'))}
data = {
    'name': 'Live Migration Verification Scan',
    'data_sensitivity': 'high',
    'confidentiality_lifetime': '10+_years',
    'asset_exposure': 'external_internet_facing'
}

r = requests.post(f'{BASE_URL}/api/scan', files=files, data=data)
print('Scan status:', r.status_code)
scan = r.json()
sid = scan['id']
print('Scan ID:', sid, '| Scan score:', scan['summary']['risk_score'])
print('Findings total:', scan['summary']['findings_total'])

print('\n=== Verifying PQC Migration Recommendations ===')
for f in scan['findings']:
    algo = f['algorithm']
    m_rec = f.get('migration_recommendation')
    assert m_rec is not None, f"Finding {algo} missing migration_recommendation"
    
    print(f"\nFinding: {algo}")
    print(f"  Role: {m_rec.get('protocol_role')}")
    print(f"  Proposed Alternative: {m_rec.get('proposed_alternative')}")
    print(f"  Priority: {m_rec.get('priority')}")
    print(f"  Reason: {m_rec.get('reason')[:90]}...")
    print(f"  Compatibility: {m_rec.get('compatibility_considerations')[:90]}...")
    print(f"  Steps ({len(m_rec.get('implementation_steps', []))}): {m_rec.get('implementation_steps', [])[0]}")
    print(f"  Testing ({len(m_rec.get('testing_requirements', []))}): {m_rec.get('testing_requirements', [])[0]}")

# 4. Verify Plan Phases have enriched actions
print('\n=== Verifying Plan Actions ===')
plan = scan.get('plan', {})
for ph in plan.get('phases', []):
    print(f"Phase {ph['id']}: {ph['title']} ({ph['priority']})")
    for a in ph.get('actions', []):
        print(f"  Action: {a['title']} -> Replace with: {a.get('replace_with')}")
        if a.get('implementation_steps'):
            print(f"    Steps count: {len(a['implementation_steps'])}")

# 5. Verify Context Override Updates Finding & Migration Recommendation
fid = scan['findings'][0]['id']
r_override = requests.post(
    f'{BASE_URL}/api/scans/{sid}/findings/{fid}/context',
    json={'data_sensitivity': 'low', 'confidentiality_lifetime': '<1_year', 'asset_exposure': 'isolated_airgapped'}
)
print('\nOverride status:', r_override.status_code)
upd_scan = r_override.json()['scan']
upd_finding = r_override.json()['finding']
print(f"Updated finding {fid}: Risk Score = {upd_finding['risk_score']} ({upd_finding['risk_level']})")
print(f"Updated migration alternative: {upd_finding['migration_recommendation']['proposed_alternative']}")

# 6. Verify PDF Report Generation with Migration Sections
r_pdf = requests.get(f'{BASE_URL}/api/scans/{sid}/report.pdf')
print('\nPDF report status:', r_pdf.status_code, 'Length:', len(r_pdf.content))
assert r_pdf.content.startswith(b'%PDF-'), "Invalid PDF format"

print('\nAll live backend verification tests passed successfully!')
