# Q-SHIELD: Quantum Cryptography Risk Scanner

A SOC-style dashboard that scans uploaded files for cryptographic algorithms and shows how exposed each one is to quantum attacks. Flask backend, plain HTML/CSS/JavaScript frontend, no build step.

Every number on screen comes from the backend. Before the first scan every page shows an empty state.

## Run it

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py                                          # http://127.0.0.1:5000
```

Optional environment variables: `PORT`, `HOST`, `QSHIELD_DB` (SQLite path), `FLASK_DEBUG=1`.

## Demo in 60 seconds

1. Open the app. Every page shows its empty state.
2. Go to **Upload and scan** and drop `samples/payment-service.zip`, or drop the `samples/payment-service` folder.
3. Walk through Overview, Analysis results (expand a row to see the exact lines), Risk score, Migration plan.
4. Open **History and reports** and download the PDF.

The sample contains deliberately weak code and demo-only keys and certificates (RSA-2048 and RSA-1024 with SHA-1, P-256 EC, an SSH key, an nginx config, a Java file) plus a post-quantum pilot file. The results are produced by the scanner at scan time, not stored.

## What the scanner does

- **Pattern rules** (20, in `scanner.py`) for RSA, Diffie-Hellman, ECDH/X25519, ECDSA/EdDSA, ECC curves, DSA, ElGamal, MD5, SHA-1, DES, 3DES, RC4, Blowfish, deprecated SSL/TLS, AES-128, plus safe algorithms (AES-256, SHA-2/3, ChaCha20) and post-quantum names (ML-KEM, ML-DSA, SLH-DSA, Kyber, Dilithium, SPHINCS+).
- **PDF text extraction** with `pypdf`; algorithm references in embedded PDF text are scanned. Image-only PDFs are skipped.\n- **Live TLS endpoint check** connects to the explicitly supplied host and port, reports the negotiated protocol/cipher and certificate metadata, and flags selected weak/deprecated settings. It is a point-in-time check, not a complete TLS audit.\n- **Real parsing** with the `cryptography` package of PEM and DER certificates, certificate requests, public and private keys, DH parameters, and SSH public keys. This gives actual key types and sizes (for example `RSA-1024`) and flags SHA-1/MD5 certificate signatures.
- Extracts text from PDFs (up to 500 pages) and opens `.zip` and `.tar*` archives in memory. Skips binaries, keystores, `.git`, `node_modules` and similar. Skipped files are listed with the reason.
- Nothing uploaded is written to disk or executed.

### Terms

- **Finding**: one algorithm in one file (with a count of uses and the matching lines).
- **Quantum-vulnerable asset**: a file and algorithm pair that Shor's algorithm breaks (RSA, DH, ECDH, ECDSA, DSA, ElGamal, ECC).
- **Critical finding**: a finding with critical severity. Key exchange and encryption with Shor-vulnerable algorithms, DES, RC4 and embedded private keys are critical.

### Risk score

Each finding adds points by severity (critical 10, high 5, medium 2, low 1, info 0), up to 50% more for repeated use in the same file. Score = `100 × (1 − e^(−points/30))`. Levels: Low 1-24, Medium 25-49, High 50-74, Critical 75-100. The formula is shown in the UI.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Backend status and limits |
| GET | `/api/overview` | Scan list plus the latest full result |
| POST | `/api/scan` | Multipart upload: `files` (many), optional `name` |\n| POST | `/api/tls-scan` | JSON body `{ "host": "example.com", "port": 443 }`; inspect one negotiated TLS session |
| GET | `/api/scans` | Scan history |
| GET | `/api/scans/<id>` | Full result for one scan |
| GET | `/api/scans/<id>/report.pdf` | PDF report |
| DELETE | `/api/scans/<id>` / `/api/scans` | Delete one scan / clear history |

Limits: 500 files per upload, 5 MB per file, 100 MB per request. PDF text extraction reads at most 500 pages per PDF.

## Files

```
app.py            Flask routes and SQLite history
scanner.py        Detection rules, parsing, scoring, migration plan
report.py         PDF report (ReportLab)
templates/        index.html
static/           css/style.css, js/app.js (charts are plain SVG, no libraries)
samples/          demo input files
```

## Limits to be honest about

- Detection is static: it finds algorithm names and parseable keys, not what a running program negotiates. A match shows where an algorithm is named, not proof that it protects live data, so review findings in context (for example, the word "RSA" in documentation will match).
- Compiled code, encrypted files, password-protected PDFs/archives/keystores, and image-only PDFs are not inspected. PDF support reads embedded text only; it does not perform OCR.
- Migration guidance follows NIST FIPS 203/204/205. The NIST IR 8547 dates it cites are from a draft, so check the current version before quoting them.
- The app has no login. Run it locally or behind your own access control.
