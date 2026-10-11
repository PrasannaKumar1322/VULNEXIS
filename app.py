"""VULNEXIS: Quantum Cryptography Risk Scanner. Flask backend."""
import io
import json
import logging
import socket
import ssl
import ipaddress
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, g, jsonify, render_template, request, send_file
from werkzeug.exceptions import HTTPException

import migration_engine
import report
import risk_scoring
import scanner

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.environ.get("VULNEXIS_DB", os.environ.get("QSHIELD_DB", str(BASE_DIR / "qshield.db")))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB per upload
app.config["TEMPLATES_AUTO_RELOAD"] = True
log = logging.getLogger("vulnexis")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    label TEXT NOT NULL,
    files_scanned INTEGER NOT NULL,
    findings INTEGER NOT NULL,
    critical INTEGER NOT NULL,
    score INTEGER NOT NULL,
    level TEXT NOT NULL,
    result_json TEXT NOT NULL
)
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# Ensure the database parent directory exists before SQLite opens the file.
DB_FILE = Path(DB_PATH).expanduser().resolve()
DB_FILE.parent.mkdir(parents=True, exist_ok=True)
DB_PATH = str(DB_FILE)

try:
    with sqlite3.connect(DB_PATH) as _c:
        _c.execute(SCHEMA)
except sqlite3.OperationalError:
    fallback_dir = Path.home() / ".qshield"
    fallback_dir.mkdir(parents=True, exist_ok=True)
    DB_FILE = (fallback_dir / "qshield.db").resolve()
    DB_PATH = str(DB_FILE)
    with sqlite3.connect(DB_PATH) as _c:
        _c.execute(SCHEMA)


def summary_row(r):
    return {"id": r["id"], "label": r["label"], "created_at": r["created_at"], "files_scanned": r["files_scanned"],
            "findings": r["findings"], "critical": r["critical"], "score": r["score"], "level": r["level"]}


def list_scans():
    rows = get_db().execute(
        "SELECT id, created_at, label, files_scanned, findings, critical, score, level "
        "FROM scans ORDER BY id DESC").fetchall()
    return [summary_row(r) for r in rows]


def load_scan(scan_id):
    row = get_db().execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return json.loads(row["result_json"]) if row else None


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify(status="ok", certificate_parsing=scanner.HAVE_CRYPTO, pdf_reports=report.AVAILABLE,
                   limits={"max_files": scanner.MAX_UPLOAD_FILES, "max_file_mb": scanner.MAX_FILE_BYTES // (1024 * 1024),
                           "max_upload_mb": app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)})


@app.get("/api/overview")
def overview():
    scans = list_scans()
    latest = load_scan(scans[0]["id"]) if scans else None
    return jsonify(scans=scans, scan_count=len(scans), files_scanned_total=sum(s["files_scanned"] for s in scans),
                   latest=latest)


@app.post("/api/scan")
def api_scan():
    # Support both single file ('file') and multiple files ('files')
    uploaded = request.files.getlist("files") or request.files.getlist("file")
    if not uploaded and "file" in request.files:
        uploaded = [request.files["file"]]

    # Filter out empty file inputs (e.g. form submitted without choosing a file)
    valid_files = [f for f in uploaded if (f.filename and f.filename.strip())]
    if not valid_files:
        return jsonify(error="No files were received. Choose a file, folder, or archive and try again."), 400

    if len(valid_files) > scanner.MAX_UPLOAD_FILES:
        return jsonify(error=f"Too many files ({len(valid_files)}). The limit is {scanner.MAX_UPLOAD_FILES} per scan. "
                             f"Upload a .zip archive instead."), 413

    items = []
    try:
        for f in valid_files:
            # Check individual size limit
            content = f.read()
            if len(content) > scanner.MAX_FILE_BYTES and not f.filename.lower().endswith(scanner.TAR_EXT + (".zip",)):
                return jsonify(error=f"File '{f.filename}' is {len(content) // (1024 * 1024)} MB, which exceeds the {scanner.MAX_FILE_BYTES // (1024 * 1024)} MB limit."), 413
            items.append((f.filename or "unnamed", content))
    finally:
        # Guarantee closure and cleanup of underlying temporary files
        for f in valid_files:
            try:
                f.close()
            except Exception:
                pass

    scan_ctx = {}
    if request.form.get("data_sensitivity"):
        scan_ctx["data_sensitivity"] = request.form.get("data_sensitivity")
    if request.form.get("confidentiality_lifetime"):
        scan_ctx["confidentiality_lifetime"] = request.form.get("confidentiality_lifetime")
    if request.form.get("asset_exposure"):
        scan_ctx["asset_exposure"] = request.form.get("asset_exposure")

    try:
        result = scanner.scan(items, scan_context=scan_ctx if scan_ctx else None)
    except Exception as e:
        log.exception("Scan processing error")
        return jsonify(error=f"Error analyzing uploaded files: {str(e)}"), 500

    if result["summary"]["files_scanned"] == 0:
        return jsonify(error="None of the uploaded files could be read as text, configs, certificates, or supported archives. "
                             "VULNEXIS does not inspect opaque binary executables.", skipped=result["skipped"]), 422

    created = datetime.now(timezone.utc).isoformat(timespec="seconds")
    label = (request.form.get("name") or "").strip()[:80]
    s = result["summary"]
    db = get_db()
    cur = db.execute(
        "INSERT INTO scans (created_at, label, files_scanned, findings, critical, score, level, result_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, '{}')",
        (created, label or "pending", s["files_scanned"], s["findings_total"], s["critical_findings"],
         s["risk_score"], s["risk_level"]))
    sid = cur.lastrowid
    label = label or (f"{valid_files[0].filename}" if len(valid_files) == 1 else f"Scan {sid}")
    result.update(id=sid, label=label, created_at=created)
    db.execute("UPDATE scans SET label = ?, result_json = ? WHERE id = ?", (label, json.dumps(result), sid))
    db.commit()
    return jsonify(result), 201


@app.post("/api/tls-scan")
def api_tls_scan():
    """Inspect TLS negotiated by an explicitly supplied host and port."""
    payload = request.get_json(silent=True) or {}
    host = str(payload.get("host", "")).strip()
    try:
        port = int(payload.get("port", 443))
    except (TypeError, ValueError):
        return jsonify(error="Port must be a number between 1 and 65535."), 400
    if not host or len(host) > 253 or any(ch.isspace() for ch in host) or "/" in host or "\\\\" in host:
        return jsonify(error="Enter a hostname or IP address, without a URL path."), 400
    if not 1 <= port <= 65535:
        return jsonify(error="Port must be between 1 and 65535."), 400
    # Avoid accidental localhost / metadata probing. Private network targets remain
    # available for authorised internal assessments when explicitly supplied.
    is_private = False
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        if ip.is_unspecified or ip.is_multicast:
            return jsonify(error="That IP address cannot be scanned."), 400
        is_private = ip.is_private or ip.is_loopback
    except ValueError:
        pass
    default_exposure = "internal" if is_private else "internet_facing"

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=host.strip("[]")) as conn:
                cert = conn.getpeercert()
                cipher = conn.cipher()
                version = conn.version()
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                not_after = cert.get("notAfter")
                
                unified_findings = []

                def _add_tls_finding(rule_id, algorithm, severity, title, detail, quantum_classification, breaks_assumptions=False, key_size=None, mode=None):
                    f_obj = {
                        "id": len(unified_findings) + 1,
                        "scan_surface": "live_tls",
                        "file": f"{host}:{port}",
                        "asset": f"{host}:{port}",
                        "endpoint": host,
                        "port": port,
                        "rule_id": rule_id,
                        "algorithm": algorithm,
                        "category": "Transport",
                        "severity": severity,
                        "title": title,
                        "detail": detail,
                        "evidence": f"{host}:{port} negotiated {algorithm} ({detail})",
                        "quantum_status": "vulnerable" if quantum_classification == "quantum-vulnerable" else ("classical" if severity in ("high", "critical") else "weakened"),
                        "quantum_classification": quantum_classification,
                        "breaks_security_assumptions": breaks_assumptions,
                        "current_security_concerns": {"status": "broken" if severity in ("critical", "high") else "acceptable", "concerns": [detail]},
                        "key_size": key_size,
                        "mode": mode,
                        "count": 1,
                        "occurrences": [{"line": None, "snippet": f"{host}:{port} -> {detail}"}],
                        "parsed": [algorithm],
                        "description": detail,
                        "recommendation": "Upgrade to TLS 1.3 with post-quantum hybrid key exchange (X25519MLKEM768).",
                        "replacement": "TLS 1.3 / ML-KEM-768",
                    }
                    score_data = risk_scoring.calculate_finding_risk(f_obj, user_context={"asset_exposure": default_exposure})
                    f_obj.update({
                        "risk_score": score_data["score"],
                        "risk_level": score_data["level"],
                        "risk_label": score_data["risk_label"],
                        "priority": score_data["priority"],
                        "timeframe": score_data["timeframe"],
                        "remediation_timeframe": score_data["remediation_timeframe"],
                        "is_provisional": score_data["is_provisional"],
                        "confidence_flag": score_data["confidence_flag"],
                        "score_explanation": score_data["explanation"],
                        "contributing_factors": score_data["contributing_factors"],
                        "factor_scores": score_data["factor_scores"],
                        "is_long_lived_sensitive_pki": score_data["is_long_lived_sensitive_pki"],
                        "highlight_callout": score_data["highlight_callout"],
                        "score_disclaimer": score_data["disclaimer"],
                        "user_context": score_data["user_context"],
                        "weights_used": score_data["weights_used"],
                    })
                    f_obj["migration_recommendation"] = migration_engine.generate_migration_recommendation(f_obj)
                    unified_findings.append(f_obj)

                if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    _add_tls_finding("legacy_tls", version, "high", "Deprecated TLS protocol", f"Negotiated {version}. Require TLS 1.2 or newer, preferably TLS 1.3.", "unknown")
                if cipher and any(x in cipher[0].upper() for x in ("RC4", "3DES", "DES", "NULL", "EXPORT")):
                    _add_tls_finding("weak_cipher", cipher[0], "critical", "Weak negotiated cipher", f"The endpoint negotiated {cipher[0]}.", "classical", breaks_assumptions=True, key_size=cipher[2])
                if cipher and any(x in cipher[0].upper() for x in ("ECDHE", "ECDH", "DHE", "DH")):
                    _add_tls_finding("ecdh", cipher[0], "medium", "Classical key exchange", "The negotiated key exchange is not post-quantum secure. Consider hybrid ML-KEM support for long-lived confidential data.", "quantum-vulnerable", breaks_assumptions=True, key_size=cipher[2])
                if cipher and any(x in cipher[0].upper() for x in ("MLKEM", "KYBER")):
                    _add_tls_finding("pqc", cipher[0], "low", "Post-quantum key exchange", "Negotiated post-quantum hybrid key exchange.", "quantum-resistant", breaks_assumptions=False, key_size=cipher[2])
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        if expiry < datetime.now(timezone.utc):
                            _add_tls_finding("x509_expired", "X.509 Certificate", "high", "Certificate expired", f"Certificate expired on {expiry.date().isoformat()}.", "unknown")
                    except ValueError:
                        pass

                unified_findings = risk_scoring.sort_remediation_queue(unified_findings)
                for i, f in enumerate(unified_findings, 1):
                    f["id"] = i

                remediation_queue = risk_scoring.build_remediation_queue(unified_findings)
                monday_morning_plan = risk_scoring.generate_monday_morning_plan(unified_findings)
                dedup_data = risk_scoring.correlate_and_deduplicate_findings(unified_findings)

                return jsonify(
                    ok=True,
                    host=host,
                    port=port,
                    protocol=version,
                    cipher={"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]} if cipher else None,
                    certificate={"subject": subject, "issuer": issuer, "not_after": not_after,
                                 "subject_alt_names": [v for typ, v in cert.get("subjectAltName", []) if typ == "DNS"]},
                    findings=unified_findings,
                    remediation_queue=remediation_queue,
                    monday_morning_plan=monday_morning_plan,
                    deduplicated_issues=dedup_data["deduplicated_issues"],
                    quantum_note="This reports the TLS session negotiated from this scanner. It does not prove all clients or configurations negotiate the same settings."
                )
    except (socket.timeout, TimeoutError):
        return jsonify(error="Connection timed out. Check the hostname, port, firewall and network access."), 504
    except ssl.SSLCertVerificationError as e:
        return jsonify(error=f"Certificate validation failed: {e.verify_message}"), 422
    except (OSError, ssl.SSLError) as e:
        return jsonify(error=f"TLS connection failed: {str(e)[:240]}"), 502


def _is_ip(value):
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


@app.get("/api/scans")
def api_scans():
    return jsonify(scans=list_scans())


@app.get("/api/scans/<int:scan_id>")
def api_scan_get(scan_id):
    result = load_scan(scan_id)
    if result is None:
        return jsonify(error="That scan no longer exists."), 404
    return jsonify(result)


@app.delete("/api/scans/<int:scan_id>")
def api_scan_delete(scan_id):
    db = get_db()
    db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    db.commit()
    return jsonify(ok=True)


@app.get("/api/risk-scoring/config")
def api_risk_config():
    """Return transparent 4-factor risk scoring configuration, weights, and thresholds."""
    return jsonify({
        "default_weights": risk_scoring.DEFAULT_WEIGHTS,
        "risk_bands": risk_scoring.RISK_BANDS,
        "sensitivity_scores": risk_scoring.SENSITIVITY_SCORES,
        "lifetime_scores": risk_scoring.LIFETIME_SCORES,
        "exposure_scores": risk_scoring.EXPOSURE_SCORES,
        "migration_scores": risk_scoring.MIGRATION_SCORES,
        "disclaimer": "Operational prioritisation score (0–100) based on documented criteria. This is not a measured probability that an attacker will break the encryption."
    })


@app.post("/api/scans/<int:scan_id>/findings/<int:finding_id>/context")
def api_finding_context(scan_id, finding_id):
    """Allow user to provide/override asset context for a finding and re-calculate score."""
    result = load_scan(scan_id)
    if result is None:
        return jsonify(error="That scan no longer exists."), 404

    target = next((f for f in result.get("findings", []) if f.get("id") == finding_id), None)
    if target is None:
        return jsonify(error="Finding not found."), 404

    req_data = request.get_json(silent=True) or {}
    updated_score = risk_scoring.calculate_finding_risk(target, user_context=req_data)
    target.update({
        "risk_score": updated_score["score"],
        "risk_level": updated_score["level"],
        "risk_label": updated_score["risk_label"],
        "priority": updated_score["priority"],
        "timeframe": updated_score["timeframe"],
        "remediation_timeframe": updated_score["remediation_timeframe"],
        "is_provisional": updated_score["is_provisional"],
        "confidence_flag": updated_score["confidence_flag"],
        "score_explanation": updated_score["explanation"],
        "contributing_factors": updated_score["contributing_factors"],
        "factor_scores": updated_score["factor_scores"],
        "is_long_lived_sensitive_pki": updated_score["is_long_lived_sensitive_pki"],
        "highlight_callout": updated_score["highlight_callout"],
        "score_disclaimer": updated_score["disclaimer"],
        "user_context": updated_score["user_context"],
        "weights_used": updated_score["weights_used"],
    })

    # Update migration recommendation under updated context
    target["migration_recommendation"] = migration_engine.generate_migration_recommendation(
        target,
        scan_context=req_data,
    )

    # Re-sort findings using documented tie-breakers (Risk Score desc, Lifetime desc, Exposure desc)
    result["findings"] = risk_scoring.sort_remediation_queue(result["findings"])
    for i, f in enumerate(result["findings"], 1):
        f["id"] = i

    # Rebuild migration plan, remediation queue, Monday Morning Action Plan, and deduplicated issues
    result["plan"] = scanner._build_plan(result["findings"])
    result["remediation_queue"] = risk_scoring.build_remediation_queue(result["findings"])
    result["monday_morning_plan"] = risk_scoring.generate_monday_morning_plan(result["findings"])
    dedup_data = risk_scoring.correlate_and_deduplicate_findings(result["findings"])
    result["deduplicated_issues"] = dedup_data["deduplicated_issues"]

    # Update summary prioritisation bands
    result["summary"]["prioritisation_bands"] = {
        "critical": sum(1 for f in result["findings"] if f.get("risk_level") == "critical"),
        "high": sum(1 for f in result["findings"] if f.get("risk_level") == "high"),
        "medium": sum(1 for f in result["findings"] if f.get("risk_level") == "medium"),
        "low": sum(1 for f in result["findings"] if f.get("risk_level") == "low"),
    }
    result["summary"]["long_lived_sensitive_pki_count"] = sum(1 for f in result["findings"] if f.get("is_long_lived_sensitive_pki"))

    db = get_db()
    db.execute("UPDATE scans SET result_json = ? WHERE id = ?", (json.dumps(result), scan_id))
    db.commit()

    return jsonify(ok=True, finding=target, scan=result)


@app.delete("/api/scans")
def api_scans_clear():
    db = get_db()
    db.execute("DELETE FROM scans")
    db.commit()
    return jsonify(ok=True)


@app.get("/api/scans/<int:scan_id>/report.pdf")
def api_report(scan_id):
    if not report.AVAILABLE:
        return jsonify(error="PDF reports need the 'reportlab' package. Run: pip install reportlab"), 501
    result = load_scan(scan_id)
    if result is None:
        return jsonify(error="That scan no longer exists."), 404
    meta = {"id": result["id"], "label": result["label"], "created_at": result["created_at"]}
    pdf = report.build_pdf(meta, result)
    return send_file(io.BytesIO(pdf), mimetype="application/pdf", as_attachment=True,
                     download_name=f"vulnexis-report-{scan_id}.pdf")


@app.errorhandler(413)
def too_large(_e):
    return jsonify(error="The upload is larger than the 100 MB limit. Remove some files or split the scan."), 413


@app.errorhandler(Exception)
def on_error(e):
    if isinstance(e, HTTPException):
        if request.path.startswith("/api/"):
            return jsonify(error=e.description), e.code
        return e
    log.exception("Unhandled error")
    if request.path.startswith("/api/"):
        return jsonify(error="The scanner hit an unexpected error. Check the server log for details."), 500
    raise e


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")),
            debug=os.environ.get("FLASK_DEBUG") == "1")
