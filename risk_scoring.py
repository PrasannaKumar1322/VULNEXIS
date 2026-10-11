"""
Q-SHIELD Cryptographic Multi-Factor Risk Scoring and Prioritisation Engine.

Implements an explainable, configurable 4-factor risk scoring system:
1. Cryptographic Vulnerability (w1 = 0.30): Quantum vulnerability, parameters, classical weaknesses.
2. Data Sensitivity (w2 = 0.25): public, internal, confidential, highly sensitive.
3. Confidentiality Lifetime (w3 = 0.25): <1 year, 1-4 years, 5-9 years, 10+ years (HNDL threat).
4. Asset Exposure (w4 = 0.20): isolated, internal, partner/DMZ, internet-facing.

Configurable Weighted Formula:
Risk Score = (Vulnerability * 0.30) + (Sensitivity * 0.25) + (Lifetime * 0.25) + (Exposure * 0.20)

Severity Bands:
- Critical: 80–100 (Immediate attention)
- High: 60–79 (This week)
- Medium: 30–59 (Planned migration)
- Low: 0–29 (Monitor and maintain)

Queue Sorting Tie-Breakers:
1. Longer confidentiality lifetime descending (higher HNDL exposure).
2. Higher asset exposure descending (internet-facing before internal).

Also generates the developer-facing Monday Morning Action Plan ('What to Fix First')
across 4 actionable buckets with roles, prerequisites, validation tests, and concrete next actions.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------
# Default Configurable Factor Weights (Must sum to 1.0)
# --------------------------------------------------------------------------
DEFAULT_WEIGHTS = {
    "cryptographic_vulnerability": 0.30,
    "data_sensitivity": 0.25,
    "confidentiality_lifetime": 0.25,
    "asset_exposure": 0.20,
}

# --------------------------------------------------------------------------
# Documented Risk Bands & Thresholds
# --------------------------------------------------------------------------
RISK_BANDS = {
    "critical": {
        "min": 80,
        "max": 100,
        "label": "Critical",
        "timeframe": "Immediate attention",
        "priority": "Priority 1: Immediate Attention",
    },
    "high": {
        "min": 60,
        "max": 79,
        "label": "High",
        "timeframe": "This week",
        "priority": "Priority 2: This Week",
    },
    "medium": {
        "min": 30,
        "max": 59,
        "label": "Medium",
        "timeframe": "Planned migration",
        "priority": "Priority 3: Planned Migration",
    },
    "low": {
        "min": 0,
        "max": 29,
        "label": "Low",
        "timeframe": "Monitor and maintain",
        "priority": "Priority 4: Monitor and Maintain",
    },
}

# Factor 2 (Data Sensitivity) Scales (0–100)
SENSITIVITY_SCORES = {
    "highly_sensitive": 100,  # Credentials, private keys, payment data, health/PII, root secrets
    "critical": 100,          # Alias for backward compatibility
    "confidential": 75,       # Customer records, business data, active session tokens
    "high": 75,               # Alias for backward compatibility
    "internal": 40,           # Operational metadata, internal system logs, telemetry
    "medium": 40,             # Alias for backward compatibility
    "public": 10,             # Open source, test fixtures, sample/dummy data, public docs
    "low": 10,                # Alias for backward compatibility
    "unknown": 50,            # Documented neutral default baseline
}

# Factor 3 (Confidentiality Lifetime) Scales (0–100)
LIFETIME_SCORES = {
    "10+_years": 100,         # Long-term archival, root keys, legal/medical records (critical HNDL threat)
    "5-9_years": 75,          # Medium-long lifespan confidential records (high HNDL threat)
    "1-4_years": 40,          # Short-medium operational data (moderate HNDL threat)
    "<1_year": 10,            # Ephemeral session keys, short-lived transit data (minimal HNDL threat)
    "unknown": 50,            # Documented neutral default baseline
}

# Factor 4 (Asset Exposure) Scales (0–100)
EXPOSURE_SCORES = {
    "internet_facing": 100,          # Public internet endpoint, public TLS, web gateway
    "external_internet_facing": 100, # Alias for backward compatibility
    "partner_dmz": 70,               # Partner API, DMZ edge service, semi-restricted gateway
    "internal": 40,                  # Private VPC microservice, internal database connection
    "internal_network": 40,          # Alias for backward compatibility
    "isolated": 10,                  # Air-gapped host, offline processing, local client utility
    "isolated_airgapped": 10,        # Alias for backward compatibility
    "unknown": 50,                   # Documented neutral default baseline
}

# Factor 6 (Migration Path) Scales - retained for backward compatibility
MIGRATION_SCORES = {
    "complex_or_none": 85,
    "standardized_pqc_dropin": 40,
    "trivial_configuration": 15,
    "unknown": 50,
}

# Keyword patterns for automated inference
SENSITIVITY_CRITICAL_RE = re.compile(
    r"(payment|card|cvv|billing|wallet|token|password|secret|credential|auth|private_key|keypair|ssh_key|ssn|patient|health|phi|pii|vault)",
    re.IGNORECASE,
)
SENSITIVITY_HIGH_RE = re.compile(
    r"(customer|client|user_data|account|invoice|order|transaction|session|jwt|oauth|signature|confidential)",
    re.IGNORECASE,
)
SENSITIVITY_LOW_RE = re.compile(
    r"(test|mock|sample|dummy|demo|example|spec|benchmark|fixtures|temp|cache|public)",
    re.IGNORECASE,
)

EXPOSURE_EXTERNAL_RE = re.compile(
    r"(nginx|apache|envoy|caddy|ingress|gateway|router|web|public|frontend|api_gateway|tls_server|ssl_cert|proxy)",
    re.IGNORECASE,
)
EXPOSURE_INTERNAL_RE = re.compile(
    r"(internal|backend|service|worker|db|database|dao|batch|queue|daemon|job|helper|util)",
    re.IGNORECASE,
)
EXPOSURE_ISOLATED_RE = re.compile(
    r"(offline|airgap|embedded|local_only|cli|standalone|test)",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------
# Asset Context Inference Helper
# --------------------------------------------------------------------------
def infer_asset_context(
    filename: str,
    evidence: str = "",
    rule_id: str = "",
    certificate_years: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Attempt to infer data sensitivity, retention lifetime, and asset exposure
    from filename, evidence code, and certificate metadata.
    Marks any value that cannot be reliably inferred as 'unknown'.
    """
    combined = f"{filename} {evidence}"

    # 1. Infer Data Sensitivity
    if SENSITIVITY_LOW_RE.search(combined):
        sensitivity = "public"
        sens_provenance = "inferred"
        sens_reason = "File or evidence indicates test, mock, public or sample context."
    elif SENSITIVITY_CRITICAL_RE.search(combined):
        sensitivity = "highly_sensitive"
        sens_provenance = "inferred"
        sens_reason = "File or evidence contains sensitive credential, payment, private key, or PII identifiers."
    elif SENSITIVITY_HIGH_RE.search(combined):
        sensitivity = "confidential"
        sens_provenance = "inferred"
        sens_reason = "File or evidence contains customer, transactional, or session data identifiers."
    else:
        sensitivity = "unknown"
        sens_provenance = "unknown"
        sens_reason = "Data sensitivity could not be verified from static contents; defaulted to neutral assumption (50/100)."

    # 2. Infer Confidentiality Lifetime (Retention)
    if certificate_years is not None:
        if certificate_years >= 10.0:
            lifetime = "10+_years"
            life_reason = f"Certificate validity period ({certificate_years:.1f} years) indicates long-term archival retention."
        elif certificate_years >= 5.0:
            lifetime = "5-9_years"
            life_reason = f"Certificate validity period ({certificate_years:.1f} years) indicates medium-long retention."
        elif certificate_years >= 1.0:
            lifetime = "1-4_years"
            life_reason = f"Certificate validity period ({certificate_years:.1f} years) indicates standard operational retention."
        else:
            lifetime = "<1_year"
            life_reason = f"Certificate validity period ({certificate_years:.1f} years) indicates short-lived retention."
        life_provenance = "inferred"
    elif any(k in combined.lower() for k in ("ca_cert", "root_ca", "master_key", "archive", "backup", "vault")):
        lifetime = "10+_years"
        life_provenance = "inferred"
        life_reason = "Asset represents root infrastructure or archival storage with long confidentiality requirements."
    elif any(k in combined.lower() for k in ("session", "tls", "handshake", "ephemeral", "temp")):
        lifetime = "<1_year"
        life_provenance = "inferred"
        life_reason = "Asset represents ephemeral session or transit encryption."
    else:
        lifetime = "unknown"
        life_provenance = "unknown"
        life_reason = "Retention window could not be verified from file; defaulted to neutral assumption (50/100)."

    # 3. Infer Asset Exposure
    if EXPOSURE_EXTERNAL_RE.search(combined):
        exposure = "internet_facing"
        exp_provenance = "inferred"
        exp_reason = "Configuration or naming indicates edge proxy, web server, gateway, or public TLS."
    elif EXPOSURE_INTERNAL_RE.search(combined):
        exposure = "internal"
        exp_provenance = "inferred"
        exp_reason = "Component naming indicates internal backend, worker, or database service."
    elif EXPOSURE_ISOLATED_RE.search(combined):
        exposure = "isolated"
        exp_provenance = "inferred"
        exp_reason = "Component indicates local offline utility or test tool."
    else:
        exposure = "unknown"
        exp_provenance = "unknown"
        exp_reason = "Network exposure could not be verified from file; defaulted to neutral assumption (50/100)."

    return {
        "sensitivity": sensitivity,
        "sensitivity_provenance": sens_provenance,
        "sensitivity_reason": sens_reason,
        "lifetime": lifetime,
        "lifetime_provenance": life_provenance,
        "lifetime_reason": life_reason,
        "exposure": exposure,
        "exposure_provenance": exp_provenance,
        "exposure_reason": exp_reason,
    }


# --------------------------------------------------------------------------
# Factor Evaluators
# --------------------------------------------------------------------------
def evaluate_factor_cryptographic_vulnerability(
    quantum_classification: str,
    breaks_security_assumptions: bool,
    rule_id: str,
    classical_status: str = "unknown",
    key_size: Optional[int] = None,
    mode: Optional[str] = None,
    algorithm: str = "",
) -> Tuple[int, str]:
    """
    Factor 1 (30%): Cryptographic Vulnerability.
    Assesses algorithm vulnerability to future quantum attacks, key parameters,
    and known classical weaknesses.
    """
    rid = (rule_id or "").lower()
    algo_lower = (algorithm or "").lower()
    m = (mode or "").upper()

    # 1. Classical flaws / actively broken algorithms or modes (Score: 100)
    if (
        classical_status == "broken"
        or rid in ("des", "tdes", "rc4", "blowfish", "md5", "sha1", "zip_crypto")
        or m == "ECB"
        or (key_size is not None and key_size < 2048 and "rsa" in rid)
        or any(k in algo_lower for k in ("des", "rc4", "md5", "sha1"))
    ):
        return 100, (
            "Actively broken classical flaw: deprecated algorithm, weak key length (<2048-bit), "
            "or insecure cipher mode (e.g. ECB leaks plaintext patterns)."
        )

    # 2. Asymmetric quantum-vulnerable algorithms broken in polynomial time by Shor's algorithm
    if (
        quantum_classification == "quantum-vulnerable"
        or breaks_security_assumptions
        or any(k in rid for k in ("rsa", "ecc", "ecdh", "ecdsa", "dh", "dsa", "x509"))
        or any(k in algo_lower for k in ("rsa", "ecdsa", "ecdh", "elliptic"))
    ):
        if "rsa" in rid or "rsa" in algo_lower:
            if key_size is not None and key_size <= 2048:
                return 90, (
                    "RSA-2048 is vulnerable to Shor's algorithm (polynomial time factorisation) "
                    "and retains only a legacy 112-bit classical margin under NIST SP 800-131A."
                )
            return 85, (
                "Vulnerable to Shor's algorithm on a CRQC (breaks integer factorisation in polynomial time; "
                "critical Harvest-Now-Decrypt-Later exposure)."
            )
        return 85, (
            "Vulnerable to Shor's algorithm on a CRQC (breaks elliptic curve discrete logarithms in polynomial time; "
            "critical Harvest-Now-Decrypt-Later exposure)."
        )

    # 3. Symmetric algorithms weakened by Grover's algorithm (effective keyspace halved)
    if (
        rid in ("aes128", "aes_cbc", "aes_gcm")
        or quantum_classification == "weakened"
        or (key_size == 128 and "aes" in rid)
        or "aes-128" in algo_lower
    ):
        return 50, (
            "Symmetric algorithm weakened by Grover's algorithm: effective key space reduced from 128 to ~64 bits. "
            "Requires upgrade to AES-256 for high-retention data."
        )

    # 4. Quantum-resistant and Post-Quantum algorithms
    if (
        quantum_classification == "quantum-resistant"
        or rid in ("aes256", "sha2", "sha3", "pqc")
        or any(p in algo_lower for p in ("ml-kem", "ml-dsa", "slh-dsa", "kyber", "dilithium", "sphincs"))
    ):
        if rid == "pqc" or any(p in algo_lower for p in ("ml-kem", "ml-dsa", "slh-dsa")):
            return 0, "Standardized post-quantum cryptographic algorithm (NIST FIPS 203 / 204 / 205)."
        return 15, "Quantum-resistant with large security margin (e.g. AES-256 retains 128-bit quantum security under Grover)."

    return 50, "Cryptographic status not confidently classified; neutral baseline applied."


# Alias for backward compatibility
def evaluate_factor_quantum_vulnerability(
    quantum_classification: str,
    breaks_security_assumptions: bool,
    rule_id: str,
) -> Tuple[int, str]:
    return evaluate_factor_cryptographic_vulnerability(quantum_classification, breaks_security_assumptions, rule_id)


def evaluate_factor_data_sensitivity(
    user_value: Optional[str],
    inferred_data: Dict[str, Any],
) -> Tuple[int, str, str, str, bool]:
    """
    Factor 2 (25%): Data Sensitivity.
    Returns: (score, normalized_value, status, description, is_unknown)
    """
    norm_map = {
        "critical": "highly_sensitive",
        "highly_sensitive": "highly_sensitive",
        "high": "confidential",
        "confidential": "confidential",
        "medium": "internal",
        "internal": "internal",
        "low": "public",
        "public": "public",
        "unknown": "unknown",
    }
    if user_value:
        k = norm_map.get(str(user_value).lower())
        if k and k in SENSITIVITY_SCORES:
            score = SENSITIVITY_SCORES[k]
            status = "user_provided"
            desc = f"User explicitly specified data sensitivity as '{k}'."
            return score, k, status, desc, (k == "unknown")

    val = inferred_data.get("sensitivity", "unknown")
    val_norm = norm_map.get(str(val).lower(), "unknown")
    status = inferred_data.get("sensitivity_provenance", "unknown")
    score = SENSITIVITY_SCORES.get(val_norm, 50)
    is_unk = (status == "unknown" or val_norm == "unknown")
    desc = inferred_data.get("sensitivity_reason", "Neutral default assumption used (50/100) because sensitivity is unknown.")
    return score, val_norm, status, desc, is_unk


def evaluate_factor_confidentiality_lifetime(
    user_value: Optional[str],
    inferred_data: Dict[str, Any],
) -> Tuple[int, str, str, str, bool]:
    """
    Factor 3 (25%): Confidentiality Lifetime (Retention).
    Returns: (score, normalized_value, status, description, is_unknown)
    """
    if user_value:
        norm = str(user_value).strip()
        if norm.isdigit():
            y = int(norm)
            norm = "10+_years" if y >= 10 else ("5-9_years" if y >= 5 else ("1-4_years" if y >= 1 else "<1_year"))
        elif norm in ("<1_year", "1-4_years", "5-9_years", "10+_years", "unknown"):
            pass
        elif "10" in norm:
            norm = "10+_years"
        elif "5" in norm:
            norm = "5-9_years"
        elif "1" in norm:
            norm = "1-4_years"
        elif "<" in norm or "0" in norm:
            norm = "<1_year"
        else:
            norm = "unknown"

        if norm in LIFETIME_SCORES:
            score = LIFETIME_SCORES[norm]
            status = "user_provided"
            desc = f"User explicitly specified confidentiality lifetime as '{norm}'."
            return score, norm, status, desc, (norm == "unknown")

    val = inferred_data.get("lifetime", "unknown")
    status = inferred_data.get("lifetime_provenance", "unknown")
    score = LIFETIME_SCORES.get(val, 50)
    is_unk = (status == "unknown" or val == "unknown")
    desc = inferred_data.get("lifetime_reason", "Neutral default assumption used (50/100) because retention is unknown.")
    return score, val, status, desc, is_unk


def evaluate_factor_asset_exposure(
    user_value: Optional[str],
    inferred_data: Dict[str, Any],
) -> Tuple[int, str, str, str, bool]:
    """
    Factor 4 (20%): Asset Exposure.
    Returns: (score, normalized_value, status, description, is_unknown)
    """
    norm_map = {
        "external_internet_facing": "internet_facing",
        "internet_facing": "internet_facing",
        "partner_dmz": "partner_dmz",
        "internal_network": "internal",
        "internal": "internal",
        "isolated_airgapped": "isolated",
        "isolated": "isolated",
        "unknown": "unknown",
    }
    if user_value:
        k = norm_map.get(str(user_value).lower())
        if k and k in EXPOSURE_SCORES:
            score = EXPOSURE_SCORES[k]
            status = "user_provided"
            desc = f"User explicitly specified asset exposure as '{k}'."
            return score, k, status, desc, (k == "unknown")

    val = inferred_data.get("exposure", "unknown")
    val_norm = norm_map.get(str(val).lower(), "unknown")
    status = inferred_data.get("exposure_provenance", "unknown")
    score = EXPOSURE_SCORES.get(val_norm, 50)
    is_unk = (status == "unknown" or val_norm == "unknown")
    desc = inferred_data.get("exposure_reason", "Neutral default assumption used (50/100) because exposure is unknown.")
    return score, val_norm, status, desc, is_unk


def evaluate_factor_crypto_parameters(
    classical_status: str,
    key_size: Optional[int],
    mode: Optional[str],
    rule_id: str,
) -> Tuple[int, str]:
    """Factor 5: Cryptographic parameters and implementation weaknesses (retained for backward compatibility)."""
    rid = (rule_id or "").lower()
    m = (mode or "").upper()

    if classical_status == "broken" or rid in ("des", "tdes", "rc4", "blowfish", "md5", "sha1", "zip_crypto") or m == "ECB":
        return 100, "Contains actively broken classical flaw (deprecated cipher, weak key length, or insecure mode like ECB)."

    if (key_size and key_size < 2048 and "rsa" in rid) or classical_status == "legacy_warning":
        return 70, "Deprecated or phasing-out parameter (e.g. RSA-2048 legacy margin under NIST SP 800-131A)."

    if rid in ("aes256", "chacha20", "pqc") or (key_size and key_size >= 3072):
        return 10, "Hardened parameters meeting modern cryptographic best practices."

    if key_size or mode or classical_status == "acceptable":
        return 35, "Standard acceptable parameters (e.g. AES-128 GCM, P-256 ECC)."

    return 50, "Cryptographic parameters could not be fully identified; neutral baseline applied."


def evaluate_factor_migration_path(
    rule_id: str,
    replacement: str,
    quantum_classification: str,
) -> Tuple[int, str]:
    """Factor 6: Availability of a practical migration path (retained for backward compatibility)."""
    rid = (rule_id or "").lower()
    if quantum_classification == "quantum-resistant":
        return 15, "Already utilizes quantum-resistant cryptography; no urgent migration required."

    if any(k in rid for k in ("rsa", "ecdh", "ecdsa", "dh", "dsa", "ecc", "x509")):
        return 40, "Standardized drop-in PQC replacement available (NIST FIPS 203 ML-KEM / FIPS 204 ML-DSA)."

    if any(k in rid for k in ("aes", "des", "3des", "rc4", "blowfish")):
        return 25, "Standard drop-in symmetric migration available (upgrade to AES-256 GCM)."

    if any(k in rid for k in ("md5", "sha1")):
        return 20, "Drop-in hash replacement available (upgrade to SHA-256 or SHA-3)."

    return 50, "Migration path complexity is unclassified."


# --------------------------------------------------------------------------
# Main Risk Calculation Function
# --------------------------------------------------------------------------
def calculate_finding_risk(
    finding: Dict[str, Any],
    user_context: Optional[Dict[str, Any]] = None,
    custom_weights: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Calculate a transparent 4-factor risk prioritisation score (0 to 100)
    for a cryptographic finding.
    
    Formula:
    Risk Score = (Vulnerability * 0.30) + (Sensitivity * 0.25) + (Lifetime * 0.25) + (Exposure * 0.20)
    """
    weights = dict(DEFAULT_WEIGHTS)
    if custom_weights:
        weights.update(custom_weights)

    # Normalize weights so they always sum to 1.0
    w_sum = sum(weights.values()) or 1.0
    norm_weights = {k: v / w_sum for k, v in weights.items()}

    u_ctx = user_context or {}
    fname = finding.get("file", "") or finding.get("filename", "") or finding.get("asset", "")
    evidence = finding.get("evidence", "")
    rid = finding.get("rule_id", "")
    algo = finding.get("algorithm", "")
    q_class = finding.get("quantum_classification") or (
        finding.get("quantum_threat_analysis", {}).get("quantum_classification", "unknown")
    )
    breaks_assumptions = finding.get("breaks_security_assumptions", False)
    c_sec = finding.get("current_security_concerns", {})
    c_status = c_sec.get("status", "unknown")
    k_size = finding.get("key_size")
    mode = finding.get("mode")

    # Automated context inference
    cert_years = None
    if finding.get("certificate_validity_years"):
        try:
            cert_years = float(finding["certificate_validity_years"])
        except (ValueError, TypeError):
            cert_years = None
    inferred = infer_asset_context(fname, evidence, rid, cert_years)

    # Factor 1: Cryptographic Vulnerability (30%)
    f1_score, f1_desc = evaluate_factor_cryptographic_vulnerability(
        quantum_classification=q_class,
        breaks_security_assumptions=breaks_assumptions,
        rule_id=rid,
        classical_status=c_status,
        key_size=k_size,
        mode=mode,
        algorithm=algo,
    )
    f1_status = "confirmed" if q_class != "unknown" else "unknown"
    f1_is_unknown = (f1_status == "unknown")

    # Factor 2: Data Sensitivity (25%)
    user_sens = u_ctx.get("data_sensitivity")
    f2_score, f2_val, f2_status, f2_desc, f2_is_unk = evaluate_factor_data_sensitivity(user_sens, inferred)

    # Factor 3: Confidentiality Lifetime (25%)
    user_life = u_ctx.get("confidentiality_lifetime")
    f3_score, f3_val, f3_status, f3_desc, f3_is_unk = evaluate_factor_confidentiality_lifetime(user_life, inferred)

    # Factor 4: Asset Exposure (20%)
    user_exp = u_ctx.get("asset_exposure")
    f4_score, f4_val, f4_status, f4_desc, f4_is_unk = evaluate_factor_asset_exposure(user_exp, inferred)

    # Build structured contributing factors list
    factors = [
        {
            "id": "cryptographic_vulnerability",
            "name": "Cryptographic Vulnerability (Quantum & Classical)",
            "weight": norm_weights.get("cryptographic_vulnerability", 0.30),
            "raw_score": f1_score,
            "weighted_score": round(norm_weights.get("cryptographic_vulnerability", 0.30) * f1_score, 2),
            "status": f1_status,
            "value": q_class if q_class != "unknown" else f"{algo or rid} (unclassified)",
            "description": f1_desc,
            "is_unknown": f1_is_unknown,
        },
        {
            "id": "data_sensitivity",
            "name": "Data Sensitivity & Confidentiality Impact",
            "weight": norm_weights.get("data_sensitivity", 0.25),
            "raw_score": f2_score,
            "weighted_score": round(norm_weights.get("data_sensitivity", 0.25) * f2_score, 2),
            "status": f2_status,
            "value": f2_val,
            "description": f2_desc,
            "is_unknown": f2_is_unk,
        },
        {
            "id": "confidentiality_lifetime",
            "name": "Required Confidentiality Lifetime (HNDL Threat)",
            "weight": norm_weights.get("confidentiality_lifetime", 0.25),
            "raw_score": f3_score,
            "weighted_score": round(norm_weights.get("confidentiality_lifetime", 0.25) * f3_score, 2),
            "status": f3_status,
            "value": f3_val,
            "description": f3_desc,
            "is_unknown": f3_is_unk,
        },
        {
            "id": "asset_exposure",
            "name": "Asset Network Exposure & Accessibility",
            "weight": norm_weights.get("asset_exposure", 0.20),
            "raw_score": f4_score,
            "weighted_score": round(norm_weights.get("asset_exposure", 0.20) * f4_score, 2),
            "status": f4_status,
            "value": f4_val,
            "description": f4_desc,
            "is_unknown": f4_is_unk,
        },
    ]

    total_weighted = sum(f["weighted_score"] for f in factors)
    score = max(0, min(100, int(round(total_weighted))))

    # Determine Severity Band & Timeframe
    if score >= RISK_BANDS["critical"]["min"]:
        band = "critical"
    elif score >= RISK_BANDS["high"]["min"]:
        band = "high"
    elif score >= RISK_BANDS["medium"]["min"]:
        band = "medium"
    else:
        band = "low"

    band_info = RISK_BANDS[band]
    priority = band_info["priority"]
    timeframe = band_info["timeframe"]

    # Unknown inputs handling and Provisional Confidence Flag
    unknown_factors = [f["name"] for f in factors if f["is_unknown"]]
    is_provisional = len(unknown_factors) > 0
    confidence_flag = "Provisional (Default Assumptions)" if is_provisional else "Confirmed"

    # Plain text explanation of formula and assumptions
    explanation_parts = [
        f"Prioritisation score {score}/100 ({band_info['label']} Band, {timeframe}).",
        f"Weighted formula breakdown: Vulnerability ({factors[0]['weighted_score']} pts), "
        f"Sensitivity ({factors[1]['weighted_score']} pts), "
        f"Lifetime ({factors[2]['weighted_score']} pts), "
        f"Exposure ({factors[3]['weighted_score']} pts).",
    ]
    if is_provisional:
        assumptions_str = ", ".join(unknown_factors)
        explanation_parts.append(
            f"Score is flagged as PROVISIONAL because business context for ({assumptions_str}) "
            f"was unknown and evaluated using neutral default assumptions (50/100)."
        )
    explanation = " ".join(explanation_parts)

    # Special Highlight: Long-lived sensitive data protected by RSA or ECC (HNDL target)
    is_asymmetric_pki = any(k in rid for k in ("rsa", "ecc", "ecdh", "ecdsa", "dh", "dsa")) or finding.get("category") == "Public-key" or "rsa" in algo.lower()
    is_sensitive = f2_val in ("highly_sensitive", "critical", "confidential", "high")
    is_long_lived = f3_val in ("10+_years", "5-9_years")

    is_long_lived_sensitive_pki = bool(is_asymmetric_pki and is_sensitive and is_long_lived)
    highlight_callout = None
    if is_long_lived_sensitive_pki:
        highlight_callout = (
            "CRITICAL HNDL EXPOSURE: Long-lived confidential data protected by quantum-vulnerable "
            "asymmetric cryptography (RSA/ECC). Adversaries can harvest encrypted traffic today "
            "and retroactively decrypt it once a cryptographically relevant quantum computer is available."
        )

    # Factor scores dictionary for fast tie-breaking
    factor_scores_dict = {
        "cryptographic_vulnerability": f1_score,
        "data_sensitivity": f2_score,
        "confidentiality_lifetime": f3_score,
        "asset_exposure": f4_score,
    }

    return {
        "score": score,
        "risk_score": score,
        "level": band,
        "risk_level": band,
        "risk_label": band_info["label"],
        "timeframe": timeframe,
        "remediation_timeframe": timeframe,
        "priority": priority,
        "is_provisional": is_provisional,
        "confidence_flag": confidence_flag,
        "explanation": explanation,
        "contributing_factors": factors,
        "factor_scores": factor_scores_dict,
        "is_long_lived_sensitive_pki": is_long_lived_sensitive_pki,
        "highlight_callout": highlight_callout,
        "disclaimer": (
            "Operational prioritisation score (0–100) based on documented multi-factor formula. "
            "This is not a measured probability that an attacker will break the encryption."
        ),
        "weights_used": norm_weights,
        "user_context": {
            "data_sensitivity": f2_val,
            "confidentiality_lifetime": f3_val,
            "asset_exposure": f4_val,
            "sensitivity_provenance": f2_status,
            "lifetime_provenance": f3_status,
            "exposure_provenance": f4_status,
        },
    }


# --------------------------------------------------------------------------
# Queue Sorting with Strict Tie-Breakers
# --------------------------------------------------------------------------
def sort_remediation_queue(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Sort findings in the prioritisation queue:
    1. Primary sort: Risk Score descending.
    2. Tie-breaker 1: Longer confidentiality lifetime first (higher HNDL exposure).
    3. Tie-breaker 2: Higher exposure first (internet-facing before internal).
    4. Stable tie-breaker 3: Cryptographic vulnerability descending.
    5. Alphabetical file/asset and algorithm names.
    """
    return sorted(
        findings,
        key=lambda f: (
            -f.get("risk_score", 0),
            -f.get("factor_scores", {}).get("confidentiality_lifetime", 0),
            -f.get("factor_scores", {}).get("asset_exposure", 0),
            -f.get("factor_scores", {}).get("cryptographic_vulnerability", 0),
            str(f.get("file") or f.get("asset") or ""),
            str(f.get("algorithm") or ""),
        )
    )


# --------------------------------------------------------------------------
# Remediation Queue Item Builder
# --------------------------------------------------------------------------
def build_remediation_queue(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Constructs the structured remediation prioritisation queue items
    incorporating rank, affected asset, factor breakdowns, why it matters,
    recommended migration, and concrete next actions.
    """
    sorted_findings = sort_remediation_queue(findings)
    queue = []

    for idx, f in enumerate(sorted_findings, 1):
        asset = f.get("file") or f.get("asset") or f.get("filename") or "Unknown Asset"
        occurrences = f.get("occurrences", [])
        line_num = occurrences[0].get("line") if occurrences else f.get("line")
        port = f.get("port")
        
        if f.get("scan_surface") == "live_tls" or port is not None:
            location = f"{asset}:{port}" if port else asset
        else:
            location = f"{asset}:{line_num}" if line_num else asset

        algo = f.get("algorithm", "Cryptographic Primitive")
        q_analysis = f.get("quantum_threat_analysis", {})
        why_vulnerable = (
            f.get("why_vulnerable")
            or q_analysis.get("why_vulnerable")
            or f.get("score_explanation")
            or "Cryptographic algorithm has classical weaknesses or is vulnerable to quantum attacks."
        )

        m_rec = f.get("migration_recommendation", {})
        recommended_migration = (
            m_rec.get("proposed_alternative")
            or f.get("replacement")
            or "Upgrade to standardized post-quantum cryptography (FIPS 203/204/205) or AES-256-GCM."
        )

        # Concrete next action
        if m_rec.get("implementation_steps"):
            concrete_next_action = m_rec["implementation_steps"][0]
        elif f.get("recommendation"):
            concrete_next_action = f["recommendation"]
        else:
            concrete_next_action = f"Plan migration of {algo} to {recommended_migration}."

        queue_item = {
            "rank": idx,
            "priority_rank": f"#{idx}",
            "rank_number": idx,
            "id": f.get("id", idx),
            "title": f"Migrate {algo} on {asset}",
            "asset": asset,
            "location": location,
            "file": f.get("file", asset),
            "line": line_num,
            "scan_surface": f.get("scan_surface", "source_code"),
            "algorithm": algo,
            "evidence": f.get("evidence") or (occurrences[0].get("snippet") if occurrences else ""),
            "factor_scores": f.get("factor_scores", {}),
            "contributing_factors": f.get("contributing_factors", []),
            "risk_score": f.get("risk_score", 0),
            "severity": f.get("risk_label", f.get("severity", "medium").capitalize()),
            "severity_level": f.get("risk_level", f.get("severity", "medium")),
            "confidence_flag": f.get("confidence_flag", "Confirmed"),
            "is_provisional": f.get("is_provisional", False),
            "why_it_matters": why_vulnerable,
            "recommended_migration": recommended_migration,
            "concrete_next_action": concrete_next_action,
            "remediation_timeframe": f.get("remediation_timeframe", f.get("timeframe", "Planned migration")),
            "is_long_lived_sensitive_pki": f.get("is_long_lived_sensitive_pki", False),
            "highlight_callout": f.get("highlight_callout"),
        }
        queue.append(queue_item)

    return queue


# --------------------------------------------------------------------------
# Monday Morning Action Plan Generator ('What to Fix First')
# --------------------------------------------------------------------------
def generate_monday_morning_plan(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generates a practical, developer-facing summary answering 'What do we fix first?':
    Groups findings into 4 actionable buckets:
    1. Immediate attention (Critical findings >= 80, active classical weaknesses, internet-facing quantum-vulnerable endpoints).
    2. This week (High-risk findings 60–79, deprecated algorithms, exposed services).
    3. Planned migration (Medium-risk findings 30–59, internal systems, algorithms needing compatibility testing).
    4. Monitor and maintain (Lower-risk findings 0–29, non-sensitive, AES-256, standardized PQC).
    """
    sorted_queue = build_remediation_queue(findings)

    bucket_immediate: List[Dict[str, Any]] = []
    bucket_this_week: List[Dict[str, Any]] = []
    bucket_planned: List[Dict[str, Any]] = []
    bucket_monitor: List[Dict[str, Any]] = []

    for item in sorted_queue:
        score = item["risk_score"]
        # Allow special escalation: active classical weaknesses or internet-facing critical HNDL
        is_active_classical = item["factor_scores"].get("cryptographic_vulnerability", 0) == 100
        is_internet_pki = item.get("is_long_lived_sensitive_pki") and item["factor_scores"].get("asset_exposure", 0) == 100

        if score >= 80 or (score >= 70 and (is_active_classical or is_internet_pki)):
            item["owner_role"] = "Security Engineering / PKI Lead & Edge Infrastructure"
            item["prerequisites"] = [
                "Verify emergency key rotation authority",
                "Confirm TLS 1.3 / hybrid crypto support in edge proxies",
                "Ensure failover mechanisms are in place"
            ]
            item["validation_tests"] = [
                "Cipher suite renegotiation tests",
                "TLS key share inspection (X25519MLKEM768)",
                "Downgrade resistance verification"
            ]
            item["expected_outcome"] = "Deactivation of actively exploitable algorithms and immediate protection against retroactive harvesting and decryption."
            bucket_immediate.append(item)
        elif score >= 60:
            item["owner_role"] = "Backend Engineering Lead & Core Service Owners"
            item["prerequisites"] = [
                "Audit cryptographic runtime versions (OpenSSL 3.2+, BouncyCastle 1.78+, Go 1.24+) across affected microservices."
            ]
            item["validation_tests"] = [
                "End-to-end integration tests with hybrid key exchange",
                "Client compatibility matrix tests",
                "Buffer/payload size stress testing for larger PQC signatures"
            ]
            item["expected_outcome"] = "High-risk algorithms migrated with verified backward compatibility across client and partner ecosystems."
            bucket_this_week.append(item)
        elif score >= 30:
            item["owner_role"] = "Systems Architecture & DevOps Platform Teams"
            item["prerequisites"] = [
                "Establish formal Post-Quantum Cryptographic Agility roadmap and automated CI/CD staging test environments."
            ]
            item["validation_tests"] = [
                "Handshake latency profiling",
                "CPU throughput benchmarking",
                "MTU packet fragmentation verification under PQC load"
            ]
            item["expected_outcome"] = "Standardized cryptographic pipeline upgrade executed on schedule without business interruption."
            bucket_planned.append(item)
        else:
            item["owner_role"] = "Security Operations & Cryptographic Review Board"
            item["prerequisites"] = [
                "Continuous cryptographic inventory monitoring and dependency vulnerability tracking in CI/CD pipeline."
            ]
            item["validation_tests"] = [
                "Automated regression scans on pull requests to prevent re-introduction of deprecated or weak algorithms."
            ]
            item["expected_outcome"] = "Verified quantum resilience posture and sustained regulatory compliance."
            bucket_monitor.append(item)

    buckets_data = [
        {
            "id": "immediate_attention",
            "title": "Immediate Attention",
            "timeframe": "Immediate attention (Next 24–48 Hours)",
            "priority_level": "critical",
            "owner_role": "Security Engineering / PKI Lead & Edge Infrastructure",
            "rationale": (
                "Critical findings (Risk Score 80–100), actively broken classical ciphers (e.g. DES/RC4/MD5), "
                "or internet-facing quantum-vulnerable endpoints exposing confidential data to retroactive "
                "Harvest-Now-Decrypt-Later (HNDL) attacks."
            ),
            "prerequisites": (
                "Verify emergency key rotation authority; confirm TLS 1.3 / hybrid crypto support in edge proxies; "
                "ensure failover mechanisms are in place."
            ),
            "validation_tests": (
                "Cipher suite renegotiation tests; TLS key share inspection (X25519MLKEM768); "
                "downgrade resistance verification; automated certificate validation tests."
            ),
            "expected_outcome": (
                "Deactivation of actively exploitable algorithms and immediate protection against retroactive "
                "harvesting and decryption."
            ),
            "concrete_next_action": (
                "Disable deprecated ciphers/protocols; initiate key revocation for weak keys; "
                "deploy ML-KEM hybrid key exchange on edge ingress."
            ),
            "count": len(bucket_immediate),
            "items": bucket_immediate,
        },
        {
            "id": "this_week",
            "title": "This Week",
            "timeframe": "This week (Current Sprint)",
            "priority_level": "high",
            "owner_role": "Backend Engineering Lead & Core Service Owners",
            "rationale": (
                "High-risk dependencies (Risk Score 60–79), deprecated algorithm parameters (e.g. RSA-2048 legacy margins), "
                "and exposed partner services that will fail impending compliance or quantum resilience deadlines."
            ),
            "prerequisites": (
                "Audit cryptographic runtime versions (OpenSSL 3.2+, BouncyCastle 1.78+, Go 1.24+) across affected microservices."
            ),
            "validation_tests": (
                "End-to-end integration tests with hybrid key exchange; client compatibility matrix tests; "
                "buffer/payload size stress testing for larger PQC signatures."
            ),
            "expected_outcome": (
                "High-risk algorithms migrated with verified backward compatibility across client and partner ecosystems."
            ),
            "concrete_next_action": (
                "Update application configurations to enforce AES-256-GCM and deploy ML-DSA / hybrid signatures in test environments."
            ),
            "count": len(bucket_this_week),
            "items": bucket_this_week,
        },
        {
            "id": "planned_migration",
            "title": "Planned Migration",
            "timeframe": "Planned migration (Next Release Cycle / Roadmap)",
            "priority_level": "medium",
            "owner_role": "Systems Architecture & DevOps Platform Teams",
            "rationale": (
                "Medium-risk systems (Risk Score 30–59), internal network assets, and algorithms requiring compatibility "
                "and performance benchmarking before production deployment."
            ),
            "prerequisites": (
                "Establish formal Post-Quantum Cryptographic Agility roadmap and automated CI/CD staging test environments."
            ),
            "validation_tests": (
                "Handshake latency profiling, CPU throughput benchmarking, and MTU packet fragmentation verification under PQC load."
            ),
            "expected_outcome": (
                "Standardized cryptographic pipeline upgrade executed on schedule without business interruption."
            ),
            "concrete_next_action": (
                "Schedule library upgrade sprints; benchmark post-quantum performance overhead across staging clusters."
            ),
            "count": len(bucket_planned),
            "items": bucket_planned,
        },
        {
            "id": "monitor_and_maintain",
            "title": "Monitor and Maintain",
            "timeframe": "Monitor and maintain (Ongoing / Routine Review)",
            "priority_level": "low",
            "owner_role": "Security Operations & Cryptographic Review Board",
            "rationale": (
                "Lower-risk assets (Risk Score 0–29), non-sensitive data, AES-256 with 128-bit quantum security margin, "
                "or verified modern post-quantum cryptography (ML-KEM / ML-DSA / SLH-DSA)."
            ),
            "prerequisites": (
                "Continuous cryptographic inventory monitoring and dependency vulnerability tracking in CI/CD pipeline."
            ),
            "validation_tests": (
                "Automated regression scans on pull requests to prevent re-introduction of deprecated or weak algorithms."
            ),
            "expected_outcome": (
                "Verified quantum resilience posture and sustained regulatory compliance."
            ),
            "concrete_next_action": (
                "Retain current cryptographic configurations and re-evaluate annually against updated NIST/NCSC guidelines."
            ),
            "count": len(bucket_monitor),
            "items": bucket_monitor,
        },
    ]

    buckets_by_id = {b["id"]: b for b in buckets_data}

    return {
        "summary": {
            "immediate_attention_count": len(bucket_immediate),
            "this_week_count": len(bucket_this_week),
            "planned_migration_count": len(bucket_planned),
            "monitor_and_maintain_count": len(bucket_monitor),
            "total_findings": len(sorted_queue),
        },
        "buckets": buckets_data,
        "buckets_by_id": buckets_by_id,
        "queue": sorted_queue,
    }


# --------------------------------------------------------------------------
# Correlation and Deduplication
# --------------------------------------------------------------------------
def correlate_and_deduplicate_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Correlates and deduplicates findings on the same asset and algorithm/issue
    so security teams are not overwhelmed by redundant alerts.
    
    Returns:
    - deduplicated_issues: aggregated issue list grouped by (asset, algorithm)
    - findings: individual findings with correlated_issue_id attached
    """
    groups: Dict[str, List[Dict[str, Any]]] = {}

    for f in findings:
        asset = f.get("file") or f.get("asset") or f.get("filename") or "unknown"
        algo = f.get("algorithm") or f.get("rule_id") or "crypto"
        surface = f.get("scan_surface", "source_code")
        group_key = f"{surface}::{asset}::{algo}"
        groups.setdefault(group_key, []).append(f)

    deduplicated_issues = []
    for g_key, group_items in groups.items():
        primary = max(group_items, key=lambda x: x.get("risk_score", 0))
        total_occurrences = sum(x.get("count", 1) for x in group_items)
        lines = []
        for it in group_items:
            for occ in it.get("occurrences", []):
                if occ.get("line"):
                    lines.append(occ["line"])
            if it.get("line"):
                lines.append(it["line"])

        issue = {
            "issue_key": g_key,
            "asset": primary.get("file") or primary.get("asset") or "unknown",
            "scan_surface": primary.get("scan_surface", "source_code"),
            "algorithm": primary.get("algorithm", "Unknown"),
            "severity": primary.get("risk_label", primary.get("severity", "medium").capitalize()),
            "severity_level": primary.get("risk_level", primary.get("severity", "medium")),
            "max_risk_score": primary.get("risk_score", 0),
            "findings_count": len(group_items),
            "total_occurrences": total_occurrences,
            "lines": sorted(list(set(lines)))[:10],
            "primary_finding_id": primary.get("id"),
            "why_it_matters": primary.get("why_it_matters") or primary.get("why_vulnerable") or primary.get("score_explanation", ""),
            "recommended_migration": primary.get("recommended_migration") or primary.get("replacement", ""),
            "remediation_timeframe": primary.get("remediation_timeframe") or primary.get("timeframe", "Planned migration"),
        }
        deduplicated_issues.append(issue)

        # Attach issue key to each individual finding
        for item in group_items:
            item["correlated_issue_key"] = g_key

    # Sort deduplicated issues by max risk score descending
    deduplicated_issues.sort(key=lambda x: -x["max_risk_score"])

    return {
        "deduplicated_issues": deduplicated_issues,
        "correlated_count": len(deduplicated_issues),
        "raw_findings_count": len(findings),
    }
