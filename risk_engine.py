"""
Q-SHIELD Cryptographic Risk Analysis Engine.

Evaluates every detected cryptographic algorithm against:
  1. Current classical threats (key lengths, collisions, deprecated protocols, modes).
  2. Future Cryptographically Relevant Quantum Computing (CRQC) threats (Shor's, Grover's).
  3. Harvest-Now-Decrypt-Later (HNDL) exposure for long-lived confidential secrets.
  4. Quantum classifications: 'quantum-vulnerable', 'quantum-resistant', 'not yet confidently classified'.

Explicitly distinguishes theoretical future quantum risk from currently exploitable
classical vulnerabilities. Does not claim a quantum computer has broken any algorithm today.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------
# Standards References
# --------------------------------------------------------------------------
STANDARDS = {
    "NIST_SP_800_131A": "NIST SP 800-131A Rev. 2 (Transitioning the Use of Cryptographic Algorithms and Key Lengths)",
    "NIST_FIPS_203": "NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism - ML-KEM)",
    "NIST_FIPS_204": "NIST FIPS 204 (Module-Lattice-Based Digital Signature Algorithm - ML-DSA)",
    "NIST_FIPS_205": "NIST FIPS 205 (Stateless Hash-Based Digital Signature Algorithm - SLH-DSA)",
    "NIST_IR_8547": "NIST IR 8547 (Transition to Post-Quantum Cryptography Standards)",
    "RFC_8996": "RFC 8996 (Deprecating TLS 1.0 and TLS 1.1)",
    "RFC_7465": "RFC 7465 (Prohibiting RC4 Cipher Suites)",
    "NSA_CNSA_2": "NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)",
    "SWEET32": "CVE-2016-2183 (Sweet32 birthday attack on 64-bit block ciphers)",
    "SHATTERED": "SHAttered (2017 practical collision attack on SHA-1)",
}


# --------------------------------------------------------------------------
# Core Evaluation Engine
# --------------------------------------------------------------------------
def evaluate_risk(
    rule_id: str,
    key_size: Optional[int] = None,
    mode: Optional[str] = None,
    curve: Optional[str] = None,
    hash_algo: Optional[str] = None,
    confidence: str = "inferred",
    source: str = "pattern",
    evidence: str = "",
) -> Dict[str, Any]:
    """
    Perform a structured, rule-based cryptographic risk evaluation.
    Returns a comprehensive dictionary with classical threats, quantum threats,
    HNDL exposure, and remediation guidance.
    """
    params: Dict[str, Any] = {}
    if key_size:
        params["key_size"] = key_size
        params["key_size_label"] = f"{key_size}-bit"
    if mode:
        params["mode"] = mode
    if curve:
        params["curve"] = curve
    if hash_algo:
        params["hash_algorithm"] = hash_algo

    # 1. RSA
    if rule_id == "rsa":
        algo_name = "RSA"
        ksize = key_size or 2048
        is_sub_2048 = ksize < 2048

        classical_status = "broken" if is_sub_2048 else "legacy_warning"
        classical_concerns = [
            f"Key size of {ksize} bits is below the 2048-bit minimum mandated by NIST SP 800-131A Rev. 2; susceptible to distributed classical factoring."
        ] if is_sub_2048 else [
            f"Provides ~112 bits of classical security margin at {ksize} bits. NIST IR 8547 proposes disallowing RSA for new deployments by 2030."
        ]

        return {
            "algorithm_name": algo_name,
            "detected_parameters": params,
            "current_security_concerns": {
                "status": classical_status,
                "status_label": "Broken (insecure today)" if is_sub_2048 else "Legacy acceptable (phasing out)",
                "exploitable_today": is_sub_2048,
                "concerns": classical_concerns,
                "standards_reference": STANDARDS["NIST_SP_800_131A"],
            },
            "quantum_threat_analysis": {
                "breaks_security_assumptions": True,
                "quantum_classification": "quantum-vulnerable",
                "quantum_algorithm_applicable": "Shor's Algorithm",
                "why_vulnerable": (
                    "RSA relies on the computational hardness of the Integer Factorization Problem (N = p * q). "
                    "Peter Shor's 1994 algorithm computes the period of modular exponentiation in polynomial time "
                    "O((log N)^2 * log log N * log log log N) on a quantum computer using quantum Fourier transforms. "
                    "A Cryptographically Relevant Quantum Computer (CRQC) with sufficient logical qubits can efficiently "
                    "factor RSA moduli of any standardized key size (1024, 2048, 3072, 4096 bits), breaking both "
                    "RSA encryption and RSA digital signatures."
                ),
                "theoretical_vs_active": (
                    "Theoretical future risk: No CRQC capable of factoring 2048-bit RSA exists today (current devices "
                    "remain in the noisy intermediate-scale quantum / NISQ era). RSA-2048 remains unbroken by classical computers, "
                    "but migration to ML-KEM/ML-DSA is urgently required due to harvest-now-decrypt-later."
                ),
            },
            "harvest_now_decrypt_later": {
                "applicable": True,
                "risk_level": "critical",
                "explanation": (
                    "High / Critical threat for long-lived confidential data: Encrypted traffic, key exchanges, and archives "
                    "can be intercepted and stored by adversaries today ('harvested') and retroactively decrypted once a "
                    "sufficiently capable quantum computer becomes operational. If data must remain confidential for 5+ years, "
                    "it is already exposed."
                ),
            },
            "remediation_guidance": {
                "recommended_replacement": "ML-KEM (FIPS 203) for key exchange / encryption, ML-DSA (FIPS 204) for signatures",
                "transition_strategy": "Deploy hybrid key exchange (e.g. X25519MLKEM768 or RSA-ML-KEM) to protect data immediately.",
                "standards_guidance": f"{STANDARDS['NIST_FIPS_203']}, {STANDARDS['NIST_FIPS_204']}",
            },
        }

    # 2. Elliptic-Curve Cryptography (ECC, ECDH, ECDSA, EdDSA)
    if rule_id in ("ecdh", "ecdsa", "ecc_curve"):
        is_kex = rule_id == "ecdh"
        algo_name = "ECDH / X25519" if is_kex else ("ECDSA / EdDSA" if rule_id == "ecdsa" else "Elliptic-Curve Cryptography (ECC)")

        return {
            "algorithm_name": algo_name,
            "detected_parameters": params,
            "current_security_concerns": {
                "status": "acceptable_standard",
                "status_label": "Acceptable classically",
                "exploitable_today": False,
                "concerns": [
                    "Classically secure with ~128 to 256 bits of security on standard curves (P-256, P-384, Curve25519).",
                    "Implementation must defend against classical side-channel and timing attacks (constant-time scalar multiplication).",
                ],
                "standards_reference": STANDARDS["NIST_SP_800_131A"],
            },
            "quantum_threat_analysis": {
                "breaks_security_assumptions": True,
                "quantum_classification": "quantum-vulnerable",
                "quantum_algorithm_applicable": "Shor's Algorithm",
                "why_vulnerable": (
                    "Elliptic-curve cryptography relies on the Elliptic Curve Discrete Logarithm Problem (ECDLP) "
                    "over abelian groups of curve points (Q = d * P). Shor's algorithm solves the abelian hidden subgroup "
                    "problem in polynomial time, breaking ECDLP with even fewer logical qubits than required for RSA. "
                    "All standard curves (NIST P-256, P-384, P-521, secp256k1, Curve25519, Ed25519, X448) are completely breakable."
                ),
                "theoretical_vs_active": (
                    "Theoretical future risk: No quantum computer can break classical ECC curves today. ECC remains "
                    "fully secure against classical supercomputers, but will be completely broken once a CRQC is built."
                ),
            },
            "harvest_now_decrypt_later": {
                "applicable": is_kex,
                "risk_level": "critical" if is_kex else "not_applicable",
                "explanation": (
                    "Critical threat for key agreement (ECDH/X25519): Intercepted TLS/SSH handshakes recorded today "
                    "can be decrypted retroactively, exposing all session keys and transmitted confidential data."
                    if is_kex else
                    "Not subject to retroactive decryption: Digital signatures verify authenticity and integrity rather than "
                    "confidentiality. Historical signatures cannot be 'decrypted'. However, long-lived signed artifacts "
                    "(code signing, certificates) will face quantum forgery once CRQCs emerge."
                ),
            },
            "remediation_guidance": {
                "recommended_replacement": "ML-KEM (FIPS 203) for key exchange; ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures",
                "transition_strategy": "Use hybrid key exchange (e.g. X25519MLKEM768) for TLS/SSH; plan transition to ML-DSA for PKI.",
                "standards_guidance": f"{STANDARDS['NIST_FIPS_203']}, {STANDARDS['NIST_FIPS_204']}",
            },
        }

    # 3. Finite-Field Diffie-Hellman & DSA
    if rule_id in ("dh", "dsa"):
        is_dh = rule_id == "dh"
        algo_name = "Diffie-Hellman (DH/DHE)" if is_dh else "DSA"
        ksize = key_size or 2048
        is_sub_2048 = ksize < 2048

        return {
            "algorithm_name": algo_name,
            "detected_parameters": params,
            "current_security_concerns": {
                "status": "broken" if is_sub_2048 else "legacy_warning",
                "status_label": "Broken (insecure today)" if is_sub_2048 else "Legacy acceptable (phasing out)",
                "exploitable_today": is_sub_2048,
                "concerns": [
                    f"Diffie-Hellman modulus of {ksize} bits is below 2048 bits; vulnerable to classical precomputation attacks (Logjam)."
                    if is_sub_2048 else
                    f"Finite-field DH at {ksize} bits provides ~112 bits of classical security. Deprecated for new deployments."
                ],
                "standards_reference": STANDARDS["NIST_SP_800_131A"],
            },
            "quantum_threat_analysis": {
                "breaks_security_assumptions": True,
                "quantum_classification": "quantum-vulnerable",
                "quantum_algorithm_applicable": "Shor's Algorithm",
                "why_vulnerable": (
                    "Finite-field Diffie-Hellman and DSA rely on the Discrete Logarithm Problem in the multiplicative "
                    "group of integers modulo a prime (F_p*). Shor's algorithm solves discrete logarithms in polynomial time, "
                    "completely breaking key exchange and signatures once a CRQC is available."
                ),
                "theoretical_vs_active": (
                    "Theoretical future risk: Breaking DH/DSA requires a fault-tolerant CRQC. Classical DH with >= 2048-bit "
                    "moduli is not broken by classical computers, but must be migrated to post-quantum alternatives."
                ),
            },
            "harvest_now_decrypt_later": {
                "applicable": is_dh,
                "risk_level": "critical" if is_dh else "not_applicable",
                "explanation": (
                    "Critical threat for DH key exchange: Handshakes recorded today can be solved by Shor's algorithm, "
                    "retroactively decrypting all exchanged confidential payloads." if is_dh else
                    "Digital signatures are not subject to retroactive decryption, but future signature forgery becomes possible."
                ),
            },
            "remediation_guidance": {
                "recommended_replacement": "ML-KEM (FIPS 203) for key exchange; ML-DSA (FIPS 204) for signatures",
                "transition_strategy": "Replace static DH parameters with hybrid post-quantum key exchange (X25519MLKEM768).",
                "standards_guidance": STANDARDS["NIST_FIPS_203"],
            },
        }

    # 4. Symmetric Ciphers - AES
    if rule_id in ("aes128", "aes256", "aes_ecb"):
        is_ecb = rule_id == "aes_ecb" or mode == "ECB"
        ksize = 128 if rule_id == "aes128" else (key_size or 256)
        algo_name = f"AES-{ksize}" + (" (ECB mode)" if is_ecb else "")

        if is_ecb:
            c_status = "broken"
            c_label = "Broken (currently exploitable classical flaw)"
            c_exploitable = True
            c_concerns = [
                "Currently exploitable classical vulnerability: Electronic Codebook (ECB) mode encrypts identical "
                "plaintext blocks into identical ciphertext blocks, directly leaking structural patterns and data relationships."
            ]
        elif ksize == 128:
            c_status = "acceptable_standard"
            c_label = "Classically secure (weakened under quantum)"
            c_exploitable = False
            c_concerns = [
                "AES-128 is secure against known classical cryptanalysis when used with authenticated modes (GCM/CCM).",
                "NSA CNSA 2.0 and BSI disqualify 128-bit symmetric ciphers for post-quantum national security environments."
            ]
        else:
            c_status = "acceptable_standard"
            c_label = "Classically secure & quantum-resistant"
            c_exploitable = False
            c_concerns = [
                "AES-256 meets the highest classical security standards. Authenticated encryption (GCM/CCM) recommended."
            ]

        # Quantum evaluation: Grover's algorithm
        is_256 = ksize >= 256
        q_class = "quantum-resistant" if is_256 else "not yet confidently classified"
        q_why = (
            "Quantum-resistant: Lov Grover's 1996 quantum search algorithm provides a quadratic speedup for exhaustive "
            "key search (O(sqrt(2^k)) vs classical O(2^k)). For AES-256, Grover's algorithm reduces the effective brute-force "
            "complexity from 2^256 to 2^128 quantum operations. A 128-bit quantum security margin requires ~3.4 x 10^38 quantum "
            "operations, which remains completely intractable under known physical laws for any realizable quantum computer."
            if is_256 else
            "Quantum-weakened: Grover's algorithm provides a quadratic speedup for exhaustive key search, halving the effective "
            "key length exponent from 2^128 to 2^64. While 2^64 quantum operations is still non-trivial, it drops the security margin "
            "below the 112-bit safe threshold. For long-lived confidential data, AES-256 is recommended by NIST and mandated by NSA CNSA 2.0."
        )

        return {
            "algorithm_name": algo_name,
            "detected_parameters": params,
            "current_security_concerns": {
                "status": c_status,
                "status_label": c_label,
                "exploitable_today": c_exploitable,
                "concerns": c_concerns,
                "standards_reference": STANDARDS["NSA_CNSA_2"] if not is_ecb else "NIST SP 800-38A",
            },
            "quantum_threat_analysis": {
                "breaks_security_assumptions": False,
                "quantum_classification": q_class,
                "quantum_algorithm_applicable": "Grover's Algorithm",
                "why_vulnerable": q_why,
                "theoretical_vs_active": (
                    "Theoretical future risk: Grover's algorithm requires large-scale fault-tolerant quantum computers with "
                    "millions of physical qubits to run quantum circuits for AES evaluation. No such attack is possible today."
                ),
            },
            "harvest_now_decrypt_later": {
                "applicable": True,
                "risk_level": "medium" if ksize == 128 else "low",
                "explanation": (
                    f"Data encrypted with AES-{ksize} stored today could theoretically be targeted by Grover search in the far future. "
                    + ("AES-256 maintains a comfortable 128-bit margin against Grover's attack." if is_256 else
                       "AES-128 margin drops to 64 bits; sensitive data should be upgraded to AES-256.")
                ),
            },
            "remediation_guidance": {
                "recommended_replacement": "AES-256-GCM or ChaCha20-Poly1305" if (is_ecb or ksize < 256) else "Keep AES-256-GCM",
                "transition_strategy": "Migrate symmetric encryption keys to 256 bits and ensure authenticated modes (GCM/CCM).",
                "standards_guidance": STANDARDS["NSA_CNSA_2"],
            },
        }

    # 5. ChaCha20
    if rule_id == "chacha":
        return {
            "algorithm_name": "ChaCha20",
            "detected_parameters": params,
            "current_security_concerns": {
                "status": "acceptable_standard",
                "status_label": "Classically secure",
                "exploitable_today": False,
                "concerns": [
                    "ChaCha20 provides 256 bits of classical security; pair with Poly1305 for authentication."
                ],
                "standards_reference": "RFC 8439",
            },
            "quantum_threat_analysis": {
                "breaks_security_assumptions": False,
                "quantum_classification": "quantum-resistant",
                "quantum_algorithm_applicable": "Grover's Algorithm",
                "why_vulnerable": (
                    "Quantum-resistant: ChaCha20 uses a 256-bit key. Grover's algorithm reduces effective search complexity "
                    "to 2^128 operations, which remains completely infeasible for any physical quantum computer."
                ),
                "theoretical_vs_active": "Quantum search attack is theoretical and intractable against 256-bit keys.",
            },
            "harvest_now_decrypt_later": {
                "applicable": True,
                "risk_level": "low",
                "explanation": "256-bit symmetric stream cipher provides robust post-quantum defense-in-depth against HNDL.",
            },
            "remediation_guidance": {
                "recommended_replacement": "Keep ChaCha20-Poly1305",
                "transition_strategy": "No migration required; ensure proper nonce uniqueness.",
                "standards_guidance": "RFC 8439",
            },
        }

    # 6. Legacy / Broken Symmetric Ciphers (DES, 3DES, RC4, Blowfish, ZipCrypto)
    if rule_id in ("des", "tdes", "rc4", "blowfish", "zip_crypto"):
        name_map = {
            "des": "DES", "tdes": "3DES / Triple DES", "rc4": "RC4",
            "blowfish": "Blowfish", "zip_crypto": "PKWARE ZipCrypto"
        }
        name = name_map.get(rule_id, "Legacy cipher")
        reason_map = {
            "des": "DES uses a 56-bit key trivially brute-forced on commodity hardware in hours.",
            "tdes": f"Triple-DES has a 64-bit block size susceptible to Sweet32 collision attacks ({STANDARDS['SWEET32']}); retired by NIST after 2023.",
            "rc4": f"RC4 has severe keystream biases allowing plaintext recovery; prohibited in TLS ({STANDARDS['RFC_7465']}).",
            "blowfish": "Blowfish has a 64-bit block size susceptible to Sweet32 birthday collision attacks.",
            "zip_crypto": "PKWARE ZipCrypto stream cipher is cryptographically broken and cracked in minutes via known plaintext attacks.",
        }

        return {
            "algorithm_name": name,
            "detected_parameters": params,
            "current_security_concerns": {
                "status": "broken",
                "status_label": "Broken (actively exploitable classical vulnerability)",
                "exploitable_today": True,
                "concerns": [reason_map[rule_id]],
                "standards_reference": STANDARDS["NIST_SP_800_131A"],
            },
            "quantum_threat_analysis": {
                "breaks_security_assumptions": True,
                "quantum_classification": "quantum-vulnerable",
                "quantum_algorithm_applicable": "Grover's Algorithm (Superceded by Classical Attacks)",
                "why_vulnerable": (
                    f"{name} is already completely broken by classical attacks today. Any future quantum capability "
                    "would further reduce key search to triviality, but quantum computing is not required to compromise it."
                ),
                "theoretical_vs_active": (
                    "Active vulnerability today: Exploitable right now using commodity classical hardware without quantum computers."
                ),
            },
            "harvest_now_decrypt_later": {
                "applicable": True,
                "risk_level": "critical",
                "explanation": "Adversaries can decrypt this data immediately today using classical tools; no quantum waiting period is needed.",
            },
            "remediation_guidance": {
                "recommended_replacement": "AES-256-GCM or ChaCha20-Poly1305",
                "transition_strategy": "Immediately re-encrypt all stored data and replace cipher suites with AES-256-GCM.",
                "standards_guidance": STANDARDS["NIST_SP_800_131A"],
            },
        }

    # 7. Hash Functions
    if rule_id in ("sha2", "md5", "sha1"):
        if rule_id in ("md5", "sha1"):
            name = "MD5" if rule_id == "md5" else "SHA-1"
            ref = STANDARDS["SHATTERED"] if rule_id == "sha1" else "Wang et al. (2004)"
            return {
                "algorithm_name": name,
                "detected_parameters": params,
                "current_security_concerns": {
                    "status": "broken",
                    "status_label": "Broken (practical classical collision attacks)",
                    "exploitable_today": True,
                    "concerns": [
                        f"{name} has demonstrated practical collision attacks ({ref}). Disallowed for signatures and certificates."
                    ],
                    "standards_reference": STANDARDS["NIST_SP_800_131A"],
                },
                "quantum_threat_analysis": {
                    "breaks_security_assumptions": True,
                    "quantum_classification": "quantum-vulnerable",
                    "quantum_algorithm_applicable": "Grover's & BHT Algorithms (Superceded by Classical Attacks)",
                    "why_vulnerable": (
                        f"{name} is already broken classically. Quantum collision algorithms further trivialise search, "
                        "but the algorithm is already untrustworthy today."
                    ),
                    "theoretical_vs_active": "Currently exploitable classical collision vulnerabilities exist today.",
                },
                "harvest_now_decrypt_later": {
                    "applicable": False,
                    "risk_level": "not_applicable",
                    "explanation": "Hash functions are one-way digests and do not encrypt confidential payloads.",
                },
                "remediation_guidance": {
                    "recommended_replacement": "SHA-256, SHA-384, or SHA-3",
                    "transition_strategy": "Upgrade signatures and HMAC digests to SHA-256 or SHA-384. Use Argon2id for passwords.",
                    "standards_guidance": STANDARDS["NIST_SP_800_131A"],
                },
            }
        else:
            # SHA-2 / SHA-3
            return {
                "algorithm_name": "SHA-2 / SHA-3",
                "detected_parameters": params,
                "current_security_concerns": {
                    "status": "acceptable_standard",
                    "status_label": "Classically secure",
                    "exploitable_today": False,
                    "concerns": [
                        "SHA-256 and SHA-384/512 have no known practical collision or preimage attacks."
                    ],
                    "standards_reference": "NIST FIPS 180-4 / FIPS 202",
                },
                "quantum_threat_analysis": {
                    "breaks_security_assumptions": False,
                    "quantum_classification": "quantum-resistant",
                    "quantum_algorithm_applicable": "Grover's (Preimage) & BHT (Collision)",
                    "why_vulnerable": (
                        "Quantum-resistant: Hash functions have two metrics: (1) Preimage resistance: Grover's algorithm reduces "
                        "search complexity from 2^256 to 2^128 quantum operations, which remains fully secure. (2) Collision resistance: "
                        "Quantum BHT algorithms theoretically reduce collision search to O(2^(n/3)) = 2^85 operations, but require "
                        "infeasible amounts of quantum RAM (qRAM). Under practical hardware bounds, SHA-256 and SHA-384/512 provide "
                        "robust post-quantum security."
                    ),
                    "theoretical_vs_active": "Quantum attacks on SHA-2/SHA-3 are theoretical and computationally intractable.",
                },
                "harvest_now_decrypt_later": {
                    "applicable": False,
                    "risk_level": "not_applicable",
                    "explanation": "Hash functions do not store or encrypt recoverable data.",
                },
                "remediation_guidance": {
                    "recommended_replacement": "Keep SHA-256 / SHA-384 / SHA-512",
                    "transition_strategy": "Maintain standard digest usage; choose SHA-384 for NSA CNSA 2.0 compliance.",
                    "standards_guidance": STANDARDS["NSA_CNSA_2"],
                },
            }

    # 8. Post-Quantum Algorithms (ML-KEM, ML-DSA, SLH-DSA)
    if rule_id == "pqc":
        return {
            "algorithm_name": "Post-Quantum Cryptography (ML-KEM / ML-DSA / SLH-DSA)",
            "detected_parameters": params,
            "current_security_concerns": {
                "status": "acceptable_standard",
                "status_label": "NIST Standardized Post-Quantum Primitive",
                "exploitable_today": False,
                "concerns": [
                    "New implementations require careful side-channel review and constant-time polynomial multiplication."
                ],
                "standards_reference": f"{STANDARDS['NIST_FIPS_203']}, {STANDARDS['NIST_FIPS_204']}, {STANDARDS['NIST_FIPS_205']}",
            },
            "quantum_threat_analysis": {
                "breaks_security_assumptions": False,
                "quantum_classification": "quantum-resistant",
                "quantum_algorithm_applicable": "None (Lattice / Hash hardness holds against Quantum Computers)",
                "why_vulnerable": (
                    "Quantum-resistant: Based on the hardness of Module Learning With Errors (M-LWE), Module Short Integer Solution "
                    "(M-SIS), or cryptographic hash trees. No known quantum algorithm (including Shor's or Grover's) solves these "
                    "lattice problems in polynomial time."
                ),
                "theoretical_vs_active": "Formally standardized by NIST in August 2024; resistant to known quantum attacks.",
            },
            "harvest_now_decrypt_later": {
                "applicable": False,
                "risk_level": "low",
                "explanation": "ML-KEM encapsulates keys resistant to future quantum decryption, neutralizing HNDL threats.",
            },
            "remediation_guidance": {
                "recommended_replacement": "Keep ML-KEM / ML-DSA",
                "transition_strategy": "Maintain hybrid deployment (e.g. X25519MLKEM768) during transition for backwards compatibility.",
                "standards_guidance": STANDARDS["NIST_FIPS_203"],
            },
        }

    # 9. Deprecated TLS / Protocol
    if rule_id == "weak_tls":
        return {
            "algorithm_name": "Deprecated TLS / SSL Protocol",
            "detected_parameters": params,
            "current_security_concerns": {
                "status": "broken",
                "status_label": "Broken (actively exploitable classical vulnerability)",
                "exploitable_today": True,
                "concerns": [
                    f"SSL 2.0/3.0 and TLS 1.0/1.1 are deprecated by {STANDARDS['RFC_8996']} with known attacks (POODLE, BEAST, DROWN)."
                ],
                "standards_reference": STANDARDS["RFC_8996"],
            },
            "quantum_threat_analysis": {
                "breaks_security_assumptions": True,
                "quantum_classification": "quantum-vulnerable",
                "quantum_algorithm_applicable": "Shor's Algorithm (Handshake) & Classical Attacks",
                "why_vulnerable": (
                    "Negotiated handshakes rely on classical RSA/DHE key exchange vulnerable to Shor's algorithm, "
                    "and the protocol framing itself is vulnerable to classical plaintext injection."
                ),
                "theoretical_vs_active": "Currently exploitable classical protocol flaws exist today.",
            },
            "harvest_now_decrypt_later": {
                "applicable": True,
                "risk_level": "critical",
                "explanation": "Sessions negotiated using weak TLS versions can be intercepted and decrypted.",
            },
            "remediation_guidance": {
                "recommended_replacement": "TLS 1.3 with hybrid post-quantum key exchange",
                "transition_strategy": "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 in web server and TLS client configurations.",
                "standards_guidance": STANDARDS["RFC_8996"],
            },
        }

    # Default fallback
    return {
        "algorithm_name": rule_id.upper(),
        "detected_parameters": params,
        "current_security_concerns": {
            "status": "legacy_warning",
            "status_label": "Review required",
            "exploitable_today": False,
            "concerns": ["Cryptographic configuration should be evaluated against NIST SP 800-131A."],
            "standards_reference": STANDARDS["NIST_SP_800_131A"],
        },
        "quantum_threat_analysis": {
            "breaks_security_assumptions": False,
            "quantum_classification": "not yet confidently classified",
            "quantum_algorithm_applicable": "Unknown",
            "why_vulnerable": "Detailed quantum classification depends on specific primitive and key parameters.",
            "theoretical_vs_active": "Theoretical risk evaluation required.",
        },
        "harvest_now_decrypt_later": {
            "applicable": False,
            "risk_level": "low",
            "explanation": "Evaluate whether algorithm protects long-lived confidentiality.",
        },
        "remediation_guidance": {
            "recommended_replacement": "Review against NIST post-quantum guidance",
            "transition_strategy": "Conduct cryptographic inventory.",
            "standards_guidance": STANDARDS["NIST_IR_8547"],
        },
    }
