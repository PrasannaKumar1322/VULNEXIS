"""
Q-SHIELD Post-Quantum Cryptography (PQC) Migration Recommendation Engine.

Evaluates detected cryptographic algorithms and generates structured, role-aware
migration recommendations based on:
  1. Protocol role (key encapsulation, digital signature, symmetric encryption, hashing, KDF, TLS).
  2. Standards-backed alternatives (NIST FIPS 203, FIPS 204, FIPS 205, NIST SP 800-38D).
  3. Performance vs assurance trade-offs (e.g. ML-DSA vs SLH-DSA).
  4. Interoperability and backward-compatibility considerations (hybrid schemes, MTU/buffer limits).
  5. Platform and library readiness (OpenSSL 3.2+, Bouncy Castle 1.78+, Go 1.24+, Envoy).
  6. Contextual data sensitivity and retention lifetime assessments (e.g. AES-128 vs AES-256).

Strictly analytical and advisory: Never automatically alters source files or generates production keys.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------
# Standards & Ecosystem References
# --------------------------------------------------------------------------
PQC_STANDARDS = {
    "FIPS_203": "NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism - ML-KEM)",
    "FIPS_204": "NIST FIPS 204 (Module-Lattice-Based Digital Signature Algorithm - ML-DSA)",
    "FIPS_205": "NIST FIPS 205 (Stateless Hash-Based Digital Signature Algorithm - SLH-DSA)",
    "SP_800_38D": "NIST SP 800-38D (Galois/Counter Mode - GCM for Block Cipher Modes)",
    "RFC_8446": "RFC 8446 (The Transport Layer Security (TLS) Protocol Version 1.3)",
    "RFC_9180": "RFC 9180 (Hybrid Public Key Encryption - HPKE)",
    "RFC_9106": "RFC 9106 (Argon2 Memory-Hard Function for Password Hashing)",
    "RFC_5869": "RFC 5869 (HMAC-based Extract-and-Expand Key Derivation Function - HKDF)",
    "NIST_IR_8547": "NIST IR 8547 (Transition to Post-Quantum Cryptography Standards)",
    "NIST_SP_800_131A": "NIST SP 800-131A Rev. 2 (Transitioning Cryptographic Algorithms and Key Lengths)",
}

PLATFORM_ECOSYSTEM = {
    "openssl": "OpenSSL 3.2+ / 3.4+ supports TLS 1.3 hybrid key exchange (X25519MLKEM768) and OQS / third-party PQC provider modules.",
    "bouncy_castle": "Bouncy Castle Java / C# (1.78+) provides native implementations of ML-KEM, ML-DSA, and SLH-DSA.",
    "golang": "Go 1.24+ includes X25519MLKEM768 enabled by default in crypto/tls.",
    "rust": "Rust ecosystem supports PQC via 'aws-lc-rs', 'rustls' (with hybrid KEM), and the 'pqcrypto' crate suite.",
    "web_pki_envoy": "Envoy Proxy, Cloudflare, and major web browsers (Chrome 124+, Firefox 132+) negotiate hybrid X25519MLKEM768 by default.",
}


# --------------------------------------------------------------------------
# Helper: Detect Protocol Role
# --------------------------------------------------------------------------
def detect_protocol_role(
    rule_id: str,
    parsed_labels: Optional[List[str]] = None,
    snippet: str = "",
    category: str = "",
    mode: Optional[str] = None,
) -> str:
    """
    Infer the protocol role from detection metadata without making unjustified assumptions.
    """
    labels_str = " ".join(parsed_labels or []).lower()
    text = f"{snippet} {labels_str} {category}".lower()

    if rule_id in ("weak_tls",) or "tls" in category.lower() or "ssl" in category.lower():
        return "tls_transport"

    if rule_id in ("des", "tdes", "rc4", "blowfish", "zip_crypto", "pdf_crypto", "aes_ecb"):
        return "symmetric_encryption"

    if rule_id in ("aes128", "aes256"):
        return "symmetric_encryption"

    if rule_id in ("md5", "sha1"):
        if any(w in text for w in ("password", "passwd", "pwd", "auth", "bcrypt", "scrypt", "argon", "hashpw")):
            return "password_hashing"
        if any(w in text for w in ("hkdf", "pbkdf", "derive", "kdf", "key_derivation")):
            return "key_derivation"
        if any(w in text for w in ("signature", "sign", "verify", "cert", "x509", "signed")):
            return "digital_signature"
        return "cryptographic_hash"

    if rule_id == "rsa":
        if any(w in text for w in ("sign", "signature", "verify", "pss", "rsassa", "pkcs1v15_sign")):
            return "digital_signature"
        if any(w in text for w in ("encrypt", "decrypt", "oaep", "kem", "key_exchange", "cipher", "envelope")):
            return "key_establishment"
        if any(w in text for w in ("cert", "x.509", "crt", "csr", "pem")):
            return "certificate_pki"
        return "asymmetric_general"

    if rule_id in ("ecdsa", "dsa"):
        return "digital_signature"

    if rule_id in ("ecdh", "dh", "elgamal"):
        return "key_establishment"

    if rule_id == "ecc_curve":
        if any(w in text for w in ("sign", "ecdsa", "eddsa")):
            return "digital_signature"
        if any(w in text for w in ("ecdh", "kex", "exchange", "x25519", "x448")):
            return "key_establishment"
        return "asymmetric_general"

    if rule_id in ("ml_kem", "frodo_kem"):
        return "key_establishment"

    if rule_id in ("ml_dsa", "slh_dsa", "falcon"):
        return "digital_signature"

    if rule_id == "private_key":
        return "key_storage_management"

    return "general_cryptography"


# --------------------------------------------------------------------------
# Rule-Specific Recommendation Builders
# --------------------------------------------------------------------------

def _rec_rsa(finding: Dict[str, Any], context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    role = detect_protocol_role(
        "rsa",
        finding.get("parsed"),
        finding.get("occurrences", [{}])[0].get("snippet", "") if finding.get("occurrences") else "",
        finding.get("category", ""),
    )
    ksize = finding.get("key_size") or 2048
    is_sub_2048 = ksize < 2048

    if role in ("digital_signature", "certificate_pki"):
        return {
            "original_algorithm": f"RSA-{ksize} (Digital Signature / PKI)",
            "protocol_role": "Digital Signature / Public Key Infrastructure",
            "proposed_alternative": "ML-DSA-65 (FIPS 204) for general/TLS signatures, or SLH-DSA (FIPS 205) for long-lived root trust",
            "reason": (
                "RSA signatures rely on the integer factorization problem, which Shor's algorithm solves in polynomial time "
                "on a Cryptographically Relevant Quantum Computer (CRQC). While signatures are not subject to retroactive "
                "Harvest-Now-Decrypt-Later confidentiality loss, certificates and code signatures must be verified for years into the "
                "future. ML-DSA provides high performance and verification speed for interactive signing, whereas SLH-DSA provides "
                "conservative, stateless hash-based assurance for root CAs and firmware."
            ),
            "tradeoff_analysis": {
                "ml_dsa_vs_slh_dsa": {
                    "ml_dsa": {
                        "standard": PQC_STANDARDS["FIPS_204"],
                        "best_for": "General-purpose application signatures, TLS certificates, API authentication",
                        "advantages": "Fast key generation, extremely fast signature verification, practical public key size (~1,952 B) and signature size (~3,309 B for ML-DSA-65)",
                        "considerations": "Relies on module-lattice hardness assumptions (MLWE / MSIS)",
                    },
                    "slh_dsa": {
                        "standard": PQC_STANDARDS["FIPS_205"],
                        "best_for": "Root CA trust anchors, firmware signing, secure boot, code signing archives",
                        "advantages": "Stateless hash-based; security relies strictly on classical collision/preimage resistance of SHA-2/SHAKE, offering the most conservative post-quantum assurance",
                        "considerations": "Signatures are significantly larger (~7.8 KB to ~17 KB) and signing throughput is substantially slower",
                    },
                }
            },
            "standards_basis": [PQC_STANDARDS["FIPS_204"], PQC_STANDARDS["FIPS_205"], PQC_STANDARDS["NIST_IR_8547"]],
            "compatibility_considerations": (
                "1. Signature size expansion: An RSA-2048 signature is 256 bytes; ML-DSA-65 is 3,309 bytes and SLH-DSA-128s is 7,856 bytes. "
                "Ensure network packet buffers, TLS handshake records, and database signature columns accommodate the expansion.\n"
                "2. Dual / Composite signatures: During migration, consider hybrid/composite certificates (combining RSA with ML-DSA) "
                "so legacy verifiers can validate the classical component while modern peers validate the quantum-safe signature.\n"
                "3. CA & Trust Store Support: Verify WebPKI and internal enterprise CA support before revoking RSA certificates."
            ),
            "implementation_steps": [
                "1. Audit all signing endpoints to identify whether signatures are ephemeral (API tokens) or long-lived (X.509 certs, code signing).",
                "2. For general application and TLS signing, adopt ML-DSA-65 (FIPS 204); for root keys or firmware, evaluate SLH-DSA (FIPS 205).",
                "3. Update cryptographic libraries to versions supporting FIPS 204/205 (e.g. Bouncy Castle 1.78+, OpenSSL 3.4+ / OQS provider).",
                "4. Expand signature and public key buffer storage in application schemas and network protocol headers.",
                "5. Implement hybrid or composite certificate chains during transitional phases where legacy client validation is required.",
            ],
            "testing_requirements": [
                "Validate certificate chain path building across both hybrid-aware and legacy-only TLS clients.",
                "Verify network handling of multi-kilobyte certificates and handshake messages across middleboxes and firewalls.",
                "Benchmark signing and verification latency under peak transaction loads.",
                "Perform downgrade-resistance testing to confirm clients cannot be forced to accept stripped classical signatures.",
            ],
            "priority": "Immediate" if is_sub_2048 else "Medium",
        }

    # RSA Key Establishment / Encryption / General
    return {
        "original_algorithm": f"RSA-{ksize} (Key Establishment / Encryption)",
        "protocol_role": "Key Establishment / Key Encapsulation (KEM)",
        "proposed_alternative": "ML-KEM-768 (FIPS 203) with hybrid X25519MLKEM768 key exchange",
        "reason": (
            "RSA encryption and key exchange are completely vulnerable to Shor's algorithm on a CRQC. Furthermore, RSA key "
            "exchanges are exposed to the active Harvest-Now-Decrypt-Later (HNDL) threat: adversaries can intercept and record "
            "encrypted traffic today and decrypt it retroactively once a quantum computer is available. Migration to ML-KEM-768 "
            "via hybrid key exchange (X25519MLKEM768) provides immediate post-quantum confidentiality while retaining classical "
            "assurance and FIPS 140 compliance."
        ),
        "standards_basis": [PQC_STANDARDS["FIPS_203"], PQC_STANDARDS["RFC_9180"], PQC_STANDARDS["RFC_8446"]],
        "compatibility_considerations": (
            "1. Ciphertext expansion: RSA-2048 ciphertext is 256 bytes; ML-KEM-768 ciphertext is 1,088 bytes and public key is 1,184 bytes. "
            "Check network MTU, TCP segmentation, and buffer allocations.\n"
            "2. Protocol Support: In TLS, ML-KEM is deployed via hybrid groups (e.g., X25519MLKEM768 in TLS 1.3). Ensure servers and clients "
            "have TLS 1.3 enabled and support post-quantum key shares (supported in OpenSSL 3.2+, Go 1.24+, Chromium, Envoy).\n"
            "3. Data-at-Rest Envelope Encryption: For envelope encryption replacing RSA-OAEP, transition to Hybrid Public Key Encryption "
            "(HPKE, RFC 9180) combining ML-KEM with AES-256-GCM."
        ),
        "implementation_steps": [
            "1. Identify whether RSA is used for network session key exchange (TLS/SSH) or static envelope encryption (data at rest).",
            "2. For network transit, upgrade to TLS 1.3 and enable hybrid group X25519MLKEM768.",
            "3. For envelope encryption, transition from RSA-OAEP to HPKE (RFC 9180) with ML-KEM-768 encapsulation.",
            "4. Verify that client and server cryptographic libraries are updated (e.g. OpenSSL 3.2+, Go 1.24+, Bouncy Castle 1.78+).",
            "5. Maintain transitional hybrid modes to ensure non-PQC clients continue to function until deprecation deadlines.",
        ],
        "testing_requirements": [
            "Interoperability testing with both legacy and quantum-ready endpoints to ensure seamless handshake negotiation.",
            "Handshake fragmentation testing across network proxies, firewalls, and cloud load balancers.",
            "Latency and CPU profiling for ML-KEM encapsulation/decapsulation compared to legacy RSA operations.",
            "Regression testing on data-at-rest decryption to verify dual-decryption compatibility during migration.",
        ],
        "priority": "Immediate" if is_sub_2048 else "High",
    }


def _rec_ecdsa_signatures(finding: Dict[str, Any], context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    algo = finding.get("algorithm", "ECDSA")
    return {
        "original_algorithm": f"{algo} (Digital Signature)",
        "protocol_role": "Digital Signature / Authentication",
        "proposed_alternative": "ML-DSA-65 (FIPS 204) for general-purpose/TLS signing, or SLH-DSA (FIPS 205) for high-assurance root anchors",
        "reason": (
            "ECDSA, Ed25519, and conventional elliptic-curve digital signature algorithms rely on the Elliptic Curve Discrete "
            "Logarithm Problem (ECDLP). Shor's algorithm solves ECDLP in polynomial time on a quantum computer with fewer qubits "
            "than required to factor RSA. To protect future authentication, token signing, and long-lived certificate integrity, "
            "digital signatures must migrate to NIST-standardized post-quantum signature schemes."
        ),
        "tradeoff_analysis": {
            "ml_dsa_vs_slh_dsa": {
                "ml_dsa": {
                    "standard": PQC_STANDARDS["FIPS_204"],
                    "best_for": "Interactive protocols, API JWT authentication, TLS handshakes, code signing pipelines",
                    "advantages": "Sub-millisecond signing and verification speeds; practical public key (~1,952 B) and signature (~3,309 B) sizes",
                    "considerations": "Lattice-based (Module Learning With Errors / Module Short Integer Solution)",
                },
                "slh_dsa": {
                    "standard": PQC_STANDARDS["FIPS_205"],
                    "best_for": "Root CA certificates, firmware updates, secure boot ROMs, legal document preservation",
                    "advantages": "Stateless hash-based; security depends strictly on standard hash functions without new mathematical lattice hardness assumptions",
                    "considerations": "Signatures are much larger (~7.8 KB to ~17 KB); signing operations are computationally intensive",
                },
            }
        },
        "standards_basis": [PQC_STANDARDS["FIPS_204"], PQC_STANDARDS["FIPS_205"], PQC_STANDARDS["NIST_IR_8547"]],
        "compatibility_considerations": (
            "1. Major Signature Size Expansion: ECDSA P-256 signatures are 64 bytes; ML-DSA-65 signatures are 3,309 bytes (~50x larger). "
            "Verify that transport buffers, HTTP header limits (for Bearer tokens/JWTs), and database schema sizes can store 3+ KB values.\n"
            "2. Ecosystem Support: While OpenSSL 3.4+ and Bouncy Castle 1.78+ support FIPS 204/205, widespread WebPKI support is still evolving. "
            "Use hybrid dual-signature certificates where legacy verifiers cannot be updated simultaneously.\n"
            "3. Hardware Security Modules: Check HSM and smartcard vendor roadmaps for native FIPS 204/205 coprocessor acceleration."
        ),
        "implementation_steps": [
            "1. Categorize signature usage: high-volume interactive transactions (use ML-DSA-65) vs root/firmware trust anchors (use SLH-DSA).",
            "2. Update cryptographic dependencies to libraries supporting NIST FIPS 204/205 standards.",
            "3. Adjust transport protocol MTUs, HTTP header limits, and database columns for 3–8 KB signature and key payloads.",
            "4. Deploy composite/dual signing in intermediate stages: produce both an ECDSA and ML-DSA signature for cross-client compatibility.",
            "5. Plan CA hierarchy re-keying and certificate rotation aligned with ecosystem adoption.",
        ],
        "testing_requirements": [
            "Header and payload size limits verification across API gateways and reverse proxies.",
            "Interoperability tests validating dual-signature verification on both modern and legacy clients.",
            "Throughput and memory benchmarking for signature generation and verification under peak load.",
            "Validation of certificate revocation and OCSP/CRL handling with expanded PQC certificate sizes.",
        ],
        "priority": "Medium",
    }


def _rec_ecdh_kex(finding: Dict[str, Any], context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    algo = finding.get("algorithm", "ECDH")
    return {
        "original_algorithm": f"{algo} (Key Exchange)",
        "protocol_role": "Key Establishment / Key Exchange",
        "proposed_alternative": "ML-KEM-768 (FIPS 203) with hybrid X25519MLKEM768 key exchange",
        "reason": (
            "Elliptic Curve Diffie-Hellman (ECDH, X25519, X448) relies on the hardness of ECDLP, which Shor's algorithm completely "
            "breaks on a quantum computer. All data transmitted today using ECDH key exchange is susceptible to Harvest-Now-Decrypt-Later "
            "(HNDL) attacks if adversaries record network traffic. Deploying hybrid key exchange (X25519MLKEM768) immediately shields "
            "transmitted sessions from retroactive quantum decryption while preserving proven classical elliptic-curve security."
        ),
        "standards_basis": [PQC_STANDARDS["FIPS_203"], PQC_STANDARDS["RFC_8446"], PQC_STANDARDS["NIST_IR_8547"]],
        "compatibility_considerations": (
            "1. TLS 1.3 Requirement: Post-quantum hybrid key exchange (such as X25519MLKEM768 / codepoint 0x11ec) is standardized "
            "exclusively for TLS 1.3. Endpoints must support TLS 1.3.\n"
            "2. Handshake Size: Hybrid key shares in the ClientHello add ~1.2 KB of payload, which may cause ClientHello messages "
            "to span multiple TCP packets. Verify that middleboxes do not improperly reject multi-record ClientHello messages.\n"
            "3. Server / Proxy Support: Envoy, Nginx with OpenSSL 3.2+, and major CDNs (Cloudflare, AWS CloudFront) support hybrid KEX out-of-the-box."
        ),
        "implementation_steps": [
            "1. Enforce TLS 1.3 across all client and server endpoints, disabling legacy TLS versions.",
            "2. Configure the hybrid post-quantum named group `X25519MLKEM768` (or `X25519Kyber768Draft00` where interim drafts are used) as preferred in the cipher/group order.",
            "3. Verify that upstream reverse proxies and load balancers pass hybrid TLS extensions without stripping unknown group IDs.",
            "4. Verify client SDKs (Go 1.24+, Java 21+ with Bouncy Castle, Python with modern OpenSSL) support hybrid negotiation.",
            "5. Monitor TLS connection success rates to confirm legacy clients successfully fall back to standard X25519.",
        ],
        "testing_requirements": [
            "Handshake negotiation testing with both hybrid-capable and classical-only client configurations.",
            "Network packet capture analysis to verify proper TCP segmentation and reassembly of ClientHello key shares.",
            "Session resumption and 0-RTT validation with post-quantum hybrid keys.",
            "Performance benchmarking to quantify any latency impacts from the larger key exchange records.",
        ],
        "priority": "High",
    }


def _rec_weak_symmetric(finding: Dict[str, Any], context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    algo = finding.get("algorithm", "Legacy Symmetric Cipher")
    rule_id = finding.get("rule_id", "")
    is_ecb = rule_id == "aes_ecb"

    return {
        "original_algorithm": f"{algo}{' (ECB Mode)' if is_ecb else ''}",
        "protocol_role": "Symmetric Encryption / Data Protection",
        "proposed_alternative": "AES-256-GCM (NIST SP 800-38D) or ChaCha20-Poly1305 (RFC 8439)",
        "reason": (
            f"{algo} exhibits severe classical vulnerabilities: "
            + ("Electronic Codebook (ECB) mode lacks diffusion and leaks plaintext patterns directly through repeated ciphertext blocks. " if is_ecb else "")
            + ("64-bit block ciphers (DES, 3DES, Blowfish) are vulnerable to birthday attacks (Sweet32) after just ~32 GB of data. " if rule_id in ("des", "tdes", "blowfish") else "")
            + ("RC4 is vulnerable to keystream biases and plaintext recovery attacks. " if rule_id == "rc4" else "")
            + "Furthermore, legacy ciphers lack Authenticated Encryption with Associated Data (AEAD), leaving data vulnerable to ciphertext tampering. "
            "Upgrading to AES-256-GCM provides authenticated encryption classically and maintains a 128-bit quantum security margin against Grover's algorithm."
        ),
        "standards_basis": [PQC_STANDARDS["SP_800_38D"], PQC_STANDARDS["NIST_SP_800_131A"]],
        "compatibility_considerations": (
            "1. AEAD API Transition: Upgrading from unauthenticated modes (ECB, CBC) to AEAD (GCM, ChaCha20-Poly1305) requires managing "
            "a 96-bit unique Initialization Vector (IV / Nonce) and a 128-bit authentication tag. Ciphertext format must be updated.\n"
            "2. Nonce Uniqueness: AES-GCM catastrophic key recovery occurs if an IV is ever reused with the same key. Use a cryptographically "
            "secure CSPRNG or deterministic counter with strict rotation.\n"
            "3. Hardware Acceleration: AES-256-GCM is hardware-accelerated via AES-NI on modern x86/ARM CPUs. On resource-constrained embedded "
            "devices without AES-NI, ChaCha20-Poly1305 is recommended for superior software performance."
        ),
        "implementation_steps": [
            "1. Replace deprecated cipher calls with modern AEAD primitives (AES-256-GCM or ChaCha20-Poly1305).",
            "2. Update ciphertext storage structures to store the 12-byte (96-bit) nonce and 16-byte (128-bit) tag alongside the ciphertext.",
            "3. Implement secure nonce generation using a CSPRNG or monotonic counter, guaranteeing no nonce is ever reused with the same key.",
            "4. Rotate keys and re-encrypt existing historical data currently stored using the legacy cipher.",
            "5. Remove legacy cipher dependencies and disable fallback decryption routines once re-encryption is completed.",
        ],
        "testing_requirements": [
            "Tamper testing: Verify that altering any single bit of ciphertext or authentication tag causes decryption to abort cleanly.",
            "Nonce uniqueness validation under multi-threaded and distributed concurrent encryption conditions.",
            "Round-trip migration tests verifying existing data can be decrypted with legacy keys and written out under AES-256-GCM.",
            "Performance benchmarking across hardware with and without AES-NI acceleration.",
        ],
        "priority": "Immediate",
    }


def _rec_aes128(finding: Dict[str, Any], context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    ctx = context or {}
    lifetime = ctx.get("confidentiality_lifetime", "")
    sensitivity = ctx.get("data_sensitivity", "")
    is_long_lived = lifetime in ("10+_years", "5-9_years")
    is_high_sensitivity = sensitivity in ("critical", "high")

    need_upgrade = is_long_lived or is_high_sensitivity

    reason = (
        "AES-128 is classically robust today with no practical classical attacks known. However, Grover's algorithm running on a "
        "Cryptographically Relevant Quantum Computer (CRQC) theoretically speeds up exhaustive key search from 2^128 to 2^64 operations. "
        "While 2^64 quantum operations is still a formidable threshold, NIST and NSA CNSA 2.0 mandate AES-256 for long-term secret "
        "protection to ensure a full 128-bit post-quantum security margin. "
    )
    if need_upgrade:
        reason += (
            f"Because this asset has been identified as having {sensitivity or 'elevated'} sensitivity and "
            f"a {lifetime or 'multi-year'} confidentiality lifetime, upgrading to AES-256-GCM is strongly recommended to eliminate any future quantum margin degradation."
        )
    else:
        reason += (
            "Because this asset is not currently flagged as requiring multi-decade confidentiality, AES-128 remains acceptable today, "
            "but cryptographic agility planning should incorporate AES-256-GCM support into upcoming scheduled upgrades."
        )

    return {
        "original_algorithm": "AES-128 (Symmetric Block Cipher)",
        "protocol_role": "Symmetric Encryption / Authenticated Data Protection",
        "proposed_alternative": "AES-256-GCM (NIST SP 800-38D)" if need_upgrade else "AES-256-GCM (Recommended for long-term margin) / Maintain AES-128-GCM for short-lived data",
        "reason": reason,
        "assessment_factors": {
            "grover_security_margin": "AES-128 yields effective 64-bit quantum security; AES-256 yields 128-bit quantum security",
            "confidentiality_lifetime_evaluated": lifetime or "unknown / unconfirmed",
            "data_sensitivity_evaluated": sensitivity or "unknown / unconfirmed",
            "upgrade_recommended_now": need_upgrade,
        },
        "standards_basis": [PQC_STANDARDS["SP_800_38D"], PQC_STANDARDS["NIST_IR_8547"]],
        "compatibility_considerations": (
            "1. Drop-in Cipher Replacement: AES-128 and AES-256 share the same 128-bit block size and GCM mode constructs. "
            "Switching only requires a 32-byte (256-bit) key instead of a 16-byte key.\n"
            "2. Performance Overhead: AES-256 requires 14 rounds compared to 10 rounds for AES-128 (~40% more rounds). "
            "With hardware AES-NI instructions, this CPU overhead is virtually negligible (< 5% throughput impact in modern benchmarks).\n"
            "3. Key Management: Key generation, key vault storage, and KMS key policies must be updated to provision 256-bit keys."
        ),
        "implementation_steps": [
            "1. Evaluate data retention and regulatory requirements to determine if protected assets have long confidentiality lifespans (5+ years).",
            "2. Update key generation routines to derive or generate 256-bit symmetric keys.",
            "3. Transition encryption routines to AES-256-GCM with 96-bit unique nonces.",
            "4. Update KMS / secrets vault key policies to provision 256-bit keys.",
            "5. Schedule re-encryption of existing long-term ciphertext stores during routine maintenance cycles.",
        ],
        "testing_requirements": [
            "Throughput and CPU utilization benchmarks comparing AES-128-GCM and AES-256-GCM on target production hardware.",
            "Key length validation in cryptographic provider initialization to verify 32-byte key enforcement.",
            "Re-encryption pipeline verification for archived records.",
            "Interoperability testing with external integration partners to ensure 256-bit key support.",
        ],
        "priority": "High" if need_upgrade else "Low",
    }


def _rec_hash(finding: Dict[str, Any], context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    algo = finding.get("algorithm", "Legacy Hash")
    rule_id = finding.get("rule_id", "md5")
    role = detect_protocol_role(
        rule_id,
        finding.get("parsed"),
        finding.get("occurrences", [{}])[0].get("snippet", "") if finding.get("occurrences") else "",
        finding.get("category", ""),
    )

    is_md5 = rule_id == "md5"
    vuln_text = "MD5 has practical collision attacks that can be computed in seconds on commodity hardware. " if is_md5 else "SHA-1 has practical collision attacks (SHAttered, 2017) and is forbidden by NIST. "

    if role == "password_hashing":
        alt = "Argon2id (RFC 9106), scrypt, or bcrypt"
        reason = (
            f"{vuln_text}Critically, fast general-purpose hash functions (even modern ones like SHA-256) are entirely unsuitable for "
            "password storage because GPUs and ASIC rigs can compute billions of candidate hashes per second. Passwords must migrate "
            "to memory-hard, salt-enforcing password hashing functions such as Argon2id (RFC 9106)."
        )
        prio = "Immediate"
    elif role == "key_derivation":
        alt = "HKDF-SHA256 (RFC 5869) or PBKDF2 with high iterations"
        reason = (
            f"{vuln_text}For cryptographic key derivation, custom hash loops or raw hashes fail to extract uniform pseudorandomness. "
            "Migrate to HKDF (HMAC-based Extract-and-Expand Key Derivation Function, RFC 5869) using SHA-256 or SHA-384."
        )
        prio = "Immediate"
    elif role == "digital_signature":
        alt = "SHA-256 / SHA-384 with ML-DSA-65 (FIPS 204)"
        reason = (
            f"{vuln_text}When used in digital signatures or certificates, collision attacks permit adversaries to forge certificates "
            "or signatures with identical hashes. Digital signatures must migrate to collision-resistant hash functions (SHA-256/384). "
            "Note: Upgrading the hash alone does not protect against quantum attacks on the signature algorithm (RSA/ECDSA); the signature "
            "scheme itself must also transition to post-quantum algorithms like ML-DSA."
        )
        prio = "Immediate"
    else:
        alt = "SHA-256, SHA-384 (NIST FIPS 180-4) or SHA3-256 (NIST FIPS 202)"
        reason = (
            f"{vuln_text}For data integrity and HMAC authentication, migrate to modern collision-resistant hash functions. "
            "Under Grover's algorithm, preimage resistance of an n-bit hash is reduced to n/2 bits (SHA-256 provides 128 bits of quantum "
            "collision/preimage security, which remains fully secure)."
        )
        prio = "Immediate"

    return {
        "original_algorithm": f"{algo} ({role.replace('_', ' ').title()})",
        "protocol_role": role.replace('_', ' ').title(),
        "proposed_alternative": alt,
        "reason": reason,
        "role_distinctions": {
            "digital_signatures": "Requires collision-resistant SHA-256 or SHA-384. Upgrading hash does not eliminate quantum vulnerability of the signing scheme (RSA/ECDSA); pair with ML-DSA.",
            "password_hashing": "Never use SHA-256/384 for passwords. Use memory-hard Argon2id (RFC 9106), scrypt, or bcrypt to resist GPU brute-force attacks.",
            "key_derivation": "Migrate to HKDF (RFC 5869) using SHA-256/SHA-384 to guarantee entropy extraction and secure expansion.",
            "data_integrity_hmac": "HMAC-SHA256 or SHA3-256 provides strong classical and post-quantum collision resistance.",
        },
        "standards_basis": [PQC_STANDARDS["FIPS_204"], PQC_STANDARDS["RFC_9106"], PQC_STANDARDS["RFC_5869"]],
        "compatibility_considerations": (
            "1. Password Migration: Existing hashes cannot be reverse-computed. Implement migration-on-login: verify legacy hash on user "
            "login and seamlessly re-hash the validated plaintext password using Argon2id.\n"
            "2. Signature Verification: Verifiers must update their accepted digest algorithms and trust stores.\n"
            "3. Output Digest Length: SHA-256 produces 32 bytes (64 hex characters) vs MD5 (16 bytes) and SHA-1 (20 bytes). Ensure storage "
            "columns and network structures accommodate expanded digest lengths."
        ),
        "implementation_steps": [
            "1. Audit the code to identify whether the hash is used for passwords, key derivation, signatures, or simple checksums.",
            "2. For passwords, implement Argon2id with recommended parameters (memory: 64MB, iterations: 3, parallelism: 4) using migration-on-login.",
            "3. For key derivation, replace custom hash loops with HKDF-SHA256 (RFC 5869).",
            "4. For signatures and integrity, update digest calls to SHA-256 or SHA-384.",
            "5. Expand database columns and serialization schemas to accommodate 256-bit or 384-bit output lengths.",
        ],
        "testing_requirements": [
            "Password migration verification: test successful login with legacy hash and verify database records update to Argon2id.",
            "Collision resistance and digest length regression checks.",
            "KDF test vector validation against RFC 5869 test suites.",
            "Interoperability testing with client applications consuming integrity checksums.",
        ],
        "priority": prio,
    }


def _rec_weak_tls(finding: Dict[str, Any], context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "original_algorithm": "Legacy TLS / Deprecated Cipher Suites",
        "protocol_role": "Transport Layer Security / Network Transport",
        "proposed_alternative": "TLS 1.3 with Hybrid Post-Quantum Key Exchange (X25519MLKEM768)",
        "reason": (
            "SSL 2.0/3.0, TLS 1.0, and TLS 1.1 are formally deprecated by RFC 8996 due to fundamental classical vulnerabilities "
            "(POODLE, BEAST, weak MAC-then-encrypt CBC ciphers). Furthermore, TLS 1.2 connections using static RSA or conventional ECDH "
            "key exchange lack post-quantum forward secrecy and are exposed to retroactive Harvest-Now-Decrypt-Later decryption. "
            "Upgrading to TLS 1.3 removes legacy ciphers, mandates AEAD, and enables post-quantum hybrid key shares."
        ),
        "standards_basis": [PQC_STANDARDS["RFC_8446"], PQC_STANDARDS["FIPS_203"], PQC_STANDARDS["NIST_IR_8547"]],
        "platform_support": PLATFORM_ECOSYSTEM,
        "compatibility_considerations": (
            "1. Platform & Runtime Capabilities:\n"
            f"   - OpenSSL: {PLATFORM_ECOSYSTEM['openssl']}\n"
            f"   - Go: {PLATFORM_ECOSYSTEM['golang']}\n"
            f"   - Java: {PLATFORM_ECOSYSTEM['bouncy_castle']}\n"
            f"   - Web Ingress / Edge: {PLATFORM_ECOSYSTEM['web_pki_envoy']}\n"
            "2. Legacy Client Deprecation: Some legacy IoT devices and older OS versions do not support TLS 1.3. "
            "Maintain TLS 1.2 with secure AEAD cipher suites (ECDHE-ECDSA-AES256-GCM-SHA384) as a transitional minimum floor.\n"
            "3. ClientHello Padding: Ensure web server / TLS termination configurations pad ClientHello messages to avoid known middlebox fragmentation bugs."
        ),
        "implementation_steps": [
            "1. In web server and reverse proxy configs (Nginx, Envoy, Apache), set `ssl_protocols TLSv1.3 TLSv1.2;` and disable TLS 1.0/1.1.",
            "2. Enable post-quantum hybrid key exchange groups (e.g. `X25519MLKEM768` / `x25519_kyber768`) in the server's curves/groups configuration.",
            "3. Restrict TLS 1.2 cipher suites to AEAD suites (AES-GCM and ChaCha20-Poly1305), disabling CBC mode and RSA key exchange.",
            "4. Verify that application runtimes and client libraries (OpenSSL, Java, Python, Go) are updated to versions supporting modern TLS 1.3.",
            "5. Verify automated certificate renewal (ACME / cert-manager) operates smoothly under the new TLS configuration.",
        ],
        "testing_requirements": [
            "Run automated TLS handshake checks verifying TLS 1.0, 1.1, and SSL 3.0 handshakes are strictly rejected.",
            "Verify modern browsers negotiate TLS 1.3 with X25519MLKEM768 key exchange.",
            "Test legacy client fallback to confirm valid TLS 1.2 clients continue to connect without disruption.",
            "Scan TLS endpoint using SSL Labs / testssl.sh to verify 'A+' grade configuration and no weak ciphers.",
        ],
        "priority": "Immediate",
    }


def _rec_post_quantum(finding: Dict[str, Any], context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    algo = finding.get("algorithm", "Post-Quantum Cryptography")
    rule_id = finding.get("rule_id", "")
    is_kem = "kem" in rule_id.lower() or "kem" in algo.lower()

    return {
        "original_algorithm": f"{algo} (Post-Quantum Cryptography)",
        "protocol_role": "Key Encapsulation Mechanism (KEM)" if is_kem else "Digital Signature / Authentication",
        "proposed_alternative": f"Maintain {algo} aligned with final NIST standards (FIPS 203 / 204 / 205)",
        "reason": (
            f"{algo} is a recognized post-quantum algorithm designed to resist attacks by Cryptographically Relevant Quantum Computers. "
            "Ensure the deployed implementation conforms to final NIST standards published in August 2024 rather than earlier draft specifications (e.g. Kyber round 3 vs FIPS 203 ML-KEM)."
        ),
        "standards_basis": [PQC_STANDARDS["FIPS_203"] if is_kem else PQC_STANDARDS["FIPS_204"]],
        "compatibility_considerations": (
            "1. Specification Alignment: Verify that libraries have migrated from draft parameter sets (e.g., Kyber-768 draft 00) to final FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA) OIDs and bitstream representations.\n"
            "2. Hybrid Deployment: For broad interoperability during WebPKI transition, deploy in hybrid mode alongside classical algorithms (X25519 / P-256) to ensure continuous FIPS 140 compliance."
        ),
        "implementation_steps": [
            "1. Audit library dependencies to ensure adoption of final FIPS 203/204/205 releases.",
            "2. Track NIST cryptographic module validation program (CMVP) certifications for FIPS 140-3 compliance.",
            "3. Maintain crypto-agility wrappers so parameter sets or algorithms can be adjusted if cryptanalytic updates emerge.",
        ],
        "testing_requirements": [
            "Run NIST Known Answer Tests (KAT) against final FIPS 203/204/205 test vectors.",
            "Benchmark memory consumption and performance across target architectures.",
        ],
        "priority": "Ongoing",
    }


def _rec_private_key(finding: Dict[str, Any], context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "original_algorithm": "Embedded Private Key / Secret Material",
        "protocol_role": "Key Storage & Secrets Management",
        "proposed_alternative": "Hardware Security Module (HSM), Cloud KMS, or Secrets Vault",
        "reason": (
            "Private cryptographic keys stored directly in code repositories or configuration files must be considered "
            "compromised regardless of classical or quantum concerns. Any adversary with access to the source code can extract "
            "the private key and decrypt past traffic or forge digital signatures immediately."
        ),
        "standards_basis": [PQC_STANDARDS["NIST_SP_800_131A"]],
        "compatibility_considerations": (
            "1. Key Rotation: The embedded key must be revoked and rotated immediately.\n"
            "2. Secret Injection: Update deployment configurations to inject keys at runtime via environment variables or KMS API calls."
        ),
        "implementation_steps": [
            "1. Revoke the embedded key and all associated certificates immediately.",
            "2. Generate a new key pair inside a secure Key Management Service (AWS KMS, HashiCorp Vault, Azure Key Vault, or HSM).",
            "3. Update application code to request cryptographic operations or credentials via API at runtime.",
            "4. Remove the private key from git history using repo scrubbing tools (e.g., git-filter-repo).",
        ],
        "testing_requirements": [
            "Verify the application successfully boots and authenticates using dynamically retrieved credentials.",
            "Confirm old keys are invalid and rejected across all validation endpoints.",
        ],
        "priority": "Immediate",
    }


def _rec_fallback(finding: Dict[str, Any], context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    algo = finding.get("algorithm", "Cryptographic Algorithm")
    return {
        "original_algorithm": algo,
        "protocol_role": "Cryptographic Operation",
        "proposed_alternative": "Modern NIST-approved post-quantum or authenticated primitive",
        "reason": (
            f"Review usage of {algo} against current cryptographic standards. Transition asymmetric algorithms to NIST FIPS 203/204 "
            "and symmetric algorithms to AES-256-GCM to ensure quantum resistance."
        ),
        "standards_basis": [PQC_STANDARDS["NIST_IR_8547"]],
        "compatibility_considerations": "Check platform support and test interoperability with legacy client systems.",
        "implementation_steps": [
            "1. Review the algorithm purpose and assess exposure to quantum and classical attacks.",
            "2. Select an approved NIST post-quantum standard or authenticated AEAD primitive.",
            "3. Implement and test within an isolated development environment.",
        ],
        "testing_requirements": [
            "Regression testing for compatibility and performance verification.",
        ],
        "priority": "Medium",
    }


# --------------------------------------------------------------------------
# Public API Entry Point
# --------------------------------------------------------------------------
def generate_migration_recommendation(
    finding: Dict[str, Any],
    scan_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Generate a detailed, structured PQC migration recommendation for a given finding.
    """
    rule_id = finding.get("rule_id", "")

    if rule_id == "rsa":
        rec = _rec_rsa(finding, scan_context)
    elif rule_id in ("ecdsa", "dsa"):
        rec = _rec_ecdsa_signatures(finding, scan_context)
    elif rule_id in ("ecdh", "dh", "elgamal"):
        rec = _rec_ecdh_kex(finding, scan_context)
    elif rule_id in ("des", "tdes", "rc4", "blowfish", "zip_crypto", "pdf_crypto", "aes_ecb"):
        rec = _rec_weak_symmetric(finding, scan_context)
    elif rule_id == "aes128":
        rec = _rec_aes128(finding, scan_context)
    elif rule_id in ("md5", "sha1"):
        rec = _rec_hash(finding, scan_context)
    elif rule_id == "weak_tls":
        rec = _rec_weak_tls(finding, scan_context)
    elif rule_id in ("ml_kem", "ml_dsa", "slh_dsa", "frodo_kem", "falcon"):
        rec = _rec_post_quantum(finding, scan_context)
    elif rule_id == "private_key":
        rec = _rec_private_key(finding, scan_context)
    elif rule_id == "ecc_curve":
        role = detect_protocol_role("ecc_curve", finding.get("parsed"), finding.get("occurrences", [{}])[0].get("snippet", "") if finding.get("occurrences") else "")
        if role == "digital_signature":
            rec = _rec_ecdsa_signatures(finding, scan_context)
        elif role == "key_establishment":
            rec = _rec_ecdh_kex(finding, scan_context)
        else:
            rec = _rec_ecdsa_signatures(finding, scan_context)
    else:
        rec = _rec_fallback(finding, scan_context)

    # Ensure all required keys are present
    required_keys = [
        "original_algorithm",
        "proposed_alternative",
        "reason",
        "compatibility_considerations",
        "implementation_steps",
        "testing_requirements",
        "priority",
    ]
    for rk in required_keys:
        if rk not in rec:
            rec[rk] = "N/A"

    return rec
