"""
Q-SHIELD Test Sample Script: Cryptographic Operations Showcase.

This file contains various cryptographic implementations designed to test
Q-SHIELD's detection, 6-factor risk scoring, and PQC migration engine:
  - RSA-2048 encryption (Harvest-Now-Decrypt-Later, ML-KEM migration)
  - ECDSA P-256 signing (ML-DSA vs SLH-DSA evaluation)
  - ECDH X25519 key agreement (Hybrid X25519MLKEM768 migration)
  - Legacy DES / 3DES / AES-ECB (Broken classical ciphers, AEAD migration)
  - AES-128 GCM (Grover quantum margin assessment)
  - MD5 password hashing & SHA-1 signature (Role distinctions: Argon2id vs SHA-256)
  - Modern Post-Quantum Cryptography reference (ML-KEM-768)
"""
import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import AES, DES


# ==============================================================================
# 1. Quantum-Vulnerable Asymmetric Cryptography (Shor's Algorithm & HNDL)
# ==============================================================================

def rsa_key_exchange_and_encryption():
    """
    RSA-2048: Vulnerable to Shor's algorithm on a quantum computer.
    High HNDL exposure for confidential data.
    Q-SHIELD Migration: Proposes ML-KEM-768 with hybrid X25519MLKEM768.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    message = b"Confidential customer credit card record"
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def ecdsa_digital_signature():
    """
    ECDSA using curve SECP256R1 (P-256): Vulnerable to Shor's algorithm.
    Q-SHIELD Migration: Evaluates ML-DSA-65 (FIPS 204) for fast API/TLS signing
    vs SLH-DSA (FIPS 205) for high-assurance root anchors.
    """
    ec_key = ec.generate_private_key(ec.SECP256R1())
    data = b"Authorize wire transfer payload"
    sig = ec_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return sig


def ecdh_session_key_exchange():
    """
    ECDH / X25519: Vulnerable to Shor's algorithm and retroactive HNDL capture.
    Q-SHIELD Migration: Proposes hybrid X25519MLKEM768 in TLS 1.3.
    """
    server_key = ec.generate_private_key(ec.SECP384R1())
    client_key = ec.generate_private_key(ec.SECP384R1())
    shared_key = server_key.exchange(ec.ECDH(), client_key.public_key())
    return shared_key


# ==============================================================================
# 2. Broken Classical Ciphers & Modes (Sweet32, ECB plaintext leakage)
# ==============================================================================

def legacy_des_encryption():
    """
    DES with 56-bit key: Actively breakable classically.
    Q-SHIELD Migration: Proposes authenticated encryption AES-256-GCM / ChaCha20-Poly1305.
    """
    des_key = b"8bytekey"  # 56-bit effective key
    cipher = DES.new(des_key, DES.MODE_ECB)
    return cipher.encrypt(b"plaintext8bytes!")


def aes_ecb_insecure_mode():
    """
    AES in ECB mode: Lacks diffusion and leaks plaintext patterns.
    Q-SHIELD Migration: Mandates AEAD (AES-256-GCM with unique nonce).
    """
    key = os.urandom(32)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(b"repetitive_data_block_padding!!!")


# ==============================================================================
# 3. Symmetric Cryptography & Quantum Margin (Grover's Algorithm)
# ==============================================================================

def aes_128_gcm_storage():
    """
    AES-128 in GCM mode: Classically strong today.
    Under Grover's algorithm, exhaustive search is reduced to 64-bit security margin.
    Q-SHIELD Migration: Evaluates retention lifetime before recommending AES-256-GCM.
    """
    key = os.urandom(16)   # 128-bit key
    nonce = os.urandom(12)  # 96-bit unique IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(b"sensitive operational telemetry") + encryptor.finalize()


# ==============================================================================
# 4. Hash Function Misuse & Role Distinctions
# ==============================================================================

def insecure_password_hashing(password: str):
    """
    MD5 used for passwords: Severely broken classically (vulnerable to fast GPU brute-force).
    Q-SHIELD Migration: Clarifies role distinction and mandates Argon2id (RFC 9106) / bcrypt.
    """
    return hashlib.md5(password.encode()).hexdigest()


def legacy_sha1_verification(content: bytes):
    """
    SHA-1 used for digital signatures: Vulnerable to practical collision attacks (SHAttered).
    Q-SHIELD Migration: Recommends SHA-256/SHA-384 with ML-DSA-65.
    """
    return hashlib.sha1(content).hexdigest()


# ==============================================================================
# 5. Post-Quantum Cryptography Reference
# ==============================================================================

def modern_pqc_reference():
    """
    Standardized NIST Post-Quantum Cryptography (FIPS 203 ML-KEM).
    Q-SHIELD: Classified as quantum-resistant / post-quantum.
    """
    target_pqc_algorithm = "ML-KEM-768"
    pqc_signature_scheme = "ML-DSA-65"
    return f"Active PQC configuration: {target_pqc_algorithm}, {pqc_signature_scheme}"


if __name__ == "__main__":
    print("Executing cryptographic test sample routine...")
    print("PQC config:", modern_pqc_reference())
    print("Sample executed successfully.")
