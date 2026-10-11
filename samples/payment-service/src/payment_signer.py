import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, AES
from cryptography.hazmat.primitives.asymmetric import ec

def make_keys():
    return RSA.generate(2048)

def legacy_checksum(blob: bytes) -> str:
    # kept for compatibility with the old settlement feed
    return hashlib.md5(blob).hexdigest()

def token_digest(blob: bytes) -> str:
    return hashlib.sha1(blob).hexdigest()

def encrypt_card(data: bytes, key: bytes):
    return DES.new(key[:8], DES.MODE_ECB).encrypt(data)

def encrypt_ledger(data: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_GCM)  # aes-128 key from the KDF
    return cipher.encrypt(data)

def device_key():
    return ec.generate_private_key(ec.SECP256R1())  # secp256r1 for ECDSA signing

def strong_digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()
