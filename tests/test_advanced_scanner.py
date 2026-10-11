"""Comprehensive test suite for the Q-SHIELD cryptographic scanning engine and Flask backend."""
import io
import json
import unittest
import zipfile
from reportlab.pdfgen import canvas

import app
import scanner
import report


class AdvancedScannerTests(unittest.TestCase):
    def setUp(self):
        self.app = app.app.test_client()

    def test_python_ast_rsa_keygen_and_modes(self):
        py_code = b"""
import os
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib

def generate_keys():
    k1 = RSA.generate(2048)
    k2 = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    k3 = ec.generate_private_key(ec.SECP256R1())
    c1 = Cipher(algorithms.AES(os.urandom(32)), modes.GCM(os.urandom(12)))
    c2 = Cipher(algorithms.AES(os.urandom(16)), modes.ECB())
    h1 = hashlib.md5(b"test").hexdigest()
    h2 = hashlib.sha1(b"test").hexdigest()
    return k1, k2, k3
"""
        result = scanner.scan([("crypto_service.py", py_code)])
        findings = result["findings"]
        algo_map = {f["detected_algorithm"]: f for f in findings}

        # Check RSA
        self.assertIn("RSA", algo_map)
        rsa_f = algo_map["RSA"]
        self.assertEqual(rsa_f["confidence_level"], "confirmed")
        self.assertIn(rsa_f["key_size"], (2048, 4096))
        self.assertEqual(rsa_f["quantum_risk_assessment"]["status"], "vulnerable")
        self.assertEqual(rsa_f["source_location"]["type"], "source_code")
        self.assertTrue(len(rsa_f["analysis_limitations"]) > 0)

        # Check ECC
        self.assertIn("Elliptic-curve (ECC) keys and curves", algo_map)
        self.assertEqual(algo_map["Elliptic-curve (ECC) keys and curves"]["confidence_level"], "confirmed")

        # Check AES-ECB weak mode
        self.assertIn("AES in ECB mode", algo_map)
        ecb_f = algo_map["AES in ECB mode"]
        self.assertEqual(ecb_f["severity"], "critical")
        self.assertEqual(ecb_f["classical_security_assessment"]["status"], "broken")

        # Check hashes
        self.assertIn("MD5", algo_map)
        self.assertEqual(algo_map["MD5"]["classical_security_assessment"]["status"], "broken")
        self.assertIn("SHA-1", algo_map)

    def test_java_jca_parser(self):
        java_code = b"""
package com.example;
import java.security.*;
import javax.crypto.*;

public class SecurityManager {
    public void setup() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        Cipher c1 = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher c2 = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        Signature sig = Signature.getInstance("SHA256withRSA");
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    }
}
"""
        result = scanner.scan([("SecurityManager.java", java_code)])
        findings = result["findings"]
        algo_map = {f["detected_algorithm"]: f for f in findings}

        self.assertIn("RSA", algo_map)
        self.assertEqual(algo_map["RSA"]["confidence_level"], "confirmed")
        self.assertEqual(algo_map["RSA"]["key_size"], 2048)

        self.assertIn("3DES / Triple DES", algo_map)
        self.assertEqual(algo_map["3DES / Triple DES"]["confidence_level"], "confirmed")

        self.assertIn("ECDH / X25519 key exchange", algo_map)
        self.assertEqual(algo_map["ECDH / X25519 key exchange"]["confidence_level"], "confirmed")

    def test_javascript_crypto_parser(self):
        js_code = b"""
const crypto = require('crypto');

function generateKeys() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 3072,
    });
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const hash = crypto.createHash('md5');
    return { publicKey, privateKey };
}
"""
        result = scanner.scan([("auth.js", js_code)])
        findings = result["findings"]
        algo_map = {f["detected_algorithm"]: f for f in findings}

        self.assertIn("RSA", algo_map)
        self.assertEqual(algo_map["RSA"]["confidence_level"], "confirmed")
        self.assertEqual(algo_map["RSA"]["key_size"], 3072)
        self.assertIn("AES-192 / AES-256", algo_map)
        self.assertIn("MD5", algo_map)

    def test_c_cpp_openssl_parser(self):
        c_code = b"""
#include <openssl/rsa.h>
#include <openssl/evp.h>

void init_crypto() {
    RSA *r = RSA_new();
    BIGNUM *bne = BN_new();
    BN_set_word(bne, RSA_F4);
    RSA_generate_key_ex(r, 2048, bne, NULL);
    const EVP_CIPHER *c = EVP_aes_256_gcm();
    const EVP_MD *md = EVP_sha256();
}
"""
        result = scanner.scan([("crypto.cpp", c_code)])
        findings = result["findings"]
        algo_map = {f["detected_algorithm"]: f for f in findings}

        self.assertIn("RSA", algo_map)
        self.assertEqual(algo_map["RSA"]["confidence_level"], "confirmed")
        self.assertEqual(algo_map["RSA"]["key_size"], 2048)

    def test_php_openssl_parser(self):
        php_code = b"""<?php
$config = array(
    "private_key_bits" => 4096,
    "private_key_type" => OPENSSL_KEYTYPE_RSA,
);
$res = openssl_pkey_new($config);
$encrypted = openssl_encrypt($plaintext, "aes-256-gcm", $key, 0, $iv);
$sign_key = sodium_crypto_sign_keypair();
?>"""
        result = scanner.scan([("encrypt.php", php_code)])
        findings = result["findings"]
        algo_map = {f["detected_algorithm"]: f for f in findings}

        self.assertIn("RSA", algo_map)
        self.assertEqual(algo_map["RSA"]["confidence_level"], "confirmed")
        self.assertEqual(algo_map["RSA"]["key_size"], 4096)
        self.assertIn("ECDSA / EdDSA signatures", algo_map)

    def test_config_tls_and_ciphers(self):
        nginx_conf = b"""
server {
    listen 443 ssl;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:RC4-SHA:DES-CBC3-SHA;
    ssl_dhparam /etc/nginx/dhparam.pem;
}
"""
        result = scanner.scan([("nginx.conf", nginx_conf)])
        findings = result["findings"]
        algo_map = {f["detected_algorithm"]: f for f in findings}

        self.assertIn("Deprecated SSL/TLS version", algo_map)
        self.assertEqual(algo_map["Deprecated SSL/TLS version"]["confidence_level"], "confirmed")
        self.assertIn("RC4", algo_map)
        self.assertIn("3DES / Triple DES", algo_map)
        self.assertIn("Diffie-Hellman (DH/DHE)", algo_map)

    def test_confidence_level_distinction(self):
        # Comments vs Active Code
        doc_file = b"""
# Documentation file
# We are considering migrating from RSA and AES to post-quantum ML-KEM and ML-DSA.
# For historical reference, see MD5 and SHA-1 RFCs.
"""
        result = scanner.scan([("ARCHITECTURE.md", doc_file)])
        findings = result["findings"]
        for f in findings:
            self.assertEqual(f["confidence_level"], "text_match",
                             f"Finding {f['detected_algorithm']} in doc should be text_match")

    def test_pdf_inspection_and_text(self):
        buf = io.BytesIO()
        pdf = canvas.Canvas(buf)
        pdf.drawString(72, 720, "Internal spec: System integrates ML-KEM-768 for hybrid key agreement.")
        pdf.save()
        result = scanner.scan([("specification.pdf", buf.getvalue())])
        algo_map = {f["detected_algorithm"]: f for f in findings} if (findings := result["findings"]) else {}
        self.assertIn("Post-quantum algorithm", algo_map)

    def test_zip_archive_encrypted_metadata(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("test.txt", b"Secret payload")
        raw = bytearray(buf.getvalue())
        cd_pos = raw.find(b"PK\x01\x02")
        raw[cd_pos + 8] |= 1
        raw[6] |= 1
        result = scanner.scan([("archive.zip", bytes(raw))])
        findings = result["findings"]
        algo_map = {f["detected_algorithm"]: f for f in findings}
        self.assertIn("PKWARE ZipCrypto encryption", algo_map)
        zip_f = algo_map["PKWARE ZipCrypto encryption"]
        self.assertEqual(zip_f["confidence_level"], "confirmed")
        self.assertEqual(zip_f["severity"], "critical")
        self.assertEqual(zip_f["classical_security_assessment"]["status"], "broken")

    def test_structured_json_schema_fields(self):
        code = b"key = RSA.generate(2048)\n"
        result = scanner.scan([("main.py", code)])
        self.assertTrue(len(result["findings"]) > 0)
        f = result["findings"][0]

        # Verify all user-requested fields exist
        self.assertIn("filename", f)
        self.assertIn("detected_algorithm", f)
        self.assertIn("evidence", f)
        self.assertIn("source_location", f)
        self.assertIn("key_size", f)
        self.assertIn("confidence_level", f)
        self.assertIn("classical_security_assessment", f)
        self.assertIn("quantum_risk_assessment", f)
        self.assertIn("analysis_limitations", f)

        # Verify sub-fields
        self.assertIn("status", f["classical_security_assessment"])
        self.assertIn("description", f["classical_security_assessment"])
        self.assertIn("status", f["quantum_risk_assessment"])
        self.assertIn("threat_model", f["quantum_risk_assessment"])
        self.assertIsInstance(f["analysis_limitations"], list)

    def test_flask_scan_endpoint_single_file(self):
        data = {
            "file": (io.BytesIO(b"import hashlib\nh = hashlib.sha256()\n"), "service.py")
        }
        res = self.app.post("/api/scan", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 201)
        body = json.loads(res.data)
        self.assertEqual(body["summary"]["files_scanned"], 1)
        self.assertIn("findings", body)

    def test_flask_scan_endpoint_empty_file_rejected(self):
        data = {
            "file": (io.BytesIO(b""), "")
        }
        res = self.app.post("/api/scan", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 400)


if __name__ == "__main__":
    unittest.main()
