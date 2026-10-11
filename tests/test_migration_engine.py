"""
Tests for Q-SHIELD Post-Quantum Cryptography Migration Recommendation Engine.
"""
import io
import json
import unittest

import app
import migration_engine
import scanner


class TestMigrationEngine(unittest.TestCase):
    def setUp(self):
        self.app = app.app.test_client()

    def test_rsa_key_establishment_recommendation(self):
        finding = {
            "rule_id": "rsa",
            "algorithm": "RSA-2048",
            "key_size": 2048,
            "category": "asymmetric_encryption",
            "parsed": ["RSA-2048"],
            "occurrences": [{"snippet": "cipher = PKCS1_OAEP.new(rsa_key)"}],
        }
        rec = migration_engine.generate_migration_recommendation(finding)

        # Check required fields
        for field in ("original_algorithm", "proposed_alternative", "reason",
                      "compatibility_considerations", "implementation_steps",
                      "testing_requirements", "priority"):
            self.assertIn(field, rec, f"Missing required field: {field}")

        self.assertIn("ML-KEM", rec["proposed_alternative"])
        self.assertIn("hybrid", rec["proposed_alternative"].lower())
        self.assertIn("Shor", rec["reason"])
        self.assertIn("Harvest-Now-Decrypt-Later", rec["reason"])
        self.assertIn("1,088 bytes", rec["compatibility_considerations"])
        self.assertTrue(len(rec["implementation_steps"]) >= 3)
        self.assertTrue(len(rec["testing_requirements"]) >= 3)
        self.assertEqual(rec["priority"], "High")

    def test_rsa_sub_2048_has_immediate_priority(self):
        finding = {
            "rule_id": "rsa",
            "algorithm": "RSA-1024",
            "key_size": 1024,
            "category": "asymmetric_encryption",
            "parsed": ["RSA-1024"],
            "occurrences": [{"snippet": "RSA.generate(1024)"}],
        }
        rec = migration_engine.generate_migration_recommendation(finding)
        self.assertEqual(rec["priority"], "Immediate")

    def test_rsa_signature_evaluates_ml_dsa_and_slh_dsa(self):
        finding = {
            "rule_id": "rsa",
            "algorithm": "RSA-2048",
            "key_size": 2048,
            "category": "digital_signature",
            "parsed": ["RSA-2048 Signature"],
            "occurrences": [{"snippet": "pkcs1_15.new(key).sign(h)"}],
        }
        rec = migration_engine.generate_migration_recommendation(finding)

        self.assertIn("ML-DSA", rec["proposed_alternative"])
        self.assertIn("SLH-DSA", rec["proposed_alternative"])
        self.assertIn("tradeoff_analysis", rec)
        tradeoff = rec["tradeoff_analysis"]["ml_dsa_vs_slh_dsa"]
        self.assertIn("ml_dsa", tradeoff)
        self.assertIn("slh_dsa", tradeoff)
        self.assertIn("FIPS 204", tradeoff["ml_dsa"]["standard"])
        self.assertIn("FIPS 205", tradeoff["slh_dsa"]["standard"])
        self.assertIn("3,309", rec["compatibility_considerations"])

    def test_ecdsa_signatures_evaluates_ml_dsa_vs_slh_dsa(self):
        finding = {
            "rule_id": "ecdsa",
            "algorithm": "ECDSA",
            "category": "digital_signature",
            "parsed": ["P-256"],
            "occurrences": [{"snippet": "signer.sign(data)"}],
        }
        rec = migration_engine.generate_migration_recommendation(finding)

        self.assertIn("ML-DSA-65", rec["proposed_alternative"])
        self.assertIn("SLH-DSA", rec["proposed_alternative"])
        self.assertIn("tradeoff_analysis", rec)
        tradeoff = rec["tradeoff_analysis"]["ml_dsa_vs_slh_dsa"]
        self.assertIn("FIPS 204", tradeoff["ml_dsa"]["standard"])
        self.assertIn("FIPS 205", tradeoff["slh_dsa"]["standard"])
        self.assertIn("3,309 bytes", rec["compatibility_considerations"])
        self.assertTrue(len(rec["implementation_steps"]) >= 3)
        self.assertTrue(len(rec["testing_requirements"]) >= 3)

    def test_ecdh_key_exchange_recommendation(self):
        finding = {
            "rule_id": "ecdh",
            "algorithm": "ECDH / X25519",
            "category": "key_exchange",
            "parsed": ["X25519"],
            "occurrences": [{"snippet": "peer_key.exchange(ecdh)"}],
        }
        rec = migration_engine.generate_migration_recommendation(finding)

        self.assertIn("ML-KEM-768", rec["proposed_alternative"])
        self.assertIn("X25519MLKEM768", rec["proposed_alternative"])
        self.assertIn("HNDL", rec["reason"])
        self.assertIn("TLS 1.3", rec["compatibility_considerations"])
        self.assertEqual(rec["priority"], "High")

    def test_weak_symmetric_recommends_aead(self):
        for rid, name in [("des", "DES"), ("tdes", "3DES"), ("rc4", "RC4"), ("aes_ecb", "AES (ECB)")]:
            finding = {
                "rule_id": rid,
                "algorithm": name,
                "category": "symmetric_encryption",
                "parsed": [name],
                "occurrences": [{"snippet": f"{rid}_cipher_encrypt(data)"}],
            }
            rec = migration_engine.generate_migration_recommendation(finding)

            self.assertIn("AES-256-GCM", rec["proposed_alternative"])
            self.assertIn("ChaCha20-Poly1305", rec["proposed_alternative"])
            self.assertIn("AEAD", rec["compatibility_considerations"])
            self.assertIn("nonce", rec["compatibility_considerations"].lower())
            self.assertEqual(rec["priority"], "Immediate")

    def test_aes128_contextual_assessment(self):
        finding = {
            "rule_id": "aes128",
            "algorithm": "AES-128",
            "key_size": 128,
            "category": "symmetric_encryption",
            "parsed": ["AES-128-GCM"],
            "occurrences": [{"snippet": "Cipher.getInstance('AES/GCM/NoPadding')"}],
        }

        # Case 1: Short-lived / default context -> Low priority, assess requirements
        rec_default = migration_engine.generate_migration_recommendation(finding, scan_context={"confidentiality_lifetime": "<1_year"})
        self.assertEqual(rec_default["priority"], "Low")
        self.assertIn("Grover's algorithm", rec_default["reason"])
        self.assertIn("assessment_factors", rec_default)
        self.assertFalse(rec_default["assessment_factors"]["upgrade_recommended_now"])

        # Case 2: Long-lived confidential secret (10+ years, critical sensitivity) -> High priority, recommend AES-256
        rec_long_lived = migration_engine.generate_migration_recommendation(
            finding,
            scan_context={"confidentiality_lifetime": "10+_years", "data_sensitivity": "critical"}
        )
        self.assertEqual(rec_long_lived["priority"], "High")
        self.assertIn("AES-256-GCM (NIST SP 800-38D)", rec_long_lived["proposed_alternative"])
        self.assertTrue(rec_long_lived["assessment_factors"]["upgrade_recommended_now"])

    def test_hash_distinguishes_signatures_passwords_and_kdf(self):
        # Case 1: MD5 in password hashing context
        f_pwd = {
            "rule_id": "md5",
            "algorithm": "MD5",
            "category": "cryptographic_hash",
            "parsed": ["MD5"],
            "occurrences": [{"snippet": "user.password_hash = md5(password)"}],
        }
        rec_pwd = migration_engine.generate_migration_recommendation(f_pwd)
        self.assertIn("Argon2id", rec_pwd["proposed_alternative"])
        self.assertIn("role_distinctions", rec_pwd)
        self.assertIn("Never use SHA-256", rec_pwd["role_distinctions"]["password_hashing"])
        self.assertEqual(rec_pwd["protocol_role"], "Password Hashing")

        # Case 2: SHA-1 in digital signature context
        f_sig = {
            "rule_id": "sha1",
            "algorithm": "SHA-1",
            "category": "digital_signature",
            "parsed": ["SHA1withRSA"],
            "occurrences": [{"snippet": "cert.sign(hash_algo='sha1')"}],
        }
        rec_sig = migration_engine.generate_migration_recommendation(f_sig)
        self.assertIn("SHA-256", rec_sig["proposed_alternative"])
        self.assertIn("ML-DSA", rec_sig["proposed_alternative"])
        self.assertIn("quantum", rec_sig["reason"].lower())
        self.assertIn("Upgrading the hash alone does not protect", rec_sig["reason"])

        # Case 3: MD5 in key derivation context
        f_kdf = {
            "rule_id": "md5",
            "algorithm": "MD5",
            "category": "cryptographic_hash",
            "parsed": ["MD5"],
            "occurrences": [{"snippet": "key = derive_key_md5(secret)"}],
        }
        rec_kdf = migration_engine.generate_migration_recommendation(f_kdf)
        self.assertIn("HKDF", rec_kdf["proposed_alternative"])

    def test_tls_checks_platform_support(self):
        finding = {
            "rule_id": "weak_tls",
            "algorithm": "SSLv3 / TLS 1.0",
            "category": "network_protocol",
            "parsed": ["TLSv1.0"],
            "occurrences": [{"snippet": "ssl_protocols TLSv1 TLSv1.1;"}],
        }
        rec = migration_engine.generate_migration_recommendation(finding)

        self.assertIn("TLS 1.3", rec["proposed_alternative"])
        self.assertIn("X25519MLKEM768", rec["proposed_alternative"])
        self.assertIn("platform_support", rec)
        ps = rec["platform_support"]
        self.assertIn("OpenSSL", ps["openssl"])
        self.assertIn("Go", ps["golang"])
        self.assertIn("Bouncy Castle", ps["bouncy_castle"])

    def test_scanner_end_to_end_populates_migration_recommendations(self):
        sample_code = """
import hashlib
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA

def process_payment(card_num):
    key = RSA.generate(2048)
    cipher = PKCS1_OAEP.new(key)
    des = DES.new(b'12345678', DES.MODE_ECB)
    pwd_hash = hashlib.md5(card_num.encode()).hexdigest()
    return cipher, des, pwd_hash
"""
        result = scanner.scan([("payment.py", sample_code.encode("utf-8"))])

        findings = result["findings"]
        self.assertTrue(len(findings) >= 3)
        for f in findings:
            self.assertIn("migration_recommendation", f)
            m_rec = f["migration_recommendation"]
            for field in ("original_algorithm", "proposed_alternative", "reason",
                          "compatibility_considerations", "implementation_steps",
                          "testing_requirements", "priority"):
                self.assertIn(field, m_rec)

        # Check plan enrichment
        plan = result["plan"]
        self.assertTrue(len(plan["phases"]) >= 1)
        for phase in plan["phases"]:
            for action in phase["actions"]:
                self.assertIn("replace_with", action)
                if action.get("implementation_steps"):
                    self.assertIsInstance(action["implementation_steps"], list)
                if action.get("testing_requirements"):
                    self.assertIsInstance(action["testing_requirements"], list)

    def test_context_update_api_recomputes_migration_recommendation(self):
        # Create a scan with AES-128
        code = b"# AES-128 encryption routine\nfrom Crypto.Cipher import AES\nc = AES.new(b'0'*16, AES.MODE_GCM)\n"
        res = self.app.post("/api/scan", data={"name": "test_aes", "files": (io.BytesIO(code), "aes_test.py")})
        self.assertIn(res.status_code, (200, 201))
        data = res.get_json()
        scan_id = data["id"]

        aes_finding = next((f for f in data["findings"] if f["rule_id"] == "aes128"), None)
        self.assertIsNotNone(aes_finding)
        self.assertEqual(aes_finding["migration_recommendation"]["priority"], "Low")

        # Now update context to 10+ years retention and critical sensitivity
        upd = self.app.post(f"/api/scans/{scan_id}/findings/{aes_finding['id']}/context", json={
            "data_sensitivity": "critical",
            "confidentiality_lifetime": "10+_years",
            "asset_exposure": "external_internet_facing"
        })
        self.assertEqual(upd.status_code, 200)
        upd_data = upd.get_json()
        upd_finding = upd_data["finding"]
        self.assertEqual(upd_finding["migration_recommendation"]["priority"], "High")
        self.assertIn("AES-256-GCM (NIST SP 800-38D)", upd_finding["migration_recommendation"]["proposed_alternative"])


if __name__ == "__main__":
    unittest.main()
