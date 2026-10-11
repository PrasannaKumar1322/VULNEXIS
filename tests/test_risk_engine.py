"""Tests for Q-SHIELD Cryptographic Risk Analysis Engine (risk_engine.py)."""
import unittest

import risk_engine
import report
import scanner


class RiskEngineTests(unittest.TestCase):
    def test_rsa_2048_risk_evaluation(self):
        eval_res = risk_engine.evaluate_risk(
            rule_id="rsa",
            key_size=2048,
            confidence="confirmed",
            source="code_parser",
            evidence="RSA.generate(2048)",
        )
        # Parameters
        self.assertEqual(eval_res["algorithm_name"], "RSA")
        self.assertEqual(eval_res["detected_parameters"]["key_size"], 2048)

        # Classical threats
        sec = eval_res["current_security_concerns"]
        self.assertFalse(sec["exploitable_today"])
        self.assertEqual(sec["status"], "legacy_warning")
        self.assertIn("NIST SP 800-131A", sec["standards_reference"])

        # Quantum threats
        q = eval_res["quantum_threat_analysis"]
        self.assertTrue(q["breaks_security_assumptions"])
        self.assertEqual(q["quantum_classification"], "quantum-vulnerable")
        self.assertEqual(q["quantum_algorithm_applicable"], "Shor's Algorithm")
        self.assertIn("integer factorization", q["why_vulnerable"].lower())
        self.assertIn("no crqc", q["theoretical_vs_active"].lower())

        # Harvest-Now-Decrypt-Later (HNDL)
        hndl = eval_res["harvest_now_decrypt_later"]
        self.assertTrue(hndl["applicable"])
        self.assertEqual(hndl["risk_level"], "critical")
        self.assertIn("harvest", hndl["explanation"].lower())

    def test_rsa_1024_sub_minimum_is_broken_today(self):
        eval_res = risk_engine.evaluate_risk(
            rule_id="rsa",
            key_size=1024,
            confidence="confirmed",
        )
        sec = eval_res["current_security_concerns"]
        self.assertTrue(sec["exploitable_today"])
        self.assertEqual(sec["status"], "broken")

    def test_ecc_ecdh_and_ecdsa_distinction(self):
        # ECDH (Key exchange - HNDL applies)
        ecdh_res = risk_engine.evaluate_risk(rule_id="ecdh", curve="P-256")
        self.assertTrue(ecdh_res["quantum_threat_analysis"]["breaks_security_assumptions"])
        self.assertEqual(ecdh_res["quantum_threat_analysis"]["quantum_classification"], "quantum-vulnerable")
        self.assertEqual(ecdh_res["quantum_threat_analysis"]["quantum_algorithm_applicable"], "Shor's Algorithm")
        self.assertTrue(ecdh_res["harvest_now_decrypt_later"]["applicable"])
        self.assertEqual(ecdh_res["harvest_now_decrypt_later"]["risk_level"], "critical")

        # ECDSA (Signatures - not subject to retroactive decryption)
        ecdsa_res = risk_engine.evaluate_risk(rule_id="ecdsa", curve="P-256")
        self.assertTrue(ecdsa_res["quantum_threat_analysis"]["breaks_security_assumptions"])
        self.assertEqual(ecdsa_res["quantum_threat_analysis"]["quantum_classification"], "quantum-vulnerable")
        self.assertFalse(ecdsa_res["harvest_now_decrypt_later"]["applicable"])
        self.assertEqual(ecdsa_res["harvest_now_decrypt_later"]["risk_level"], "not_applicable")

    def test_symmetric_evaluation_aes128_vs_aes256(self):
        # AES-128: Grover reduces to 64-bit margin (not yet confidently classified / weakened)
        res_128 = risk_engine.evaluate_risk(rule_id="aes128", key_size=128, mode="GCM")
        q128 = res_128["quantum_threat_analysis"]
        self.assertFalse(q128["breaks_security_assumptions"])
        self.assertEqual(q128["quantum_classification"], "not yet confidently classified")
        self.assertEqual(q128["quantum_algorithm_applicable"], "Grover's Algorithm")
        self.assertIn("64", q128["why_vulnerable"])

        # AES-256: Grover leaves 128-bit margin (quantum-resistant)
        res_256 = risk_engine.evaluate_risk(rule_id="aes256", key_size=256, mode="GCM")
        q256 = res_256["quantum_threat_analysis"]
        self.assertFalse(q256["breaks_security_assumptions"])
        self.assertEqual(q256["quantum_classification"], "quantum-resistant")
        self.assertIn("128", q256["why_vulnerable"])

    def test_aes_ecb_mode_classical_flaw(self):
        res_ecb = risk_engine.evaluate_risk(rule_id="aes_ecb", mode="ECB")
        sec = res_ecb["current_security_concerns"]
        self.assertTrue(sec["exploitable_today"])
        self.assertEqual(sec["status"], "broken")
        self.assertIn("ecb", sec["concerns"][0].lower())

    def test_legacy_ciphers_broken_today(self):
        for rid in ("des", "tdes", "rc4", "blowfish", "zip_crypto"):
            res = risk_engine.evaluate_risk(rule_id=rid)
            sec = res["current_security_concerns"]
            self.assertTrue(sec["exploitable_today"], f"{rid} should be marked exploitable today")
            self.assertEqual(sec["status"], "broken")

    def test_hash_functions_distinction(self):
        # MD5 / SHA-1: Broken today
        md5_res = risk_engine.evaluate_risk(rule_id="md5")
        self.assertTrue(md5_res["current_security_concerns"]["exploitable_today"])
        self.assertEqual(md5_res["current_security_concerns"]["status"], "broken")

        sha1_res = risk_engine.evaluate_risk(rule_id="sha1")
        self.assertTrue(sha1_res["current_security_concerns"]["exploitable_today"])
        self.assertEqual(sha1_res["current_security_concerns"]["status"], "broken")

        # SHA-2: Quantum-resistant
        sha2_res = risk_engine.evaluate_risk(rule_id="sha2")
        self.assertFalse(sha2_res["current_security_concerns"]["exploitable_today"])
        self.assertEqual(sha2_res["quantum_threat_analysis"]["quantum_classification"], "quantum-resistant")
        self.assertIn("preimage", sha2_res["quantum_threat_analysis"]["why_vulnerable"].lower())

    def test_post_quantum_algorithms_evaluation(self):
        pqc_res = risk_engine.evaluate_risk(rule_id="pqc")
        self.assertFalse(pqc_res["quantum_threat_analysis"]["breaks_security_assumptions"])
        self.assertEqual(pqc_res["quantum_threat_analysis"]["quantum_classification"], "quantum-resistant")
        self.assertFalse(pqc_res["harvest_now_decrypt_later"]["applicable"])
        self.assertIn("fips 203", pqc_res["remediation_guidance"]["standards_guidance"].lower())

    def test_end_to_end_scan_risk_fields(self):
        code = b"""
import rsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import hashlib

key = RSA.generate(2048)
cipher = AES.new(b"0123456789abcdef", AES.MODE_GCM)
h = hashlib.sha256(b"data").hexdigest()
"""
        res = scanner.scan([("crypto_module.py", code)])
        self.assertGreater(len(res["findings"]), 0)

        # Check RSA finding
        rsa_finding = next((f for f in res["findings"] if f["rule_id"] == "rsa"), None)
        self.assertIsNotNone(rsa_finding)
        self.assertEqual(rsa_finding["quantum_classification"], "quantum-vulnerable")
        self.assertTrue(rsa_finding["breaks_security_assumptions"])
        self.assertIn("shor", rsa_finding["why_vulnerable"].lower())
        self.assertIn("theoretical future", rsa_finding["theoretical_vs_active"].lower())
        self.assertTrue(rsa_finding["harvest_now_decrypt_later"]["applicable"])
        self.assertEqual(rsa_finding["harvest_now_decrypt_later"]["risk_level"], "critical")
        self.assertIn("harvest", rsa_finding["hndl_explanation"].lower())
        self.assertEqual(rsa_finding["detected_parameters"]["key_size"], 2048)
        self.assertIn("analysis_limitations", rsa_finding)

        # Check AES finding
        aes_finding = next((f for f in res["findings"] if "aes" in f["rule_id"]), None)
        self.assertIsNotNone(aes_finding)
        self.assertIn(aes_finding["quantum_classification"], ("quantum-resistant", "not yet confidently classified"))
        self.assertFalse(aes_finding["breaks_security_assumptions"])
        self.assertIn("grover", aes_finding["why_vulnerable"].lower())

    def test_pdf_report_build_with_risk_engine_fields(self):
        code = b"""
from Crypto.PublicKey import RSA
key = RSA.generate(2048)
"""
        scan_res = scanner.scan([("test_service.py", code)])
        meta = {"id": 99, "label": "test_service.py", "created_at": "2026-10-11T00:00:00Z"}
        pdf_bytes = report.build_pdf(meta, scan_res)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_bytes), 1000)


if __name__ == "__main__":
    unittest.main()

