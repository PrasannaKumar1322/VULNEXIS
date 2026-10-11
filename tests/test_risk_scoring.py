"""Unit and integration tests for Q-SHIELD 4-factor multi-factor risk scoring system (risk_scoring.py)."""
import io
import json
import unittest

import app
import risk_scoring
import scanner


class RiskScoringTests(unittest.TestCase):
    def setUp(self):
        self.sample_rsa_finding = {
            "rule_id": "rsa",
            "file": "payment_gateway.py",
            "algorithm": "RSA",
            "category": "Public-key",
            "severity": "critical",
            "quantum_status": "vulnerable",
            "quantum_classification": "quantum-vulnerable",
            "breaks_security_assumptions": True,
            "current_security_concerns": {"status": "legacy_warning"},
            "key_size": 2048,
            "mode": None,
            "replacement": "ML-KEM (FIPS 203)",
            "evidence": "RSA.generate(2048)",
            "scan_surface": "source_code",
            "asset": "payment_gateway.py",
        }

    def test_four_factors_calculation_and_normalization(self):
        res = risk_scoring.calculate_finding_risk(self.sample_rsa_finding)

        self.assertIsInstance(res["score"], int)
        self.assertGreaterEqual(res["score"], 0)
        self.assertLessEqual(res["score"], 100)
        self.assertIn(res["level"], ("critical", "high", "medium", "low"))
        self.assertIn("Priority", res["priority"])

        factors = res["contributing_factors"]
        self.assertEqual(len(factors), 4)

        factor_ids = [f["id"] for f in factors]
        expected_ids = [
            "cryptographic_vulnerability",
            "data_sensitivity",
            "confidentiality_lifetime",
            "asset_exposure",
        ]
        self.assertEqual(factor_ids, expected_ids)

        # Check default weights: 0.30, 0.25, 0.25, 0.20 -> sum = 1.0
        total_weight = sum(f["weight"] for f in factors)
        self.assertAlmostEqual(total_weight, 1.0, places=4)
        weights_by_id = {f["id"]: f["weight"] for f in factors}
        self.assertAlmostEqual(weights_by_id["cryptographic_vulnerability"], 0.30, places=4)
        self.assertAlmostEqual(weights_by_id["data_sensitivity"], 0.25, places=4)
        self.assertAlmostEqual(weights_by_id["confidentiality_lifetime"], 0.25, places=4)
        self.assertAlmostEqual(weights_by_id["asset_exposure"], 0.20, places=4)

        # Verify operational notice
        self.assertIn("prioritisation", res["disclaimer"].lower())
        self.assertIn("not a measured probability", res["disclaimer"].lower())

    def test_unknown_inputs_marked_unknown_without_false_assumptions(self):
        plain_finding = {
            "rule_id": "custom_cipher",
            "file": "misc_data.dat",
            "algorithm": "UnknownCipher",
            "category": "Symmetric",
            "severity": "medium",
            "quantum_status": "unclassified",
            "quantum_classification": "unknown",
            "breaks_security_assumptions": False,
            "current_security_concerns": {"status": "unknown"},
            "key_size": None,
            "mode": None,
            "replacement": "",
            "evidence": "process_data()",
            "scan_surface": "source_code",
            "asset": "misc_data.dat",
        }

        res = risk_scoring.calculate_finding_risk(plain_finding)
        self.assertTrue(res["is_provisional"])
        self.assertIn("Provisional", res["confidence_flag"])

        factors_by_id = {f["id"]: f for f in res["contributing_factors"]}

        # Check that un-inferred factors are explicitly marked unknown
        self.assertTrue(factors_by_id["data_sensitivity"]["is_unknown"])
        self.assertEqual(factors_by_id["data_sensitivity"]["status"], "unknown")
        self.assertEqual(factors_by_id["data_sensitivity"]["raw_score"], 50)

        self.assertTrue(factors_by_id["confidentiality_lifetime"]["is_unknown"])
        self.assertEqual(factors_by_id["confidentiality_lifetime"]["status"], "unknown")
        self.assertEqual(factors_by_id["confidentiality_lifetime"]["raw_score"], 50)

        self.assertTrue(factors_by_id["asset_exposure"]["is_unknown"])
        self.assertEqual(factors_by_id["asset_exposure"]["status"], "unknown")
        self.assertEqual(factors_by_id["asset_exposure"]["raw_score"], 50)

    def test_user_context_overrides_and_severity_bands(self):
        # 1. Critical context: highly_sensitive (100), 10+_years (100), internet_facing (100)
        # Vuln: RSA-2048 returns 90 (legacy margin)
        # Expected: 90 * 0.30 (27) + 100 * 0.25 (25) + 100 * 0.25 (25) + 100 * 0.20 (20) = 97 (Critical: 80-100)
        user_ctx_critical = {
            "data_sensitivity": "highly_sensitive",
            "confidentiality_lifetime": "10+_years",
            "asset_exposure": "internet_facing",
        }
        res_crit = risk_scoring.calculate_finding_risk(self.sample_rsa_finding, user_context=user_ctx_critical)
        self.assertEqual(res_crit["score"], 97)
        self.assertEqual(res_crit["level"], "critical")
        self.assertEqual(res_crit["remediation_timeframe"], "Immediate attention")
        self.assertEqual(res_crit["priority"], "Priority 1: Immediate Attention")
        self.assertFalse(res_crit["is_provisional"])

        factors_by_id = {f["id"]: f for f in res_crit["contributing_factors"]}
        self.assertEqual(factors_by_id["data_sensitivity"]["status"], "user_provided")
        self.assertEqual(factors_by_id["data_sensitivity"]["raw_score"], 100)
        self.assertEqual(factors_by_id["confidentiality_lifetime"]["status"], "user_provided")
        self.assertEqual(factors_by_id["confidentiality_lifetime"]["raw_score"], 100)
        self.assertEqual(factors_by_id["asset_exposure"]["status"], "user_provided")
        self.assertEqual(factors_by_id["asset_exposure"]["raw_score"], 100)

        # 2. Low context: public (10), <1_year (10), isolated (10)
        # Vuln: RSA-2048 -> 90 * 0.30 (27) + 10 * 0.25 (2.5) + 10 * 0.25 (2.5) + 10 * 0.20 (2) = 34 (Medium: 30-59)
        user_ctx_low = {
            "data_sensitivity": "public",
            "confidentiality_lifetime": "<1_year",
            "asset_exposure": "isolated",
        }
        res_low = risk_scoring.calculate_finding_risk(self.sample_rsa_finding, user_context=user_ctx_low)
        self.assertLess(res_low["score"], res_crit["score"])
        self.assertEqual(res_low["score"], 34)
        self.assertEqual(res_low["level"], "medium")
        self.assertEqual(res_low["remediation_timeframe"], "Planned migration")

    def test_long_lived_sensitive_rsa_ecc_highlight(self):
        user_ctx_hndl = {
            "data_sensitivity": "highly_sensitive",
            "confidentiality_lifetime": "10+_years",
        }
        res = risk_scoring.calculate_finding_risk(self.sample_rsa_finding, user_context=user_ctx_hndl)
        self.assertTrue(res["is_long_lived_sensitive_pki"])
        self.assertIsNotNone(res["highlight_callout"])
        self.assertIn("HNDL EXPOSURE", res["highlight_callout"])

        # Ephemeral lifetime (<1 year) => No long-lived highlight
        user_ctx_short = {
            "data_sensitivity": "highly_sensitive",
            "confidentiality_lifetime": "<1_year",
        }
        res_short = risk_scoring.calculate_finding_risk(self.sample_rsa_finding, user_context=user_ctx_short)
        self.assertFalse(res_short["is_long_lived_sensitive_pki"])

    def test_custom_weights_configuration(self):
        custom = {
            "cryptographic_vulnerability": 0.50,
            "data_sensitivity": 0.20,
            "confidentiality_lifetime": 0.20,
            "asset_exposure": 0.10,
        }
        res = risk_scoring.calculate_finding_risk(self.sample_rsa_finding, custom_weights=custom)
        f_crypto = next(f for f in res["contributing_factors"] if f["id"] == "cryptographic_vulnerability")
        self.assertAlmostEqual(f_crypto["weight"], 0.50, places=4)
        self.assertEqual(f_crypto["weighted_score"], 45.0)

    def test_tie_breakers_queue_sorting(self):
        """
        Verify strict tie-breaking order:
        Primary: risk_score descending
        Tie-breaker 1: confidentiality_lifetime descending
        Tie-breaker 2: asset_exposure descending
        """
        finding_a = dict(self.sample_rsa_finding, id=1, asset="asset_a.py", algorithm="RSA-A")
        finding_b = dict(self.sample_rsa_finding, id=2, asset="asset_b.py", algorithm="RSA-B")
        finding_c = dict(self.sample_rsa_finding, id=3, asset="asset_c.py", algorithm="RSA-C")

        # Force identical risk score to strictly test tie-breaker 1 (lifetime) and tie-breaker 2 (exposure)
        item_a = dict(finding_a, risk_score=70, factor_scores={"confidentiality_lifetime": 40, "asset_exposure": 100})
        item_b = dict(finding_b, risk_score=70, factor_scores={"confidentiality_lifetime": 100, "asset_exposure": 10})
        item_c = dict(finding_c, risk_score=70, factor_scores={"confidentiality_lifetime": 100, "asset_exposure": 70})

        sorted_items = risk_scoring.sort_remediation_queue([item_a, item_b, item_c])

        # Expected order:
        # item_c and item_b have lifetime 100 > item_a's 40.
        # Between item_c and item_b (both lifetime 100), item_c has exposure 70 > item_b's 10.
        # Thus: item_c (id=3), item_b (id=2), item_a (id=1).
        self.assertEqual(sorted_items[0]["id"], 3)  # item_c
        self.assertEqual(sorted_items[1]["id"], 2)  # item_b
        self.assertEqual(sorted_items[2]["id"], 1)  # item_a

    def test_monday_morning_action_plan_generation(self):
        findings = [
            # Critical (80-100) -> Immediate attention
            dict(self.sample_rsa_finding, id=1, risk_score=90, risk_level="critical",
                 remediation_timeframe="Immediate attention",
                 factor_scores={"cryptographic_vulnerability": 90, "confidentiality_lifetime": 100, "asset_exposure": 100}),
            # High (60-79) -> This week
            dict(self.sample_rsa_finding, id=2, algorithm="ECDSA", risk_score=65, risk_level="high",
                 remediation_timeframe="This week",
                 factor_scores={"cryptographic_vulnerability": 85, "confidentiality_lifetime": 75, "asset_exposure": 70}),
            # Medium (30-59) -> Planned migration
            dict(self.sample_rsa_finding, id=3, algorithm="AES-128", risk_score=45, risk_level="medium",
                 remediation_timeframe="Planned migration",
                 factor_scores={"cryptographic_vulnerability": 50, "confidentiality_lifetime": 40, "asset_exposure": 40}),
            # Low (0-29) -> Monitor and maintain
            dict(self.sample_rsa_finding, id=4, algorithm="AES-256", risk_score=15, risk_level="low",
                 remediation_timeframe="Monitor and maintain",
                 factor_scores={"cryptographic_vulnerability": 10, "confidentiality_lifetime": 10, "asset_exposure": 10}),
        ]
        queue = risk_scoring.build_remediation_queue(findings)
        self.assertEqual(len(queue), 4)
        self.assertEqual(queue[0]["rank"], 1)

        plan = risk_scoring.generate_monday_morning_plan(findings)
        self.assertIn("immediate_attention", plan["buckets_by_id"])
        self.assertIn("this_week", plan["buckets_by_id"])
        self.assertIn("planned_migration", plan["buckets_by_id"])
        self.assertIn("monitor_and_maintain", plan["buckets_by_id"])

        imm_bucket = plan["buckets_by_id"]["immediate_attention"]
        self.assertEqual(len(imm_bucket["items"]), 1)
        item = imm_bucket["items"][0]
        self.assertTrue(item["owner_role"])
        self.assertIsInstance(item["prerequisites"], list)
        self.assertIsInstance(item["validation_tests"], list)
        self.assertTrue(item["expected_outcome"])
        self.assertTrue(item["concrete_next_action"])

    def test_correlate_and_deduplicate_findings(self):
        f1 = dict(self.sample_rsa_finding, id=1, file="payment.py", asset="payment.py", algorithm="RSA", scan_surface="source_code", risk_score=85)
        f2 = dict(self.sample_rsa_finding, id=2, file="payment.py", asset="payment.py", algorithm="RSA", scan_surface="source_code", risk_score=85)
        f3 = dict(self.sample_rsa_finding, id=3, file="api.company.com:443", asset="api.company.com:443", algorithm="RSA", scan_surface="live_tls", risk_score=90)

        res = risk_scoring.correlate_and_deduplicate_findings([f1, f2, f3])
        dedup = res["deduplicated_issues"]
        # Two unique asset-algorithm pairs: (source_code::payment.py::RSA) and (live_tls::api.company.com:443::RSA)
        self.assertEqual(len(dedup), 2)
        payment_issue = next(i for i in dedup if i["asset"] == "payment.py")
        self.assertEqual(payment_issue["findings_count"], 2)
        self.assertEqual(payment_issue["scan_surface"], "source_code")

    def test_flask_api_endpoints(self):
        client = app.app.test_client()

        # 1. GET /api/risk-scoring/config
        r_cfg = client.get("/api/risk-scoring/config")
        self.assertEqual(r_cfg.status_code, 200)
        cfg = r_cfg.get_json()
        self.assertIn("default_weights", cfg)
        self.assertIn("risk_bands", cfg)
        self.assertIn("disclaimer", cfg)
        self.assertAlmostEqual(cfg["default_weights"]["cryptographic_vulnerability"], 0.30)
        self.assertAlmostEqual(cfg["default_weights"]["data_sensitivity"], 0.25)
        self.assertAlmostEqual(cfg["default_weights"]["confidentiality_lifetime"], 0.25)
        self.assertAlmostEqual(cfg["default_weights"]["asset_exposure"], 0.20)

        # 2. POST /api/scan with context parameters
        test_code = b"""
from Crypto.PublicKey import RSA
key = RSA.generate(2048)
"""
        r_scan = client.post(
            "/api/scan",
            data={
                "files": (io.BytesIO(test_code), "auth_service.py"),
                "name": "Auth Test Scan",
                "data_sensitivity": "highly_sensitive",
                "confidentiality_lifetime": "10+_years",
                "asset_exposure": "internet_facing",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(r_scan.status_code, 201)
        scan_data = r_scan.get_json()
        scan_id = scan_data["id"]
        findings = scan_data["findings"]
        self.assertGreater(len(findings), 0)

        rsa_f = findings[0]
        self.assertGreaterEqual(rsa_f["risk_score"], 80)
        self.assertEqual(rsa_f["risk_level"], "critical")
        self.assertEqual(rsa_f["remediation_timeframe"], "Immediate attention")
        self.assertTrue(rsa_f["is_long_lived_sensitive_pki"])

        # Check remediation_queue and monday_morning_plan in returned scan
        self.assertIn("remediation_queue", scan_data)
        self.assertIn("monday_morning_plan", scan_data)
        self.assertIn("deduplicated_issues", scan_data)

        # 3. POST /api/scans/<id>/findings/<id>/context to update finding context
        fid = rsa_f["id"]
        r_update = client.post(
            f"/api/scans/{scan_id}/findings/{fid}/context",
            data=json.dumps({
                "data_sensitivity": "public",
                "confidentiality_lifetime": "<1_year",
                "asset_exposure": "isolated",
            }),
            content_type="application/json",
        )
        self.assertEqual(r_update.status_code, 200)
        up_data = r_update.get_json()
        self.assertTrue(up_data["ok"])
        updated_f = up_data["finding"]
        self.assertLess(updated_f["risk_score"], rsa_f["risk_score"])
        self.assertFalse(updated_f["is_long_lived_sensitive_pki"])


if __name__ == "__main__":
    unittest.main()

