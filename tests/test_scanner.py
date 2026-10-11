"""Offline smoke tests for the Q-SHIELD scanning engine."""
import io
import unittest
from reportlab.pdfgen import canvas
import scanner
import report


class ScannerSmokeTests(unittest.TestCase):
    def test_source_text_finds_quantum_vulnerable_and_pqc_names(self):
        result = scanner.scan([("app.py", b"RSA.generate(2048)\\nuse ML-KEM-768\\n")])
        names = {item["name"] for item in result["algorithms"]}
        self.assertIn("RSA", names)
        self.assertIn("Post-quantum algorithm", names)
        self.assertGreater(result["summary"]["findings_total"], 0)

    def test_zip_sample_scans(self):
        from pathlib import Path
        sample = Path(__file__).parents[1] / "samples" / "payment-service.zip"
        result = scanner.scan([(sample.name, sample.read_bytes())])
        self.assertGreater(result["summary"]["files_scanned"], 0)
        self.assertGreater(result["summary"]["quantum_vulnerable_assets"], 0)

    def test_pdf_embedded_text_is_scanned(self):
        buf = io.BytesIO()
        pdf = canvas.Canvas(buf)
        pdf.drawString(72, 720, "Legacy uses RSA and AES-128; migrate to ML-KEM.")
        pdf.save()
        result = scanner.scan([("audit.pdf", buf.getvalue())])
        names = {item["name"] for item in result["algorithms"]}
        self.assertIn("RSA", names)
        self.assertIn("AES-128", names)

    def test_pdf_report_is_generated(self):
        result = scanner.scan([("app.py", b"RSA and AES-128")])
        payload = report.build_pdf(
            {"id": 1, "label": "smoke-test", "created_at": "2026-10-11T00:00:00+00:00"},
            result,
        )
        self.assertTrue(payload.startswith(b"%PDF-"))


if __name__ == "__main__":
    unittest.main()
