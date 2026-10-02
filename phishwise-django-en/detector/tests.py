from unittest.mock import patch

import torch
from django.test import SimpleTestCase

from . import services
from .virustotal import _stats_result


class UrlFeatureTests(SimpleTestCase):
    def test_features_match_random_forest_training_pipeline(self):
        url = "http://103.24.5.6/secure/update.exe?id=9"

        features = services.extract_url_features(url)

        self.assertEqual(list(features), services.RF_FEATURE_NAMES)
        self.assertEqual(features["is_ip_address"], 1)
        self.assertEqual(features["has_suspicious_keyword"], 1)
        self.assertEqual(features["has_executable_extension"], 1)
        self.assertEqual(features["is_https"], 0)

    def test_local_network_destination_is_blocked(self):
        with self.assertRaisesRegex(ValueError, "non-public"):
            services._assert_public_destination("http://127.0.0.1/admin")


class HtmlPipelineTests(SimpleTestCase):
    def test_tokenizer_matches_colab_rules_and_length(self):
        original_vocab = services.vocab
        services.vocab = {"<PAD>": 0, "<UNK>": 1, "html": 2, "script": 3}
        try:
            tensor = services.tokenize_html(
                "<html><script>run123()</script></html>", max_len=5
            )
        finally:
            services.vocab = original_vocab

        # Opening and closing tag names are both retained, exactly as in Colab.
        self.assertEqual(tensor.tolist(), [[2, 3, 3, 2, 0]])

    def test_bilstm_output_shape_matches_binary_classifier(self):
        model = services.PhishingBiLSTM(vocab_size=20)
        output = model(torch.zeros((2, 10), dtype=torch.long))
        self.assertEqual(tuple(output.shape), (2, 2))

    @patch("detector.services._safe_get")
    def test_process_html_content_unpacks_safe_get_tuple(self, mock_safe_get):
        from unittest.mock import MagicMock

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.content = b"<html><body>Test</body></html>"
        mock_resp.text = "<html><body>Test</body></html>"

        # _safe_get returns a 3-tuple: (response, current_url, chain)
        mock_safe_get.return_value = (mock_resp, "https://example.com", ["https://example.com"])

        original_vocab = services.vocab
        services.vocab = {"<PAD>": 0, "<UNK>": 1, "test": 2}
        try:
            tensor = services.process_html_content("https://example.com", max_len=5)
            self.assertIsNotNone(tensor)
            self.assertEqual(tensor.shape, (1, 5))
        finally:
            services.vocab = original_vocab


class ScanLogicTests(SimpleTestCase):
    def setUp(self):
        self.vt_patcher = patch(
            "detector.services.inspect_download_with_virustotal",
            return_value={
                "download_detected": False,
                "download_name": "",
                "download_size": 0,
                "status": "not_applicable",
                "risk_score": None,
            },
        )
        self.vt_mock = self.vt_patcher.start()
        self.addCleanup(self.vt_patcher.stop)

    @patch("detector.services.fetch_ip_location", return_value="Bangkok, Thailand")
    @patch(
        "detector.services.fetch_ssl_status",
        return_value=(True, "Test CA", "valid"),
    )
    @patch(
        "detector.services.fetch_domain_age_days",
        return_value=(1000, "2 years", "established"),
    )
    @patch("detector.services.resolve_final_url")
    @patch("detector.services._predict_model_risks")
    @patch("detector.services.load_resources")
    def test_model_risk_is_used_in_final_score(
        self,
        _load_resources,
        predict_risks,
        resolve_url,
        _domain_age,
        _ssl,
        _location,
    ):
        resolve_url.return_value = ("https://example.com", False)
        predict_risks.return_value = [0.8, 0.6]

        result = services.scan_url_logic("https://example.com")

        self.assertEqual(result["ai_risk_score"], 70)
        self.assertEqual(result["score"], 30)
        self.assertEqual(result["status"], "mostly_danger")
        self.assertEqual(result["model_results"]["url_model"]["risk_score"], 0.8)
        self.assertEqual(result["model_results"]["content_model"]["risk_score"], 0.6)

    @patch("detector.services.fetch_ip_location", return_value="Unknown")
    @patch(
        "detector.services.fetch_ssl_status",
        return_value=(True, "Test CA", "valid"),
    )
    @patch(
        "detector.services.fetch_domain_age_days",
        return_value=(None, "unknown", "unknown"),
    )
    @patch(
        "detector.services.resolve_final_url",
        return_value=("https://example.com", False),
    )
    @patch("detector.services._predict_model_risks", return_value=[])
    @patch("detector.services.load_resources")
    def test_missing_models_return_neutral_not_safe(
        self, *_mocks
    ):
        result = services.scan_url_logic("https://example.com")
        self.assertEqual(result["ai_risk_score"], 50)
        self.assertEqual(result["status"], "warning")

    @patch("detector.services.fetch_ip_location", return_value="Unknown")
    @patch(
        "detector.services.fetch_ssl_status",
        return_value=(False, "Not Secure", "invalid"),
    )
    @patch(
        "detector.services.fetch_domain_age_days",
        return_value=(None, "unknown", "unknown"),
    )
    @patch(
        "detector.services.resolve_final_url",
        return_value=("http://103.245.13.99/miner.sh", False),
    )
    @patch("detector.services._predict_model_risks", return_value=[0.21])
    @patch("detector.services.load_resources")
    def test_obvious_ip_payload_is_dangerous_even_when_model_is_weak(
        self, *_mocks
    ):
        result = services.scan_url_logic("http://103.245.13.99/miner.sh")
        self.assertEqual(result["ai_risk_score"], 100)
        self.assertEqual(result["status"], "danger")

    @patch("detector.services.fetch_ip_location", return_value="Unknown")
    @patch(
        "detector.services.fetch_ssl_status",
        return_value=(True, "Test CA", "valid"),
    )
    @patch(
        "detector.services.fetch_domain_age_days",
        return_value=(1000, "old", "established"),
    )
    @patch(
        "detector.services.resolve_final_url",
        return_value=("https://example.com/file.exe", False),
    )
    @patch("detector.services._predict_model_risks", return_value=[0.05])
    @patch("detector.services.load_resources")
    def test_virustotal_danger_cannot_be_diluted_by_low_ai_score(
        self, *_mocks
    ):
        self.vt_mock.return_value = {
            "download_detected": True,
            "download_name": "file.exe",
            "download_size": 100,
            "status": "danger",
            "risk_score": 100,
        }
        result = services.scan_url_logic("https://example.com/file.exe")
        self.assertEqual(result["ai_risk_score"], 100)
        self.assertEqual(result["status"], "danger")


class VirusTotalScoringTests(SimpleTestCase):
    def test_three_malicious_engines_force_danger(self):
        result = _stats_result(
            {
                "malicious": 3,
                "suspicious": 1,
                "harmless": 20,
                "undetected": 40,
            },
            "abc",
            "sample.exe",
        )
        self.assertEqual(result["status"], "danger")
        self.assertEqual(result["risk_score"], 100)

    def test_clean_report_does_not_override_local_model(self):
        result = _stats_result(
            {"malicious": 0, "suspicious": 0, "harmless": 10, "undetected": 50},
            "abc",
            "sample.pdf",
        )
        self.assertEqual(result["status"], "clean")
        self.assertEqual(result["risk_score"], 0)


class OcrPipelineTests(SimpleTestCase):
    def test_clean_ocr_url_patterns(self):
        from .ocr_pipeline import clean_ocr_url_text, validate_and_normalize_url

        # 1. Lone/ione protocol
        t1 = clean_ocr_url_text("https:lone graup.com/lxx.js")
        self.assertEqual(validate_and_normalize_url(t1), "https://one-graup.com/LXX.js")

        # 2. ift protocol
        t2 = clean_ocr_url_text("https: iftuiskr.com/")
        self.assertEqual(validate_and_normalize_url(t2), "https://tuiskr.com/")

        # 3. lft protocol with path slash
        t3 = clean_ocr_url_text("https:lftogethers.tvftogethers.exe")
        self.assertEqual(validate_and_normalize_url(t3), "https://togethers.tv/togethers.exe")

        # 4. Comma in IP
        t4 = clean_ocr_url_text("http'//175.175,192.169:54382/i")
        self.assertEqual(validate_and_normalize_url(t4), "http://175.175.192.169:54382/i")

        # 5. Missing dot before extension and cir1 -> cjr1
        t5 = clean_ocr_url_text("https://tuiskr.com/cir1jpg")
        self.assertEqual(validate_and_normalize_url(t5), "https://tuiskr.com/cjr1.jpg")

        # 6. Timestamp bleeding stripped
        t6 = clean_ocr_url_text("2026-09-03 12:35:09 https://tuiskr.com/path")
        self.assertEqual(validate_and_normalize_url(t6), "https://tuiskr.com/path")
