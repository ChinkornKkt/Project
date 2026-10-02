from io import BytesIO
from datetime import timedelta
from unittest.mock import patch

import cv2
import numpy as np
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from detector.models import ScanHistory
from detector.article_utils import render_article_markdown

from .views import decode_qr_image, decode_image_url_or_qr, extract_urls_from_text


class QrUploadTests(SimpleTestCase):
    def test_real_qr_image_is_decoded(self):
        target_url = "https://example.com/download.exe"
        image = cv2.QRCodeEncoder_create().encode(target_url)
        encoded, png_bytes = cv2.imencode(".png", image)
        self.assertTrue(encoded)
        upload = SimpleUploadedFile(
            "qr.png", png_bytes.tobytes(), content_type="image/png"
        )
        url, source = decode_image_url_or_qr(upload)
        self.assertEqual(url, target_url)
        self.assertEqual(source, "image_qr")

    def test_extract_urls_from_text_helper(self):
        text = "Please visit https://scb-verify.com/login urgently"
        urls = extract_urls_from_text(text)
        self.assertEqual(urls, ["https://scb-verify.com/login"])

        text_www = "Website www.test-bank.co.th is safe"
        urls_www = extract_urls_from_text(text_www)
        self.assertEqual(urls_www, ["https://www.test-bank.co.th"])

    def test_non_image_upload_is_rejected(self):
        upload = SimpleUploadedFile(
            "sample.txt", b"not a qr image", content_type="text/plain"
        )
        with self.assertRaisesRegex(ValueError, "Only image files"):
            decode_image_url_or_qr(upload)

    def test_invalid_image_is_rejected(self):
        upload = SimpleUploadedFile(
            "sample.png", BytesIO(b"not an image").read(), content_type="image/png"
        )
        with self.assertRaisesRegex(ValueError, "Unable to open image"):
            decode_image_url_or_qr(upload)


class QrScanViewTests(TestCase):
    @patch("dashboard.views.scan_url_logic")
    def test_uploaded_qr_flows_into_normal_url_scanner(self, scan_url):
        target_url = "https://example.com/download.exe"
        scan_url.return_value = {
            "url": target_url,
            "score": 0,
            "status": "danger",
            "ai_risk_score": 100,
            "ssl_title": "Test CA",
            "ssl_sub": "valid",
            "domain_age": "2 years",
            "domain_sub": "established",
            "is_blacklisted": True,
            "google_safe": False,
            "location": "Unknown",
            "has_redirection": False,
            "download_detected": True,
            "download_name": "download.exe",
            "download_size": 100,
            "virustotal": {"status": "danger", "risk_score": 100},
        }
        image = cv2.QRCodeEncoder_create().encode(target_url)
        _, png_bytes = cv2.imencode(".png", image)
        upload = SimpleUploadedFile(
            "qr.png", png_bytes.tobytes(), content_type="image/png"
        )

        response = self.client.post("/scan/", {"file": upload})

        self.assertRedirects(response, "/result/")
        scan_url.assert_called_once_with(target_url)

    @patch("dashboard.views.get_easyocr_reader")
    @patch("dashboard.views.scan_url_logic")
    def test_uploaded_ocr_image_flows_into_scanner(self, scan_url, mock_get_reader):
        target_url = "https://ocr-phish.xyz/login"
        scan_url.return_value = {
            "url": target_url,
            "score": 10,
            "status": "danger",
            "ai_risk_score": 90,
            "ssl_title": "Not Secure",
            "ssl_sub": "expired",
            "domain_age": "5 days",
            "domain_sub": "new",
            "is_blacklisted": True,
            "google_safe": False,
            "location": "Bangkok, Thailand",
            "has_redirection": False,
            "download_detected": False,
            "download_name": "",
            "download_size": 0,
            "virustotal": {"status": "not_applicable", "risk_score": None},
        }

        # Mock OCR reader
        class MockReader:
            def readtext(self, image, detail=0):
                return ["Please verify at https://ocr-phish.xyz/login immediately"]
        mock_get_reader.return_value = MockReader()

        # Non-QR plain image
        plain_img = np.zeros((100, 200, 3), dtype=np.uint8)
        _, png_bytes = cv2.imencode(".png", plain_img)
        upload = SimpleUploadedFile(
            "screen.png", png_bytes.tobytes(), content_type="image/png"
        )

        response = self.client.post("/scan/", {"file": upload})

        self.assertRedirects(response, "/result/")
        scan_url.assert_called_once_with(target_url)
        last_scan = ScanHistory.objects.latest("timestamp")
        self.assertEqual(last_scan.source_type, "image_ocr")
        self.assertEqual(last_scan.url, target_url)

    @patch("dashboard.views.get_easyocr_reader")
    @patch("dashboard.views.scan_url_logic")
    def test_uploaded_image_with_multiple_urls_shows_modal_and_can_be_selected(self, scan_url, mock_get_reader):
        scan_url.return_value = {
            "url": "https://first-link.xyz/path",
            "score": 80,
            "status": "safe",
            "ai_risk_score": 20,
            "ssl_title": "Let's Encrypt",
            "ssl_sub": "Valid",
            "domain_age": "1 year",
            "domain_sub": "Normal",
            "is_blacklisted": False,
            "google_safe": True,
            "location": "Bangkok, Thailand",
            "has_redirection": False,
            "download_detected": False,
            "download_name": "",
            "download_size": 0,
            "virustotal": {"status": "not_applicable", "risk_score": None},
        }

        class MockReader:
            def readtext(self, image, detail=0):
                return ["Link 1: https://first-link.xyz/path and Link 2: https://second-link.xyz/login"]
        mock_get_reader.return_value = MockReader()

        plain_img = np.zeros((100, 200, 3), dtype=np.uint8)
        _, png_bytes = cv2.imencode(".png", plain_img)
        upload = SimpleUploadedFile("screen.png", png_bytes.tobytes(), content_type="image/png")

        # 1. Upload image with multiple links -> redirects to home with session
        response = self.client.post("/scan/", {"file": upload})
        self.assertRedirects(response, "/")

        # 2. Home page shows modal with pre-selected first URL and confirm button
        home_res = self.client.get("/")
        self.assertEqual(home_res.status_code, 200)
        self.assertContains(home_res, "url-select-modal")
        self.assertContains(home_res, "https://first-link.xyz/path")
        self.assertContains(home_res, "https://second-link.xyz/login")
        self.assertContains(home_res, "Confirm Selection")
        self.assertContains(home_res, "selected")

        # 3. Confirm selection -> scans selected URL and redirects to result
        confirm_res = self.client.post("/select-url/", {"selected_url": "https://first-link.xyz/path"})
        self.assertRedirects(confirm_res, "/result/")
        scan_url.assert_called_with("https://first-link.xyz/path")


class StatisticsReportTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="member@test.com",
            email="member@test.com",
            password="securepass123",
            first_name="Member",
        )
        self.client.force_login(self.user)
        self._scan("safe", 90, timezone.now())
        self._scan("warning", 60, timezone.now() - timedelta(days=2))
        self._scan("danger", 20, timezone.now() - timedelta(days=40))

    def _scan(self, status, score, timestamp):
        return ScanHistory.objects.create(
            user=self.user, url=f"https://{status}.example", score=score,
            status=status, ai_risk_score=100 - score, ssl_title="Test CA",
            ssl_sub="valid", domain_age="2 years", domain_sub="established",
            is_blacklisted=status == "danger", google_safe=status != "danger",
            location="Thailand", has_redirection=False, timestamp=timestamp,
        )

    def test_report_uses_the_logged_in_users_real_scans(self):
        response = self.client.get("/dashboard/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["total_users"], 1)
        self.assertEqual(response.context["total_scans"], 2)
        self.assertEqual(
            response.context["safe_count"]
            + response.context["warning_count"]
            + response.context["danger_count"],
            response.context["total_scans"],
        )
        self.assertContains(response, "Download PDF Report")
        self.assertContains(response, "Scan Summary by User")

    def test_pdf_report_is_a_downloadable_two_page_document(self):
        response = self.client.get("/statistics/report.pdf")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertIn("attachment;", response["Content-Disposition"])
        self.assertTrue(response.content.startswith(b"%PDF"))
        self.assertGreater(len(response.content), 20_000)

    def test_statistics_period_filter_changes_all_summary_values(self):
        seven_days = self.client.get("/dashboard/?period=7")
        all_time = self.client.get("/dashboard/?period=all")

        self.assertEqual(seven_days.context["selected_period"], "7")
        self.assertEqual(seven_days.context["total_scans"], 2)
        self.assertEqual(all_time.context["selected_period"], "all")
        self.assertEqual(all_time.context["total_scans"], 3)
        self.assertNotEqual(
            seven_days.context["trend_values"],
            all_time.context["trend_values"],
        )

    def test_admin_gets_admin_pdf_and_member_gets_personal_pdf(self):
        # Member downloads PDF: personal report
        member_res = self.client.get("/statistics/report.pdf")
        self.assertEqual(member_res.status_code, 200)
        self.assertTrue(member_res.content.startswith(b"%PDF"))

        # Admin downloads PDF: system report
        admin = User.objects.create_superuser("admin_pdf@test.com", "admin_pdf@test.com", "securepass123")
        self.client.force_login(admin)
        admin_res = self.client.get("/statistics/report.pdf")
        self.assertEqual(admin_res.status_code, 200)
        self.assertTrue(admin_res.content.startswith(b"%PDF"))


class AuthenticationAndAdminTests(TestCase):
    def test_registration_creates_a_hashed_django_user(self):
        response = self.client.post("/register/", {
            "name": "Test Member", "email": "new@test.com",
            "password": "securepass123", "password_confirm": "securepass123",
        })
        user = User.objects.get(username="new@test.com")
        self.assertRedirects(response, "/login/")
        self.assertTrue(user.check_password("securepass123"))

    def test_member_cannot_open_admin_page(self):
        member = User.objects.create_user("member@test.com", password="pass12345")
        self.client.force_login(member)
        self.assertRedirects(self.client.get("/admin/"), "/login/?next=/admin/")

    def test_admin_can_suspend_a_member(self):
        admin = User.objects.create_superuser("admin@test.com", "admin@test.com", "pass12345")
        member = User.objects.create_user("member@test.com", password="pass12345")
        self.client.force_login(admin)
        response = self.client.post(f"/admin/users/{member.id}/toggle/")
        member.refresh_from_db()
        self.assertRedirects(response, "/admin/#users")
        self.assertFalse(member.is_active)


class AnalysisPdfReportTests(TestCase):
    def test_analysis_pdf_is_downloadable(self):
        session = self.client.session
        session["last_scan_result"] = {
            "url": "https://example.com/download.exe",
            "score": 24,
            "ai_risk_score": 76,
            "ssl_title": "Example CA",
            "domain_age": "2 years",
            "domain_sub": "established",
            "google_safe": False,
            "is_blacklisted": True,
            "has_redirection": True,
            "location": "Thailand",
            "download_detected": True,
            "download_name": "download.exe",
            "virustotal": {
                "status": "danger",
                "risk_score": 90,
                "malicious": 9,
                "suspicious": 2,
                "total_engines": 70,
                "sha256": "a" * 64,
            },
        }
        session.save()

        response = self.client.get("/result/report.pdf")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertIn("attachment;", response["Content-Disposition"])
        self.assertTrue(response.content.startswith(b"%PDF"))
        self.assertGreater(len(response.content), 20_000)

from detector.models import DomainStatistic, SuspiciousSiteReport
from detector.reporting import create_site_report, record_domain_scan, review_site_report


class DomainReportingTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("member@example.com", password="pass12345")
        self.admin = User.objects.create_superuser("admin@example.com", "admin@example.com", "pass12345")

    def test_member_can_report_domain_but_not_duplicate_pending_report(self):
        self.client.force_login(self.user)
        payload = {"url": "https://Example.COM/path", "reason": "phishing", "details": "test"}
        response = self.client.post("/report/", payload)
        self.assertRedirects(response, "/report/")
        self.assertEqual(SuspiciousSiteReport.objects.count(), 1)
        self.assertEqual(DomainStatistic.objects.get(domain="example.com").report_count, 1)
        self.client.post("/report/", payload)
        self.assertEqual(SuspiciousSiteReport.objects.count(), 1)

    def test_approved_reports_from_three_users_enable_community_warning(self):
        reports = []
        for number in range(3):
            user = User.objects.create_user(f"member{number}@example.com", password="pass12345")
            reports.append(create_site_report(user=user, url="https://alert.example/path", reason="scam", details="test"))
        for report in reports:
            review_site_report(report, status=SuspiciousSiteReport.APPROVED, reviewer=self.admin)
        self.assertEqual(DomainStatistic.objects.get(domain="alert.example").approved_report_count, 3)
        session = self.client.session
        session["last_scan_result"] = {"url": "https://alert.example/path", "score": 50, "ai_risk_score": 50}
        session.save()
        response = self.client.get("/result/")
        self.assertTrue(response.context["community_warning"])

    def test_scan_statistics_counts_unique_authenticated_users(self):
        first = User.objects.create_user("first@example.com", password="pass12345")
        second = User.objects.create_user("second@example.com", password="pass12345")
        record_domain_scan("https://stats.example/one", first)
        record_domain_scan("https://stats.example/two", first)
        record_domain_scan("https://stats.example/three", second)
        statistic = DomainStatistic.objects.get(domain="stats.example")
        self.assertEqual(statistic.scan_count, 3)
        self.assertEqual(statistic.unique_scanner_count, 2)


from detector.models import KnowledgeArticle
import json


class KnowledgeArticleTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser("admin@example.com", "admin@example.com", "pass12345")
        self.member = User.objects.create_user("member@example.com", password="pass12345")

    def test_admin_can_create_edit_toggle_and_delete_article(self):
        self.client.force_login(self.admin)
        content_json = json.dumps({
            "sections": [
                {"title": "Section 1", "text": "Details about security."}
            ],
            "key_takeaways": ["Takeaway 1"]
        })

        # 1. Create
        create_res = self.client.post("/admin/articles/create/", {
            "title": "Test Security Guide",
            "category": "Security",
            "author": "PhishWise Team",
            "author_role": "Security Lead",
            "date": "24 Aug 2026",
            "read_time": "3 min read",
            "desc": "Short description for the guide",
            "image": "https://example.com/image.jpg",
            "summary": "Summary text",
            "content": content_json,
            "status": "published",
        })
        self.assertRedirects(create_res, "/admin/#knowledge")
        article = KnowledgeArticle.objects.get(title="Test Security Guide")
        self.assertEqual(article.category, "Security")
        self.assertEqual(len(article.sections), 1)
        self.assertEqual(article.status, "published")

        # 2. Toggle status (published -> draft)
        toggle_res = self.client.post(f"/admin/articles/{article.id}/toggle/")
        self.assertRedirects(toggle_res, "/admin/#knowledge")
        article.refresh_from_db()
        self.assertEqual(article.status, "draft")

        # 3. Edit
        edit_res = self.client.post(f"/admin/articles/{article.id}/edit/", {
            "title": "Updated Security Guide",
            "category": "Phishing",
            "author": "New Author",
            "author_role": "Specialist",
            "date": "25 Aug 2026",
            "read_time": "5 min read",
            "desc": "Updated desc",
            "image": "https://example.com/new.jpg",
            "summary": "Updated summary",
            "status": "published",
            "content": content_json,
        })
        self.assertRedirects(edit_res, "/admin/#knowledge")
        article.refresh_from_db()
        self.assertEqual(article.title, "Updated Security Guide")
        self.assertEqual(article.category, "Phishing")

        # 4. View in knowledge list and detail
        k_list = self.client.get("/knowledge/")
        self.assertEqual(k_list.status_code, 200)
        self.assertContains(k_list, "Updated Security Guide")

        k_detail = self.client.get(f"/knowledge/{article.id}/")
        self.assertEqual(k_detail.status_code, 200)
        self.assertContains(k_detail, "Updated Security Guide")
        self.assertContains(k_detail, "Section 1")

        # 5. Delete
        del_res = self.client.post(f"/admin/articles/{article.id}/delete/")
        self.assertRedirects(del_res, "/admin/#knowledge")
        self.assertFalse(KnowledgeArticle.objects.filter(pk=article.id).exists())

    def test_non_staff_cannot_create_article(self):
        self.client.force_login(self.member)
        res = self.client.post("/admin/articles/create/", {"title": "Unauthorized"})
        self.assertRedirects(res, "/login/?next=/admin/articles/create/")
        self.assertEqual(KnowledgeArticle.objects.count(), 0)

    def test_upload_article_image(self):
        self.client.force_login(self.admin)
        dummy_img = SimpleUploadedFile("cover.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01", content_type="image/jpeg")
        res = self.client.post("/admin/articles/upload-image/", {"image": dummy_img})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("success"))
        self.assertTrue(data.get("url", "").startswith("/media/articles/"))

    def test_article_markdown_strips_script_tag(self):
        """Test case description."""
        raw = "# English test comment
        result = render_article_markdown(raw)
        self.assertNotIn("<script>", result)
        self.assertNotIn("alert(", result)

    def test_article_markdown_strips_event_handler_attribute(self):
        """Test case description."""
        raw = '<img src="x" onerror="alert(1)">'
        result = render_article_markdown(raw)
        self.assertNotIn("onerror", result)

    def test_article_markdown_allows_basic_formatting(self):
        """Test case description."""
        raw = "**Bold** and [link](https://example.com)"
        result = render_article_markdown(raw)
        self.assertIn("<strong>", result)
        self.assertIn("<a href=", result)

    def test_admin_can_create_and_preview_markdown_article(self):
        """Test case description."""
        self.client.force_login(self.admin)
        md_text = "# English test comment

        # Test preview API
        preview_res = self.client.post("/admin/articles/preview/", {"content_markdown": md_text})
        self.assertEqual(preview_res.status_code, 200)
        self.assertIn("<h2>Security Guide</h2>", preview_res.json()["html"])
        self.assertIn("<strong>Bold</strong>", preview_res.json()["html"])

        # Test create with markdown
        create_res = self.client.post("/admin/articles/create/", {
            "title": "Markdown Article Test",
            "category": "Security",
            "desc": "Short desc",
            "content_markdown": md_text,
            "status": "published",
        })
        self.assertRedirects(create_res, "/admin/#knowledge")
        art = KnowledgeArticle.objects.get(title="Markdown Article Test")
        self.assertEqual(art.content_markdown, md_text)
        self.assertIn("<strong>Bold</strong>", art.content_html)

        # Test view detail renders content_html
        detail_res = self.client.get(f"/knowledge/{art.id}/")
        self.assertEqual(detail_res.status_code, 200)
        self.assertContains(detail_res, "<strong>Bold</strong>")


class DeepAnalysisResultViewTests(TestCase):
    def test_result_view_renders_deep_analysis_pure_thai_and_accordions(self):
        """Test case description."""
        session = self.client.session
        session["last_scan_result"] = {
            "url": "http://192.168.1.1/login.exe",
            "score": 0,
            "status": "danger",
            "ssl_title": "Not Secure",
            "ssl_sub": "No SSL/TLS encryption",
            "domain_age": "No WHOIS record found",
            "domain_age_days": None,
            "domain_sub": "Unable to determine domain age",
            "location": "Bangkok, Thailand",
            "has_redirection": True,
            "redirect_count": 2,
            "redirect_chain": [
                "http://short.url/abc",
                "http://mid.url/login",
                "http://192.168.1.1/login.exe",
            ],
            "ai_risk_score": 100,
            "url_features": {
                "url_length": 29,
                "is_ip_address": 1,
                "count_dots": 3,
                "count_hyphens": 0,
                "count_at": 0,
                "count_question": 0,
                "count_equal": 0,
                "count_slash": 3,
                "has_suspicious_keyword": 1,
                "has_executable_extension": 1,
                "is_https": 0,
            },
            "is_blacklisted": False,
            "google_safe": False,
            "download_detected": True,
            "download_name": "login.exe",
            "download_size": "1.2 MB",
            "virustotal": {
                "download_detected": True,
                "download_name": "login.exe",
                "download_size": "1.2 MB",
                "status": "danger",
                "malicious": 15,
                "suspicious": 2,
                "total_engines": 70,
                "risk_score": 95,
            },
        }
        session.save()

        response = self.client.get("/result/")
        self.assertEqual(response.status_code, 200)

        # English test comment
        self.assertContains(response, "Deep Analysis Results")
        self.assertNotContains(response, "Deep Analysis Results (Deep Analysis)")
        self.assertContains(response, "Multi-layer hybrid analysis pipeline")
        self.assertNotContains(response, "Legacy Pipeline Analysis")
        self.assertContains(response, "Server Location")
        self.assertNotContains(response, "Server Location (Primary)")

        # English test comment
        self.assertContains(response, "View 11 URL Features")
        self.assertContains(response, "URL length")
        self.assertContains(response, "Uses IP address instead of domain")
        self.assertContains(response, "Contains phishing keywords")
        self.assertContains(response, "Executable file extension")
        self.assertContains(response, "Encrypted HTTPS connection")

        # English test comment
        self.assertContains(response, "This link redirects through 2 intermediate hop(s)")
        self.assertContains(response, "View redirection path (2 hops)")
        self.assertContains(response, "http://short.url/abc")
        self.assertContains(response, "http://mid.url/login")
        self.assertContains(response, "http://192.168.1.1/login.exe")


class ArticleImageUploadTests(TestCase):
    def setUp(self):
        self.staff_user = User.objects.create_user(
            username="staff_editor", password="StaffPassword123", is_staff=True
        )
        self.normal_user = User.objects.create_user(
            username="normal_user", password="UserPassword123", is_staff=False
        )
        self.created_files = []

    def tearDown(self):
        import os
        from django.conf import settings
        from pathlib import Path

        for filepath in self.created_files:
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except OSError:
                    pass

    def test_anonymous_cannot_upload_image(self):
        """Test case description."""
        file = SimpleUploadedFile("test.png", b"fake_png_data", content_type="image/png")
        res = self.client.post("/admin/articles/upload-image/", {"image": file})
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.url)

    def test_non_staff_cannot_upload_image(self):
        """Test case description."""
        self.client.force_login(self.normal_user)
        file = SimpleUploadedFile("test.png", b"fake_png_data", content_type="image/png")
        res = self.client.post("/admin/articles/upload-image/", {"image": file})
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.url)

    def test_staff_upload_without_file_returns_error(self):
        """Test case description."""
        self.client.force_login(self.staff_user)
        res = self.client.post("/admin/articles/upload-image/", {})
        self.assertEqual(res.status_code, 400)
        data = res.json()
        self.assertFalse(data["success"])
        self.assertIn("Please select an image file", data["error"])

    def test_staff_upload_disallowed_extension_returns_error(self):
        """Test case description."""
        self.client.force_login(self.staff_user)
        file = SimpleUploadedFile("script.exe", b"executable_data", content_type="application/octet-stream")
        res = self.client.post("/admin/articles/upload-image/", {"image": file})
        self.assertEqual(res.status_code, 400)
        data = res.json()
        self.assertFalse(data["success"])
        self.assertIn("Only image files are supported", data["error"])

    def test_staff_upload_oversized_file_returns_error(self):
        """Test case description."""
        self.client.force_login(self.staff_user)
        oversized_data = b"0" * (10 * 1024 * 1024 + 512)
        file = SimpleUploadedFile("large.png", oversized_data, content_type="image/png")
        res = self.client.post("/admin/articles/upload-image/", {"image": file})
        self.assertEqual(res.status_code, 400)
        data = res.json()
        self.assertFalse(data["success"])
        self.assertIn("10MB", data["error"])

    def test_staff_upload_valid_image_succeeds(self):
        """Test case description."""
        from django.conf import settings
        from pathlib import Path

        self.client.force_login(self.staff_user)
        file = SimpleUploadedFile("sample_cover.jpg", b"fake_jpeg_content", content_type="image/jpeg")
        res = self.client.post("/admin/articles/upload-image/", {"image": file})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertTrue(data["url"].startswith("/media/articles/art_"))
        self.assertTrue(data["url"].endswith(".jpg"))

        # English test comment
        filename = data["url"].split("/")[-1]
        saved_path = Path(settings.MEDIA_ROOT) / "articles" / filename
        self.assertTrue(saved_path.exists())
        self.created_files.append(str(saved_path))

    def test_article_can_store_and_render_local_media_image(self):
        """Test case description."""
        from detector.models import KnowledgeArticle

        media_url = "/media/articles/art_test123456.jpg"
        art = KnowledgeArticle(
            title="Local media test article",
            category="Security",
            desc="Test description",
            image=media_url,
            status=KnowledgeArticle.STATUS_PUBLISHED,
        )
        # English test comment
        art.full_clean()
        art.save()

        # English test comment
        res = self.client.get(f"/knowledge/{art.id}/")
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, media_url)


class DomainHistoryDisplayTests(TestCase):
    def test_result_card_shows_system_history_without_phishwise_name(self):
        """Test case description."""
        session = self.client.session
        session["last_scan_result"] = {
            "url": "https://example-test.com/path",
            "score": 90,
            "status": "safe",
            "ai_risk_score": 10,
            "ssl_title": "Secure",
            "ssl_sub": "Valid",
            "domain_age": "1 year",
            "domain_sub": "Established domain",
            "is_blacklisted": False,
            "google_safe": True,
            "location": "Thailand",
            "has_redirection": False,
        }
        session.save()
        res = self.client.get("/result/")
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "System History")
        self.assertNotContains(res, "PhishWise System History")

    def test_domain_history_breakdown_shows_only_detected_risks(self):
        """Test case description."""
        domain_url = "https://test-breakdown.com"
        now = timezone.now()

        # English test comment
        for _ in range(9):
            ScanHistory.objects.create(
                url=f"{domain_url}/page", score=90, status="safe", ai_risk_score=10,
                ssl_title="Secure", ssl_sub="", domain_age="", domain_sub="",
                location="Thailand", has_redirection=False, timestamp=now,
            )
        ScanHistory.objects.create(
            url=f"{domain_url}/suspicious", score=30, status="mostly_danger", ai_risk_score=70,
            ssl_title="Insecure", ssl_sub="", domain_age="", domain_sub="",
            location="Thailand", has_redirection=False, timestamp=now,
        )
        ScanHistory.objects.create(
            url=f"{domain_url}/malicious", score=10, status="danger", ai_risk_score=90,
            ssl_title="Insecure", ssl_sub="", domain_age="", domain_sub="",
            location="Thailand", has_redirection=False, timestamp=now,
        )

        session = self.client.session
        session["last_scan_result"] = {"url": f"{domain_url}/page", "score": 90, "ai_risk_score": 10}
        session.save()

        res = self.client.get("/result/")
        self.assertEqual(res.status_code, 200)
        ctx = res.context

        history_text = ctx["domain_history_text"]
        self.assertNotIn("Total scans", history_text)
        self.assertEqual(history_text, "Safe 9 time(s) Caution 1 time(s) Dangerous 1 time(s)")

        # English test comment
        self.assertNotIn("Mostly Safe", history_text)
        self.assertNotIn("Suspicious", history_text)

        # English test comment
        self.assertEqual(ctx["phishwise_db"]["label"], "Risk History Detected")

    def test_domain_history_no_scans_shows_no_history_message(self):
        """Test case description."""
        session = self.client.session
        session["last_scan_result"] = {"url": "https://brand-new-domain-never-scanned.org/test", "score": 90, "ai_risk_score": 10}
        session.save()

        res = self.client.get("/result/")
        self.assertEqual(res.status_code, 200)
        ctx = res.context

        self.assertEqual(ctx["domain_history_text"], "No scan history recorded in system")
        self.assertEqual(ctx["phishwise_db"]["label"], "First Scan")

    def test_domain_history_modal_rendered_in_result_page(self):
        """Test case description."""
        domain_url = "https://modal-history-test.com"
        now = timezone.now()
        ScanHistory.objects.create(
            url=f"{domain_url}/", score=85, status="safe", ai_risk_score=15,
            ssl_title="Secure", ssl_sub="", domain_age="", domain_sub="",
            location="Thailand", has_redirection=False, timestamp=now,
        )

        session = self.client.session
        session["last_scan_result"] = {"url": f"{domain_url}/page", "score": 85, "ai_risk_score": 15}
        session.save()

        res = self.client.get("/result/")
        self.assertEqual(res.status_code, 200)

        # English test comment
        self.assertContains(res, "openDomainHistoryModal()")
        self.assertContains(res, 'id="domain-history-modal"')
        self.assertContains(res, "closeDomainHistoryModal()")

        # English test comment
        ctx = res.context
        self.assertIn("domain_history_breakdown", ctx)
        self.assertEqual(len(ctx["domain_history_breakdown"]), 5)
        self.assertEqual(ctx["domain_total_scans"], 1)

        # English test comment
        safe_item = next(item for item in ctx["domain_history_breakdown"] if item["key"] == "safe")
        self.assertEqual(safe_item["count"], 1)

        # English test comment
        self.assertEqual(ctx.get("target_domain"), "modal-history-test.com")
        self.assertContains(res, "modal-history-test.com")






