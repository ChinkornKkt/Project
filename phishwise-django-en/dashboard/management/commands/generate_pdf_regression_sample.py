from pathlib import Path
from django.conf import settings
from django.core.management.base import BaseCommand
from dashboard.analysis_weasyprint import build_analysis_pdf


class Command(BaseCommand):
    help = "Generate sample analysis PDF report using WeasyPrint"

    def handle(self, *args, **options):
        output = Path(settings.BASE_DIR) / "output" / "pdf" / "phishwise-analysis-sample-en.pdf"
        output.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "result_id": "#PW-EN-TEST",
            "status_label": "High Risk",
            "status_key": "mostly_danger",
            "ai_risk_score": 71,
            "score": 29,
            "confidence_text": "High (99.9%)",
            "scan_time_text": "0.45s",
            "url": "https://example.test/security-verification-check",
            "ssl_title": "No Secure Encryption Found",
            "domain_age": "Unknown",
            "domain_sub": "No domain registration history found",
            "is_blacklisted": False,
            "google_safe": True,
            "has_redirection": False,
            "location": "Bangkok, Thailand",
            "download_detected": False,
            "download_name": "",
            "download_size": 0,
            "virustotal": {},
        }
        output.write_bytes(build_analysis_pdf(data))
        self.stdout.write(self.style.SUCCESS(f"Sample PDF created: {output}"))
