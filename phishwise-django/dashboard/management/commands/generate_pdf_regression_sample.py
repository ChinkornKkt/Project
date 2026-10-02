from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand

from dashboard.analysis_weasyprint import build_analysis_pdf


class Command(BaseCommand):
    help = "สร้าง PDF ตัวอย่างสำหรับตรวจตำแหน่งสระและวรรณยุกต์ภาษาไทย"

    def handle(self, *args, **options):
        output = Path(settings.BASE_DIR) / "output" / "pdf" / "thai-font-regression-sample.pdf"
        output.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "result_id": "#PH-THAI-TEST",
            "status_label": "มีแนวโน้มอันตราย",
            "status_key": "mostly_danger",
            "ai_risk_score": 71,
            "score": 29,
            "confidence_text": "สูง (99.9%)",
            "scan_time_text": "0.45s",
            "url": "https://example.test/ทดสอบวรรณยุกต์",
            "ssl_title": "ไม่พบการเข้ารหัสที่ปลอดภัย",
            "domain_age": "ไม่พบข้อมูล",
            "domain_sub": "ไม่พบประวัติการจดทะเบียนโดเมน",
            "is_blacklisted": False,
            "google_safe": True,
            "has_redirection": False,
            "location": "กรุงเทพมหานคร ประเทศไทย",
            "download_detected": False,
            "download_name": "",
            "download_size": 0,
            "virustotal": {},
        }
        output.write_bytes(build_analysis_pdf(data))
        self.stdout.write(self.style.SUCCESS(f"สร้างไฟล์ตรวจสอบแล้ว: {output}"))
