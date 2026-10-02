from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand

from dashboard.statistics_weasyprint import build_statistics_pdf


class Command(BaseCommand):
    help = "สร้างรายงานสถิติตัวอย่างด้วย WeasyPrint"

    def handle(self, *args, **options):
        output = Path(settings.BASE_DIR) / "output/pdf/phishwise-statistics-weasyprint-sample.pdf"
        output.parent.mkdir(parents=True, exist_ok=True)
        users = [
            {"name": "สมชาย ใจดี", "email": "somchai@example.com", "total": 34, "safe": 22, "warning": 8, "danger": 4, "last_scan": "03/08/2026 18:42"},
            {"name": "พิมพ์ชนก แสงทอง", "email": "pimchanok@example.com", "total": 29, "safe": 20, "warning": 6, "danger": 3, "last_scan": "03/08/2026 17:15"},
            {"name": "ธนกฤต ศรีสุข", "email": "thanakrit@example.com", "total": 37, "safe": 24, "warning": 8, "danger": 5, "last_scan": "03/08/2026 16:08"},
            {"name": "กัญญารัตน์ มีชัย", "email": "kanyarat@example.com", "total": 28, "safe": 19, "warning": 7, "danger": 2, "last_scan": "02/08/2026 21:34"},
        ]
        data = {
            "prepared_by": "ผู้ดูแลระบบ PhishWise", "report_number": "PW-STAT-2026-008",
            "report_date": "03/08/2026 22:30", "report_period": "30 วันล่าสุด",
            "total_users": 4, "total_scans": 128, "safe_count": 85,
            "warning_count": 29, "danger_count": 14, "safe_percentage": 66,
            "warning_percentage": 23, "danger_percentage": 11, "sample_users": users,
            "trend_labels": ["สัปดาห์ 1", "สัปดาห์ 2", "สัปดาห์ 3", "สัปดาห์ 4"],
            "trend_values": [24, 31, 29, 44],
        }
        output.write_bytes(build_statistics_pdf(data))
        self.stdout.write(self.style.SUCCESS(f"สร้างไฟล์ตัวอย่างแล้ว: {output}"))
