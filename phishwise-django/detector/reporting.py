from urllib.parse import urlparse

from django.db import IntegrityError, transaction
from django.utils import timezone

from .models import DomainStatistic, SuspiciousSiteReport


def domain_from_url(value):
    parsed = urlparse((value or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("กรุณาระบุ URL ที่ขึ้นต้นด้วย http:// หรือ https:// และมีชื่อโดเมน")
    return parsed.hostname.rstrip(".").lower()


def record_domain_scan(url, user=None, status=None, score=None):
    try:
        domain = domain_from_url(url)
    except ValueError:
        return None
    with transaction.atomic():
        statistic, _ = DomainStatistic.objects.select_for_update().get_or_create(domain=domain)
        statistic.scan_count += 1
        if user and user.is_authenticated and not statistic.scanned_by.filter(pk=user.pk).exists():
            statistic.scanned_by.add(user)
            statistic.unique_scanner_count += 1
        if status:
            statistic.last_status = status
        if score is not None:
            statistic.last_score = score
        statistic.save(update_fields=("scan_count", "unique_scanner_count", "last_status", "last_score", "updated_at"))
    return statistic



def create_site_report(*, user, url, reason, details):
    domain = domain_from_url(url)
    try:
        with transaction.atomic():
            statistic, _ = DomainStatistic.objects.select_for_update().get_or_create(domain=domain)
            report = SuspiciousSiteReport.objects.create(user=user, domain=domain, url=url.strip(), reason=reason, details=details.strip())
            statistic.report_count += 1
            statistic.save(update_fields=("report_count", "updated_at"))
    except IntegrityError as exc:
        raise ValueError("คุณได้รายงานโดเมนนี้แล้ว และรายการยังอยู่ระหว่างตรวจสอบหรือได้รับอนุมัติ") from exc
    return report


def review_site_report(report, *, status, reviewer):
    if status not in {SuspiciousSiteReport.APPROVED, SuspiciousSiteReport.REJECTED}:
        raise ValueError("สถานะการตรวจสอบไม่ถูกต้อง")
    with transaction.atomic():
        report = SuspiciousSiteReport.objects.select_for_update().get(pk=report.pk)
        old_status = report.status
        report.status, report.reviewed_by, report.reviewed_at = status, reviewer, timezone.now()
        report.save(update_fields=("status", "reviewed_by", "reviewed_at"))
        statistic, _ = DomainStatistic.objects.select_for_update().get_or_create(domain=report.domain)
        if old_status != status:
            if old_status == SuspiciousSiteReport.APPROVED:
                statistic.approved_report_count = max(0, statistic.approved_report_count - 1)
            if status == SuspiciousSiteReport.APPROVED:
                statistic.approved_report_count += 1
            statistic.save(update_fields=("approved_report_count", "updated_at"))
    return report