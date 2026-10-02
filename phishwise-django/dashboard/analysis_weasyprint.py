from .weasyprint_runtime import font_context, write_pdf


def _context(data):
    status_key = data.get("status_key", "warning")
    vt = data.get("virustotal") or {}
    ssl_safe = data.get("ssl_title") != "Not Secure"
    if status_key in {"safe", "mostly_safe"}:
        status_color = "#059669"
    elif status_key == "warning":
        status_color = "#d97706"
    else:
        status_color = "#e11d48"
    url_model = data.get("url_model_result") or {}
    content_model = data.get("content_model_result") or {}
    phishwise_db = data.get("phishwise_db") or {}

    checks = [
        ("โครงสร้าง URL (Random Forest)", "วิเคราะห์คุณลักษณะ 11 ด้านของ URL", url_model.get("label", "ปกติ")),
        ("เนื้อหาหน้าเว็บ (BiLSTM)", "วิเคราะห์โทเคน HTML ในหน้าเว็บ", content_model.get("label", "ตรวจไม่ได้")),
        ("ใบรับรอง SSL", data.get("ssl_title", "-"), "ผ่าน" if ssl_safe else "ควรระวัง"),
        ("อายุโดเมน", data.get("domain_age", "-"), data.get("domain_sub", "-")),
        ("ประวัติในระบบ", phishwise_db.get("desc", "ยังไม่มีประวัติในระบบ"), phishwise_db.get("label", "สแกนครั้งแรก")),
        ("การส่งต่อ URL", "ตรวจพบ" if data.get("has_redirection") else "ไม่พบ", "ควรระวัง" if data.get("has_redirection") else "ผ่าน"),
        ("ตำแหน่งเซิร์ฟเวอร์", data.get("location", "-"), "ข้อมูลประกอบการพิจารณา"),
    ]
    return {
        **font_context(), **data, "status_color": status_color, "checks": checks,
        "virustotal": vt,
        "download_display_name": data.get("download_name") or vt.get("file_name") or "-",
        "danger": status_key not in {"safe", "mostly_safe"} or vt.get("status") in {"danger", "high_risk", "suspicious"},
    }


def build_analysis_pdf(data):
    return write_pdf("pdf/analysis_report.html", _context(data))
