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
        ("URL Structure (Random Forest)", "Analyzed 11 URL structural features", url_model.get("label", "Standard")),
        ("Web Content (BiLSTM)", "Analyzed HTML tokens on page", content_model.get("label", "Unavailable")),
        ("SSL/TLS Certificate", data.get("ssl_title", "-"), "Valid" if ssl_safe else "Caution"),
        ("Domain Age", data.get("domain_age", "-"), data.get("domain_sub", "-")),
        ("System History", phishwise_db.get("desc", "No prior system scan history"), phishwise_db.get("label", "First Scan")),
        ("URL Redirection", "Detected" if data.get("has_redirection") else "None", "Caution" if data.get("has_redirection") else "Passed"),
        ("Server Location", data.get("location", "-"), "Informational"),
    ]
    return {
        **font_context(), **data, "status_color": status_color, "checks": checks,
        "virustotal": vt,
        "download_display_name": data.get("download_name") or vt.get("file_name") or "-",
        "danger": status_key not in {"safe", "mostly_safe"} or vt.get("status") in {"danger", "high_risk", "suspicious"},
    }


def build_analysis_pdf(data):
    try:
        return write_pdf("pdf/analysis_report.html", _context(data))
    except Exception:
        from .analysis_pdf_report import build_analysis_pdf_reportlab
        return build_analysis_pdf_reportlab(data)
