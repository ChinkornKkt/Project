from io import BytesIO
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

DARK = colors.HexColor("#0f172a")
SLATE = colors.HexColor("#475569")
LIGHT = colors.HexColor("#f1f5f9")
LINE = colors.HexColor("#cbd5e1")
BLUE = colors.HexColor("#1d4ed8")
GREEN = colors.HexColor("#059669")
AMBER = colors.HexColor("#d97706")
RED = colors.HexColor("#e11d48")


def _register_fonts():
    if "AnalysisThai" in pdfmetrics.getRegisteredFontNames():
        return
    assets = Path(__file__).resolve().parent.parent / "assets" / "fonts"
    noto_fonts = assets / "noto-sans-thai"
    sarabun_fonts = assets / "sarabun"
    candidates = [
        (sarabun_fonts / "Sarabun-Regular.ttf", sarabun_fonts / "Sarabun-Bold.ttf"),
        (noto_fonts / "NotoSansThai-Regular.ttf", noto_fonts / "NotoSansThai-Bold.ttf"),
        (Path("C:/Windows/Fonts/LeelawUI.ttf"), Path("C:/Windows/Fonts/LeelaUIb.ttf")),
        (Path("C:/Windows/Fonts/tahoma.ttf"), Path("C:/Windows/Fonts/tahomabd.ttf")),
        (
            Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
            Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
        ),
    ]
    for regular, bold in candidates:
        if regular.exists() and bold.exists():
            pdfmetrics.registerFont(TTFont("AnalysisThai", str(regular)))
            pdfmetrics.registerFont(TTFont("AnalysisThai-Bold", str(bold)))
            return
    raise RuntimeError("A Unicode font is required to generate the PDF report")


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "AnalysisTitle", parent=base["Title"], fontName="AnalysisThai-Bold",
            fontSize=22, leading=28, textColor=DARK, alignment=TA_CENTER,
            spaceAfter=4 * mm,
            shaping=True,
        ),
        "subtitle": ParagraphStyle(
            "AnalysisSubtitle", parent=base["BodyText"], fontName="AnalysisThai",
            fontSize=10, leading=16, textColor=SLATE, alignment=TA_CENTER,
            shaping=True,
        ),
        "heading": ParagraphStyle(
            "AnalysisHeading", parent=base["Heading2"], fontName="AnalysisThai-Bold",
            fontSize=15, leading=20, textColor=DARK, spaceBefore=4 * mm,
            spaceAfter=3 * mm,
            shaping=True,
        ),
        "body": ParagraphStyle(
            "AnalysisBody", parent=base["BodyText"], fontName="AnalysisThai",
            fontSize=9.5, leading=16, textColor=SLATE,
            shaping=True,
        ),
        "small": ParagraphStyle(
            "AnalysisSmall", parent=base["BodyText"], fontName="AnalysisThai",
            fontSize=8, leading=12, textColor=SLATE,
            shaping=True,
        ),
        "small_center": ParagraphStyle(
            "AnalysisSmallCenter", parent=base["BodyText"], fontName="AnalysisThai",
            fontSize=8, leading=12, textColor=SLATE, alignment=TA_CENTER,
            shaping=True,
        ),
        "table_header": ParagraphStyle(
            "AnalysisTableHeader", parent=base["BodyText"], fontName="AnalysisThai-Bold",
            fontSize=8, leading=12, textColor=colors.white, shaping=True,
        ),
    }


def _header_footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(0.7)
    canvas.line(18 * mm, 282 * mm, 192 * mm, 282 * mm)
    canvas.setFont("AnalysisThai-Bold", 8)
    canvas.setFillColor(BLUE)
    canvas.drawString(18 * mm, 286 * mm, "PHISHWISE SECURITY REPORT")
    canvas.setFont("AnalysisThai", 8)
    canvas.setFillColor(SLATE)
    canvas.drawRightString(192 * mm, 286 * mm, "Detailed Analysis Report", shaping=True)
    canvas.line(18 * mm, 14 * mm, 192 * mm, 14 * mm)
    canvas.drawString(18 * mm, 8.5 * mm, "PhishWise Educational Cybersecurity Project", shaping=True)
    canvas.drawRightString(192 * mm, 8.5 * mm, f"Page {doc.page}", shaping=True)
    canvas.restoreState()


def _p(value, style):
    return Paragraph(str(value or "-").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), style)


def _html(value, style):
    return Paragraph(str(value or "-"), style)


def _table(rows, widths, styles, header=True):
    if header and rows:
        rows[0] = [
            Paragraph(cell.getPlainText() if isinstance(cell, Paragraph) else str(cell), styles["table_header"])
            for cell in rows[0]
        ]
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    commands = [
        ("FONTNAME", (0, 0), (-1, -1), "AnalysisThai"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("TEXTCOLOR", (0, 0), (-1, -1), DARK),
        ("GRID", (0, 0), (-1, -1), 0.5, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]
    if header:
        commands.extend([
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "AnalysisThai-Bold"),
        ])
    table.setStyle(TableStyle(commands))
    return table


def _status_color(status_key):
    if status_key in {"safe", "mostly_safe"}:
        return GREEN
    if status_key == "warning":
        return AMBER
    return RED


def build_analysis_pdf_reportlab(data):
    _register_fonts()
    styles = _styles()
    buffer = BytesIO()
    document = BaseDocTemplate(
        buffer, pagesize=A4, title="PhishWise Detailed Analysis Report",
        author="PhishWise", subject="URL and Download Security Assessment Report",
        leftMargin=20 * mm, rightMargin=20 * mm, topMargin=22 * mm, bottomMargin=20 * mm,
    )
    frame = Frame(document.leftMargin, document.bottomMargin, document.width, document.height, id="analysis-frame")
    document.addPageTemplates([PageTemplate(id="analysis-report", frames=[frame], onPage=_header_footer)])

    status_color = _status_color(data["status_key"])
    summary = Table(
        [
            [
                _html(f'<b>Report ID</b><br/>{data["result_id"]}', styles["small"]),
                _html("<b>Inspection Type</b><br/>URL & Download Security Assessment", styles["small"]),
                _html("<b>Report Status</b><br/>Complete", styles["small"]),
            ]
        ],
        colWidths=[53 * mm, 72 * mm, 45 * mm],
    )
    summary.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.6, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE),
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))

    score_box = Table(
        [[
            _html(f'<font color="{status_color.hexval()}"><b>{data["status_label"]}</b></font><br/><font size="8">Risk Assessment</font>', styles["small_center"]),
            _html(f'<font color="{status_color.hexval()}"><b>{data["ai_risk_score"]}/100</b></font><br/><font size="8">Risk Score</font>', styles["small_center"]),
            _html(f'<b>{data["confidence_text"]}</b><br/><font size="8">Confidence</font>', styles["small_center"]),
            _html(f'<b>{data["scan_time_text"]}</b><br/><font size="8">Scan Duration</font>', styles["small_center"]),
        ]],
        colWidths=[50 * mm, 40 * mm, 40 * mm, 40 * mm],
    )
    score_box.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.7, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 11),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
    ]))

    ssl_result = "Valid SSL Certificate" if data["ssl_title"] != "Not Secure" else "No Secure Encryption"
    checks = [
        ["Check Item", "Observed Value", "Evaluation"],
        ["URL Structure", data["url"], "Normal" if data["score"] >= 50 else "Risk Found"],
        ["SSL Certificate", f'{ssl_result} - {data["ssl_title"]}', "Passed" if data["ssl_title"] != "Not Secure" else "Caution"],
        ["Domain Age", data["domain_age"], data["domain_sub"]],
        ["Blacklist Database", "Listed" if data["is_blacklisted"] else "Not Listed", "Dangerous" if data["is_blacklisted"] else "Passed"],
        ["Safe Browsing", "No Warning" if data["google_safe"] else "Warning Found", "Passed" if data["google_safe"] else "Dangerous"],
        ["URL Redirection", "Detected" if data["has_redirection"] else "None", "Caution" if data["has_redirection"] else "Passed"],
        ["Server Location", data["location"], "Informational"],
    ]
    check_rows = [[_p(cell, styles["small"]) for cell in row] for row in checks]

    story = [
        Spacer(1, 8 * mm),
        _p("Detailed Analysis Report", styles["title"]),
        _p("Risk Assessment of URL, QR Code, and Downloaded Files by PhishWise", styles["subtitle"]),
        Spacer(1, 7 * mm), summary, Spacer(1, 7 * mm),
        _p("1. Assessment Summary", styles["heading"]),
        _p(
            f'The system analyzed the target URL and classified it as "{data["status_label"]}" '
            f'with an AI risk score of {data["ai_risk_score"]} out of 100. '
            "Users should review the detailed checklist below before entering credentials or downloading files.",
            styles["body"],
        ),
        Spacer(1, 4 * mm), score_box,
        _p("2. Target Information", styles["heading"]),
        _table(
            [
                [_p("Scanned URL", styles["small"]), _p(data["url"], styles["small"])],
                [_p("Report Reference ID", styles["small"]), _p(data["result_id"], styles["small"])],
            ],
            [42 * mm, 128 * mm], styles, header=False,
        ),
        _p("3. In-Depth Inspection Results", styles["heading"]),
        _table(check_rows, [38 * mm, 84 * mm, 48 * mm], styles),
        PageBreak(),
        _p("4. Downloaded File Analysis", styles["heading"]),
    ]

    vt = data.get("virustotal") or {}
    if data.get("download_detected"):
        vt_rows = [
            ["Parameter", "Details"],
            ["Filename", data.get("download_name") or vt.get("file_name") or "-"],
            ["VirusTotal Status", vt.get("status") or "Pending / No Result"],
            ["System Message", vt.get("message") or "-"],
            ["Malicious / Suspicious", f'{vt.get("malicious", 0)} / {vt.get("suspicious", 0)} of {vt.get("total_engines", 0)} Security Vendors'],
            ["VirusTotal Risk Score", f'{vt.get("risk_score", "-")}/100'],
            ["SHA-256", vt.get("sha256") or "-"],
        ]
        story.append(_table([[_p(c, styles["small"]) for c in row] for row in vt_rows], [50 * mm, 120 * mm], styles))
    else:
        story.append(_p("No downloadable file detected in this inspection.", styles["body"]))

    danger = data["status_key"] not in {"safe", "mostly_safe"} or vt.get("status") in {"danger", "high_risk", "suspicious"}
    recommendations = [
        ["Priority", "Action Recommendation"],
        ["Urgent" if danger else "Standard", "Avoid submitting personal credentials or downloading files when alerted"],
        ["Verification", "Verify domain spelling, sender identity, and link origin before proceeding"],
        ["File Download", "Do not open files flagged by VirusTotal; alert system administrator"],
    ]
    story.extend([
        _p("5. Security Recommendations", styles["heading"]),
        _table([[_p(c, styles["small"]) for c in row] for row in recommendations], [42 * mm, 128 * mm], styles),
        _p("6. Analysis Disclaimers & Limitations", styles["heading"]),
        _p(
            "This report is a risk assessment based on observable data at the time of inspection. "
            "It does not certify absolute security. VirusTotal data represents third-party threat intelligence "
            "and may update over time as antivirus vendor definitions evolve.",
            styles["body"],
        ),
    ])
    document.build(story)
    return buffer.getvalue()


# WeasyPrint implementation.  Kept below the former ReportLab builder so the
# public function name remains unchanged while older imports keep working.
def _configure_weasyprint_runtime():
    import os

    if os.name != "nt":
        return
    configured = os.environ.get("WEASYPRINT_DLL_DIRECTORIES", "")
    candidates = [Path(item.strip()) for item in configured.split(os.pathsep) if item.strip()]
    candidates.extend([Path("C:/msys64/mingw64/bin"), Path("C:/msys64/ucrt64/bin")])
    for directory in candidates:
        if directory.is_dir():
            os.environ["PATH"] = f"{directory}{os.pathsep}{os.environ.get('PATH', '')}"
            if hasattr(os, "add_dll_directory"):
                os.add_dll_directory(str(directory))
            return


def _weasyprint_context(data):
    from django.conf import settings

    status_key = data.get("status_key", "warning")
    vt = data.get("virustotal") or {}
    ssl_safe = data.get("ssl_title") != "Not Secure"
    checks = [
        ("URL Structure", data.get("url", "-"), "Normal" if data.get("score", 0) >= 50 else "Risk Found"),
        ("SSL Certificate", data.get("ssl_title", "-"), "Valid" if ssl_safe else "Caution"),
        ("Domain Age", data.get("domain_age", "-"), data.get("domain_sub", "-")),
        ("Blacklist Database", "Listed" if data.get("is_blacklisted") else "Clean", "Dangerous" if data.get("is_blacklisted") else "Passed"),
        ("Safe Browsing", "No Warning" if data.get("google_safe") else "Warning Found", "Passed" if data.get("google_safe") else "Dangerous"),
        ("URL Redirection", "Detected" if data.get("has_redirection") else "None", "Caution" if data.get("has_redirection") else "Passed"),
        ("Server Location", data.get("location", "-"), "Informational"),
    ]
    if status_key in {"safe", "mostly_safe"}:
        status_color = "#059669"
    elif status_key == "warning":
        status_color = "#d97706"
    else:
        status_color = "#e11d48"
    return {
        **data,
        "status_color": status_color,
        "checks": checks,
        "virustotal": vt,
        "download_display_name": data.get("download_name") or vt.get("file_name") or "-",
        "danger": status_key not in {"safe", "mostly_safe"} or vt.get("status") in {"danger", "high_risk", "suspicious"},
        "font_regular_uri": (Path(settings.BASE_DIR) / "assets/fonts/sarabun/Sarabun-Regular.ttf").as_uri(),
        "font_bold_uri": (Path(settings.BASE_DIR) / "assets/fonts/sarabun/Sarabun-Bold.ttf").as_uri(),
    }


def build_analysis_pdf(data):
    """Build report using HTML/CSS (WeasyPrint) with graceful ReportLab fallback."""
    from django.conf import settings
    from django.template.loader import render_to_string

    try:
        _configure_weasyprint_runtime()
        from weasyprint import HTML

        html = render_to_string("pdf/analysis_report.html", _weasyprint_context(data))
        return HTML(string=html, base_url=str(settings.BASE_DIR)).write_pdf()
    except Exception:
        return build_analysis_pdf_reportlab(data)
