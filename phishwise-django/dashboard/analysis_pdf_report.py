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
    canvas.drawRightString(192 * mm, 286 * mm, "รายงานผลการวิเคราะห์", shaping=True)
    canvas.line(18 * mm, 14 * mm, 192 * mm, 14 * mm)
    canvas.drawString(18 * mm, 8.5 * mm, "เอกสารประกอบโครงงานทางการศึกษา", shaping=True)
    canvas.drawRightString(192 * mm, 8.5 * mm, f"หน้า {doc.page}", shaping=True)
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


def build_analysis_pdf(data):
    _register_fonts()
    styles = _styles()
    buffer = BytesIO()
    document = BaseDocTemplate(
        buffer, pagesize=A4, title="รายงานผลการวิเคราะห์ PhishWise",
        author="PhishWise", subject="รายงานการประเมินความเสี่ยง URL และไฟล์ดาวน์โหลด",
        leftMargin=20 * mm, rightMargin=20 * mm, topMargin=22 * mm, bottomMargin=20 * mm,
    )
    frame = Frame(document.leftMargin, document.bottomMargin, document.width, document.height, id="analysis-frame")
    document.addPageTemplates([PageTemplate(id="analysis-report", frames=[frame], onPage=_header_footer)])

    status_color = _status_color(data["status_key"])
    summary = Table(
        [
            [
                _html(f'<b>เลขที่รายงาน</b><br/>{data["result_id"]}', styles["small"]),
                _html("<b>ประเภทการตรวจสอบ</b><br/>URL และความเสี่ยงจากไฟล์ดาวน์โหลด", styles["small"]),
                _html("<b>สถานะรายงาน</b><br/>ฉบับสมบูรณ์", styles["small"]),
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
            _html(f'<font color="{status_color.hexval()}"><b>{data["status_label"]}</b></font><br/><font size="8">ผลการประเมิน</font>', styles["small_center"]),
            _html(f'<font color="{status_color.hexval()}"><b>{data["ai_risk_score"]}/100</b></font><br/><font size="8">คะแนนความเสี่ยง</font>', styles["small_center"]),
            _html(f'<b>{data["confidence_text"]}</b><br/><font size="8">ความเชื่อมั่น</font>', styles["small_center"]),
            _html(f'<b>{data["scan_time_text"]}</b><br/><font size="8">เวลาที่ใช้ตรวจสอบ</font>', styles["small_center"]),
        ]],
        colWidths=[50 * mm, 40 * mm, 40 * mm, 40 * mm],
    )
    score_box.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.7, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 11),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
    ]))

    ssl_result = "มีใบรับรอง SSL" if data["ssl_title"] != "Not Secure" else "ไม่พบการเข้ารหัสที่ปลอดภัย"
    checks = [
        ["หัวข้อการตรวจสอบ", "ผลที่ตรวจพบ", "การแปลผล"],
        ["โครงสร้าง URL", data["url"], "ปกติ" if data["score"] >= 50 else "พบความเสี่ยง"],
        ["ใบรับรอง SSL", f'{ssl_result} - {data["ssl_title"]}', "ผ่าน" if data["ssl_title"] != "Not Secure" else "ควรระวัง"],
        ["อายุโดเมน", data["domain_age"], data["domain_sub"]],
        ["ฐานข้อมูลบัญชีดำ", "พบรายการ" if data["is_blacklisted"] else "ไม่พบรายการ", "อันตราย" if data["is_blacklisted"] else "ผ่าน"],
        ["Google Safe Browsing", "ไม่พบคำเตือน" if data["google_safe"] else "พบคำเตือน", "ผ่าน" if data["google_safe"] else "อันตราย"],
        ["การส่งต่อ URL", "ตรวจพบ" if data["has_redirection"] else "ไม่พบ", "ควรระวัง" if data["has_redirection"] else "ผ่าน"],
        ["ตำแหน่งเซิร์ฟเวอร์", data["location"], "ข้อมูลประกอบการพิจารณา"],
    ]
    check_rows = [[_p(cell, styles["small"]) for cell in row] for row in checks]

    story = [
        Spacer(1, 8 * mm),
        _p("รายงานผลการวิเคราะห์", styles["title"]),
        _p("การประเมินความเสี่ยงของ URL, QR Code และไฟล์ดาวน์โหลดด้วยระบบ PhishWise", styles["subtitle"]),
        Spacer(1, 7 * mm), summary, Spacer(1, 7 * mm),
        _p("1. บทสรุปผลการประเมิน", styles["heading"]),
        _p(
            f'ระบบได้วิเคราะห์ URL ที่ระบุและประเมินผลอยู่ในระดับ “{data["status_label"]}” '
            f'โดยมีคะแนนความเสี่ยง {data["ai_risk_score"]} จาก 100 คะแนน '
            "ผู้ใช้งานควรพิจารณารายละเอียดการตรวจสอบในแต่ละหัวข้อก่อนเปิดเผยข้อมูลส่วนบุคคลหรือดาวน์โหลดไฟล์",
            styles["body"],
        ),
        Spacer(1, 4 * mm), score_box,
        _p("2. ข้อมูลเป้าหมาย", styles["heading"]),
        _table(
            [
                [_p("URL ที่ตรวจสอบ", styles["small"]), _p(data["url"], styles["small"])],
                [_p("เลขอ้างอิงผลตรวจ", styles["small"]), _p(data["result_id"], styles["small"])],
            ],
            [42 * mm, 128 * mm], styles, header=False,
        ),
        _p("3. ผลการตรวจสอบเชิงลึก", styles["heading"]),
        _table(check_rows, [38 * mm, 84 * mm, 48 * mm], styles),
        PageBreak(),
        _p("4. ผลการตรวจสอบไฟล์ดาวน์โหลด", styles["heading"]),
    ]

    vt = data.get("virustotal") or {}
    if data.get("download_detected"):
        vt_rows = [
            ["รายการ", "รายละเอียด"],
            ["ชื่อไฟล์", data.get("download_name") or vt.get("file_name") or "-"],
            ["สถานะ VirusTotal", vt.get("status") or "ยังไม่มีผลสรุป"],
            ["ข้อความจากระบบ", vt.get("message") or "-"],
            ["Malicious / Suspicious", f'{vt.get("malicious", 0)} / {vt.get("suspicious", 0)} จาก {vt.get("total_engines", 0)} ผู้ให้บริการความปลอดภัย (Security Vendors)'],
            ["คะแนนความเสี่ยง VirusTotal", f'{vt.get("risk_score", "-")}/100'],
            ["SHA-256", vt.get("sha256") or "-"],
        ]
        story.append(_table([[_p(c, styles["small"]) for c in row] for row in vt_rows], [50 * mm, 120 * mm], styles))
    else:
        story.append(_p("ไม่พบ URL ที่นำไปสู่การดาวน์โหลดไฟล์ในการตรวจสอบครั้งนี้", styles["body"]))

    danger = data["status_key"] not in {"safe", "mostly_safe"} or vt.get("status") in {"danger", "high_risk", "suspicious"}
    recommendations = [
        ["ระดับคำแนะนำ", "แนวทางปฏิบัติ"],
        ["เร่งด่วน" if danger else "ทั่วไป", "หลีกเลี่ยงการกรอกข้อมูลส่วนบุคคลหรือดาวน์โหลดไฟล์ หากระบบแสดงคำเตือน"],
        ["ตรวจสอบเพิ่มเติม", "ยืนยันชื่อโดเมน ผู้ส่ง และแหล่งที่มาของลิงก์ก่อนเข้าใช้งาน"],
        ["กรณีไฟล์ดาวน์โหลด", "หยุดเปิดไฟล์เมื่อ VirusTotal ตรวจพบความเสี่ยง และแจ้งผู้ดูแลระบบ"],
    ]
    story.extend([
        _p("5. ข้อเสนอแนะด้านความปลอดภัย", styles["heading"]),
        _table([[_p(c, styles["small"]) for c in row] for row in recommendations], [42 * mm, 128 * mm], styles),
        _p("6. ข้อจำกัดของผลการวิเคราะห์", styles["heading"]),
        _p(
            "ผลรายงานเป็นการประเมินความเสี่ยงจากข้อมูลที่ระบบตรวจสอบได้ ณ เวลานั้น "
            "ไม่ใช่การรับรองว่าเว็บไซต์หรือไฟล์ปลอดภัยโดยสมบูรณ์ คะแนนจาก VirusTotal เป็นข้อมูลจากบริการภายนอก "
            "และอาจเปลี่ยนแปลงเมื่อฐานข้อมูลของผู้ให้บริการได้รับการปรับปรุง",
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
        ("โครงสร้าง URL", data.get("url", "-"), "ปกติ" if data.get("score", 0) >= 50 else "พบความเสี่ยง"),
        ("ใบรับรอง SSL", data.get("ssl_title", "-"), "ผ่าน" if ssl_safe else "ควรระวัง"),
        ("อายุโดเมน", data.get("domain_age", "-"), data.get("domain_sub", "-")),
        ("ฐานข้อมูลบัญชีดำ", "พบรายการ" if data.get("is_blacklisted") else "ไม่พบรายการ", "อันตราย" if data.get("is_blacklisted") else "ผ่าน"),
        ("Google Safe Browsing", "ไม่พบคำเตือน" if data.get("google_safe") else "พบคำเตือน", "ผ่าน" if data.get("google_safe") else "อันตราย"),
        ("การส่งต่อ URL", "ตรวจพบ" if data.get("has_redirection") else "ไม่พบ", "ควรระวัง" if data.get("has_redirection") else "ผ่าน"),
        ("ตำแหน่งเซิร์ฟเวอร์", data.get("location", "-"), "ข้อมูลประกอบการพิจารณา"),
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
    """สร้างรายงานด้วย HTML/CSS และคืนค่าเป็น bytes เหมือน interface เดิม"""
    from django.conf import settings
    from django.template.loader import render_to_string

    _configure_weasyprint_runtime()
    from weasyprint import HTML

    html = render_to_string("pdf/analysis_report.html", _weasyprint_context(data))
    return HTML(string=html, base_url=str(settings.BASE_DIR)).write_pdf()
