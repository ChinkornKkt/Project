from io import BytesIO
from pathlib import Path

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, Rect, String
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

BLUE = colors.HexColor("#1D4ED8")
DARK = colors.HexColor("#0F172A")
SLATE = colors.HexColor("#475569")
LIGHT = colors.HexColor("#F1F5F9")
GREEN = colors.HexColor("#059669")
AMBER = colors.HexColor("#D97706")
RED = colors.HexColor("#E11D48")


def _register_fonts():
    bundled_fonts = Path(__file__).resolve().parent.parent / "assets" / "fonts" / "sarabun"
    candidates = [
        (
            bundled_fonts / "Sarabun-Regular.ttf",
            bundled_fonts / "Sarabun-Bold.ttf",
        ),
        (
            Path("C:/Windows/Fonts/LeelawUI.ttf"),
            Path("C:/Windows/Fonts/LeelaUIb.ttf"),
        ),
        (
            Path("C:/Windows/Fonts/tahoma.ttf"),
            Path("C:/Windows/Fonts/tahomabd.ttf"),
        ),
        (
            Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
            Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
        ),
    ]
    for regular, bold in candidates:
        if regular.exists() and bold.exists():
            pdfmetrics.registerFont(TTFont("ReportThai", str(regular)))
            pdfmetrics.registerFont(TTFont("ReportThai-Bold", str(bold)))
            return
    raise RuntimeError("A Unicode font is required to generate the PDF report")


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontName="ReportThai-Bold",
            fontSize=23,
            leading=29,
            textColor=DARK,
            spaceAfter=4 * mm,
            shaping=True,
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle",
            parent=base["Normal"],
            fontName="ReportThai",
            fontSize=10,
            leading=15,
            textColor=SLATE,
            shaping=True,
        ),
        "section": ParagraphStyle(
            "ReportSection",
            parent=base["Heading2"],
            fontName="ReportThai-Bold",
            fontSize=14,
            leading=18,
            textColor=DARK,
            spaceBefore=3 * mm,
            spaceAfter=3 * mm,
            shaping=True,
        ),
        "body": ParagraphStyle(
            "ReportBody",
            parent=base["BodyText"],
            fontName="ReportThai",
            fontSize=9.5,
            leading=15,
            textColor=SLATE,
            shaping=True,
        ),
        "small": ParagraphStyle(
            "ReportSmall",
            parent=base["BodyText"],
            fontName="ReportThai",
            fontSize=8,
            leading=11,
            textColor=SLATE,
            shaping=True,
        ),
        "right": ParagraphStyle(
            "ReportRight",
            parent=base["BodyText"],
            fontName="ReportThai",
            fontSize=8.5,
            leading=13,
            textColor=SLATE,
            alignment=TA_RIGHT,
            shaping=True,
        ),
        "center": ParagraphStyle(
            "ReportCenter",
            parent=base["BodyText"],
            fontName="ReportThai",
            fontSize=8.5,
            leading=12,
            alignment=TA_CENTER,
            shaping=True,
        ),
        "table_header": ParagraphStyle(
            "ReportTableHeader",
            parent=base["BodyText"],
            fontName="ReportThai-Bold",
            fontSize=8.5,
            leading=12,
            textColor=colors.white,
            alignment=TA_CENTER,
            shaping=True,
        ),
    }


def _header_footer(canvas, doc):
    canvas.saveState()
    width, height = A4
    canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
    canvas.line(18 * mm, height - 15 * mm, width - 18 * mm, height - 15 * mm)
    canvas.setFont("ReportThai-Bold", 8)
    canvas.setFillColor(BLUE)
    canvas.drawString(18 * mm, height - 11.5 * mm, "PHISHWISE SECURITY REPORT")
    canvas.setFont("ReportThai", 8)
    canvas.setFillColor(SLATE)
    canvas.drawRightString(
        width - 18 * mm, height - 11.5 * mm, "Scan Statistics Report", shaping=True
    )
    canvas.line(18 * mm, 14 * mm, width - 18 * mm, 14 * mm)
    canvas.drawString(18 * mm, 9.5 * mm, "PhishWise Educational Cybersecurity Project", shaping=True)
    canvas.drawRightString(
        width - 18 * mm, 9.5 * mm, f"Page {doc.page}", shaping=True
    )
    canvas.restoreState()


def _summary_table(data, styles):
    rows = [
        [
            ("Total Users", data["total_users"], DARK),
            ("Total Scans", data["total_scans"], BLUE),
            ("Safe", data["safe_count"], GREEN),
            ("Caution", data["warning_count"], AMBER),
            ("Dangerous", data["danger_count"], RED),
        ]
    ]
    cells = []
    for label, value, color in rows[0]:
        cells.append(
            Table(
                [
                    [
                        Paragraph(
                            f'<font color="#64748B">{label}</font>',
                            ParagraphStyle(
                                f"summary-label-{label}",
                                parent=styles["center"],
                                fontSize=8,
                                leading=9,
                            ),
                        )
                    ],
                    [
                        Paragraph(
                            f'<font color="{color.hexval()}">{value}</font>',
                            ParagraphStyle(
                                f"summary-value-{label}",
                                parent=styles["center"],
                                fontName="ReportThai-Bold",
                                fontSize=20,
                                leading=22,
                            ),
                        )
                    ],
                    [
                        Paragraph(
                            '<font color="#94A3B8">scans</font>',
                            ParagraphStyle(
                                f"summary-unit-{label}",
                                parent=styles["center"],
                                fontSize=7,
                                leading=8,
                            ),
                        )
                    ],
                ],
                colWidths=[32 * mm],
                rowHeights=[5 * mm, 9 * mm, 4 * mm],
                style=TableStyle(
                    [
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 0),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                        ("TOPPADDING", (0, 0), (-1, -1), 0),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                    ]
                ),
            )
        )
    table = Table([cells], colWidths=[34.6 * mm] * 5, rowHeights=[25 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    return table


def _risk_chart(data):
    drawing = Drawing(170 * mm, 72 * mm)
    pie = Pie()
    pie.x = 12 * mm
    pie.y = 7 * mm
    pie.width = 55 * mm
    pie.height = 55 * mm
    pie_values = [data["safe_count"], data["warning_count"], data["danger_count"]]
    pie.data = pie_values if sum(pie_values) else [1, 0, 0]
    pie.labels = None
    pie.slices[0].fillColor = GREEN
    pie.slices[1].fillColor = AMBER
    pie.slices[2].fillColor = RED
    pie.slices.strokeColor = colors.white
    pie.slices.strokeWidth = 1
    drawing.add(pie)
    risk_legend = [
        (GREEN, "Safe", 9 * mm),
        (AMBER, "Caution", 33 * mm),
        (RED, "Dangerous", 61 * mm),
    ]
    for color, label, x_position in risk_legend:
        drawing.add(Rect(x_position, 1.5 * mm, 3 * mm, 3 * mm, fillColor=color, strokeColor=None))
        drawing.add(
            String(
                x_position + 4.5 * mm,
                1.5 * mm,
                label,
                fontName="ReportThai",
                fontSize=7,
                fillColor=DARK,
            )
        )

    bar = VerticalBarChart()
    bar.x = 92 * mm
    bar.y = 12 * mm
    bar.width = 72 * mm
    bar.height = 48 * mm
    bar.data = [data["trend_values"]]
    bar.categoryAxis.categoryNames = data["trend_labels"]
    bar.categoryAxis.labels.fontName = "ReportThai"
    bar.categoryAxis.labels.fontSize = 6.5
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = 30
    bar.valueAxis.valueStep = 5
    bar.valueAxis.labels.fontName = "ReportThai"
    bar.valueAxis.labels.fontSize = 6.5
    bar.bars[0].fillColor = BLUE
    bar.bars[0].strokeColor = BLUE
    drawing.add(bar)
    drawing.add(
        String(
            111 * mm,
            65 * mm,
            "7-Day Trend",
            fontName="ReportThai-Bold",
            fontSize=8,
            fillColor=DARK,
        )
    )
    return drawing


def _users_table(data, styles):
    header = [
        "User",
        "Total",
        "Safe",
        "Caution",
        "Dangerous",
        "Latest Scan",
    ]
    rows = [[Paragraph(item, styles["table_header"]) for item in header]]
    for user in data["sample_users"]:
        rows.append(
            [
                Paragraph(
                    f'<b>{user["name"]}</b><br/><font size="7">{user["email"]}</font>',
                    styles["small"],
                ),
                str(user["total"]),
                str(user["safe"]),
                str(user["warning"]),
                str(user["danger"]),
                user["last_scan"],
            ]
        )
    rows.append(
        [
            "Grand Total",
            str(data["total_scans"]),
            str(data["safe_count"]),
            str(data["warning_count"]),
            str(data["danger_count"]),
            "-",
        ]
    )
    table = Table(
        rows,
        colWidths=[47 * mm, 19 * mm, 19 * mm, 20 * mm, 18 * mm, 49 * mm],
        repeatRows=1,
    )
    table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, -1), "ReportThai"),
                ("FONTNAME", (0, 0), (-1, 0), "ReportThai-Bold"),
                ("FONTNAME", (0, -1), (-1, -1), "ReportThai-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BACKGROUND", (0, 0), (-1, 0), DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BACKGROUND", (0, -1), (-1, -1), LIGHT),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (1, 1), (4, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("TEXTCOLOR", (2, 1), (2, -2), GREEN),
                ("TEXTCOLOR", (3, 1), (3, -2), AMBER),
                ("TEXTCOLOR", (4, 1), (4, -2), RED),
            ]
        )
    )
    return table


def build_statistics_pdf(data):
    _register_fonts()
    styles = _styles()
    output = BytesIO()
    doc = BaseDocTemplate(
        output,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=22 * mm,
        bottomMargin=20 * mm,
        title="PhishWise Scan Statistics Report",
        author="PhishWise",
        subject="Educational Cybersecurity Project Report",
    )
    frame = Frame(
        doc.leftMargin,
        doc.bottomMargin,
        doc.width,
        doc.height,
        id="report-frame",
    )
    doc.addPageTemplates(
        [PageTemplate(id="formal-report", frames=[frame], onPage=_header_footer)]
    )

    meta = Table(
        [
            [
                Paragraph(
                    '<font color="#1D4ED8"><b>PHISHWISE</b></font><br/>'
                    '<font size="8">URL & QR Code Risk Assessment System</font>',
                    styles["subtitle"],
                ),
                Paragraph(
                    f'<b>Report ID:</b> {data["report_number"]}<br/>'
                    f'<b>Period:</b> {data["report_period"]}<br/>'
                    f'<b>Date:</b> {data["report_date"]}<br/>'
                    f'<b>Prepared By:</b> {data["prepared_by"]}',
                    styles["right"],
                ),
            ]
        ],
        colWidths=[88 * mm, 84 * mm],
    )
    meta.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))

    story = [
        Spacer(1, 4 * mm),
        meta,
        Spacer(1, 9 * mm),
        Paragraph("Scan Statistics Report", styles["title"]),
        Paragraph(
            "Comprehensive summary of URL and QR Code scans, risk level distributions, and per-user activity.",
            styles["subtitle"],
        ),
        Spacer(1, 8 * mm),
        Paragraph("1. Executive Summary", styles["section"]),
        Paragraph(
            "This report provides an executive overview of PhishWise inspection activity during the specified period, covering user engagement, scan channels, and 5-tier risk evaluations (Safe, Mostly Safe, Caution, High Risk, Dangerous).",
            styles["body"],
        ),
        Spacer(1, 4 * mm),
        _summary_table(data, styles),
        Spacer(1, 7 * mm),
        Paragraph("2. Inspection Overview", styles["section"]),
        KeepTogether([_risk_chart(data)]),
        Spacer(1, 5 * mm),
        Table(
            [
                [
                    Paragraph(
                        "<b>Key Findings</b><br/>"
                        f"Identified {data['danger_count']} dangerous item(s) and {data['warning_count']} caution item(s) out of {data['total_scans']} total scans.",
                        styles["body"],
                    ),
                    Paragraph(
                        "<b>Recommendations</b><br/>"
                        "Avoid opening flagged links or downloading attachments when alerted, and always verify domain spelling before submitting credentials.",
                        styles["body"],
                    ),
                ]
            ],
            colWidths=[86 * mm, 86 * mm],
            style=TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
                    ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#CBD5E1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 9),
                ]
            ),
        ),
        PageBreak(),
        Paragraph("3. User Statistics", styles["section"]),
        Paragraph(
            "The following table details scanning breakdown per user account, aligned with the executive summary aggregates.",
            styles["body"],
        ),
        Spacer(1, 4 * mm),
        _users_table(data, styles),
        Spacer(1, 8 * mm),
        Paragraph("4. Risk Assessment Criteria", styles["section"]),
        Table(
            [
                ["Risk Level", "Score Range", "Recommended Action"],
                ["Safe", "Risk Score 0–20", "Safe to browse, but verify domain name"],
                ["Mostly Safe", "Risk Score 21–40", "Verify source before entering credentials"],
                ["Caution", "Risk Score 41–60", "Avoid submitting sensitive personal info"],
                ["High Risk", "Risk Score 61–80", "Do not open link or download files"],
                ["Dangerous", "Risk Score 81–100", "Halt usage immediately and do not download files"],
            ],
            colWidths=[28 * mm, 68 * mm, 76 * mm],
            style=TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, -1), "ReportThai"),
                    ("FONTNAME", (0, 0), (-1, 0), "ReportThai-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("BACKGROUND", (0, 0), (-1, 0), DARK),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 7),
                    ("TEXTCOLOR", (0, 1), (0, 1), GREEN),
                    ("TEXTCOLOR", (0, 2), (0, 2), colors.HexColor("#0D9488")),
                    ("TEXTCOLOR", (0, 3), (0, 3), AMBER),
                    ("TEXTCOLOR", (0, 4), (0, 4), colors.HexColor("#EA580C")),
                    ("TEXTCOLOR", (0, 5), (0, 5), RED),
                    ("TEXTCOLOR", (0, 3), (0, 3), RED),
                ]
            ),
        ),
        Spacer(1, 9 * mm),
        Paragraph("5. Report Disclaimers & Limitations", styles["section"]),
        Paragraph(
            "This report is generated for academic demonstration and cybersecurity risk assessment. Scan results represent preliminary evaluations and do not certify absolute security."
            "Inspection results represent preliminary risk evaluations and do not certify absolute security.",
            styles["body"],
        ),
    ]
    doc.build(story)
    output.seek(0)
    return output.getvalue()
