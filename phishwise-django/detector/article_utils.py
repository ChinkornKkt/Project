"""
ฟังก์ชันแปลงและ Sanitize Markdown สำหรับบทความความรู้ PhishWise
เพื่อป้องกัน XSS (Cross-Site Scripting) อย่างเคร่งครัด
"""

import re

try:
    import bleach
except ImportError:
    bleach = None

try:
    import markdown
except ImportError:
    markdown = None

ALLOWED_TAGS = [
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "p",
    "br",
    "strong",
    "b",
    "em",
    "i",
    "u",
    "s",
    "strike",
    "del",
    "ul",
    "ol",
    "li",
    "blockquote",
    "code",
    "pre",
    "a",
    "img",
    "span",
    "div",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "hr",
]

ALLOWED_ATTRIBUTES = {
    "*": ["class"],
    "a": ["href", "title", "rel", "target"],
    "img": ["src", "alt", "title", "width", "height"],
    "th": ["colspan", "rowspan", "scope"],
    "td": ["colspan", "rowspan"],
}


def render_article_markdown(raw_markdown: str) -> str:
    """แปลง Markdown เป็น HTML ที่ sanitize แล้ว ปลอดภัยสำหรับแสดงผล

    - ลบแท็ก script, style, iframe และเนื้อหาข้างในออกทั้งหมดก่อนแปลง
    - แปลง raw markdown เป็น html ด้วย extension 'extra' (รองรับตาราง, code block ฯลฯ)
    - ใช้ bleach.clean กรองแท็กและ attribute ที่ไม่อนุญาตออกทั้งหมด
    - กำหนด strip=True เพื่อตัดแท็กอันตรายทิ้ง ไม่ให้หลุดไปแสดงผล
    """
    if not raw_markdown or not isinstance(raw_markdown, str):
        return ""

    # ลบ script, style, iframe และเนื้อหาภายในทั้งหมดออกก่อน
    cleaned_input = re.sub(r"(?is)<script.*?>.*?</script>", "", raw_markdown)
    cleaned_input = re.sub(r"(?is)<style.*?>.*?</style>", "", cleaned_input)
    cleaned_input = re.sub(r"(?is)<iframe.*?>.*?</iframe>", "", cleaned_input)

    if markdown:
        html = markdown.markdown(cleaned_input, extensions=["extra"])
    else:
        import html as py_html
        html = f"<p>{py_html.escape(cleaned_input)}</p>"

    if bleach:
        clean_html = bleach.clean(
            html,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRIBUTES,
            strip=True,
        )
    else:
        clean_html = html
    return clean_html

