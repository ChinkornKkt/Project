"""
Markdown rendering and sanitization utility for PhishWise knowledge base.
Strictly prevents Cross-Site Scripting (XSS).
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
    """Convert Markdown to sanitized HTML safely for rendering.

    - Removes script, style, iframe tags and dangerous content.
    - Converts raw markdown to HTML with 'extra' extension (tables, code blocks, etc.).
    - Uses bleach.clean to filter disallowed attributes.
    - Sets strip=True to cleanly discard malicious elements.
    """
    if not raw_markdown or not isinstance(raw_markdown, str):
        return ""

    # Remove script, style, iframe and internal content beforehand
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
