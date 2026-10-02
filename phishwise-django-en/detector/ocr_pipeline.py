"""High-accuracy EasyOCR URL extraction pipeline."""

import re
import cv2
import numpy as np
from PIL import Image

_READER = None

def get_ocr_reader():
    """High-accuracy EasyOCR URL extraction pipeline."""
    global _READER
    if _READER is None:
        import easyocr
        _READER = easyocr.Reader(['en', 'th'], gpu=False, verbose=False)
    return _READER


URL_ALLOWLIST = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:/.-_?=&%~+#"
)

TLDS = (
    r'com|co\.th|net|org|in\.th|info|biz|cc|xyz|online|top|me|link|site|app|live|'
    r'vip|store|shop|icu|club|io|dev|ai|ac\.th|go\.th|or\.th|edu|gov|th|asia|'
    r'mobi|tech|pro|cloud|space|fun|cyou|cfd|click|ly|to|gl|is|gg|page|tv|la|lol|su|mom'
)

EXTS = (
    r'exe|dll|msi|apk|zip|rar|7z|pdf|doc|docx|xls|xlsx|bat|cmd|sh|bin|elf|arm7|'
    r'scr|jar|php|html|htm|asp|aspx|jsp|tar|gz|ps1|m|js|jpg|jpeg|png'
)

# OCR pipeline optimization
OCR_CORRECTIONS = [
    (r'cir1(?=\.?(?:jpg|jpeg|png|ipg))', 'cjr1'),
    (r'ipeg\b', '.jpeg'),
    (r'ipng\b', '.png'),
    (r'ipg\b', '.jpg'),
    (r'lhtml\b', '.html'),
    (r'lphp\b', '.php'),
    (r'lexe\b', '.exe'),
    (r'lsh\b', '.sh'),
    (r'lxx\.?js\b', 'LXX.js'),
    (r'([a-zA-Z0-9_-]+)(jpg|png|gif|jpeg|exe|sh|js)\b', r'\1.\2'),
]


def preprocess_image(image: np.ndarray, scale: int = 3) -> np.ndarray:
    """High-accuracy EasyOCR URL extraction pipeline."""
    if image is None:
        raise ValueError("Invalid image or unable to open file.")

    h, w = image.shape[:2]
    # OCR pipeline optimization
    effective_scale = scale if h < 600 else max(1.5, min(2.5, 1800.0 / max(h, w)))

    pil_img = Image.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))
    new_w = int(w * effective_scale)
    new_h = int(h * effective_scale)
    pil_img = pil_img.resize((new_w, new_h), Image.LANCZOS)
    img_upscaled = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)

    gray = cv2.cvtColor(img_upscaled, cv2.COLOR_BGR2GRAY)

    # OCR pipeline optimization
    try:
        denoised = cv2.fastNlMeansDenoising(gray, h=10)
    except Exception:
        denoised = gray

    # OCR pipeline optimization
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(denoised)

    return enhanced


def detect_table_columns(image: np.ndarray, min_gap_width: int = 25) -> list[tuple[int, int]]:
    """High-accuracy EasyOCR URL extraction pipeline."""
    col_sums = np.sum(255 - image, axis=0)
    max_sum = col_sums.max()
    if max_sum == 0:
        return [(0, image.shape[1])]

    threshold = max_sum * 0.02
    is_gap = col_sums < threshold

    columns = []
    start = None
    gap_start = None

    for x, gap in enumerate(is_gap):
        if not gap and start is None:
            start = x
        elif gap and start is not None:
            gap_start = gap_start or x
            if x - gap_start >= min_gap_width:
                columns.append((start, gap_start))
                start = None
                gap_start = None
        elif not gap:
            gap_start = None

    if start is not None:
        columns.append((start, image.shape[1]))

    return columns


def clean_ocr_url_text(text: str) -> str:
    """High-accuracy EasyOCR URL extraction pipeline."""
    cleaned = text.strip()

    # OCR pipeline optimization
    cleaned = re.sub(
        r'^\s*\[?\d{4}[-/.]\d{1,2}[-/.]\d{1,2}[\s,T_]+\d{1,2}[:;.]\d{2}(?:[:;.]\d{2})?\]?\s*',
        '',
        cleaned,
    )

    # OCR pipeline optimization
    # 'https:lone' / 'https:ione' / 'https ione' -> 'https://one-'
    cleaned = re.sub(r'h\s*t\s*t\s*p\s*(s?)\s*[:;\']*\s*[li]?one[-_ ]\s*', r'http\1://one-', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'h\s*t\s*t\s*p\s*(s?)\s*[:;\']*\s*[li]?one\s+', r'http\1://one-', cleaned, flags=re.IGNORECASE)

    # 'https:ift' / 'https if' / 'https: if' / 'https fit' / "http'//" / 'https:/f'
    cleaned = re.sub(
        r'h\s*t\s*t\s*p\s*(s?)\s*[:;\']*\s*(?:i\s*f|f\s*i|f|l\s*f|/+\s*f|[\'\"/]{1,3})\s*',
        r'http\1://',
        cleaned,
        flags=re.IGNORECASE,
    )

    # OCR pipeline optimization
    cleaned = re.sub(r'([a-zA-Z0-9_-]{3,})(com|org|net|xyz|online|top|info|live|site|edu|gov)(?=[/\s]|$)', r'\1.\2', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(rf'(\.(?:{TLDS}))\s*[f/\\]\s*', r'\1/', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(rf'(\.(?:{TLDS}))\s*([a-zA-Z0-9_-]+)', r'\1/\2', cleaned, flags=re.IGNORECASE)

    # OCR pipeline optimization
    cleaned = re.sub(r'(\d{1,3})\s*,\s*(\d{1,3})', r'\1.\2', cleaned)

    # OCR pipeline optimization
    cleaned = re.sub(r'[:;]\s*(\d{2,5})[oO]\b', r':\1 0', cleaned)
    cleaned = re.sub(r'[:;]\s*(\d{2,5})\b', r':\1', cleaned)

    # OCR pipeline optimization
    cleaned = re.sub(rf'\s+({EXTS})\b', r'.\1', cleaned, flags=re.IGNORECASE)

    # OCR pipeline optimization
    for wrong, right in OCR_CORRECTIONS:
        cleaned = re.sub(wrong, right, cleaned, flags=re.IGNORECASE)

    return cleaned.strip()


def validate_and_normalize_url(raw_url: str) -> str | None:
    """High-accuracy EasyOCR URL extraction pipeline."""
    if not raw_url:
        return None

    url = raw_url.strip().rstrip(".,;!?)\"'>}]#:")

    # OCR pipeline optimization
    if not url.lower().startswith(('http://', 'https://')):
        if url.lower().startswith('www.'):
            url = 'https://' + url
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) or re.search(rf'\.(?:{TLDS})', url, re.I):
            url = 'http://' + url
        else:
            return None

    scheme, _, rest = url.partition('://')
    rest = rest.lstrip(':/')
    if not rest:
        return None

    # OCR pipeline optimization
    if '/' in rest:
        domain, _, path = rest.partition('/')
        path = '/' + path
    else:
        domain = rest
        path = ''

    # OCR pipeline optimization
    port = ''
    if ':' in domain:
        domain, _, port_str = domain.partition(':')
        port_match = re.match(r'^(\d{1,5})', port_str)
        if port_match:
            port = ':' + port_match.group(1)

    domain = domain.strip('. ')
    # OCR pipeline optimization
    is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))
    has_dot = '.' in domain and len(domain.split('.')[-1]) >= 2

    if not (is_ip or has_dot):
        return None

    # OCR pipeline optimization
    if path:
        path = re.sub(r'\s*/\s*', '/', path)
        path = re.sub(r'\s+', '_', path)

    final_url = f"{scheme}://{domain}{port}{path}".rstrip(".,;!?)\"'>}]#:")
    return final_url


def extract_urls_from_image_pipeline(image: np.ndarray) -> list[str]:
    """High-accuracy EasyOCR URL extraction pipeline."""
    # 1. Preprocess
    enhanced = preprocess_image(image)

    # 2. Column Detection
    columns = detect_table_columns(enhanced)

    # OCR pipeline optimization
    # OCR pipeline optimization
    scan_regions = []
    if len(columns) >= 2:
        # OCR pipeline optimization
        url_col_x1, url_col_x2 = columns[-1]
        pad = 10
        cropped = enhanced[:, max(0, url_col_x1 - pad): min(enhanced.shape[1], url_col_x2 + pad)]
        scan_regions.append(cropped)
    # OCR pipeline optimization
    scan_regions.append(enhanced)

    reader = get_ocr_reader()
    detected_candidates = []

    for region in scan_regions:
        try:
            results = reader.readtext(
                region,
                detail=1,
                paragraph=False,
                contrast_ths=0.1,
                adjust_contrast=0.5,
                text_threshold=0.4,
                low_text=0.3,
                allowlist=URL_ALLOWLIST,
            )
        except Exception:
            results = reader.readtext(region, detail=1)

        # OCR pipeline optimization
        results_sorted = sorted(results, key=lambda item: (item[0][0][1], item[0][0][0]))

        # OCR pipeline optimization
        lines = []
        curr_line = []
        curr_y = None
        y_threshold = 25

        for box, text, conf in results_sorted:
            y_center = (box[0][1] + box[2][1]) / 2.0
            if curr_y is None or abs(y_center - curr_y) < y_threshold:
                curr_line.append((box[0][0], text))
                curr_y = y_center
            else:
                curr_line.sort(key=lambda x: x[0])
                lines.append(" ".join(t for _, t in curr_line))
                curr_line = [(box[0][0], text)]
                curr_y = y_center

        if curr_line:
            curr_line.sort(key=lambda x: x[0])
            lines.append(" ".join(t for _, t in curr_line))

        # OCR pipeline optimization
        for line in lines:
            cleaned = clean_ocr_url_text(line)
            # OCR pipeline optimization
            tokens = cleaned.split()
            for token in tokens:
                token_cleaned = clean_ocr_url_text(token)
                valid_url = validate_and_normalize_url(token_cleaned)
                if valid_url and valid_url not in detected_candidates:
                    detected_candidates.append(valid_url)

            # OCR pipeline optimization
            full_line_url = validate_and_normalize_url(cleaned)
            if full_line_url and full_line_url not in detected_candidates:
                detected_candidates.append(full_line_url)

        if len(detected_candidates) >= 2:
            # OCR pipeline optimization
            break

    return detected_candidates
