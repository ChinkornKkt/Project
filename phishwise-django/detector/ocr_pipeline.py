"""
detector/ocr_pipeline.py

Pipeline สำหรับตรวจจับและสกัด URL จากภาพ/ตาราง log ด้วย EasyOCR ให้แม่นยำสูง
ตามข้อกำหนดใน .agents/ocr-url-pipeline-for-gemini.md

ขั้นตอน 5 ชั้น:
    1. Preprocess ภาพ (upscale LANCZOS, grayscale, fastNlMeansDenoising, CLAHE contrast)
    2. Column Detection (หา whitespace gap เพื่อตัดคอลัมน์ timestamp ออก ป้องกัน column bleeding)
    3. EasyOCR (allowlist สำหรับ URL, paragraph=False, ปรับ threshold สำหรับอักขระขนาดเล็ก)
    4. Post-processing Pattern Corrections (แก้ pattern ที่ OCR มักสับสน เช่น ://, ipg, lexe, 4404o)
    5. Validation & Filtering (ตรวจสอบโครงสร้าง URL และคืนผลลัพธ์ที่ถูกต้อง)
"""

import re
import cv2
import numpy as np
from PIL import Image

_READER = None

def get_ocr_reader():
    """โหลด EasyOCR Reader แบบ Singleton ครั้งเดียว"""
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

# รายการ Pattern ที่ EasyOCR อ่านเพี้ยนบ่อยสำหรับ URL
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
    """
    ชั้นที่ 1: Image Preprocessing
    Upscale (LANCZOS) + Grayscale + fastNlMeansDenoising + CLAHE
    ช่วยให้ฟอนต์ขนาดเล็ก (12-15px) ขยายใหญ่ขึ้นโดยเส้นตัวอักษรไม่แตก และคอนทราสต์คมชัด
    """
    if image is None:
        raise ValueError("รูปภาพไม่ถูกต้องหรือไม่สามารถเปิดได้")

    h, w = image.shape[:2]
    # ปรับ scale ให้เหมาะสม หากภาพเดิมเล็กมากให้ขยาย 3x หากภาพใหญ่แล้วให้ขยายตามสัดส่วน
    effective_scale = scale if h < 600 else max(1.5, min(2.5, 1800.0 / max(h, w)))

    pil_img = Image.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))
    new_w = int(w * effective_scale)
    new_h = int(h * effective_scale)
    pil_img = pil_img.resize((new_w, new_h), Image.LANCZOS)
    img_upscaled = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)

    gray = cv2.cvtColor(img_upscaled, cv2.COLOR_BGR2GRAY)

    # Denoise แบบถนอมเส้นขอบตัวอักษร
    try:
        denoised = cv2.fastNlMeansDenoising(gray, h=10)
    except Exception:
        denoised = gray

    # ปรับ contrast แบบ Adaptive (CLAHE)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(denoised)

    return enhanced


def detect_table_columns(image: np.ndarray, min_gap_width: int = 25) -> list[tuple[int, int]]:
    """
    ชั้นที่ 2: Column Detection
    หาช่องว่างแนวตั้ง (whitespace gap) เพื่อแยกคอลัมน์ URL ออกจากคอลัมน์อื่น เช่น Timestamp
    ป้องกันปัญหา Column Bleeding
    """
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
    """
    ชั้นที่ 4: Post-processing Pattern Corrections
    แก้ข้อผิดพลาดจากการอ่านสัญลักษณ์ของ OCR สำหรับ URL
    """
    cleaned = text.strip()

    # 1. ตัด Timestamp / วันที่-เวลา ที่อาจหลุดมาข้างหน้า เช่น 2026-09-03 12:35:09
    cleaned = re.sub(
        r'^\s*\[?\d{4}[-/.]\d{1,2}[-/.]\d{1,2}[\s,T_]+\d{1,2}[:;.]\d{2}(?:[:;.]\d{2})?\]?\s*',
        '',
        cleaned,
    )

    # 2. แก้ Protocol และ Slashes ที่ OCR สับสน
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

    # 3. แก้สแลชและจุดระหว่าง TLD กับ Path เช่น .tvftogethers -> .tv/Togethers, .comfcir1 -> .com/cir1
    cleaned = re.sub(r'([a-zA-Z0-9_-]{3,})(com|org|net|xyz|online|top|info|live|site|edu|gov)(?=[/\s]|$)', r'\1.\2', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(rf'(\.(?:{TLDS}))\s*[f/\\]\s*', r'\1/', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(rf'(\.(?:{TLDS}))\s*([a-zA-Z0-9_-]+)', r'\1/\2', cleaned, flags=re.IGNORECASE)

    # 4. แก้ comma ใน IP Address: เช่น 175,192 -> 175.192
    cleaned = re.sub(r'(\d{1,3})\s*,\s*(\d{1,3})', r'\1.\2', cleaned)

    # 5. แก้ Port ที่เพี้ยน เช่น :4404o -> :44040, ;54382 -> :54382
    cleaned = re.sub(r'[:;]\s*(\d{2,5})[oO]\b', r':\1 0', cleaned)
    cleaned = re.sub(r'[:;]\s*(\d{2,5})\b', r':\1', cleaned)

    # 6. แก้ช่องว่างหน้านามสกุลไฟล์ เช่น 'cir1 jpg' -> 'cir1.jpg', 'bin sh' -> 'bin.sh'
    cleaned = re.sub(rf'\s+({EXTS})\b', r'.\1', cleaned, flags=re.IGNORECASE)

    # 7. ปรับแก้คำผิดเฉพาะจุดจากตารางข้อผิดพลาด
    for wrong, right in OCR_CORRECTIONS:
        cleaned = re.sub(wrong, right, cleaned, flags=re.IGNORECASE)

    return cleaned.strip()


def validate_and_normalize_url(raw_url: str) -> str | None:
    """
    ชั้นที่ 5: Validation & Filtering
    ตรวจสอบความสมบูรณ์ของโครงสร้าง URL
    """
    if not raw_url:
        return None

    url = raw_url.strip().rstrip(".,;!?)\"'>}]#:")

    # ต้องมี http:// หรือ https:// นำหน้า (หากไม่มีแต่มี www. หรือ IP ให้เติม)
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

    # แยก domain กับ path
    if '/' in rest:
        domain, _, path = rest.partition('/')
        path = '/' + path
    else:
        domain = rest
        path = ''

    # ตรวจสอบ Port
    port = ''
    if ':' in domain:
        domain, _, port_str = domain.partition(':')
        port_match = re.match(r'^(\d{1,5})', port_str)
        if port_match:
            port = ':' + port_match.group(1)

    domain = domain.strip('. ')
    # โดเมนต้องมีจุด หรือเป็น IPv4 และยาวอย่างน้อย 3 ตัวอักษร
    is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))
    has_dot = '.' in domain and len(domain.split('.')[-1]) >= 2

    if not (is_ip or has_dot):
        return None

    # จัดระเบียบ path
    if path:
        path = re.sub(r'\s*/\s*', '/', path)
        path = re.sub(r'\s+', '_', path)

    final_url = f"{scheme}://{domain}{port}{path}".rstrip(".,;!?)\"'>}]#:")
    return final_url


def extract_urls_from_image_pipeline(image: np.ndarray) -> list[str]:
    """
    ฟังก์ชันหลักที่รัน Pipeline ทั้ง 5 ชั้น
    รับ input เป็นภาพ OpenCV BGR numpy array
    คืนค่าเป็น list ของ URL ที่สกัดได้
    """
    # 1. Preprocess
    enhanced = preprocess_image(image)

    # 2. Column Detection
    columns = detect_table_columns(enhanced)

    # หากตรวจพบคอลัมน์ตาราง ให้ตัดคอลัมน์ด้านขวา (ซึ่งมักเป็น URL ในตาราง log)
    # แต่ถ้าไม่แน่ใจ ให้สแกนทั้งคอลัมน์ขวา และภาพรวม
    scan_regions = []
    if len(columns) >= 2:
        # คอลัมน์ขวาสุด
        url_col_x1, url_col_x2 = columns[-1]
        pad = 10
        cropped = enhanced[:, max(0, url_col_x1 - pad): min(enhanced.shape[1], url_col_x2 + pad)]
        scan_regions.append(cropped)
    # ใส่ภาพหลักไว้ด้วยเป็น Fallback
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

        # จัดเรียงกล่องข้อความตามแกน Y (บนลงล่าง)
        results_sorted = sorted(results, key=lambda item: (item[0][0][1], item[0][0][0]))

        # รวมข้อความในแถวเดียวกัน (Row Clustering)
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

        # ประมวลผลและทำความสะอาดแต่ละบรรทัด
        for line in lines:
            cleaned = clean_ocr_url_text(line)
            # ค้นหาก้อนข้อความที่น่าจะเป็น URL
            tokens = cleaned.split()
            for token in tokens:
                token_cleaned = clean_ocr_url_text(token)
                valid_url = validate_and_normalize_url(token_cleaned)
                if valid_url and valid_url not in detected_candidates:
                    detected_candidates.append(valid_url)

            # ลองตรวจสอบทั้งบรรทัดด้วย
            full_line_url = validate_and_normalize_url(cleaned)
            if full_line_url and full_line_url not in detected_candidates:
                detected_candidates.append(full_line_url)

        if len(detected_candidates) >= 2:
            # หากตรวจพบคอลัมน์และได้ URL เพียงพอแล้ว ไม่ต้องสแกน fallback ซ้ำ
            break

    return detected_candidates
