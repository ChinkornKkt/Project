# CODE_MAP.md — แผนที่โค้ด PhishWise

> **วัตถุประสงค์**: ระบุว่าถ้าต้องการแก้ไขพฤติกรรมส่วนใดของระบบ ควรไปแก้ที่ไฟล์ใด บรรทัดใด และข้อมูลไหลไปที่ไหนบ้าง

---

## ภาพรวม Flow ทั้งระบบ

```
[ผู้ใช้] กรอก URL / อัปโหลดภาพ / สแกน QR
         │
         ▼
[templates/home.html] — หน้าแรก / ฟอร์มกรอก URL / อัปโหลดภาพ
         │ POST /scan/
         ▼
[dashboard/views.py] scan_view() — รับ Request, ตัดสินว่าเป็น URL / QR / OCR
         │
         ├─ QR Code → decode_image_url_or_qr() → ได้ URL string
         │
         ├─ OCR (ภาพทั่วไป) → decode_image_url_or_qr() + extract_urls_from_text()
         │       ├─ พบ URL เดียว → ส่งตรงไปสแกน
         │       └─ พบหลาย URL → Session → หน้าหลัก → Modal เลือก URL
         │
         ▼
[detector/services.py] scan_url_logic() — วิเคราะห์ URL หลัก
         ├─ resolve_final_url()       — ตรวจ Redirect
         ├─ fetch_domain_age_days()   — WHOIS อายุโดเมน
         ├─ fetch_ssl_status()        — ตรวจ SSL/HTTPS
         ├─ fetch_ip_location()       — IP Geolocation
         ├─ inspect_download_with_virustotal() — ตรวจไฟล์ดาวน์โหลด
         └─ _predict_model_risks()
               ├─ Random Forest (URL Features)
               └─ BiLSTM (HTML Content)
         │
         ▼
[detector/risk_levels.py] classify_risk() — แปลง score → ระดับ
         │
         ▼
Session["last_scan_result"] → redirect /result/ → [templates/result.html]
```

---

## 1. ส่วนรับ Input จากผู้ใช้ (Frontend)

### `templates/home.html`

| บรรทัด | หน้าที่ |
|---|---|
| 44 | `<form action="/scan/" method="POST">` — Form หลักที่ส่งข้อมูลไป scan_view |
| 46 | `<input name="source_type">` — บอกว่า input มาจากไหน: `direct_url` / `camera_qr` / `image_qr` |
| 315–318 | Auto-switch แท็บ QR เมื่อมี messages error |
| 322–332 | JavaScript เปิด Modal เลือก URL อัตโนมัติเมื่อ `pending_ocr_urls` มีค่า |
| 334–406 | Modal HTML + JavaScript สำหรับแสดง Dropdown เลือก URL |

**ถ้าต้องการแก้:**
- แก้หน้าตาปุ่มกรอก URL → บรรทัดประมาณ 60–130
- แก้ Modal เลือก URL → บรรทัด 334–406
- แก้ข้อความ Error/Alert → บรรทัด 31–40

---

## 2. ส่วนรับ Request และควบคุม Flow (Controller)

### `dashboard/views.py`

#### `scan_view()` — บรรทัด 1428–1481

| บรรทัด | หน้าที่ |
|---|---|
| 1423 | รับ `url` จากฟอร์ม direct URL |
| 1424 | รับ `uploaded_file` จากการอัปโหลดภาพ |
| 1425–1427 | ตรวจ `source_type` ว่าถูกต้องหรือไม่ |
| 1429–1450 | ถ้าไม่มี URL ตรง แต่มีไฟล์ → เรียก `decode_image_url_or_qr()` |
| 1440–1441 | **พบ URL เดียว** → เก็บใน `url` แล้วสแกนต่อ |
| 1442–1445 | **พบหลาย URL** → เก็บใน `session["pending_ocr_urls"]` → redirect กลับ home ให้ Modal ขึ้น |
| 1452–1471 | เรียก `scan_url_logic(url)` → บันทึก `ScanHistory` → เก็บผลใน Session → redirect /result/ |

**ถ้าต้องการแก้:**
- เปลี่ยน Logic การตัดสินใจ (URL เดียว vs หลาย) → บรรทัด 1440–1448
- เพิ่มการ validate URL ก่อนส่งสแกน → บรรทัด 1451 (ก่อนเรียก scan_url_logic)
- แก้ข้อมูลที่บันทึกลง Database → บรรทัด 1454–1471

---

#### `decode_image_url_or_qr()` — บรรทัด 538–628

> **หน้าที่**: รับไฟล์ภาพ → ลอง QR Code → ถ้าไม่ได้ → OCR → คืน list ของ URL ที่พบ

| บรรทัด | หน้าที่ |
|---|---|
| 538–548 | ตรวจสอบ file type และ file size (ต้องเป็น image, ≤ 10MB) |
| 549–582 | **ส่วน QR Code**: ใช้ OpenCV หลาย scale/border → คืน [url] ถ้าพบ |
| 588–600 | **OCR Pass 1**: รัน EasyOCR บนภาพต้นฉบับ ถ้าพบ URL → คืนทันที |
| 602–623 | **OCR Pass 2**: ขยายภาพ 2–3.5x ด้วย Lanczos4 + Sharpen แล้ว OCR ซ้ำ |

**Parameters OCR Pass 1** (บรรทัด 590–594):
- `text_threshold=0.5` — ความมั่นใจขั้นต่ำที่จะยอมรับตัวอักษร
- `low_text=0.3` — sensitivity สำหรับพื้นที่ข้อความขนาดเล็ก (จุด, เครื่องหมาย)
- `mag_ratio=1.2` — ขยายภาพเล็กน้อยก่อน OCR

**Parameters OCR Pass 2** (บรรทัด 613–616):
- `text_threshold=0.4` — ลดลงเพื่อให้จับได้มากขึ้น
- `link_threshold=0.6` — เกณฑ์การเชื่อมตัวอักษรเป็น word
- `mag_ratio=1.5` — ขยายภาพมากขึ้น

**ถ้าต้องการแก้:**
- OCR อ่านได้ไม่ชัด → ลด `text_threshold` บรรทัด 591, 613
- จุดและเครื่องหมายหาย → ลด `low_text` บรรทัด 592, 614
- ต้องการขยายภาพมากขึ้น → แก้ scale formula บรรทัด 604
- เพิ่ม Pass 3 → เพิ่มโค้ดหลังบรรทัด 623

---

#### `extract_urls_from_text()` — บรรทัด 439–532

> **หน้าที่**: รับข้อความดิบจาก OCR → สกัด URL ออกมาทั้งหมด → คืน list

| บรรทัด | หน้าที่ |
|---|---|
| 444 | กำหนด `tlds` — รายชื่อ TLD ที่ระบบรู้จัก |
| 445 | กำหนด `exts` — นามสกุลไฟล์ที่รู้จัก (.exe, .apk, .sh, .ps1 ฯลฯ) |
| 447 | แปลง comma ใน IP: `105,186.250,56` → `105.186.250.56` |
| 450–457 | Regex หา URL blocks จากข้อความ |
| 464–476 | Normalize Protocol: `http:/` `https:/ /` → `http://` `https://` |
| 477–482 | แยก Domain และ Path จาก URL |
| 483–488 | แยก Port ออกจาก Domain (เช่น `:38301`) |
| 490–491 | Domain: แปลง space/comma/semicolon → จุด . |
| 493–525 | Path: เพิ่มจุดหน้า extension, ตัดข้อความส่วนเกิน (คอลัมน์ตาราง) |
| 526–530 | Validate และเพิ่ม URL ลงใน list ถ้า domain ถูกต้อง |

**ถ้าต้องการแก้:**
- เพิ่ม TLD ใหม่ → บรรทัด 444 แก้ `tlds = ...`
- เพิ่มนามสกุลไฟล์ → บรรทัด 445 แก้ `exts = ...`
- OCR อ่านจุดหาย → แก้ Domain Normalization บรรทัด 490
- URL จากตารางมี text เกิน → แก้ boundary truncation บรรทัด 512–521

---

#### `select_url_view()` — บรรทัด 1487–1533

> **หน้าที่**: รับ URL ที่ผู้ใช้เลือกจาก Modal → สแกนและแสดงผล

| บรรทัด | หน้าที่ |
|---|---|
| 1491–1492 | รับ URL ที่ผู้ใช้เลือกจาก POST form |
| 1493–1494 | ล้าง pending_ocr_urls ออกจาก session |
| 1498–1516 | เรียก scan_url_logic() และบันทึก ScanHistory |
| 1522–1529 | GET → ดึง URL list จาก session → render select_url.html |

---

## 3. ส่วนวิเคราะห์ความเสี่ยง (Core Logic)

### `detector/services.py`

#### `scan_url_logic(url)` — บรรทัด 448–527

> **หน้าที่**: รับ URL → วิเคราะห์ทุกด้าน → คืน dict ผลลัพธ์ครบชุด

```
scan_url_logic(url)
    ├─ normalize URL        normalize_url()   บรรทัด 121
    ├─ ตรวจ Redirect        resolve_final_url()   บรรทัด 174
    ├─ อายุโดเมน            fetch_domain_age_days()   บรรทัด 189
    ├─ ตรวจ SSL             fetch_ssl_status()   บรรทัด 216
    ├─ IP Geolocation       fetch_ip_location()   บรรทัด 233
    ├─ ตรวจไฟล์ดาวน์โหลด   inspect_download_with_virustotal()   บรรทัด 326
    └─ AI Models            _predict_model_risks()   บรรทัด 416
           ├─ Random Forest (URL features)
           └─ BiLSTM (HTML content)
```

**การคำนวณ Risk Score สุดท้าย** (บรรทัด 477–503):

| บรรทัด | Rule | ผล |
|---|---|---|
| 477 | เฉลี่ย AI model (0–100), ถ้าไม่มี model → 50 (Neutral) | base score |
| 482–486 | IP address + Executable Extension | score = 100 |
| 487–491 | Suspicious keyword + ไม่มี HTTPS | score ≥ 95 |
| 493–494 | อายุโดเมน ≤ 30 วัน | +40 |
| 495–496 | อายุโดเมน ≤ 180 วัน | +20 |
| 497–498 | ไม่มี SSL | +30 |
| 499–500 | Executable Extension ใน URL | +20 |
| 501–502 | มี VirusTotal result | ใช้ค่าสูงสุด |

**ถ้าต้องการแก้:**
- น้ำหนัก SSL → บรรทัด 498
- น้ำหนักอายุโดเมน → บรรทัด 493–496
- เพิ่ม Rule ใหม่ → เพิ่มหลังบรรทัด 502

---

#### `extract_url_features()` — บรรทัด 248–293

> **หน้าที่**: แปลง URL → feature vector สำหรับ Random Forest

| Feature | บรรทัด | คำอธิบาย |
|---|---|---|
| `url_length` | 278 | ความยาว URL ทั้งหมด |
| `is_ip_address` | 279 | มี IP address ใน URL หรือไม่ |
| `count_dots` | 280 | จำนวนจุดใน URL |
| `count_hyphens` | 281 | จำนวนขีด - |
| `count_at` | 282 | จำนวน @ |
| `count_question` | 283 | จำนวน ? |
| `count_equal` | 284 | จำนวน = |
| `count_slash` | 285 | จำนวน / |
| `has_suspicious_keyword` | 286–288 | มีคำเช่น login, verify, banking ไหม |
| `has_executable_extension` | 289–291 | มีนามสกุล .exe .apk .sh ฯลฯ ไหม |
| `is_https` | 292 | ใช้ HTTPS ไหม |

**ถ้าต้องการแก้:**
- เพิ่ม suspicious keywords → บรรทัด 256–265 แก้ list `suspicious_keywords`
- เพิ่ม executable extensions → บรรทัด 267–276 แก้ list `executable_extensions`

---

#### ความปลอดภัย SSRF — `_assert_public_destination()` บรรทัด 135–150

> ทุก request ออกนอกระบบจะต้องผ่านฟังก์ชันนี้ก่อน

| บรรทัด | หน้าที่ |
|---|---|
| 139–146 | Resolve hostname → ได้ IP addresses ทั้งหมด |
| 149 | ปฏิเสธถ้า IP ไม่ใช่ public (private, loopback, link-local) |

---

## 4. ระดับความเสี่ยง

### `detector/risk_levels.py` — ไฟล์เดียว 21 บรรทัด

```python
RISK_LEVELS = (
    (20,  "safe",         "ปลอดภัย"),
    (40,  "mostly_safe",  "ค่อนข้างปลอดภัย"),
    (60,  "warning",      "ควรระวัง"),
    (80,  "mostly_danger","มีแนวโน้มอันตราย"),
    (100, "danger",       "อันตราย"),
)
```

- **`classify_risk(score)`** บรรทัด 10–16: รับ 0–100 → คืน `{key, label, risk_score}`
- **ถ้าต้องการเปลี่ยนเกณฑ์:** แก้ตัวเลขในบรรทัด 2–6 โดยตรง

---

## 5. ฐานข้อมูล

### `detector/models.py`

| Model | บรรทัด | หน้าที่ |
|---|---|---|
| `ScanHistory` | 6–36 | เก็บประวัติการสแกนทุกครั้ง |
| `DomainStatistic` | 39–60 | สถิติสะสมต่อ domain |
| `SuspiciousSiteReport` | 64–85 | รายงานจากผู้ใช้ |
| `KnowledgeArticle` | 88–132 | บทความความรู้ |

**Field สำคัญใน ScanHistory:**

| Field | ความหมาย |
|---|---|
| `score` | คะแนนความปลอดภัย = 100 - risk (แสดงในหน้า result) |
| `ai_risk_score` | คะแนนความเสี่ยงดิบ 0–100 (ไม่แสดงผู้ใช้) |
| `status` | ระดับ: `safe` / `mostly_safe` / `warning` / `mostly_danger` / `danger` |
| `source_type` | `direct_url` / `camera_qr` / `image_qr` |

---

## 6. URL Routing

### `dashboard/urls.py`

| URL Path | View Function | ชื่อ |
|---|---|---|
| `/` | `home` | `home` |
| `/scan/` | `scan_view` | `scan_view` |
| `/result/` | `result_view` | `result` |
| `/select-url/` | `select_url_view` | `select_url` |
| `/history/` | `history_view` | `history` |
| `/dashboard/` | `dashboard_view` | `dashboard` |
| `/report/` | `report_view` | `report` |
| `/knowledge/` | `knowledge_view` | `knowledge` |
| `/admin/` | `admin_view` | `admin` |
| `/result/report.pdf` | `analysis_pdf_view` | `analysis_pdf` |
| `/statistics/report.pdf` | `statistics_pdf_view` | `statistics_pdf` |

---

## 7. Templates

| ไฟล์ | หน้าที่ |
|---|---|
| `base.html` | โครงสร้าง HTML หลัก, Font, Tailwind config, Navbar |
| `home.html` | หน้าแรก, ฟอร์มกรอก URL, อัปโหลดภาพ, Modal เลือก URL |
| `result.html` | แสดงผลการวิเคราะห์ URL (ระดับ, SSL, อายุโดเมน, VirusTotal) |
| `select_url.html` | หน้า fallback เลือก URL (ถ้า Modal ไม่แสดง) |
| `dashboard.html` | สถิติการตรวจสอบ กราฟ จำนวนสแกน |
| `admin.html` | จัดการผู้ใช้, รายงาน, บทความ |
| `history.html` | ประวัติการสแกนของผู้ใช้ |
| `report.html` | ฟอร์มรายงานเว็บน่าสงสัย |
| `knowledge.html` | รายการบทความ |
| `pdf/` | Template สำหรับสร้าง PDF (WeasyPrint) |

---

## 8. ML Models

### `detector/ml_models/`

| ไฟล์ | หน้าที่ |
|---|---|
| `url_random_forest_model.pt` | Random Forest (pickle) ทำนายจาก URL features |
| `advanced_model_bi_lstm.pt` | BiLSTM (PyTorch) ทำนายจาก HTML content |
| `vocab_final.pkl` | Vocabulary สำหรับ tokenize HTML |

**โหลดครั้งเดียวตอน startup** → `load_resources()` บรรทัด 72–118 ใน services.py

---

## 9. VirusTotal Integration

### `detector/virustotal.py`

> ใช้ตรวจ**ไฟล์ดาวน์โหลด**เท่านั้น ไม่ใช่แหล่งตัดสิน URL ทุกลิงก์

- `analyse_file_bytes(file_bytes, file_name)` → ส่ง bytes ไป VirusTotal API
- ใช้ environment variable `VIRUSTOTAL_API_KEY` (ห้าม hardcode ลงโค้ด)
- ไฟล์ดาวน์โหลดอ่านเข้า **RAM เท่านั้น** — ไม่บันทึกลงดิสก์เด็ดขาด

---

## 10. สรุป: จะแก้อะไร ไปที่ไหน

| ต้องการแก้ | ไฟล์ | บรรทัด |
|---|---|---|
| OCR อ่านไม่ชัด / จุดหาย | `dashboard/views.py` | 590–594 (Pass 1), 613–616 (Pass 2) |
| OCR ขยายภาพมากขึ้น | `dashboard/views.py` | 604 (scale formula) |
| OCR สกัด URL ผิด | `dashboard/views.py` | 439–532 (extract_urls_from_text) |
| เพิ่ม TLD ที่รู้จัก | `dashboard/views.py` | 444 (tlds) |
| เพิ่มนามสกุลไฟล์อันตราย | `dashboard/views.py` | 445 (exts) |
| เพิ่ม suspicious keywords | `detector/services.py` | 256–265 |
| เพิ่ม executable extensions (risk) | `detector/services.py` | 267–276 |
| เปลี่ยนเกณฑ์ระดับความเสี่ยง | `detector/risk_levels.py` | 2–6 |
| เพิ่ม/ลดน้ำหนัก SSL | `detector/services.py` | 497–498 |
| เพิ่ม/ลดน้ำหนักอายุโดเมน | `detector/services.py` | 493–496 |
| เพิ่ม Rule ความเสี่ยงใหม่ | `detector/services.py` | 500–503 |
| แก้ Modal เลือก URL | `templates/home.html` | 334–406 |
| แก้หน้าผลลัพธ์ | `templates/result.html` | ทั้งไฟล์ |
| แก้ข้อมูลที่บันทึก DB | `dashboard/views.py` | 1454–1471 |
| เพิ่ม field ใน DB | `detector/models.py` + makemigrations | — |
| แก้ PDF รายงาน | `templates/pdf/` | — |
| เพิ่ม URL route ใหม่ | `dashboard/urls.py` | ทั้งไฟล์ |