# 🛡️ PhishWise — AI-Powered Phishing & Malicious URL Risk Assessment System

> **ระบบประเมินความเสี่ยงและตรวจจับเว็บไซต์ฟิชชิ่งด้วยเทคโนโลยีปัญญาประดิษฐ์ (AI & Computer Vision)**

[![Python Version](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Django](https://img.shields.io/badge/Framework-Django%205.x-092E20.svg)](https://www.djangoproject.com/)
[![TailwindCSS](https://img.shields.io/badge/Frontend-TailwindCSS-38B2AC.svg)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/Project-Academic%20%2F%20Portfolio-orange.svg)](#)

---

## 📌 ภาพรวมโครงการ (Project Overview)

**PhishWise** เป็นเว็บแอปพลิเคชันความปลอดภัยทางไซเบอร์ที่พัฒนาขึ้นเพื่อประเมินความเสี่ยงและตรวจจับ URL ต้องสงสัย เว็บไซต์หลอกลวง (Phishing) และไฟล์แนบอันตราย ด้วยการผสานรวมระหว่าง **Machine Learning (Random Forest)**, **Deep Learning (BiLSTM)**, **Computer Vision (OpenCV & EasyOCR)** และการตรวจสอบคุณลักษณะเชิงเทคนิค (SSL/TLS, WHOIS Domain Age, Redirection Chain)

ระบบแบ่งระดับความเสี่ยงออกเป็น **5 ระดับมาตรฐาน** เพื่อช่วยให้ผู้ใช้ทั่วไป องค์กร และสมาชิกสามารถตัดสินใจได้อย่างแม่นยำก่อนเปิดลิงก์ที่ไม่น่าไว้วางใจ

---

## 📂 โครงสร้าง Repository (Project Structure)

ภายใน Repository นี้จัดเตรียมไว้ให้ 2 เวอร์ชัน:

```text
├── phishwise-django/       # 🇹🇭 เวอร์ชันหลักภาษาไทย (Complete Thai Edition)
│   ├── docs/               # 📖 เอกสารวิศวกรรมระบบและโมเดล AI (Technical Documentation)
│   │   ├── AI_MODEL.md     # รายละเอียดโมเดล Random Forest, BiLSTM, OCR & Risk Weights
│   │   ├── RISK_LEVELS.md  # เกณฑ์การตัดสินระดับความเสี่ยง 5 ระดับ
│   │   ├── CODE_MAP.md     # แผนผังโครงสร้างโค้ดและการเชื่อมต่อ Component
│   │   └── REPORTING_SYSTEM.md # สถาปัตยกรรมระบบรับแจ้งเบาะแสและโมเดอเรชัน
│   ├── core/               # การตั้งค่าระบบ Django Settings & Root URL Router
│   ├── dashboard/          # ส่วนแสดงผล UI, หน้าสถิติ, คลังความรู้, PDF Exporter
│   ├── detector/           # AI Pipeline, OCR Extraction, Heuristics & Data Models
│   └── templates/          # HTML Templates (Tailwind CSS)
│
├── phishwise-django-en/    # 🇬🇧 เวอร์ชันภาษาอังกฤษล้วน (Standalone English Edition)
│   ├── README.md           # English Installation & Usage Guide
│   ├── core/, dashboard/, detector/, templates/
│
└── .gitignore              # ไฟล์กำหนดการละเว้นไฟล์ชั่วคราวและไฟล์ขนาดใหญ่
```

---

## ✨ คุณสมบัติเด่นของระบบ (Key Features)

1. **การตรวจสอบ 2 ช่องทาง (Dual Scanning Modes)**:
   - **Direct URL Scanner**: กรอก URL เพื่อสแกนวิเคราะห์เชิงลึกได้ทันที
   - **QR Code & OCR Image Upload**: สกัด URL จากภาพถ่าย หน้าจอแชต หรือ QR Code ด้วย OpenCV และ EasyOCR พร้อมแก้ปัญหา Column Bleeding อัตโนมัติ

2. **การประเมินความเสี่ยง 5 ระดับ (5-Level Granular Risk Classification)**:
   - 🟢 **Safe / ปลอดภัย** (`0–20`): เว็บไซต์ปกติ มีประวัติโดเมนยาวนาน มี SSL ถูกต้อง
   - 🟢 **Mostly Safe / ค่อนข้างปลอดภัย** (`21–40`): มีจุดผิดปกติเล็กน้อยแต่ไม่มีพฤติกรรมหลอกลวงเด่นชัด
   - 🟡 **Caution / ควรระวัง** (`41–60`): มีความเสี่ยง โดเมนจดใหม่ หรือการส่งต่อลิงก์กำกวม
   - 🟠 **High Risk / ค่อนข้างอันตราย** (`61–80`): พบสัญญาณฟิชชิ่งเด่นชัด มีคีย์เวิร์ดหลอกลวง
   - 🔴 **Dangerous / อันตราย** (`81–100`): เว็บหลอกลวงยืนยันแล้ว ติด Blacklist หรือเป็น Payload อันตราย

3. **การวิเคราะห์เชิงลึก (Deep Technical Inspection)**:
   - **11 Structural URL Features**: คำนวณคุณลักษณะโครงสร้าง URL เช่น ความยาว, การใช้ IP Address, นามสกุลไฟล์เสี่ยง, คีย์เวิร์ดฟิชชิ่ง, โปรโตคอล HTTPS
   - **SSL/TLS & WHOIS Intelligence**: ตรวจอายุโดเมนย้อนหลังและใบรับรองความปลอดภัย
   - **Redirect Chain Tracer**: แกะรอยลิงก์ย่อและ intermediate hops สู่ปลายทางจริง
   - **File Download Inspection**: เชื่อมต่อตรวจสอบความปลอดภัยไฟล์ร่วมกับ Threat Intelligence

4. **ระบบรายงานสถิติและส่งออก PDF (Dual-Engine PDF Export)**:
   - กราฟแนวโน้มการตรวจสอบและสถิติแยกตามช่วงเวลา (7 วัน, 30 วัน, ทั้งหมด)
   - ส่งออกรายงานการตรวจวิเคราะห์และรายงานสถิติเป็นเอกสาร PDF ทางการ (รองรับ WeasyPrint และ ReportLab fallback)

5. **คลังความรู้ภัยไซเบอร์ (Cybersecurity Knowledge Base)**:
   - บทความความรู้ด้านความปลอดภัยกว่า 12 หัวข้อ
   - ระบบจัดการบทความสำหรับแอดมินด้วย Markdown Editor พร้อมตัวกรองความปลอดภัย XSS และ Live Preview

6. **ระบบรับแจ้งเบาะแส (Threat Reporting & Moderation)**:
   - สมาชิกสามารถแจ้งเบาะแส URL ต้องสงสัย พร้อมระบุประเภทภัยคุกคาม
   - ผู้ดูแลระบบมีหน้า Console ตรวจสอบ อนุมัติ หรือปฏิเสธรายงาน

---

## 🛠️ สถาปัตยกรรมและเทคโนโลยี (Tech Stack)

| ส่วนประกอบ | เทคโนโลยีที่เลือกใช้ |
| :--- | :--- |
| **Backend** | Python 3.11+, Django 5.x |
| **Frontend** | HTML5, Tailwind CSS, FontAwesome 6, Chart.js |
| **AI / Machine Learning** | Scikit-learn (Random Forest URL Classifier), PyTorch (BiLSTM Web Content Classifier) |
| **Computer Vision / OCR** | OpenCV, EasyOCR, NumPy |
| **PDF Reporting Engine** | ReportLab & WeasyPrint (Dual Engine Architecture) |
| **Database** | SQLite3 (Development) / PostgreSQL Compatible |

---

## 🚀 การติดตั้งและเริ่มต้นใช้งาน (Quick Start)

### 1. โคลน Repository
```bash
git clone https://github.com/Akanomiji/Project.git
cd Project
```

### 2. รันเวอร์ชันหลัก (ภาษาไทย)
```bash
cd phishwise-django
pip install -r requirements.txt
python manage.py migrate
python manage.py seed_articles
python manage.py seed_demo_statistics
python manage.py runserver 8000
```
เปิดบราวเซอร์ที่: **http://127.0.0.1:8000/**

### 3. หรือรันเวอร์ชันภาษาอังกฤษ (English Edition)
```bash
cd phishwise-django-en
pip install -r requirements.txt
python manage.py migrate
python manage.py seed_articles
python manage.py seed_demo_statistics
python manage.py runserver 8001
```
เปิดบราวเซอร์ที่: **http://127.0.0.1:8001/**

---

## 🔑 บัญชีผู้ใช้ตัวอย่างสำหรับการทดสอบ (Demo Accounts)

| สิทธิ์การใช้งาน | Username | Password | สิทธิ์การเข้าถึง |
| :--- | :--- | :--- | :--- |
| **ผู้ดูแลระบบ (Admin)** | `admin` | `Admin1234!` | หน้าจัดการ Admin, ตรวจรับรายงานเบาะแส, จัดการบทความ |
| **สมาชิก (Member)** | `member` | `Member1234!` | ดูประวัติสแกน, สถิติการตรวจ, ส่งออกรายงาน PDF, แจ้งเบาะแส |
| **ผู้ใช้ทั่วไป (Guest)** | *(ไม่ต้องล็อกอิน)* | - | สแกน URL, สแกน QR Code/รูปภาพ, อ่านคลังความรู้ |

---

## 📜 หมายเหตุและการอ้างอิงทางวิชาการ
โครงงานนี้พัฒนาขึ้นเพื่อการศึกษาและการวิจัยด้านความปลอดภัยสารสนเทศ ผลการประเมินความเสี่ยงเป็นการวิเคราะห์เบื้องต้นจากข้อมูลที่ตรวจวัดได้ ณ ขณะตรวจสอบ เพื่อใช้ประกอบการระมัดระวังในการใช้งานอินเทอร์เน็ต
