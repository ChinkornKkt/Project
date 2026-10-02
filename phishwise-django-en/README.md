# PhishWise (English Edition)
**AI-Powered Phishing & Malicious URL Risk Assessment System**

PhishWise is a comprehensive educational web application designed to evaluate and identify phishing URLs, deceptive hyperlinks, and malicious downloads. It features multi-layered AI heuristic inspection, QR code & OCR screenshot extraction, domain intelligence analysis, threat reporting, and downloadable security audit reports.

---

## 🌟 Key Features

1. **Dual Scanning Modes**:
   - **Direct URL Input**: Instant heuristic and machine-learning risk evaluation of any web address.
   - **QR Code & OCR Image Upload**: Automatic detection and URL extraction from QR codes or screenshot images using computer vision (OpenCV & EasyOCR).

2. **5-Level Granular Risk Classification**:
   - 🟢 **Safe** (`0–20`): Normal website with established domain history and valid SSL certificate.
   - 🟢 **Mostly Safe** (`21–40`): Minor irregularities, but no prominent phishing characteristics.
   - 🟡 **Caution** (`41–60`): Elevated risk indicators, new domain, or ambiguous redirection patterns.
   - 🟠 **High Risk** (`61–80`): Multiple phishing signals or deceptive keywords detected.
   - 🔴 **Dangerous** (`81–100`): Confirmed phishing structure, malware payload, or blacklisted domain.

3. **In-Depth Technical Inspection**:
   - **11 Structural URL Features**: URL length, IP address usage, suspicious keywords, executable extensions, special characters, HTTPS status, and more.
   - **Domain Intelligence & SSL Verification**: Real-time WHOIS registration age and SSL/TLS certificate validity checks.
   - **Redirect Chain Tracer**: Unpacks shortened and intermediate URLs to disclose the real final destination.
   - **File Download & Antivirus Integration**: Inspects downloadable attachments and correlates detection rates.

4. **Threat Reporting & Community Intelligence**:
   - Authenticated members can submit suspicious domains with categorized reasons (Credential Theft, Financial Scam, Malware).
   - Administrative review queue allows staff to investigate, approve, or reject submissions.

5. **Cybersecurity Knowledge Base**:
   - Pre-loaded with 12 comprehensive security articles covering phishing defense, password entropy, call center scams, ransomware, 2FA, Wi-Fi hygiene, and deepfakes.
   - Admin markdown editor with sanitization and instant preview.

6. **Scan Statistics & PDF Reporting**:
   - Interactive charts showing scan distribution and trends over 7 days, 30 days, or all time.
   - Dual-engine PDF export (WeasyPrint / ReportLab) generating formal security audit summaries.

---

## 🛠️ Technology Stack

- **Backend**: Python 3.11+, Django 5.x
- **Frontend**: HTML5, Tailwind CSS, FontAwesome 6, Chart.js
- **Machine Learning**: Scikit-learn (Random Forest URL classifier), PyTorch (BiLSTM content model)
- **Computer Vision & OCR**: OpenCV, EasyOCR, NumPy
- **Reporting**: ReportLab & WeasyPrint
- **Database**: SQLite3 (default) / PostgreSQL compatible

---

## 🚀 Quick Start Guide

### 1. Prerequisites
Ensure Python 3.10+ is installed on your system.

### 2. Navigate to Project Directory
```bash
cd phishwise-django-en
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Database Setup & Migrations
```bash
python manage.py migrate
```

### 5. Seed Knowledge Base & Demo Statistics
Populate the knowledge base articles and generate realistic scan history:
```bash
python manage.py seed_articles
python manage.py seed_demo_statistics
```

### 6. Run the Development Server
You can launch the English server on port 8000 (or port 8001 if port 8000 is occupied):
```bash
python manage.py runserver 8000
```
Visit **http://127.0.0.1:8000/** in your browser.

---

## 🔑 Default Accounts (Demo)

| Role | Username | Password | Access Level |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `Admin1234!` | Full system administration, article manager, threat review portal |
| **Member User** | `member` | `Member1234!` | Scan history, statistical dashboard, PDF export, threat reporting |
| **Guest** | *(None)* | *(None)* | Public URL inspection, QR scanner, knowledge base reader |

---

## 📁 Project Architecture

```
phishwise-django-en/
├── core/                       # Django project configuration & settings
├── dashboard/                  # UI views, PDF generators, routes & tests
│   ├── analysis_weasyprint.py  # WeasyPrint analysis PDF builder
│   ├── analysis_pdf_report.py  # ReportLab fallback analysis PDF builder
│   ├── pdf_report.py           # ReportLab statistics PDF generator
│   └── views.py                # Core web controllers & demo article fixtures
├── detector/                   # AI detection pipeline, OCR, & models
│   ├── risk_levels.py          # 5-level risk classification engine
│   ├── services.py             # URL inspection logic, WHOIS, & SSL checks
│   ├── ocr_pipeline.py         # EasyOCR & image processing pipeline
│   ├── virustotal.py           # Antivirus threat intelligence integration
│   └── models.py               # ScanHistory, SuspiciousSiteReport, KnowledgeArticle
├── templates/                  # Pure English HTML templates
│   ├── pdf/                    # WeasyPrint HTML/CSS PDF report templates
│   ├── base.html               # Main application layout
│   ├── home.html               # URL & QR scanner landing page
│   ├── result.html             # Detailed assessment results
│   ├── dashboard.html          # Scan statistics & metrics
│   ├── knowledge.html          # Cybersecurity knowledge base
│   └── admin.html              # Administrator moderation console
└── static/                     # Static styling, brand assets, and scripts
```

---

## 📄 License & Academic Note
PhishWise is developed for educational and research purposes. Risk evaluations are preliminary diagnostic assessments and should be used alongside standard organizational cybersecurity best practices.
