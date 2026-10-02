# บริบทโครงการ PhishWise

อัปเดตล่าสุด: 21 สิงหาคม 2026

## วัตถุประสงค์

PhishWise เป็นเว็บแอปพลิเคชัน Django สำหรับโครงงานการศึกษา ช่วยผู้ใช้ประเมินความเสี่ยงของ URL ก่อนเปิดลิงก์ กรอกข้อมูล หรือดาวน์โหลดไฟล์ ระบบรับ URL โดยตรง รวมถึง URL ที่อ่านจาก QR Code ผ่านกล้องหรือรูปภาพ

ระบบไม่ควรกล่าวว่าเว็บไซต์ “ปลอดภัยแน่นอน” ผลทุกครั้งเป็นเพียงการประเมินความเสี่ยงเบื้องต้นและอาจเกิด False Positive หรือ False Negative ได้

## เทคโนโลยีหลัก

- Django และ Django REST Framework
- SQLite สำหรับข้อมูลผู้ใช้และประวัติการตรวจ
- PyTorch สำหรับ BiLSTM
- scikit-learn สำหรับ Random Forest
- pandas สำหรับจัดรูปคุณลักษณะของ URL ก่อนป้อนเข้า Random Forest
- OpenCV สำหรับอ่าน QR Code จากรูปภาพ
- WeasyPrint สำหรับรายงาน PDF ภาษาไทย
- python-whois, socket และ ssl สำหรับข้อมูลโดเมน เครือข่าย และใบรับรอง
- VirusTotal API v3 สำหรับตรวจไฟล์ดาวน์โหลด

เวอร์ชันที่กำหนดไว้ให้ดูจาก `requirements.txt` เท่านั้น

## เส้นทางการทำงานหลัก

1. ผู้ใช้ส่ง URL โดยตรง สแกน QR ด้วยกล้อง หรืออัปโหลดรูป QR
2. ระบบทำ URL normalization และตรวจว่าเป็น HTTP/HTTPS ที่ถูกต้อง
3. ระบบป้องกันการเรียก private/non-public network และจำกัดจำนวน redirect
4. ตรวจ URL สุดท้าย อายุโดเมน SSL ตำแหน่ง IP และการส่งต่อ
5. Random Forest ประเมินโครงสร้าง URL
6. ระบบดาวน์โหลด HTML ภายใต้ข้อจำกัด แล้ว BiLSTM ประเมินเนื้อหา HTML
7. ถ้าปลายทางเป็นไฟล์ดาวน์โหลด ระบบคำนวณ SHA-256 และสอบถาม VirusTotal; จะอัปโหลดไฟล์ที่ไม่เคยมีรายงานเฉพาะเมื่อตั้งค่าอนุญาต
8. รวมผลโมเดลและกฎประกอบเป็นค่าความเสี่ยงภายใน จากนั้นแปลงเป็น 5 ระดับ
9. บันทึก `ScanHistory` และแสดงผลเป็นระดับพร้อมคำอธิบาย

## ส่วนประกอบและไฟล์สำคัญ

- `core/settings.py` — การตั้งค่า Django และอ่าน environment variables
- `core/urls.py` — รวม URL routes
- `detector/services.py` — การดึงข้อมูล URL, feature extraction, โหลดโมเดลและรวมผล
- `detector/virustotal.py` — ติดต่อ VirusTotal สำหรับไฟล์
- `detector/risk_levels.py` — แหล่งจริงของเกณฑ์ 5 ระดับ
- `detector/models.py` — โมเดลฐานข้อมูล `ScanHistory`
- `detector/views.py` — REST API ตรวจ URL และประวัติ
- `dashboard/views.py` — หน้าเว็บ การเข้าสู่ระบบ QR สถิติ แอดมิน ผลตรวจ และ PDF
- `templates/home.html` — หน้าหลักสำหรับ URL และ QR Code
- `templates/result.html` — หน้าผลการวิเคราะห์
- `templates/dashboard.html` — หน้าสถิติการตรวจสอบ
- `templates/admin.html` — หน้าผู้ดูแลระบบ
- `templates/pdf/` — HTML/CSS สำหรับ PDF
- `dashboard/analysis_weasyprint.py` — เตรียมข้อมูลรายงานผลการตรวจ
- `dashboard/statistics_weasyprint.py` — เตรียมข้อมูลรายงานสถิติ
- `dashboard/weasyprint_runtime.py` — สร้าง PDF ด้วย WeasyPrint
- `detector/tests.py`, `dashboard/tests.py` — ชุดทดสอบหลัก

## หน้าและความสามารถของผู้ใช้

- หน้าหลัก: กรอก URL, เปิดกล้อง QR, อัปโหลดรูป QR
- ผลการวิเคราะห์: ระดับรวม ผลจากโมเดลแต่ละตัว และหลักฐานประกอบ
- สถิติการตรวจสอบ: ช่วง 7 วัน, 30 วัน และทั้งหมด
- ประวัติ: รายการตรวจของผู้ใช้
- ความปลอดภัยในโลกไซเบอร์: บทความความรู้
- ผู้ดูแลระบบ: ผู้ใช้ สถานะบัญชี และภาพรวมการตรวจ
- รายงาน PDF: รายงานผลรายครั้งและรายงานสถิติ

## บัญชีและข้อมูล

- ใช้ระบบผู้ใช้ของ Django
- ผู้ใช้ทั่วไปเห็นสถิติและประวัติของตนเอง
- ผู้ดูแลระบบใช้ `is_staff`
- ห้ามบันทึกรหัสผ่านแบบข้อความธรรมดาหรือสร้างบัญชีตัวอย่างใน source code
- ข้อมูลสาธิตสร้างผ่าน management command ไม่ควรผสมกับข้อมูลจริงโดยไม่แจ้งผู้ใช้

## Environment variables

ค่าจริงอยู่ใน `.env` ข้าง `manage.py` และไม่ควรถูกอ่านหรือส่งออกโดย AI

- `VIRUSTOTAL_API_KEY`
- `VIRUSTOTAL_UPLOAD_UNKNOWN_FILES`
- `VIRUSTOTAL_POLL_ATTEMPTS`
- `VIRUSTOTAL_POLL_SECONDS`
- `WEASYPRINT_DLL_DIRECTORIES`

