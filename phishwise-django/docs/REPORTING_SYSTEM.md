# ระบบรายงานเว็บไซต์น่าสงสัย

อัปเดตล่าสุด: 24 สิงหาคม 2026

เอกสารนี้อธิบายระบบรายงานจากผู้ใช้และสถิติรายโดเมน เพื่อให้ผู้รับช่วงหรือ AI เข้าใจขอบเขตและจุดแก้ไขได้รวดเร็ว

## หลักการสำคัญ

- ผลจากชุมชนเป็นข้อมูลประกอบ แยกจากผล AI และ VirusTotal
- “ชุมชนแจ้งเตือน” หมายถึงมีรายงานที่ผู้ดูแลอนุมัติอย่างน้อย 3 รายการจากผู้ใช้ต่างกัน ไม่ใช่ข้อสรุปว่าเว็บไซต์อันตรายแน่นอน
- VirusTotal ในโครงการนี้ใช้กับไฟล์ดาวน์โหลดเท่านั้น ไม่ใช่การตรวจ URL ทุกลิงก์
- โดเมนเก็บเป็น hostname ตัวพิมพ์เล็ก เช่น `example.com` โดยแยกจาก URL ด้วย `urllib.parse.urlparse()`

## โมเดลข้อมูล

อยู่ใน `detector/models.py`

### `DomainStatistic`

เก็บสถิติสะสมต่อหนึ่งโดเมน

| field | ความหมาย |
|---|---|
| `domain` | hostname ที่ไม่ซ้ำ |
| `scan_count` | จำนวนการตรวจทั้งหมด |
| `unique_scanner_count` | จำนวนผู้ใช้ที่เข้าสู่ระบบและตรวจโดเมนนั้นแบบไม่ซ้ำ |
| `report_count` | จำนวนรายงานจากผู้ใช้ทั้งหมด |
| `approved_report_count` | จำนวนรายงานที่ผู้ดูแลอนุมัติ |
| `scanned_by` | ความสัมพันธ์ผู้ใช้สำหรับนับผู้ตรวจไม่ซ้ำ |

### `SuspiciousSiteReport`

เก็บรายงานแต่ละรายการ: ผู้ส่ง, URL, โดเมน, เหตุผล, รายละเอียด, สถานะ, ผู้ตรวจ และเวลาตรวจ

สถานะมี 3 ค่า:

- `pending` — รอตรวจสอบ
- `approved` — ผู้ดูแลอนุมัติ
- `rejected` — ผู้ดูแลปฏิเสธ

มี partial unique constraint ชื่อ `one_open_or_approved_report_per_user_domain`:

- ผู้ใช้คนเดิมรายงานโดเมนเดิมไม่ได้ หากมีรายการ `pending` หรือ `approved`
- หากรายการก่อนหน้าถูก `rejected` ผู้ใช้ส่งรายงานใหม่ของโดเมนเดิมได้

## Service กลาง

ไฟล์ `detector/reporting.py`

- `domain_from_url(value)` ตรวจ URL ว่าเป็น HTTP/HTTPS และคืน hostname แบบ lowercase
- `record_domain_scan(url, user)` เพิ่มยอดตรวจ และเพิ่มยอดผู้ตรวจไม่ซ้ำเฉพาะบัญชีที่เข้าสู่ระบบ
- `create_site_report(user, url, reason, details)` สร้างรายงานและเพิ่ม `report_count`; แปลงข้อผิดพลาด constraint เป็นข้อความภาษาไทย
- `review_site_report(report, status, reviewer)` อนุมัติ/ปฏิเสธ และปรับ `approved_report_count` ให้ถูกต้อง

ทุกฟังก์ชันที่แก้ยอดสะสมใช้ database transaction เพื่อให้สถานะและสถิติสอดคล้องกัน

## Flow การทำงาน

1. ผู้ใช้ตรวจ URL ผ่านหน้าเว็บหรือ REST API
2. ระบบบันทึก `ScanHistory` ตามเดิม
3. ระบบเรียก `record_domain_scan()` เพื่ออัปเดต `DomainStatistic`
4. สมาชิกที่เข้าสู่ระบบส่งรายงานผ่าน `/report/`
5. ระบบเรียก `create_site_report()` และป้องกันรายงานซ้ำ
6. ผู้ดูแลตรวจรายการจากหน้า `/admin/` แล้วส่ง POST ไปที่ `admin/reports/<report_id>/review/`
7. ระบบเรียก `review_site_report()` และอัปเดตยอดอนุมัติ
8. หน้าผล `/result/` โหลดสถิติของโดเมนและตั้ง `community_warning=True` เมื่อ `approved_report_count >= 3`

## หน้าจอที่เกี่ยวข้อง

- `templates/report.html` — แบบฟอร์มรายงานภาษาไทยและประวัติรายงานของผู้ใช้
- `templates/result.html` — สถิติรายโดเมนและกล่องข้อมูลชุมชน
- `templates/admin.html` — รายงานที่รอตรวจสอบ, ปุ่มอนุมัติ/ปฏิเสธ, สถิติรายโดเมน

## ไฟล์และ route สำคัญ

- `detector/models.py`
- `detector/reporting.py`
- `detector/migrations/0004_domainstatistic_suspicioussitereport.py`
- `detector/views.py` — เรียก `record_domain_scan()` สำหรับ REST API
- `dashboard/views.py` — เรียก `record_domain_scan()` สำหรับหน้าเว็บ, รับรายงาน, ตรวจรายงาน, เตรียม context หน้าผล
- `dashboard/urls.py` — route ตรวจรายงานของผู้ดูแล

## การทดสอบล่าสุด

ชุด `dashboard.tests.DomainReportingTests` ครอบคลุม:

- ป้องกันรายงานซ้ำระหว่างรออนุมัติ
- รายงานอนุมัติจากผู้ใช้ 3 คนทำให้แสดง “ชุมชนแจ้งเตือน”
- นับจำนวนตรวจและผู้ตรวจไม่ซ้ำ

ผลล่าสุดเมื่อ 24 สิงหาคม 2026:

```cmd
python manage.py makemigrations --check
python manage.py check
python manage.py test dashboard.tests.DomainReportingTests detector.tests --verbosity 2
```

ผ่านทั้งหมด: migration check, Django system check และ tests ที่เกี่ยวข้อง 13 รายการ

