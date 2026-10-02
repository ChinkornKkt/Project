# คู่มือการติดตั้งและเปิดใช้งาน PhishWise

คู่มือนี้ใช้สำหรับ Windows PowerShell โดยกำหนดให้โฟลเดอร์ `.venv` อยู่ใน
`D:\work\Project\Project` และอยู่ข้างโฟลเดอร์ `phishwise-django`

โครงสร้างโฟลเดอร์ที่แนะนำ:

```text
D:\work\Project\Project\
├── .venv\
└── phishwise-django\
    ├── manage.py
    ├── requirements.txt
    └── .env
```

## 1. ตรวจสอบและสร้าง Virtual Environment (ทำครั้งแรกเท่านั้น)

โปรเจกต์นี้ต้องใช้ **Python 3.13** เนื่องจากโมเดลถูกบันทึกด้วย
`scikit-learn 1.6.1` ซึ่งไม่รองรับการติดตั้งบน Python 3.14

ตรวจสอบว่าเครื่องมี Python 3.13:

```powershell
py -3.13 --version
```

ผลลัพธ์ควรขึ้นต้นด้วย `Python 3.13`

เปิด PowerShell แล้วรัน:

```powershell
cd D:\work\Project\Project
py -3.13 -m venv .venv
```

หากมีโฟลเดอร์ `.venv` อยู่แล้ว ไม่ต้องสร้างซ้ำ ให้ข้ามไปขั้นตอนถัดไป
แต่หากตรวจพบว่า `.venv` เดิมใช้ Python 3.14 ต้องเปลี่ยนชื่อหรือลบ `.venv`
เดิม แล้วสร้างใหม่ด้วย Python 3.13

## 2. เปิดใช้งาน Virtual Environment

```powershell
cd D:\work\Project\Project
.\.venv\Scripts\Activate.ps1
```

เมื่อเปิดสำเร็จ จะเห็น `(.venv)` อยู่ด้านหน้าบรรทัดคำสั่ง

ตรวจสอบว่าใช้ Python ภายใน `.venv`:

```powershell
python -c "import sys; print(sys.executable)"
```

ผลลัพธ์ควรชี้ไปที่:

```text
D:\work\Project\Project\.venv\Scripts\python.exe
```

## 3. ติดตั้งไลบรารีของโปรเจกต์

```powershell
cd D:\work\Project\Project\phishwise-django
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

ตรวจสอบเวอร์ชัน scikit-learn ซึ่งต้องตรงกับโมเดลที่เทรนไว้:

```powershell
python -c "import sklearn; print(sklearn.__version__)"
```

ผลลัพธ์ควรเป็น `1.6.1`

### ติดตั้งระบบสร้าง PDF ภาษาไทยบน Windows (ทำครั้งแรกเท่านั้น)

รายงานผลการวิเคราะห์ใช้ WeasyPrint และ Pango/HarfBuzz เพื่อจัดตำแหน่งสระและ
วรรณยุกต์ภาษาไทยให้ถูกต้อง ติดตั้ง MSYS2 แล้วเพิ่ม Pango ด้วยคำสั่งต่อไปนี้:

```powershell
winget install --id MSYS2.MSYS2 --exact --source winget
& "C:\msys64\usr\bin\bash.exe" -lc "pacman -S --noconfirm --needed mingw-w64-x86_64-pango"
```

โปรเจกต์จะค้นหา DLL ที่ `C:\msys64\mingw64\bin` อัตโนมัติ หากติดตั้งไว้
ตำแหน่งอื่น ให้กำหนด `WEASYPRINT_DLL_DIRECTORIES` ในไฟล์ `.env`

ตรวจสอบโดยสร้างรายงานตัวอย่าง:

```powershell
python manage.py generate_pdf_regression_sample
python manage.py generate_statistics_pdf_sample
```

ไฟล์จะอยู่ในโฟลเดอร์ `output\pdf`

## 4. ตั้งค่า VirusTotal API Key

คัดลอกไฟล์ตัวอย่างเป็น `.env`:

```powershell
Copy-Item .env.example .env
```

เปิดไฟล์ `.env` แล้วกรอก API key ของตนเอง:

```env
VIRUSTOTAL_API_KEY=ใส่_api_key_ของคุณที่นี่
VIRUSTOTAL_UPLOAD_UNKNOWN_FILES=false
VIRUSTOTAL_POLL_ATTEMPTS=3
VIRUSTOTAL_POLL_SECONDS=2
```

ไม่ควรส่งไฟล์ `.env` ให้ผู้อื่นหรือนำขึ้น Git เพราะภายในมี API key ส่วนตัว

แนะนำให้คง `VIRUSTOTAL_UPLOAD_UNKNOWN_FILES=false` ไว้ เพื่อไม่ให้อัปโหลดไฟล์ที่
VirusTotal ไม่รู้จักโดยอัตโนมัติ การเปลี่ยนเป็น `true` อาจทำให้ไฟล์ถูกส่งให้
VirusTotal และพันธมิตรเพื่อใช้ในการวิเคราะห์

## 5. เตรียมฐานข้อมูล

```powershell
python manage.py check
python manage.py migrate
```

## 6. สร้างบัญชีผู้ดูแลระบบ (ทำครั้งแรกเท่านั้น)

```powershell
python manage.py createsuperuser
```

กำหนด Username และ Password ที่ต้องการ ตอนพิมพ์ Password จะไม่มีตัวอักษรแสดงบน
หน้าจอ แต่ระบบยังรับค่าตามปกติ หากมีบัญชีผู้ดูแลอยู่แล้ว ไม่ต้องสร้างซ้ำ

## 7. เปิดใช้งานเว็บไซต์

```powershell
python manage.py runserver
```

จากนั้นเปิดเว็บไซต์ที่:

```text
http://127.0.0.1:8000/
```

หยุดเซิร์ฟเวอร์ด้วย `Ctrl+C`

## คำสั่งสำหรับเปิดโปรเจกต์ในครั้งถัดไป

หลังจากติดตั้งครั้งแรกแล้ว ใช้เพียง:

```powershell
cd D:\work\Project\Project
.\.venv\Scripts\Activate.ps1
cd phishwise-django
python manage.py runserver
```

## การแก้ปัญหาเบื้องต้น

หากพบ `ModuleNotFoundError: No module named 'dotenv'`:

```powershell
python -m pip install -r requirements.txt
```

หาก PowerShell ไม่อนุญาตให้เปิด `.venv` ให้เปิดสิทธิ์เฉพาะหน้าต่างปัจจุบัน:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

หาก scikit-learn ไม่ใช่เวอร์ชัน `1.6.1`:

```powershell
python -m pip install --force-reinstall scikit-learn==1.6.1
```

หากการติดตั้งแสดง `Preparing metadata` และพยายามคอมไพล์ scikit-learn หรือมี
ข้อความ `Run-time dependency python found: YES 3.14` แสดงว่า `.venv` ถูกสร้างด้วย
Python 3.14 ให้สร้าง `.venv` ใหม่ด้วยคำสั่ง `py -3.13 -m venv .venv`
