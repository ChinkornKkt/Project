# หลักการโมเดลและการคำนวณของ PhishWise

อัปเดตล่าสุด: 27 สิงหาคม 2026

## ภาพรวม

PhishWise ใช้การประเมินความเสี่ยงแบบผสมผสาน (Hybrid Pipeline) โดยไม่พึ่งพาโมเดลใดโมเดลหนึ่งเพียงตัวเดียว ประกอบด้วย:

1. **Random Forest**: วิเคราะห์คุณลักษณะเชิงโครงสร้างของ URL (Lexical & Structural URL Analysis)
2. **Bi-directional LSTM**: วิเคราะห์ลำดับ token จากเนื้อหา HTML และข้อความของหน้าเว็บ (Web Content Analysis)
3. **Security Rule Engine**: กฎประกอบจากอายุโดเมน (WHOIS), ใบรับรอง SSL, รูปแบบไฟล์ดาวน์โหลด และผลตรวจ VirusTotal

คะแนนความน่าจะเป็นภายในของโมเดลใช้สำหรับการประเมินระดับความเสี่ยงภายในระบบเท่านั้น หน้าเว็บสำหรับผู้ใช้ทั่วไปจะแสดงเป็นระดับความเสี่ยง 5 ระดับและคำอธิบายข้อสังเกต

---

## 1. Random Forest: โมเดลโครงสร้าง URL

- **ไฟล์โมเดล**: `detector/ml_models/url_random_forest_model.pt`
- **แหล่งที่มาของ Dataset สำหรับทดลอง**:
  - ฝั่งอันตราย (Malicious / Botnet / Malware Distribution URLs): **URLhaus API (Abuse.ch)** จำนวน 5,000 รายการ
  - ฝั่งปลอดภัย (Legitimate Domain URLs): **Tranco Top 1M Sites** จำนวน 5,000 รายการ
  - รวม 10,000 รายการ (สัดส่วนสมดุล 50:50)
- **การสกัดคุณลักษณะ (11 Hand-crafted Features)**:
  - `url_length`: ความยาว URL ทั้งหมด
  - `is_ip_address`: ใช้ IP Address ตรงแทนชื่อโดเมน
  - `count_dots`: จำนวนจุด (`.`)
  - `count_hyphens`: จำนวนขีดกลาง (`-`)
  - `count_at`: จำนวนเครื่องหมาย `@`
  - `count_question`: จำนวนเครื่องหมาย `?`
  - `count_equal`: จำนวนเครื่องหมาย `=`
  - `count_slash`: จำนวนเครื่องหมาย `/`
  - `has_suspicious_keyword`: มีคำสำคัญต้องสงสัย เช่น `login`, `secure`, `banking`, `verify`, `account`
  - `has_executable_extension`: ตรวจจับนามสกุลไฟล์รันระบบ เช่น `.sh`, `.exe`, `.arm7`, `.bin`, `.elf`, `.apk`
  - `is_https`: การใช้โปรโตคอล HTTPS
- **สถาปัตยกรรม & Hyperparameters**:
  - `RandomForestClassifier(n_estimators=150, max_depth=12, class_weight='balanced', random_state=42)`
- **ผลการทดสอบเชิงประจักษ์ (Empirical Evaluation)**:
  - เมื่อทำ **Deduplication** ข้อมูล 10,000 แถวตามค่าของ Features ทั้งหมด พบว่ามีรูปแบบ Features ที่ไม่ซ้ำกันจริง **551 รูปแบบ (Unique Feature Vectors)** (ฝั่ง Benign 110 รูปแบบ, ฝั่ง Malicious 441 รูปแบบ)
  - **ผล 5-Fold Stratified Cross-Validation บน 551 Unique Feature Vectors (Overlap 0.00%)**:
    - **Mean Accuracy**: **99.64% (± 0.73%)**
    - **Mean Precision**: **99.67% (± 0.67%)**
    - **Mean Recall**: **99.64% (± 0.73%)**
    - **Mean F1-Score**: **99.64% (± 0.72%)**
    - *ผลแยกราย Fold*:
      - Fold 1: Accuracy = 100.00%, F1-Score = 100.00% (Val Size = 111)
      - Fold 2: Accuracy = 98.18%, F1-Score = 98.21% (Val Size = 110)
      - Fold 3: Accuracy = 100.00%, F1-Score = 100.00% (Val Size = 110)
      - Fold 4: Accuracy = 100.00%, F1-Score = 100.00% (Val Size = 110)
      - Fold 5: Accuracy = 100.00%, F1-Score = 100.00% (Val Size = 110)
- **ข้อสังเกตและข้อจำกัดของโมเดล Random Forest**:
  - ความแม่นยำเฉลี่ยที่สูง (99.64%) สัมพันธ์กับลักษณะของชุดข้อมูลทดลอง ที่ฝั่งอันตรายจาก URLhaus ส่วนใหญ่เป็นลิงก์มัลแวร์/บ็อตเน็ตที่ใช้ IP ตรง หรือเป็น HTTP ที่มีพาธไฟล์ executable ชัดเจน ขณะที่ Tranco เป็นโดเมนหลัก HTTPS
  - ในโลกความจริง ฟิชชิ่งรุ่นใหม่อาจใช้ HTTPS และจดชื่อโดเมนที่ไม่มีคีย์เวิร์ดต้องสงสัย ทำให้โมเดลโครงสร้าง URL เพียงอย่างเดียวอาจตรวจไม่พบ จึงต้องมีโมเดล BiLSTM และกลไกตรวจเช็กอื่นร่วมด้วย

---

## 2. Bi-directional LSTM: โมเดลเนื้อหาเว็บไซต์ (HTML Content Analysis)

- **ไฟล์น้ำหนัก**: `detector/ml_models/advanced_model_bi_lstm.pt`
- **ไฟล์คลังคำศัพท์**: `detector/ml_models/vocab_final.pkl` (ขนาดคำศัพท์ 15,000 คำ)
- **แหล่งที่มาของ Dataset**:
  - **Zenodo Record 8041387** (Web Security HTML Dataset)
  - ข้อมูลเว็บไซต์ปลอดภัย: 84,228 ไฟล์ HTML
  - ข้อมูลเว็บไซต์อันตราย: 27,827 ไฟล์ HTML
- **กระบวนการ Preprocessing & Tokenization**:
  1. ดึงเนื้อหา HTML จาก HTTP Response Code 200 (ขนาดไม่เกิน 2 MB)
  2. ทำความสะอาดข้อความ แยกแท็ก HTML แปลงเป็นตัวพิมพ์เล็ก
  3. คัดกรอง Token ความยาว 2–20 ตัวอักษร สูงสุด 250 Tokens ต่อหน้าเว็บ
  4. แมป Token เข้ากับ Vocabulary Index (คำนอกคลังใช้ `<UNK>`, ข้อมูลสั้นใช้ `<PAD>`)
- **สถาปัตยกรรมโมเดล**:
  - `Embedding Layer (vocab_size=15,000, embedding_dim=64)`
  - `Bi-directional LSTM (hidden_dim=128, num_layers=2, dropout=0.3)`
  - `Global Average Pooling`
  - `Fully Connected Linear Layer -> Softmax (2 Classes: Benign / Malicious)`
- **ผลการประเมินประสิทธิภาพบน Test Set (2,000 ตัวอย่าง - Zenodo Benchmark)**:
  - **Accuracy**: **92.10%**
  - **Benign (ปลอดภัย)**: Precision = 90.87%, Recall = 93.60%, **F1-Score = 92.22%** (TN: 936, FP: 64)
  - **Malicious (อันตราย)**: Precision = 93.40%, Recall = 90.60%, **F1-Score = 91.98%** (TP: 906, FN: 94)
  - **Macro Average F1-Score**: **92.10%**
- **ข้อสังเกตและข้อจำกัดของโมเดล BiLSTM**:
  - หากเว็บไซต์ปลายทางไม่ตอบสนอง ปิดกั้น bot มีระบบ Cloudflare หรือเนื้อหาไม่ใช่ HTML โมเดลนี้จะไม่สามารถให้ผลได้ ระบบจะต้องแสดงสถานะ "ตรวจไม่ได้" โดยไม่สรุปเอาเองว่าปลอดภัย

---

## 3. กลไกการรวมผลความเสี่ยง (Hybrid Aggregation Logic)

อ้างอิงโค้ดจริงใน `scan_url_logic()` จาก `detector/services.py`:

1. **กรณีมีผลจากทั้งสองโมเดล**: ใช้ค่าเฉลี่ยความเสี่ยงจาก Random Forest และ BiLSTM
2. **กรณีมีเพียงโมเดลเดียวให้ผล**: ใช้ค่าความเสี่ยงของโมเดลที่พร้อมทำงาน
3. **กรณีไม่สามารถรันโมเดลได้**: เริ่มต้นที่ค่าความเสี่ยงตั้งต้น 50 (ไม่ถือว่าปลอดภัย)
4. **กฎความปลอดภัยเสริม (Security Rule Engine)**:
   - ตรวจพบ IP Address ตรงร่วมกับ Executable Extension (`.exe`, `.sh`, `.arm7`): ปรับความเสี่ยงเป็น **100** ทันที
   - ตรวจพบ Suspicious Keyword บน HTTP ที่ไม่มี SSL: ปรับความเสี่ยงอย่างน้อย **95**
   - โดเมนเพิ่งจดใหม่ $\le 30$ วัน: บวกเพิ่ม **+40**
   - โดเมนอายุ $31 - 180$ วัน: บวกเพิ่ม **+20**
   - ไม่พบใบรับรองความปลอดภัย SSL: บวกเพิ่ม **+30**
   - พบนามสกุลไฟล์รันอัตโนมัติ: บวกเพิ่ม **+20**
5. **VirusTotal Engine**:
   - เรียกตรวจเฉพาะไฟล์ดาวน์โหลด (จำกัดขนาด $\le 32$ MB)
   - หากตรวจพบ Malicious $\ge 3$ เครื่องยนต์: ปรับค่าความเสี่ยงเป็น **100**
6. **การแปลงเป็น 5 ระดับความเสี่ยง (`classify_risk()`)**:
   - 0 – 20: **ปลอดภัย (Safe)** (`safe`)
   - 21 – 40: **ค่อนข้างปลอดภัย (Mostly Safe)** (`mostly_safe`)
   - 41 – 60: **ควรระวัง (Warning)** (`warning`)
   - 61 – 80: **มีแนวโน้มอันตราย (Mostly Danger)** (`mostly_danger`)
   - 81 – 100: **อันตราย (Danger)** (`danger`)

---

## 4. ข้อจำกัดและความโปร่งใสทางวิชาการ (Academic Defense)

- **ความโปร่งใสของ Dataset**: ใช้ชุดข้อมูลเปิดเผยที่อ้างอิงได้ (Zenodo Record 8041387 และ URLhaus / Tranco)
- **การแบ่งระดับ 5 ชั้น**: เป็น Business Logic ของระบบสำหรับสื่อสารกับผู้ใช้ ไม่ใช่ Label 5 คลาสจากการเทรนโมเดล
- **ความตรงไปตรงมา**: เมื่อโมเดลหรือบริการภายนอกให้ผลไม่ได้ ระบบจะแสดงสถานะ "ตรวจไม่ได้" อย่างชัดเจน
- **ข้อมูลประกอบ**: SSL และอายุโดเมนเป็นเพียงตัวบ่งชี้เสริม ไม่สามารถใช้รับรองความปลอดภัยได้อย่างสมบูรณ์
