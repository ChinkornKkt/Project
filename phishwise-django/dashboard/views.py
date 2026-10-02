import os
import uuid
from pathlib import Path
from datetime import timedelta
from collections import Counter
from urllib.parse import urlparse
import cv2
import numpy as np
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST
import json
from detector.models import DomainStatistic, KnowledgeArticle, ScanHistory, SuspiciousSiteReport
from detector.reporting import create_site_report, domain_from_url, record_domain_scan, review_site_report
from detector.risk_levels import classify_risk
from detector.services import scan_url_logic
from detector.article_utils import render_article_markdown

ARTICLES = [
    {
        "id": 1,
        "title": "วิธีสังเกตลิงก์ปลอม (Phishing) แบบมือโปร",
        "category": "Phishing",
        "author": "PhishWise Team",
        "author_role": "Cybersecurity Specialist",
        "date": "29 ม.ค. 2026",
        "read_time": "4 นาที",
        "desc": "เจาะลึกเทคนิคการตรวจสอบ URL แปลกๆ ก่อนคลิก ป้องกันการถูกหลอกกรอกข้อมูลส่วนตัว",
        "image": "https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&q=80&w=1200",
        "summary": "Phishing เป็นภัยไซเบอร์อันดับ 1 ที่ผู้ใช้อินเทอร์เน็ตมักตกเป็นเหยื่อ โดยแฮกเกอร์จะสร้างเว็บไซต์ปลอมที่เลียนแบบหน้าตาเว็บธนาคารหรือโซเชียลมีเดีย เพื่อหลอกเอาข้อมูลรหัสผ่านและบัตรเครดิต",
        "sections": [
            {
                "title": "1. สังเกตชื่อโดเมน (Domain Name) ให้ละเอียด",
                "text": "แฮกเกอร์มักใช้เทคนิค Typosquatting หรือการจดชื่อโดเมนที่เขียนคล้ายกับของจริงจนผู้ใช้ไม่ทันสังเกต เช่น เปลี่ยนตัว l เป็นเลข 1 หรือเติมคำหลอกลวงข้างหลังชื่อแบรนด์",
                "image": "https://images.unsplash.com/photo-1618060932014-4deda4932554?auto=format&fit=crop&q=80&w=1000",
                "caption": "ตัวอย่างการสังเกตชื่อโดเมนในช่อง Address Bar",
                "examples": [
                    {
                        "label": "URL ของจริง",
                        "url": "https://www.scb.co.th",
                        "is_safe": True,
                    },
                    {
                        "label": "URL ปลอม (สะกดผิด)",
                        "url": "https://www.scb-verify-online.com",
                        "is_safe": False,
                    },
                    {
                        "label": "URL ปลอม (ใช้ตัวเลขแทน)",
                        "url": "http://www.g00gle.com",
                        "is_safe": False,
                    },
                ],
            },
            {
                "title": "2. เช็กการเข้ารหัส SSL/TLS (https://)",
                "text": "หากพบว่าเว็บไหนขึ้นต้นด้วย http:// (ไม่มี s) ให้สงสัยไว้ก่อนว่าเป็นเว็บที่ไม่ปลอดภัย และไม่ควรกรอกข้อมูลสำคัญใดๆ เด็ดขาด",
                "callout": {
                    "type": "warning",
                    "title": "⚠️ ข้อควรระวัง!",
                    "text": "การมีรูปแม่กุญแจ 🔒 (https://) ไม่ได้แปลว่าเว็บนั้นเป็นเว็บดี 100% เพราะแฮกเกอร์ก็สามารถขอใบรับรอง SSL ฟรีได้เช่นกัน จึงต้องเช็กชื่อโดเมนควบคู่กันเสมอ",
                },
            },
            {
                "title": "3. ระวัง Short URL หรือ Dynamic QR Code",
                "text": "คนร้ายมักซ่อน URL จริงไว้หลังบริการย่อลิงก์ เช่น bit.ly, tinyurl หรือคิวอาร์โค้ดตามป้ายประกาศ เพื่อปิดบังปลายทางที่แท้จริง",
                "callout": {
                    "type": "tip",
                    "title": "💡 Pro Tip จาก PhishWise",
                    "text": "หากเจอลิงก์ย่อ หรือ QR Code สามารถนำมาสแกนผ่าน PhishWise เพื่อถอดรหัสหาลิงก์ปลายทางจริงได้ก่อนกดเข้าไปครับ",
                },
            },
        ],
        "key_takeaways": [
            "อย่ารีบร้อนคลิกลิงก์จาก SMS หรืออีเมลที่ไม่คุ้นเคย",
            "ตรวจสอบชื่อโดเมนหลัก (คำที่อยู่หน้า .com / .co.th) ทุกครั้ง",
            "หากไม่แน่ใจ ให้พิมพ์ชื่อเว็บเพื่อเข้าใช้งานด้วยตนเองเสมอ",
        ],
    },
    {
        "id": 2,
        "title": "รหัสผ่านที่ปลอดภัยคืออะไร?",
        "category": "Security",
        "author": "SecAdmin",
        "author_role": "Security Engineer",
        "date": "30 ม.ค. 2026",
        "read_time": "3 นาที",
        "desc": "เลิกใช้ 123456 แล้วเปลี่ยนมาใช้ Passphrase เพื่อความปลอดภัยขั้นสุด",
        "image": "https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?auto=format&fit=crop&q=80&w=1200",
        "summary": "รหัสผ่านเปรียบเสมือนด่านแรกในการปกป้องข้อมูลส่วนตัว การใช้รหัสผ่านที่เดาง่ายทำให้บัญชีของคุณเสี่ยงต่อการถูกแฮกแบบ Brute Force หรือ Dictionary Attack",
        "sections": [
            {
                "title": "1. เปลี่ยนจาก Password เป็น Passphrase",
                "text": "แทนที่จะใช้รหัสผ่านสั้นๆ แต่จำยาก เช่น P@ssw0rd! ให้เปลี่ยนมาใช้ประโยคยาวๆ ที่นำคำที่ไม่เกี่ยวข้องกันมารวมกัน เช่น 'CoffeeCatMoon2026!' ซึ่งสุ่มเดาได้ยากมากสำหรับระบบคอมพิวเตอร์",
                "image": "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?auto=format&fit=crop&q=80&w=1000",
                "caption": "ความยาวของรหัสผ่านสำคัญกว่าความซับซ้อนในการป้องกันการสุ่มรหัสผ่าน",
            },
            {
                "title": "2. ห้ามใช้รหัสผ่านซ้ำกันเด็ดขาด",
                "text": "หากคุณใช้รหัสผ่านเดียวกันในทุกบริการ เมื่อมีเว็บใดเว็บหนึ่งทำข้อมูลรั่วไหล แฮกเกอร์จะนำรหัสผ่านนั้นไปลองเข้าสู่ระบบในบริการอื่นๆ (Credential Stuffing) ทันที",
                "callout": {
                    "type": "warning",
                    "title": "🔒 ตัวช่วยจัดการรหัสผ่าน",
                    "text": "แนะนำให้ใช้ Password Manager เช่น Bitwarden หรือ 1Password ในการช่วยสุ่มและบันทึกรหัสผ่านที่ซับซ้อนให้คุณโดยไม่ต้องจำเอง",
                },
            },
        ],
        "key_takeaways": [
            "ความยาวรหัสผ่านควรมีอย่างน้อย 12-16 ตัวอักษรขึ้นไป",
            "ผสมผสานตัวอักษรใหญ่ เล็ก ตัวเลข และสัญลักษณ์",
            "หลีกเลี่ยงข้อมูลส่วนตัว เช่น วันเกิด เบอร์โทรศัพท์ หรือชื่อสัตว์เลี้ยง",
        ],
    },
    {
        "id": 3,
        "title": "เตือนภัย! แก๊งคอลเซ็นเตอร์รูปแบบใหม่",
        "category": "Scams",
        "author": "Cyber Alert",
        "author_role": "Threat Intelligence",
        "date": "1 ก.พ. 2026",
        "read_time": "5 นาที",
        "desc": "เจาะลึกจิตวิทยาการหลอกลวงทางโทรศัพท์ข่มขู่ให้โอนเงิน",
        "image": "https://images.unsplash.com/photo-1516321318423-f06f85e504b3?auto=format&fit=crop&q=80&w=1200",
        "summary": "แก๊งคอลเซ็นเตอร์พัฒนารูปแบบการหลอกลวงอย่างต่อเนื่อง โดยใช้บทบาทสมมติเป็นเจ้าหน้าที่รัฐ ไปรษณีย์ หรือค่ายมือถือ เพื่อข่มขู่ให้เหยื่อเกิดความกลัวและโอนเงินตรวจสอบ",
        "sections": [
            {
                "title": "1. บทบาทสมมติที่มักถูกอ้างถึง",
                "text": "มักแอบอ้างเป็นตำรวจ เจ้าหน้าที่กรมภาษี DSI หรือพนักงานขนส่ง อ้างว่ามีพัสดุผิดกฎหมายส่งมาถึงคุณ หรือบัญชีของคุณเข้าไปเกี่ยวข้องกับการฟอกเงิน",
                "callout": {
                    "type": "warning",
                    "title": "🚫 กฎเหล็กของหน่วยงานรัฐ",
                    "text": "หน่วยงานราชการและธนาคารไม่มีนโยบายโทรศัพท์มาขอรหัส OTP หรือให้โอนเงินมาเพื่อ 'ตรวจสอบ' โดยเด็ดขาด",
                },
            },
            {
                "title": "2. การตัดสายและตรวจสอบย้อนกลับ",
                "text": "หากได้รับสายที่น่าสงสัย ให้ตั้งสติและ 'กดตัดสายทันที' อย่าสนทนาต่อ จากนั้นให้ติดต่อกลับไปยังเบอร์ Call Center อย่างเป็นทางการของหน่วยงานนั้นๆ ด้วยตนเอง",
            },
        ],
        "key_takeaways": [
            "อย่าโอนเงินตามคำบอกเล่าทางโทรศัพท์ไม่ว่ากรณีใดๆ",
            "ตั้งสติและอย่าหลงเชื่อคำข่มขู่ที่ให้ตัดสินใจทันที",
            "บันทึกเบอร์โทรศัพท์สายด่วนแจ้งความภัยออนไลน์ 1441",
        ],
    },
    {
        "id": 4,
        "title": "Ransomware คืออะไร? รู้ทันไวรัสเรียกค่าไถ่",
        "category": "Malware",
        "author": "MalwareHunter",
        "author_role": "Incident Responder",
        "date": "2 ก.พ. 2026",
        "read_time": "4 นาที",
        "desc": "แนวทางป้องกันไม่ให้ไฟล์และระบบของคุณถูกล็อกเรียกค่าไถ่",
        "image": "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&q=80&w=1200",
        "summary": "Ransomware คือมัลแวร์ประเภทหนึ่งที่จะทำการเข้ารหัสลับ (Encrypt) ไฟล์ทั้งหมดบนเครื่องคอมพิวเตอร์ ทำให้อ่านไฟล์ไม่ได้ แล้วแสดงข้อความเรียกค่าไถ่เป็น Cryptocurrency",
        "sections": [
            {
                "title": "1. ช่องทางการแพร่กระจาย",
                "text": "ส่วนใหญ่มากับไฟล์แนบในอีเมล (เช่น .exe, .zip, .pdf ปลอม) หรือการดาวน์โหลดซอฟต์แวร์เถื่อน/สายมืดผ่านเว็บไซต์ที่ไม่น่าเชื่อถือ",
                "image": "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&q=80&w=1000",
                "caption": "หน้าจอแสดงข้อความเรียกค่าไถ่เมื่อเครื่องติด Ransomware",
            },
            {
                "title": "2. กลยุทธ์การสำรองข้อมูล 3-2-1",
                "text": "สำรองข้อมูลอย่างน้อย 3 ชุด ไว้ในสื่อจัดเก็บ 2 ประเภทที่แตกต่างกัน และเก็บไว้ภายนอกสถานที่หรือ Offline 1 ชุด (เช่น External Hard Drive ที่ไม่ได้เสียบค้างไว้)",
                "callout": {
                    "type": "tip",
                    "title": "💡 คำแนะนำ",
                    "text": "หากเครื่องติด Ransomware ไม่แนะนำให้จ่ายค่าไถ่ เพราะไม่มีหลักประกันว่าจะได้รหัสปลดล็อกคืน และเป็นการสนับสนุนกลุ่มอาชญากร",
                },
            },
        ],
        "key_takeaways": [
            "ทำความสะอาดเครื่องด้วย Antivirus และอัปเดตระบบปฏิบัติการสม่ำเสมอ",
            "ไม่เปิดไฟล์แนบอีเมลจากผู้ส่งที่ไม่รู้จัก",
            "สำรองข้อมูลสำคัญแบบ Offline เป็นประจำ",
        ],
    },
    {
        "id": 5,
        "title": "2FA คืออะไร ทำไมต้องเปิดใช้งานเดี๋ยวนี้?",
        "category": "Security",
        "author": "AuthExpert",
        "author_role": "IAM Specialist",
        "date": "3 ก.พ. 2026",
        "read_time": "3 นาที",
        "desc": "ยกระดับความปลอดภัยด้วยการยืนยันตัวตนสองปัจจัย",
        "image": "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?auto=format&fit=crop&q=80&w=1200",
        "summary": "Two-Factor Authentication (2FA) คือการใช้ปัจจัยยืนยันตัวตนอย่างน้อย 2 อย่างขึ้นไปในการเข้าสู่ระบบ แม้แฮกเกอร์จะรู้รหัสผ่านของคุณ แต่ก็จะเข้าใช้งานไม่ได้หากไม่มีปัจจัยที่สอง",
        "sections": [
            {
                "title": "1. ปัจจัยในการยืนยันตัวตนมีอะไรบ้าง?",
                "text": "1. สิ่งที่คุณรู้ (เช่น รหัสผ่าน, PIN) \n2. สิ่งที่คุณมี (เช่น สมาร์ตโฟน, แอป Authenticator, Security Key) \n3. สิ่งที่คุณเป็น (เช่น ลายนิ้วมือ, ใบหน้า)",
                "image": "https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&q=80&w=1000",
                "caption": "แอป Authenticator ปลอดภัยกว่าการรับ OTP ผ่าน SMS",
            },
            {
                "title": "2. ทำไมควรเลือกแอป Authenticator แทน SMS?",
                "text": "การรับ OTP ผ่าน SMS มีความเสี่ยงที่จะถูกดักจับหรือทำ SIM Swap ได้ แนะนำให้ใช้แอป เช่น Google Authenticator, Microsoft Authenticator หรือ Passkey แทน",
                "callout": {
                    "type": "tip",
                    "title": "💡 อย่าลืมเก็บ Backup Codes!",
                    "text": "เมื่อเปิดใช้งาน 2FA ระบบจะให้รหัสสำรอง (Backup Codes) ควรพิมพ์หรือเซฟเก็บไว้ในที่ปลอดภัย เผื่อกรณีโทรศัพท์หาย",
                },
            },
        ],
        "key_takeaways": [
            "เปิดใช้งาน 2FA ในทุกบัญชีสำคัญ เช่น อีเมล โซเชียล และแอปการเงิน",
            "เลี่ยงการรับ OTP ผ่าน SMS หากเลือกใช้แอป Authenticator ได้",
            "เก็บรักษา Backup Codes ไว้ในสถานที่ปลอดภัย",
        ],
    },
    {
        "id": 6,
        "title": "Public Wi-Fi อันตรายแค่ไหน? ใช้ยังไงให้รอด",
        "category": "Security",
        "author": "NetGuard",
        "author_role": "Network Security Engineer",
        "date": "5 ก.พ. 2026",
        "read_time": "4 นาที",
        "desc": "เล่นเน็ตฟรีตามคาเฟ่หรือสนามบินอย่างไรไม่ให้ถูกแอบดักข้อมูล",
        "image": "https://images.unsplash.com/photo-1563013544-824ae1b704d3?auto=format&fit=crop&q=80&w=1200",
        "summary": "Wi-Fi สาธารณะเปิดโอกาสให้ผู้ไม่หวังดีสามารถใช้เทคนิค Man-in-the-Middle (MitM) เพื่อดักจับข้อมูลการใช้อินเทอร์เน็ตที่ไม่ได้เข้ารหัสได้อย่างง่ายดาย",
        "sections": [
            {
                "title": "1. สัญญาณอันตรายจาก Wi-Fi ปลอม (Evil Twin)",
                "text": "แฮกเกอร์อาจตั้งชื่อ Wi-Fi เลียนแบบสถานที่ เช่น 'Cafe_Free_WiFi' เพื่อหลอกให้คุณเชื่อมต่อ แล้วดักจับข้อมูลทั้งหมดที่วิ่งผ่าน",
                "callout": {
                    "type": "warning",
                    "title": "⚠️ ข้อห้ามสำคัญ",
                    "text": "อย่าทำธุรกรรมทางการเงินหรือกรอกรหัสผ่านสำคัญเมื่อเชื่อมต่อ Wi-Fi สาธารณะ",
                },
            },
            {
                "title": "2. วิธีป้องกันตัวเมื่อจำเป็นต้องใช้งาน",
                "text": "หากจำเป็นต้องใช้ ให้เชื่อมต่อผ่าน VPN (Virtual Private Network) เสมอ เพื่อทำการเข้ารหัสข้อมูลตั้งแต่เครื่องของคุณจนถึงปลายทาง",
            },
        ],
        "key_takeaways": [
            "ปิดการตั้งค่า Auto-Connect Wi-Fi ในโทรศัพท์",
            "เปิดใช้งาน VPN ทุกครั้งที่ต่อเน็ตสาธารณะ",
            "ใช้ Personal Hotspot จากมือถือตัวเองดีที่สุด",
        ],
    },
    {
        "id": 7,
        "title": "Deepfake: ภัยเงียบจาก AI ปลอมภาพและเสียง",
        "category": "Scams",
        "author": "AI Watch",
        "author_role": "AI Research Ethics",
        "date": "7 ก.พ. 2026",
        "read_time": "4 นาที",
        "desc": "เมื่อรูปภาพและคลิปเสียงไม่สามารถเชื่อได้อีกต่อไป",
        "image": "https://images.unsplash.com/photo-1677442136019-21780ecad995?auto=format&fit=crop&q=80&w=1200",
        "summary": "เทคโนโลยี AI ในปัจจุบันสามารถเลียนแบบใบหน้าและเสียงของบุคคลได้อย่างแนบเนียน คนร้ายจึงนำมาใช้ปลอมเป็นญาติหรือผู้บริหารเพื่อหลอกให้โอนเงิน",
        "sections": [
            {
                "title": "1. วิธีสังเกตวิดีโอ Deepfake",
                "text": "สังเกตการกระพริบตาที่ไม่เป็นธรรมชาติ ขอบใบหน้าหรือเส้นผมที่ดูเบลอๆ หรือจังหวะการขยับปากที่ไม่ตรงกับเสียงพูด",
                "image": "https://images.unsplash.com/photo-1618060932014-4deda4932554?auto=format&fit=crop&q=80&w=1000",
                "caption": "เทคโนโลยี AI เจนเนอเรทีฟสามารถสร้างใบหน้าคนปลอมได้อย่างสมบูรณ์",
            },
            {
                "title": "2. วิธีรับมือเมื่อสงสัยว่าโดนปลอมเสียงหรือหน้า",
                "text": "ลองตั้งคำถามส่วนตัวที่มีเพียงคุณกับเขาเท่านั้นที่รู้ หรือขอให้ผู้พูดหันหน้าข้างเพื่อสังเกตความผิดปกติของภาพ AI",
                "callout": {
                    "type": "tip",
                    "title": "💡 ยืนยันผ่านช่องทางอื่น",
                    "text": "โทรกลับหาบุคคลนั้นโดยตรงผ่านเบอร์โทรศัพท์ปกติ แทนการคุยผ่านแอปพลิเคชันที่ติดต่อมา",
                },
            },
        ],
        "key_takeaways": [
            "อย่าปักใจเชื่อวิดีโอคอลหรือคลิปเสียงขอยืมเงินทันที",
            "สังเกตรายละเอียดรอบใบหน้า แสง และเงา",
            "ตั้งรหัสลับเฉพาะครอบครัวสำหรับยืนยันตัวตนกรณีฉุกเฉิน",
        ],
    },
    {
        "id": 8,
        "title": "วิธีเช็กว่าข้อมูลหลุดไปใน Dark Web หรือไม่",
        "category": "Privacy",
        "author": "PrivacyFirst",
        "author_role": "Data Privacy Consultant",
        "date": "8 ก.พ. 2026",
        "read_time": "3 นาที",
        "desc": "ตรวจสอบและป้องกันเมื่ออีเมลหรือรหัสผ่านถูกนำไปซื้อขายในตลาดมืด",
        "image": "https://images.unsplash.com/photo-1558494949-ef010cbdcc51?auto=format&fit=crop&q=80&w=1200",
        "summary": "เมื่อเว็บไซต์ที่คุณใช้งานถูกแฮก ข้อมูลบัญชีและรหัสผ่านมักถูกนำไปรวบรวมเพื่อขายใน Dark Web ทำให้อาจโดนสวมรอยเข้าใช้งานในบริการอื่นได้",
        "sections": [
            {
                "title": "1. ตรวจสอบข้อมูลรั่วไหลได้อย่างไร?",
                "text": "สามารถใช้บริการตรวจสอบที่น่าเชื่อถือ เช่น 'Have I Been Pwned' หรือฟีเจอร์ Password Checkup ใน Google Chrome เพื่อเช็กว่าอีเมลของคุณอยู่ในฐานข้อมูลที่หลุดหรือไม่",
                "callout": {
                    "type": "warning",
                    "title": "🚨 สิ่งที่ต้องทำทันทีหากข้อมูลหลุด",
                    "text": "1. เปลี่ยนรหัสผ่านของบัญชีนั้นๆ ทันที \n2. เปลี่ยนรหัสผ่านของเว็บอื่นที่ใช้รหัสเดียวกัน \n3. เปิดใช้งาน 2FA ทันที",
                },
            }
        ],
        "key_takeaways": [
            "หมั่น ตรวจสอบประวัติการรั่วไหลของอีเมลตนเอง",
            "เปิดแจ้งเตือนการเข้าสู่ระบบจากอุปกรณ์ใหม่",
            "เปลี่ยนรหัสผ่านเป็นประจำหากสงสัยว่ามีความเสี่ยง",
        ],
    },
    {
        "id": 9,
        "title": "แอปดูดเงินทำงานอย่างไร? และวิธีป้องกันบนสมาร์ตโฟน",
        "category": "Malware",
        "author": "Tech Insider",
        "author_role": "Mobile Security Researcher",
        "date": "10 ก.พ. 2026",
        "read_time": "5 นาที",
        "desc": "เจาะลึกภัยร้ายจากการหลอกให้ติดตั้งแอป APK นอก Store และสิทธิ์ Accessibility",
        "image": "https://images.unsplash.com/photo-1512428559087-560fa5ceab42?auto=format&fit=crop&q=80&w=1200",
        "summary": "แอปดูดเงินไม่ได้แฮกจากระบบธนาคารโดยตรง แต่ใช้วิธีหลอกให้เหยื่อติดตั้งแอปแฝงมัลแวร์ แล้วขอสิทธิ์ Accessibility Service เพื่อเข้าควบคุมหน้าจอมือถือของเหยื่อ",
        "sections": [
            {
                "title": "1. ขั้นตอนการหลอกลวงของมัลแวร์",
                "text": "1. ส่ง SMS หรือโทรหลอกว่าเป็นเจ้าหน้าที่ \n2. ให้แอดไลน์แล้วส่งลิงก์ดาวน์โหลดไฟล์ .APK \n3. หลอกให้เปิดสิทธิ์การเข้าถึง (Accessibility Services) \n4. หน้าจอโทรศัพท์จะค้างหรือดับไป ในขณะที่คนร้ายกำลังโอนเงินออก",
                "callout": {
                    "type": "warning",
                    "title": "⛔ ข้อห้ามเด็ดขาด",
                    "text": "อย่าดาวน์โหลดหรือติดตั้งไฟล์แอปพลิเคชันที่มีนามสกุล .APK จากลิงก์ในไลน์หรือเว็บนอก Play Store / App Store เด็ดขาด",
                },
            }
        ],
        "key_takeaways": [
            "ดาวน์โหลดแอปพลิเคชันจาก Official Store เท่านั้น",
            "ไม่เปิดสิทธิ์ Accessibility Service ให้แอปที่ไม่รู้จัก",
            "หากโทรศัพท์ค้างและสงสัยโดนควบคุม ให้รีบกดปิดเครื่องหรือตัดสัญญาณเน็ตทันที",
        ],
    },
    {
        "id": 10,
        "title": "ทำความรู้จักกับ Social Engineering (จิตวิทยาการหลอกลวง)",
        "category": "Scams",
        "author": "PsyCyber",
        "author_role": "Cyberpsychologist",
        "date": "12 ก.พ. 2026",
        "read_time": "4 นาที",
        "desc": "เข้าใจศิลปะการเจาะระบบผ่านจุดอ่อนที่สุด นั่นคือ 'ความรู้สึกของมนุษย์'",
        "image": "https://images.unsplash.com/photo-1551836022-d5d88e9218df?auto=format&fit=crop&q=80&w=1200",
        "summary": "Social Engineering ไม่ได้ใช้การเขียนโค้ดที่ซับซ้อน แต่เป็นการเล่นกับอารมณ์ของมนุษย์ เช่น ความกลัว ความโลภ ความเห็นใจ หรือความเร่งรีบ เพื่อให้เหยื่อยอมส่งมอบข้อมูลสำคัญด้วยตนเอง",
        "sections": [
            {
                "title": "1. อารมณ์ที่คนร้ายมักนำมาใช้หลอกลวง",
                "text": "• **ความเร่งด่วน:** 'บัญชีของคุณจะถูกปิดภายใน 2 ชั่วโมง!' \n• **ความโลภ:** 'คุณคือผู้โชคดีได้รับรางวัลใหญ่ กดรับเลย!' \n• **ความกลัว:** 'คุณมีส่วนเกี่ยวข้องกับคดีฟอกเงิน!'",
                "callout": {
                    "type": "tip",
                    "title": "💡 วิธีแก้ทาง Social Engineering",
                    "text": "จำไว้ว่า 'เมื่อไหร่ก็ตามที่มีคนมาทำให้เราตกใจ ดีใจสุดขีด หรือเร่งรีบ ให้หยุดคิด 10 วินาที' ก่อนทำรายการเสมอ",
                },
            }
        ],
        "key_takeaways": [
            "มีสติทุกครั้งที่ได้รับข้อความกระตุ้นอารมณ์",
            "อย่าให้ข้อมูลส่วนตัวกับคนที่เพิ่งรู้จักทางออนไลน์",
            "ตรวจสอบข้อมูลกับแหล่งข่าวอย่างเป็นทางการเสมอ",
        ],
    },
    {
        "id": 11,
        "title": "ช้อปปิ้งออนไลน์อย่างไรให้ปลอดภัย ไม่โดนร้านค้าปลอมโกง",
        "category": "Privacy",
        "author": "ShopSafe",
        "author_role": "E-Commerce Analyst",
        "date": "14 ก.พ. 2026",
        "read_time": "3 นาที",
        "desc": "ข้อควรรู้ก่อนโอนเงินซื้อของออนไลน์ ป้องกันเพจปลอมและการเชิดเงินหนี",
        "image": "https://images.unsplash.com/photo-1563013544-824ae1b704d3?auto=format&fit=crop&q=80&w=1200",
        "summary": "การซื้อของออนไลน์สะดวกสบาย แต่ก็มาพร้อมมิจฉาชีพที่สร้างเพจปลอมขึ้นมาหลอกขายสินค้า โดยเฉพาะสินค้าที่มีราคาถูกกว่าท้องตลาดอย่างผิดปกติ",
        "sections": [
            {
                "title": "1. เช็กความน่าเชื่อถือของเพจและร้านค้า",
                "text": "เช็กประวัติการเปลี่ยนชื่อเพจ จำนวนผู้ติดตาม วันที่สร้างเพจ และลองเอาชื่อบัญชีธนาคารไปค้นหาในเว็บ Blacklistseller ก่อนโอนเงินทุกครั้ง",
                "callout": {
                    "type": "warning",
                    "title": "🛒 ตัวเลือกการชำระเงินที่ปลอดภัย",
                    "text": "แนะนำให้เลือกชำระเงินผ่านแพลตฟอร์มกลาง (เช่น Shopee, Lazada) ที่มีระบบการคุ้มครองผู้ซื้อ หรือเลือกบริการเก็บเงินปลายทาง",
                },
            }
        ],
        "key_takeaways": [
            "ระวังสินค้าราคาถูกกว่าความเป็นจริงมากๆ",
            "นำชื่อ-นามสกุล และเลขบัญชีผู้ขายไปค้นหาประวัติการโกงก่อนโอน",
            "เลี่ยงการซื้อขายผ่านการโอนตรงนอกแพลตฟอร์ม",
        ],
    },
    {
        "id": 12,
        "title": "จัดการ Cookie ใน Browser เพื่อความเป็นส่วนตัวสูงสุด",
        "category": "Privacy",
        "author": "DataGuard",
        "author_role": "Privacy Engineer",
        "date": "15 ก.พ. 2026",
        "read_time": "3 นาที",
        "desc": "เข้าใจการทำงานของไฟล์คุกกี้ และเทคนิคการลบเพื่อไม่ให้ถูกดักติดตามพฤติกรรม",
        "image": "https://images.unsplash.com/photo-1516321497487-e288fb19713f?auto=format&fit=crop&q=80&w=1200",
        "summary": "Cookies คือไฟล์ขนาดเล็กที่เว็บไซต์บันทึกไว้ในเครื่องของคุณ แม้จะมีประโยชน์ในการจดจำการเข้าสู่ระบบ แต่ Third-Party Cookies ก็ถูกนำมาใช้ติดตามพฤติกรรมของคุณเพื่อการโฆษณาได้เช่นกัน",
        "sections": [
            {
                "title": "1. วิธีการเคลียร์ Cookie และ Cache สม่ำเสมอ",
                "text": "การล้าง Cookie และท่องเว็บผ่านโหมด Incognito หรือใช้อุปกรณ์เสริมเพื่อความเป็นส่วนตัว จะช่วยลดโอกาสที่ข้อมูลเซสชันการเข้าสู่ระบบของคุณจะถูกขโมยผ่าน Session Hijacking ได้",
                "callout": {
                    "type": "tip",
                    "title": "💡 เบราว์เซอร์เน้นความเป็นส่วนตัว",
                    "text": "พิจารณาใช้งานเว็บเบราว์เซอร์ที่เน้น Privacy เป็นหลัก เช่น Brave หรือ Firefox เพื่อบล็อก Tracker อัตโนมัติ",
                },
            }
        ],
        "key_takeaways": [
            "เลือกกดยอมรับเฉพาะ Cookie ที่จำเป็น (Essential Cookies) บนเว็บไซต์",
            "หมั่นล้างประวัติการท่องเว็บและคุกกี้เป็นประจำ",
            "เปิดใช้งานฟังก์ชัน Block Third-Party Cookies ในเบราว์เซอร์",
        ],
    },
]


import re

_easyocr_reader = None

def get_easyocr_reader():
    from detector.ocr_pipeline import get_ocr_reader
    return get_ocr_reader()


def extract_urls_from_text(text):
    if not text:
        return []
        
    tlds = r'com|co\.th|net|org|in\.th|info|biz|cc|xyz|online|top|me|link|site|app|live|vip|store|shop|icu|club|io|dev|ai|ac\.th|go\.th|or\.th|edu|gov|th|asia|mobi|tech|pro|cloud|space|fun|cyou|cfd|click|ly|to|gl|is|gg|page|tv|la|lol|su|dev|mom'
    exts = r'exe|dll|msi|apk|zip|rar|7z|pdf|doc|docx|xls|xlsx|bat|cmd|sh|bin|elf|arm7|scr|jar|php|html|htm|asp|aspx|jsp|tar|gz|ps1|m'
    
    # 1. แปลง comma ใน IP Address ที่ OCR อ่านเพี้ยน: เช่น 105,186.250,56:38301 -> 105.186.250.56:38301
    cleaned = re.sub(r'(\d{1,3})\s*,\s*(\d{1,3})', r'\1.\2', text)
    
    # 2. ค้นหากลุ่มข้อความที่น่าจะเป็น URL
    raw_blocks = re.findall(
        r'(?:h\s*t\s*t\s*p\s*s?\s*[:;/]|www\.|(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[a-zA-Z0-9_-]+\.(?:' + tlds + r'))[^\u0E00-\u0E7F\n\r"\'<>]+',
        cleaned,
        flags=re.IGNORECASE
    )
    if not raw_blocks:
        raw_blocks = [cleaned]

    expanded_blocks = []
    for rb in raw_blocks:
        parts = re.split(
            r'\s+(?=(?:h\s*t\s*t\s*p\s*s?\s*[:;/]|www\.|(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[a-zA-Z0-9_-]+\.(?:' + tlds + r')))',
            rb,
            flags=re.IGNORECASE,
        )
        for p in parts:
            p = p.strip()
            if p:
                expanded_blocks.append(p)
    raw_blocks = expanded_blocks

    url_candidates = []
    
    for raw_block in raw_blocks:
        raw_block = raw_block.strip().rstrip(".,;!?)\"'>}]#:")
        if not raw_block:
            continue
            
        # ปรับโพรโทคอลให้สมบูรณ์
        block = re.sub(
            r'^h\s*t\s*t\s*p\s*(s?)\s*[:;]?\s*(?:/\s*/|/)?\s*',
            lambda g: 'https://' if g.group(1) else 'http://',
            raw_block,
            flags=re.IGNORECASE,
        )
        if not block.lower().startswith(('http://', 'https://')):
            if block.lower().startswith('www.'):
                block = 'https://' + block
            elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', block) or re.search(r'\.(?:' + tlds + r')', block, re.I):
                block = 'http://' + block
            else:
                continue
                
        scheme, _, rest = block.partition('://')
        rest = rest.lstrip(':/')
        if not rest:
            continue
            
        # แยก Domain และ Path
        if '/' in rest:
            domain_part, _, path_part = rest.partition('/')
            path_part = '/' + path_part
        else:
            domain_part = rest
            path_part = ''
            
        port_part = ''
        if ':' in domain_part:
            domain_part, _, port_part = domain_part.partition(':')
            port_match = re.match(r'^\s*(\d{2,5})', port_part)
            if port_match:
                port_part = ':' + port_match.group(1)
            else:
                port_part = ''
                
        # ในส่วนโดเมน: ช่องว่าง จุลภาค หรือเซมิโคลอน -> จุด '.'
        domain_part = re.sub(r'[\s,;]+', '.', domain_part).strip('.')
        domain_part = re.sub(r'\.+', '.', domain_part)
        
        # ในส่วน Path:
        if path_part:
            path_part = re.sub(r'\s*([.:/?=&%#_~-])\s*', r'\1', path_part)
            path_part = re.sub(rf'/([^\s/]+)\s+({exts})(?=[\s?#]|$)', r'/\1.\2', path_part, flags=re.IGNORECASE)
            path_part = re.sub(rf'\s+({exts})(?=[\s?#]|$)', r'.\1', path_part, flags=re.IGNORECASE)
            
            # ตัดจบคอลัมน์อื่นในตาราง (เช่น เมื่อเจอนามสกุลไฟล์แล้วตามด้วยช่องว่าง)
            ext_trunc = re.search(rf'^(.*?\.({exts}))(?:\s+.*|$)', path_part, flags=re.IGNORECASE)
            if ext_trunc:
                path_part = ext_trunc.group(1)
            else:
                query_trunc = re.search(r'^(.*?[?=&][^\s]*)(?:\s+.*|$)', path_part)
                if query_trunc:
                    path_part = query_trunc.group(1)
                else:
                    path_part = path_part.split()[0] if path_part else ''
                    
            path_part = re.sub(r'\s*/\s*', '/', path_part)
            path_part = re.sub(r'\s+', '_', path_part)
            
        full_url = f"{scheme}://{domain_part}{port_part}{path_part}".rstrip(".,;!?)\"'>}]#:")
        
        if ('.' in domain_part or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain_part)) and len(domain_part) >= 4:
            if full_url not in url_candidates:
                url_candidates.append(full_url)
                
    return url_candidates


MAX_QR_IMAGE_BYTES = 10 * 1024 * 1024


def decode_image_url_or_qr(uploaded_file):
    if not (uploaded_file.content_type or "").startswith("image/"):
        raise ValueError("รองรับเฉพาะไฟล์รูปภาพ (เช่น .jpg, .png, .webp)")
    if uploaded_file.size > MAX_QR_IMAGE_BYTES:
        raise ValueError("รูปภาพต้องมีขนาดไม่เกิน 10 MB")

    file_bytes = np.frombuffer(uploaded_file.read(), dtype=np.uint8)
    image = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("ไม่สามารถเปิดไฟล์รูปภาพได้")

    # 1. ตรวจสอบ QR Code ด้วย OpenCV
    detector = cv2.QRCodeDetector()
    for scale in (1, 2, 4):
        scaled = (
            image
            if scale == 1
            else cv2.resize(
                image, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST
            )
        )
        for border in (0, 30, 80):
            candidate = (
                scaled
                if border == 0
                else cv2.copyMakeBorder(
                    scaled,
                    border,
                    border,
                    border,
                    border,
                    cv2.BORDER_CONSTANT,
                    value=[255, 255, 255],
                )
            )
            decoded, _, _ = detector.detectAndDecode(candidate)
            if decoded and decoded.strip():
                return decoded.strip(), "image_qr"
            success, decoded_items, _, _ = detector.detectAndDecodeMulti(candidate)
            if success:
                first = next(
                    (item.strip() for item in decoded_items if item.strip()), ""
                )
                if first:
                    return first, "image_qr"

    # 2. Fallback: OCR ข้อความจากรูปภาพ (Enhanced 5-layer OCR Pipeline)
    try:
        from detector.ocr_pipeline import extract_urls_from_image_pipeline
        pipeline_urls = extract_urls_from_image_pipeline(image)
        if pipeline_urls:
            print(f"[OCR Pipeline] สกัดพบ {len(pipeline_urls)} URL: {pipeline_urls}")
            return (pipeline_urls if len(pipeline_urls) > 1 else pipeline_urls[0]), "image_ocr"
    except Exception as e:
        print(f"[OCR Pipeline Warning] OCR Pipeline พลาด ขยับไปใช้ fallback: {e}")

    try:
        reader = get_easyocr_reader()
        # Pass 1: รูปภาพต้นฉบับ ปรับ threshold ให้อ่านจุดและเครื่องหมายวรรคตอนได้ละเอียดขึ้น
        try:
            ocr_results = reader.readtext(
                image,
                detail=0,
                text_threshold=0.5,
                low_text=0.3,
                mag_ratio=1.2,
            )
        except TypeError:
            ocr_results = reader.readtext(image, detail=0)
        full_text = " ".join(ocr_results)
        print(f"[EasyOCR Pass 1] ข้อความที่อ่านได้จากภาพ: '{full_text}'")
        urls = extract_urls_from_text(full_text)
        if urls:
            print(f"[EasyOCR] สกัดพบ URL: {urls[0]}")
            return (urls if len(urls) > 1 else urls[0]), "image_ocr"

        # Pass 2: Super-Resolution (ขยายภาพ 2.5x ด้วย Lanczos4) + Grayscale + Sharpening
        h, w = image.shape[:2]
        scale = max(2.0, min(3.5, 2000.0 / max(h, w)))
        upscaled = cv2.resize(image, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_LANCZOS4)
        gray = cv2.cvtColor(upscaled, cv2.COLOR_BGR2GRAY)
        sharpen_kernel = np.array([[-1, -1, -1], [-1, 9, -1], [-1, -1, -1]])
        enhanced = cv2.filter2D(gray, -1, sharpen_kernel)

        try:
            ocr_results_2 = reader.readtext(
                enhanced,
                detail=0,
                text_threshold=0.4,
                low_text=0.3,
                link_threshold=0.6,
                mag_ratio=1.5,
            )
        except TypeError:
            ocr_results_2 = reader.readtext(enhanced, detail=0)
        full_text_2 = " ".join(ocr_results_2)
        print(f"[EasyOCR Pass 2] ข้อความที่อ่านได้ (Enhanced): '{full_text_2}'")
        urls_2 = extract_urls_from_text(full_text_2)
        if urls_2:
            print(f"[EasyOCR] สกัดพบ URL (จาก Pass 2): {urls_2[0]}")
            return (urls_2 if len(urls_2) > 1 else urls_2[0]), "image_ocr"
    except Exception as e:
        print(f"[EasyOCR Error] เกิดข้อผิดพลาดขณะรัน OCR: {e}")

    raise ValueError("ไม่พบ QR Code หรือข้อความ URL ในรูปภาพที่อัปโหลด")


def decode_qr_image(uploaded_file):
    result, _ = decode_image_url_or_qr(uploaded_file)
    if isinstance(result, list):
        return result[0] if result else ""
    return result


def current_user(request):
    if not request.user.is_authenticated:
        return None
    return {
        "name": request.user.get_full_name() or request.user.username,
        "email": request.user.email,
        "role": "ADMIN" if request.user.is_staff else "USER",
    }


def home(request):
    pending_urls = request.session.get("pending_ocr_urls", [])
    return render(request, "home.html", {
        "current_user": current_user(request),
        "pending_ocr_urls": pending_urls,
    })


def login_view(request):
    error = ""
    if request.method == "POST":
        email = request.POST.get("email", "").strip().lower()
        password = request.POST.get("password", "")
        user = authenticate(request, username=email, password=password)
        if user is not None and user.is_active:
            login(request, user)
            return redirect("admin" if user.is_staff else "dashboard")
        error = "อีเมลหรือรหัสผ่านไม่ถูกต้อง"
    return render(
        request, "login.html", {"error": error, "current_user": current_user(request)}
    )


def logout_view(request):
    logout(request)
    return redirect("home")


def register_view(request):
    success = False
    error = ""
    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        email = request.POST.get("email", "").strip().lower()
        password = request.POST.get("password", "")
        password_confirm = request.POST.get("password_confirm", "")
        if not name or not email or not password:
            error = "กรุณากรอกข้อมูลให้ครบถ้วน"
        elif password != password_confirm:
            error = "รหัสผ่านและการยืนยันรหัสผ่านไม่ตรงกัน"
        elif len(password) < 8:
            error = "รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร"
        elif User.objects.filter(username=email).exists():
            error = "อีเมลนี้ถูกใช้งานแล้ว"
        else:
            first_name, _, last_name = name.partition(" ")
            User.objects.create_user(
                username=email,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
            )
            messages.success(request, "สมัครสมาชิกสำเร็จ กรุณาเข้าสู่ระบบ")
            return redirect("login")
    return render(
        request,
        "register.html",
        {"error": error, "current_user": current_user(request)},
    )


def forgot_password_view(request):
    success = False
    email = ""
    if request.method == "POST":
        email = request.POST.get("email", "")
        success = True
    return render(
        request,
        "forgot_password.html",
        {"success": success, "email": email, "current_user": current_user(request)},
    )


def statistics_report_context(request):
    period = request.GET.get("period", "30")
    if period not in {"7", "30", "all"}:
        period = "30"
    now = timezone.now()
    period_labels = {"7": "7 วันล่าสุด", "30": "30 วันล่าสุด", "all": "ข้อมูลทั้งหมด"}
    scans = ScanHistory.objects.all()
    if request.user.is_authenticated and not request.user.is_staff:
        scans = scans.filter(user=request.user)
    if period == "7":
        scans = scans.filter(timestamp__gte=now - timedelta(days=7))
    elif period == "30":
        scans = scans.filter(timestamp__gte=now - timedelta(days=30))

    if period == "7":
        dates = [timezone.localdate() - timedelta(days=i) for i in range(6, -1, -1)]
        trend_labels = [date.strftime("%d/%m") for date in dates]
        trend_values = [scans.filter(timestamp__date=date).count() for date in dates]
    elif period == "30":
        trend_labels, trend_values = [], []
        for index in range(4, 0, -1):
            start = now - timedelta(days=index * 7)
            end = now - timedelta(days=(index - 1) * 7)
            trend_labels.append(f"สัปดาห์ {5 - index}")
            trend_values.append(scans.filter(timestamp__gte=start, timestamp__lt=end).count())
    else:
        trend_labels, trend_values = [], []
        today = timezone.localdate()
        for offset in range(5, -1, -1):
            month_index = today.year * 12 + today.month - 1 - offset
            year, month_zero = divmod(month_index, 12)
            month = month_zero + 1
            trend_labels.append(f"{month:02d}/{year}")
            trend_values.append(scans.filter(timestamp__year=year, timestamp__month=month).count())

    users = User.objects.filter(is_staff=False, is_active=True)
    if request.user.is_authenticated and not request.user.is_staff:
        users = users.filter(pk=request.user.pk)
    sample_users = []
    for user in users:
        user_scans = scans.filter(user=user)
        latest = user_scans.order_by("-timestamp").first()
        sample_users.append({
            "name": user.get_full_name() or user.username,
            "email": user.email,
            "total": user_scans.count(),
            "safe_exact": user_scans.filter(status="safe").count(),
            "mostly_safe": user_scans.filter(status="mostly_safe").count(),
            "safe": user_scans.filter(status__in=["safe", "mostly_safe"]).count(),
            "warning": user_scans.filter(status="warning").count(),
            "mostly_danger": user_scans.filter(status="mostly_danger").count(),
            "danger_exact": user_scans.filter(status="danger").count(),
            "danger": user_scans.filter(status__in=["danger", "mostly_danger"]).count(),
            "last_scan": timezone.localtime(latest.timestamp).strftime("%d/%m/%Y %H:%M") if latest else "-",
        })
    active_user = current_user(request)
    total_scans = sum(item["total"] for item in sample_users)
    safe_count = sum(item["safe"] for item in sample_users)
    warning_count = sum(item["warning"] for item in sample_users)
    danger_count = sum(item["danger"] for item in sample_users)
    safe_exact_count = sum(item["safe_exact"] for item in sample_users)
    mostly_safe_count = sum(item["mostly_safe"] for item in sample_users)
    mostly_danger_count = sum(item["mostly_danger"] for item in sample_users)
    danger_exact_count = sum(item["danger_exact"] for item in sample_users)

    is_admin_report = bool(request.user.is_authenticated and request.user.is_staff)
    user_display_name = (active_user or {}).get("name", "ผู้ใช้งานระบบ")
    user_email = (active_user or {}).get("email", "")
    if is_admin_report:
        prepared_by = "ผู้ดูแลระบบ PhishWise"
        report_number = f"PW-STAT-{timezone.now().strftime('%Y-%m')}"
    else:
        prepared_by = f"{user_display_name} ({user_email})" if user_email else user_display_name
        report_number = f"PW-USR-{timezone.now().strftime('%Y-%m')}"

    five_levels = [
        {
            "key": "safe",
            "name": "ปลอดภัย",
            "color": "#059669",
            "score_range": "0 - 20",
            "count": safe_exact_count,
            "percentage": round(safe_exact_count * 100 / total_scans, 1) if total_scans else 0,
            "action": "ใช้งานได้ แต่ควรตรวจสอบชื่อโดเมน",
        },
        {
            "key": "mostly_safe",
            "name": "ค่อนข้างปลอดภัย",
            "color": "#0d9488",
            "score_range": "21 - 40",
            "count": mostly_safe_count,
            "percentage": round(mostly_safe_count * 100 / total_scans, 1) if total_scans else 0,
            "action": "ตรวจสอบแหล่งที่มาก่อนกรอกข้อมูล",
        },
        {
            "key": "warning",
            "name": "ควรระวัง",
            "color": "#d97706",
            "score_range": "41 - 60",
            "count": warning_count,
            "percentage": round(warning_count * 100 / total_scans, 1) if total_scans else 0,
            "action": "หลีกเลี่ยงการกรอกข้อมูลสำคัญ",
        },
        {
            "key": "mostly_danger",
            "name": "มีแนวโน้มอันตราย",
            "color": "#ea580c",
            "score_range": "61 - 80",
            "count": mostly_danger_count,
            "percentage": round(mostly_danger_count * 100 / total_scans, 1) if total_scans else 0,
            "action": "ไม่แนะนำให้เปิดลิงก์หรือดาวน์โหลดไฟล์",
        },
        {
            "key": "danger",
            "name": "อันตราย",
            "color": "#e11d48",
            "score_range": "81 - 100",
            "count": danger_exact_count,
            "percentage": round(danger_exact_count * 100 / total_scans, 1) if total_scans else 0,
            "action": "หยุดใช้งานและอย่าดาวน์โหลดไฟล์",
        },
    ]

    return {
        "current_user": active_user,
        "is_admin_report": is_admin_report,
        "user_display_name": user_display_name,
        "user_email": user_email,
        "prepared_by": prepared_by,
        "report_number": report_number,
        "report_date": timezone.localtime().strftime("%d/%m/%Y %H:%M"),
        "report_period": period_labels[period],
        "selected_period": period,
        "selected_period_label": period_labels[period],
        "total_users": len(sample_users),
        "total_scans": total_scans,
        "safe_count": safe_count,
        "warning_count": warning_count,
        "danger_count": danger_count,
        "safe_exact_count": safe_exact_count,
        "mostly_safe_count": mostly_safe_count,
        "mostly_danger_count": mostly_danger_count,
        "danger_exact_count": danger_exact_count,
        "warning_and_danger_count": warning_count + danger_count,
        "safe_percentage": round(safe_count * 100 / total_scans) if total_scans else 0,
        "warning_percentage": round(warning_count * 100 / total_scans) if total_scans else 0,
        "danger_percentage": round(danger_count * 100 / total_scans) if total_scans else 0,
        "sample_users": sample_users,
        "five_levels": five_levels,
        "trend_labels": trend_labels,
        "trend_values": trend_values,
        "trend_max": max(trend_values or [0]),
        "source_labels": ["ลิงก์โดยตรง", "QR Code จากกล้อง", "รูปภาพ QR Code", "OCR ข้อความจากภาพ"],
        "source_values": [
            scans.filter(source_type="direct_url").count(),
            scans.filter(source_type="camera_qr").count(),
            scans.filter(source_type="image_qr").count(),
            scans.filter(source_type="image_ocr").count(),
        ],
    }


@login_required(login_url="login")
def dashboard_view(request):
    context = statistics_report_context(request)
    return render(request, "dashboard.html", context)


@login_required(login_url="login")
def statistics_pdf_view(request):
    from .statistics_weasyprint import build_statistics_pdf

    pdf_bytes = build_statistics_pdf(statistics_report_context(request))
    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    response["Content-Disposition"] = (
        'attachment; filename="phishwise-statistics-report.pdf"'
    )
    return response


@staff_member_required(login_url="login")
def admin_view(request):
    users = User.objects.filter(is_staff=False).order_by("-date_joined")
    scans = ScanHistory.objects.all()
    reports = SuspiciousSiteReport.objects.select_related("user").order_by("-created_at")
    domains = DomainStatistic.objects.all().order_by("-scan_count")
    db_articles = KnowledgeArticle.objects.all().order_by("order", "-created_at")

    safe_count = scans.filter(status="safe").count()
    mostly_safe_count = scans.filter(status="mostly_safe").count()
    warning_count = scans.filter(status="warning").count()
    mostly_danger_count = scans.filter(status="mostly_danger").count()
    danger_count = scans.filter(status="danger").count()

    articles_dict = {}
    for art in db_articles:
        articles_dict[art.id] = {
            "id": art.id,
            "title": art.title,
            "category": art.category,
            "author": art.author,
            "author_role": art.author_role,
            "date": art.date,
            "read_time": art.read_time,
            "desc": art.desc,
            "image": art.image,
            "summary": art.summary,
            "status": art.status,
            "content_markdown": art.content_markdown or "",
            "content_html": art.content_html or "",
            "sections": art.sections,
            "key_takeaways": art.key_takeaways,
        }
    articles_json_data = json.dumps(articles_dict, ensure_ascii=False)

    return render(
        request,
        "admin.html",
        {
            "current_user": current_user(request),
            "hide_navbar": True,
            "users": users,
            "total_users": users.count(),
            "active_users": users.filter(is_active=True).count(),
            "banned_users": users.filter(is_active=False).count(),
            "total_scans": scans.count(),
            "danger_scans": danger_count + mostly_danger_count,
            "safe_count": safe_count,
            "mostly_safe_count": mostly_safe_count,
            "warning_count": warning_count,
            "mostly_danger_count": mostly_danger_count,
            "danger_count": danger_count,
            "recent_scans": scans.select_related("user").order_by("-timestamp")[:15],
            "pending_reports": reports.filter(status=SuspiciousSiteReport.PENDING)[:50],
            "all_reports": reports,
            "pending_reports_count": reports.filter(status=SuspiciousSiteReport.PENDING).count(),
            "approved_reports_count": reports.filter(status=SuspiciousSiteReport.APPROVED).count(),
            "rejected_reports_count": reports.filter(status=SuspiciousSiteReport.REJECTED).count(),
            "domain_statistics": domains,
            "total_domains": domains.count(),
            "db_articles": db_articles,
            "total_articles": db_articles.count(),
            "published_articles_count": db_articles.filter(status=KnowledgeArticle.STATUS_PUBLISHED).count(),
            "draft_articles_count": db_articles.filter(status=KnowledgeArticle.STATUS_DRAFT).count(),
            "articles_json_data": articles_json_data,
        },
    )


@require_POST
@staff_member_required(login_url="login")
def admin_toggle_user(request, user_id):
    user = User.objects.filter(pk=user_id, is_staff=False).first()
    if user:
        user.is_active = not user.is_active
        user.save(update_fields=["is_active"])
    return redirect(f"{reverse('admin')}#users")


def analysis_report_context(request):
    session_result = request.session.get("last_scan_result") or {}
    latest_scan = ScanHistory.objects.order_by("-timestamp").first()

    source = session_result or (
        {
            "url": latest_scan.url,
            "score": latest_scan.score,
            "status": latest_scan.status,
            "ai_risk_score": latest_scan.ai_risk_score,
            "ssl_title": latest_scan.ssl_title,
            "ssl_sub": latest_scan.ssl_sub,
            "domain_age": latest_scan.domain_age,
            "domain_sub": latest_scan.domain_sub,
            "is_blacklisted": latest_scan.is_blacklisted,
            "google_safe": latest_scan.google_safe,
            "location": latest_scan.location,
            "has_redirection": latest_scan.has_redirection,
        }
        if latest_scan
        else {}
    )

    score = int(source.get("score", 0) or 0)
    ai_risk_score = int(source.get("ai_risk_score", 100 - score) or (100 - score))

    level = classify_risk(ai_risk_score)
    status_label = level["label"]
    status_key = level["key"]

    if status_key == "safe":
        theme_color = "#10b981"
        status_badge_class = "bg-emerald-100 text-emerald-700 border-emerald-200"
        status_text_class = "text-emerald-600"
        risk_bar_class = "bg-emerald-500"
    elif status_key == "mostly_safe":
        theme_color = "#0d9488"
        status_badge_class = "bg-teal-100 text-teal-700 border-teal-200"
        status_text_class = "text-teal-600"
        risk_bar_class = "bg-teal-500"
    elif status_key == "warning":
        theme_color = "#f59e0b"
        status_badge_class = "bg-amber-100 text-amber-700 border-amber-200"
        status_text_class = "text-amber-500"
        risk_bar_class = "bg-amber-500"
    elif status_key == "mostly_danger":
        theme_color = "#ea580c"
        status_badge_class = "bg-orange-100 text-orange-700 border-orange-200"
        status_text_class = "text-orange-600"
        risk_bar_class = "bg-orange-600"
    else:
        theme_color = "#e11d48"
        status_badge_class = "bg-rose-100 text-rose-700 border-rose-200"
        status_text_class = "text-rose-600"
        risk_bar_class = "bg-rose-600"

    ssl_title = source.get("ssl_title") or "Not Secure"
    ssl_sub = source.get("ssl_sub") or "ไม่พบรายละเอียดใบรับรอง"
    domain_age = source.get("domain_age") or "ไม่พบข้อมูล"
    domain_sub = source.get("domain_sub") or "ไม่พบประวัติข้อมูลระบบจัดทะเบียน"
    location = source.get("location") or "Unknown"
    # จำแนกหมวดอายุโดเมนจากค่าที่ scan_url_logic คำนวณไว้
    # ใช้ domain_age_days (int) ถ้ามี มิฉะนั้น fallback จาก domain_sub text
    _age_days = source.get("domain_age_days")
    if _age_days is not None:
        _age_days = int(_age_days)
        if _age_days <= 30:
            domain_age_category = "new"          # เสี่ยง — โดเมนใหม่มาก
        elif _age_days <= 180:
            domain_age_category = "recent"       # ระวัง — โดเมนค่อนข้างใหม่
        else:
            domain_age_category = "established"  # อายุพอสมควร
    elif domain_age == "ไม่พบข้อมูล":
        domain_age_category = "unknown"
    elif "วัน" in domain_sub and "เพิ่งจด" in domain_sub:
        domain_age_category = "new"
    elif "ระยะหนึ่ง" in domain_sub:
        domain_age_category = "established"
    else:
        domain_age_category = "unknown"
    has_redirection = bool(source.get("has_redirection"))
    is_blacklisted = bool(source.get("is_blacklisted"))
    google_safe = bool(source.get("google_safe", True))
    url = source.get("url") or "ไม่ระบุ URL"

    def _safe_domain(val):
        if not val or not isinstance(val, str):
            return ""
        val = val.strip()
        try:
            return domain_from_url(val)
        except ValueError:
            pass
        try:
            if not val.startswith(("http://", "https://")):
                val = "http://" + val
            return domain_from_url(val)
        except Exception:
            return ""

    target_domain = _safe_domain(url)
    try:
        domain_statistic = DomainStatistic.objects.filter(domain=target_domain).first() if target_domain else None
    except Exception:
        domain_statistic = None
    community_warning = bool(domain_statistic and domain_statistic.approved_report_count >= 3)
    virustotal = source.get("virustotal") or {}
    download_detected = bool(source.get("download_detected"))
    download_name = source.get("download_name") or virustotal.get("file_name", "")
    raw_size = source.get("download_size", 0)
    try:
        download_size = int(raw_size or 0)
    except (ValueError, TypeError):
        download_size = raw_size
    result_id = f"#PH-{latest_scan.id:05d}" if latest_scan else "#PH-00000"

    model_results = source.get("model_results") or {}
    model_badges = {
        "safe": "bg-emerald-100 text-emerald-700 border-emerald-200",
        "mostly_safe": "bg-teal-100 text-teal-700 border-teal-200",
        "warning": "bg-amber-100 text-amber-700 border-amber-200",
        "mostly_danger": "bg-orange-100 text-orange-700 border-orange-200",
        "danger": "bg-rose-100 text-rose-700 border-rose-200",
    }

    def model_display(key):
        result = model_results.get(key) or {}
        risk = result.get("risk_score")
        if not result.get("available") or risk is None:
            return {
                "available": False,
                "label": "ตรวจไม่ได้",
                "status_key": "unknown",
                "badge_class": "bg-slate-100 text-slate-600 border-slate-200",
            }
        model_level = classify_risk(float(risk) * 100)
        return {
            "available": True,
            "label": model_level["label"],
            "status_key": model_level["key"],
            "badge_class": model_badges[model_level["key"]],
        }

    url_model_result = model_display("url_model")
    content_model_result = model_display("content_model")

    risk_bar_widths = {
        "safe": 20,
        "mostly_safe": 40,
        "warning": 60,
        "mostly_danger": 80,
        "danger": 100,
    }
    risk_bar_width = risk_bar_widths.get(status_key, 60)

    if url_model_result.get("available") and content_model_result.get("available"):
        confidence_text = "ระดับสูง"
    elif url_model_result.get("available"):
        confidence_text = "ระดับปานกลาง"
    else:
        confidence_text = "ประเมินเบื้องต้น"

    if latest_scan and latest_scan.timestamp:
        scan_time_text = timezone.localtime(latest_scan.timestamp).strftime("%H:%M:%S")
    else:
        scan_time_text = timezone.localtime(timezone.now()).strftime("%H:%M:%S")

    risk_guidelines = {
        "safe": {
            "summary": "ยังไม่พบสัญญาณเด่นที่บ่งชี้ว่าเป็นเว็บไซต์อันตราย",
            "action": "ตรวจสอบชื่อโดเมนให้ตรงกับบริการจริงก่อนกรอกข้อมูลสำคัญ",
        },
        "mostly_safe": {
            "summary": "มีความเสี่ยงต่ำและโครงสร้างส่วนใหญ่เป็นปกติ",
            "action": "ยืนยันแหล่งที่มาของลิงก์ก่อนเข้าใช้งานหรือทำธุรกรรม",
        },
        "warning": {
            "summary": "พบสัญญาณบางส่วนที่ควรตรวจสอบเพิ่มเติมก่อนใช้งาน",
            "action": "หลีกเลี่ยงการกรอกข้อมูลสำคัญหรือรหัสผ่านจนกว่าจะตรวจสอบเพิ่มเติม",
        },
        "mostly_danger": {
            "summary": "พบสัญญาณความเสี่ยงหลายส่วนที่มีแนวโน้มเป็นอันตราย",
            "action": "ไม่แนะนำให้เปิดเผยข้อมูลส่วนบุคคลหรือดาวน์โหลดไฟล์",
        },
        "danger": {
            "summary": "พบรูปแบบภัยคุกคามหรือพฤติกรรมฟิชชิ่ง/มัลแวร์ชัดเจน",
            "action": "หยุดใช้งานลิงก์นี้ทันที และอย่าเปิดหรือดาวน์โหลดไฟล์",
        },
    }
    guideline = risk_guidelines.get(status_key, risk_guidelines["danger"])
    result_summary = guideline["summary"]
    action_text = guideline["action"]

    # ข้อมูลประวัติในระบบ (DomainStatistic และ ScanHistory)
    status_counts = Counter()
    domain_scans_count = 0
    if target_domain:
        candidates = ScanHistory.objects.filter(url__icontains=target_domain)
        for s in candidates:
            if _safe_domain(s.url) == target_domain:
                status_counts[s.status] += 1
                domain_scans_count += 1

    total_scans = domain_scans_count
    if total_scans == 0 and domain_statistic and domain_statistic.scan_count > 0:
        total_scans = domain_statistic.scan_count
        if domain_statistic.last_status:
            status_counts[domain_statistic.last_status] = domain_statistic.scan_count
    elif domain_statistic and domain_statistic.scan_count > total_scans:
        total_scans = domain_statistic.scan_count

    status_order = [
        ("safe", "ปลอดภัย", "bg-emerald-100 text-emerald-700 border-emerald-200", "fa-solid fa-circle-check text-emerald-500"),
        ("mostly_safe", "ค่อนข้างปลอดภัย", "bg-teal-100 text-teal-700 border-teal-200", "fa-solid fa-circle-check text-teal-500"),
        ("warning", "ควรระวัง", "bg-amber-100 text-amber-700 border-amber-200", "fa-solid fa-triangle-exclamation text-amber-500"),
        ("mostly_danger", "ค่อนข้างอันตราย", "bg-orange-100 text-orange-700 border-orange-200", "fa-solid fa-circle-xmark text-orange-500"),
        ("danger", "อันตราย", "bg-rose-100 text-rose-700 border-rose-200", "fa-solid fa-circle-xmark text-rose-500"),
    ]
    domain_history_breakdown = []
    for k, lbl, badge, icon in status_order:
        cnt = status_counts.get(k, 0)
        domain_history_breakdown.append({
            "key": k,
            "label": lbl,
            "count": cnt,
            "badge_class": badge,
            "icon_class": icon,
        })

    if total_scans > 0:
        parts = []
        for item in domain_history_breakdown:
            if item["count"] > 0:
                parts.append(f"{item['label']} {item['count']} ครั้ง")
        if domain_statistic and domain_statistic.approved_report_count > 0:
            parts.append(f"(มีการแจ้งเบาะแส {domain_statistic.approved_report_count} ครั้ง)")
        domain_history_text = " ".join(parts) if parts else "ยังไม่มีประวัติการตรวจสอบในระบบ"
    else:
        domain_history_text = "ยังไม่มีประวัติการตรวจสอบในระบบ"

    if domain_statistic and domain_statistic.approved_report_count >= 3:
        phishwise_db = {
            "status": "danger",
            "label": "พบประวัติความเสี่ยง",
            "desc": domain_history_text,
            "badge_class": "bg-rose-100 text-rose-700 border-rose-200",
            "icon_class": "fa-solid fa-circle-xmark text-red-500 text-[22px]",
        }
    elif status_counts.get("danger", 0) > 0 or status_counts.get("mostly_danger", 0) > 0 or (domain_statistic and domain_statistic.last_status in {"danger", "mostly_danger"}):
        phishwise_db = {
            "status": "danger",
            "label": "พบประวัติความเสี่ยง",
            "desc": domain_history_text,
            "badge_class": "bg-rose-100 text-rose-700 border-rose-200",
            "icon_class": "fa-solid fa-circle-xmark text-red-500 text-[22px]",
        }
    elif status_counts.get("warning", 0) > 0 or (domain_statistic and domain_statistic.last_status == "warning"):
        phishwise_db = {
            "status": "warning",
            "label": "ควรระวัง",
            "desc": domain_history_text,
            "badge_class": "bg-amber-100 text-amber-700 border-amber-200",
            "icon_class": "fa-solid fa-triangle-exclamation text-amber-500 text-[22px]",
        }
    elif total_scans > 0:
        phishwise_db = {
            "status": "safe",
            "label": "ปลอดภัย",
            "desc": domain_history_text,
            "badge_class": "bg-green-100 text-green-700 border-green-200",
            "icon_class": "fa-solid fa-circle-check text-green-500 text-[22px]",
        }
    else:
        phishwise_db = {
            "status": "neutral",
            "label": "ตรวจครั้งแรก",
            "desc": "ยังไม่มีประวัติการตรวจสอบในระบบ",
            "badge_class": "bg-slate-100 text-slate-600 border-slate-200",
            "icon_class": "fa-solid fa-circle-info text-blue-500 text-[22px]",
        }

    # ข้อมูลการเปลี่ยนเส้นทาง (Redirection)
    redirect_count = int(source.get("redirect_count", 1 if has_redirection else 0))
    redirect_chain = source.get("redirect_chain") or ([url] if not has_redirection else [url, url])
    if redirect_count > 0:
        redirect_desc = f"ลิงก์นี้พาไปยังเว็บไซต์อื่นอีก {redirect_count} ต่อก่อนถึงปลายทางจริง ซึ่งเป็นวิธีที่มิจฉาชีพมักใช้เพื่อหลบเลี่ยงการตรวจสอบ"
    else:
        redirect_desc = "ลิงก์นี้เข้าถึงปลายทางโดยตรง ไม่มีการเปลี่ยนเส้นทาง"

    # คุณลักษณะโครงสร้าง URL 11 ด้าน (URL Structure Features)
    from detector.services import extract_url_features
    features_dict = source.get("url_features") or extract_url_features(url)
    url_len = features_dict.get("url_length", len(url))
    url_features_details = [
        {
            "name": "url_length",
            "label": "ความยาวของลิงก์ URL",
            "value": f"{url_len} ตัวอักษร",
            "is_risky": url_len > 75,
            "desc": "ลิงก์ยาวผิดปกติ มักใช้ซ่อนชื่อปลายทางจริง" if url_len > 75 else "ความยาวอยู่ในเกณฑ์ปกติ",
        },
        {
            "name": "is_ip_address",
            "label": "ใช้หมายเลข IP แทนชื่อเว็บไซต์",
            "value": "พบการใช้หมายเลข IP" if features_dict.get("is_ip_address") else "ไม่พบ (ใช้ชื่อโดเมนปกติ)",
            "is_risky": bool(features_dict.get("is_ip_address")),
            "desc": "ใช้ IP ตรงแทนชื่อเว็บไซต์ มักพบในเซิร์ฟเวอร์หลอกลวง" if features_dict.get("is_ip_address") else "ใช้ชื่อโดเมนปกติ ไม่ใช้ IP ตรง",
        },
        {
            "name": "count_dots",
            "label": "จำนวนจุด (.) ในลิงก์",
            "value": f"{features_dict.get('count_dots', 0)} จุด",
            "is_risky": features_dict.get("count_dots", 0) > 3,
            "desc": "มีจุดหลายจุด อาจเป็นโดเมนย่อยซับซ้อนเพื่อเลียนแบบ" if features_dict.get("count_dots", 0) > 3 else "จำนวนจุดอยู่ในเกณฑ์ปกติ",
        },
        {
            "name": "count_hyphens",
            "label": "จำนวนเครื่องหมายขีด (-) ในลิงก์",
            "value": f"{features_dict.get('count_hyphens', 0)} ตัว",
            "is_risky": features_dict.get("count_hyphens", 0) > 2,
            "desc": "มีเครื่องหมายขีดหลายตัว มักใช้เลียนแบบชื่อแบรนด์" if features_dict.get("count_hyphens", 0) > 2 else "จำนวนขีดอยู่ในเกณฑ์ปกติ",
        },
        {
            "name": "count_at",
            "label": "มีเครื่องหมาย @ ในลิงก์",
            "value": f"พบ {features_dict.get('count_at', 0)} ตัว" if features_dict.get("count_at", 0) > 0 else "ไม่พบ",
            "is_risky": features_dict.get("count_at", 0) > 0,
            "desc": "มีเครื่องหมาย @ อาจทำให้เบราว์เซอร์มองข้ามข้อความข้างหน้า" if features_dict.get("count_at", 0) > 0 else "ไม่พบเครื่องหมาย @",
        },
        {
            "name": "count_question",
            "label": "จำนวนเครื่องหมายคำถาม (?) ในลิงก์",
            "value": f"{features_dict.get('count_question', 0)} ตัว",
            "is_risky": features_dict.get("count_question", 0) > 1,
            "desc": "มีพารามิเตอร์ซักถามหลายชุด" if features_dict.get("count_question", 0) > 1 else "ปกติ",
        },
        {
            "name": "count_equal",
            "label": "จำนวนเครื่องหมายเท่ากับ (=) ในลิงก์",
            "value": f"{features_dict.get('count_equal', 0)} ตัว",
            "is_risky": features_dict.get("count_equal", 0) > 3,
            "desc": "มีการส่งต่อพารามิเตอร์จำนวนมาก" if features_dict.get("count_equal", 0) > 3 else "ปกติ",
        },
        {
            "name": "count_slash",
            "label": "จำนวนเครื่องหมายทับ (/) ในลิงก์",
            "value": f"{features_dict.get('count_slash', 0)} ตัว",
            "is_risky": features_dict.get("count_slash", 0) > 5,
            "desc": "มีเส้นทางโฟลเดอร์ซ้อนกันลึกผิดปกติ" if features_dict.get("count_slash", 0) > 5 else "โครงสร้างโฟลเดอร์ปกติ",
        },
        {
            "name": "has_suspicious_keyword",
            "label": "มีคำที่มักพบในเว็บหลอกลวง",
            "value": "ตรวจพบคำน่าสงสัย" if features_dict.get("has_suspicious_keyword") else "ไม่พบคำน่าสงสัย",
            "is_risky": bool(features_dict.get("has_suspicious_keyword")),
            "desc": "พบคำเช่น login, verify, account, update ฯลฯ ในลิงก์" if features_dict.get("has_suspicious_keyword") else "ไม่พบคำที่นิยมใช้ในการฟิชชิ่ง",
        },
        {
            "name": "has_executable_extension",
            "label": "มีนามสกุลไฟล์ที่อาจเป็นอันตราย",
            "value": "ตรวจพบนามสกุลไฟล์อันตราย" if features_dict.get("has_executable_extension") else "ไม่พบนามสกุลไฟล์อันตราย",
            "is_risky": bool(features_dict.get("has_executable_extension")),
            "desc": "ลิงก์นำไปสู่ไฟล์สั่งการ เช่น .exe, .sh, .apk ฯลฯ" if features_dict.get("has_executable_extension") else "ไม่มีนามสกุลไฟล์อันตราย",
        },
        {
            "name": "is_https",
            "label": "การเชื่อมต่อแบบเข้ารหัส (HTTPS)",
            "value": "ใช้งาน HTTPS (เข้ารหัสปลอดภัย)" if features_dict.get("is_https") else "ไม่ได้ใช้ HTTPS (ไม่ปลอดภัย)",
            "is_risky": not bool(features_dict.get("is_https")),
            "desc": "การเชื่อมต่อได้รับการเข้ารหัสปลอดภัย" if features_dict.get("is_https") else "ไม่ได้เข้ารหัส ข้อมูลอาจถูกดักจับได้",
        },
    ]

    context = {
        "current_user": current_user(request),
        "url": url,
        "target_domain": target_domain,
        "score": score,
        "status_label": status_label,
        "status_key": status_key,
        "theme_color": theme_color,
        "status_badge_class": status_badge_class,
        "status_text_class": status_text_class,
        "risk_bar_class": risk_bar_class,
        "risk_bar_width": risk_bar_width,
        "ai_risk_score": ai_risk_score,
        "confidence_text": confidence_text,
        "scan_time_text": scan_time_text,
        "ssl_title": ssl_title,
        "ssl_sub": ssl_sub,
        "domain_age": domain_age,
        "domain_age_category": domain_age_category,
        "domain_sub": domain_sub,
        "location": location,
        "has_redirection": has_redirection,
        "redirect_count": redirect_count,
        "redirect_chain": redirect_chain,
        "redirect_desc": redirect_desc,
        "url_features_details": url_features_details,
        "domain_history_text": domain_history_text,
        "domain_total_scans": total_scans,
        "domain_approved_reports": domain_statistic.approved_report_count if domain_statistic else 0,
        "domain_history_breakdown": domain_history_breakdown,
        "is_blacklisted": is_blacklisted,
        "google_safe": google_safe,
        "phishwise_db": phishwise_db,
        "virustotal": virustotal,
        "download_detected": download_detected,
        "download_name": download_name,
        "download_size": download_size,
        "result_id": result_id,
        "url_model_result": url_model_result,
        "content_model_result": content_model_result,
        "result_summary": result_summary,
        "action_text": action_text,
        "domain_statistic": domain_statistic,
        "community_warning": community_warning,
    }
    return context


def result_view(request):
    return render(request, "result.html", analysis_report_context(request))


def analysis_pdf_view(request):
    from .analysis_weasyprint import build_analysis_pdf

    pdf_bytes = build_analysis_pdf(analysis_report_context(request))
    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    response["Content-Disposition"] = (
        'attachment; filename="phishwise-analysis-report.pdf"'
    )
    return response


@login_required(login_url="login")
def report_view(request):
    if request.method == "POST":
        url, reason, details = request.POST.get("url", ""), request.POST.get("reason", ""), request.POST.get("details", "")
        if reason not in {choice[0] for choice in SuspiciousSiteReport.REASON_CHOICES}:
            messages.error(request, "กรุณาเลือกเหตุผลของการแจ้ง")
        else:
            try:
                create_site_report(user=request.user, url=url, reason=reason, details=details)
                messages.success(request, "ส่งรายงานแล้ว รายการจะรอการตรวจสอบจากผู้ดูแล")
                return redirect("report")
            except ValueError as exc:
                messages.error(request, str(exc))
    return render(request, "report.html", {"current_user": current_user(request), "reasons": SuspiciousSiteReport.REASON_CHOICES, "my_reports": SuspiciousSiteReport.objects.filter(user=request.user)[:10]})


@require_POST
@staff_member_required(login_url="login")
def admin_review_report(request, report_id):
    report = SuspiciousSiteReport.objects.filter(pk=report_id).first()
    if not report:
        messages.error(request, "ไม่พบรายงานที่ต้องการ")
    else:
        try:
            review_site_report(report, status=request.POST.get("status"), reviewer=request.user)
            messages.success(request, "อัปเดตสถานะรายงานแล้ว")
        except ValueError as exc:
            messages.error(request, str(exc))
    return redirect(f"{reverse('admin')}#reports")

def history_view(request):
    my_reports = [
        {
            "id": 1,
            "url": "http://scb-verify-login.com",
            "type": "Phishing",
            "date": "12 ก.พ. 2026",
            "status": "Pending",
        },
        {
            "id": 2,
            "url": "https://free-iphone-15.net",
            "type": "Scam",
            "date": "10 ก.พ. 2026",
            "status": "Verified",
        },
        {
            "id": 3,
            "url": "https://www.google.com",
            "type": "Other",
            "date": "05 ก.พ. 2026",
            "status": "Rejected",
        },
        {
            "id": 4,
            "url": "http://bit.ly/fake-bank",
            "type": "Phishing",
            "date": "04 ก.พ. 2026",
            "status": "Pending",
        },
        {
            "id": 5,
            "url": "https://secure-pay-web.com",
            "type": "Scam",
            "date": "03 ก.พ. 2026",
            "status": "Verified",
        },
        {
            "id": 6,
            "url": "http://malware-site.net",
            "type": "Malware",
            "date": "02 ก.พ. 2026",
            "status": "Pending",
        },
        {
            "id": 7,
            "url": "https://verify-account.io",
            "type": "Phishing",
            "date": "01 ก.พ. 2026",
            "status": "Rejected",
        },
    ]
    return render(
        request,
        "history.html",
        {"my_reports": my_reports, "current_user": current_user(request)},
    )


@login_required(login_url="login")
def scan_history_view(request):
    scan_data = ScanHistory.objects.filter(user=request.user).order_by("-timestamp")
    return render(
        request,
        "scan_history.html",
        {"scan_data": scan_data, "current_user": current_user(request)},
    )


def knowledge_view(request):
    # ดึงจาก DB ก่อน ถ้ายังว่างค่อย fallback ไปใช้ ARTICLES list
    db_articles = KnowledgeArticle.objects.filter(status=KnowledgeArticle.STATUS_PUBLISHED).order_by("order", "-created_at")
    if db_articles.exists():
        articles_data = list(db_articles.values(
            "id", "title", "category", "author", "author_role",
            "date", "read_time", "desc", "image", "summary", "status",
        ))
    else:
        articles_data = ARTICLES
    return render(
        request,
        "knowledge.html",
        {"articles": articles_data, "current_user": current_user(request)},
    )


def knowledge_detail_view(request, id):
    # ลองหาจาก DB ก่อน
    db_article = KnowledgeArticle.objects.filter(pk=id).first()
    if db_article:
        article = {
            "id": db_article.id,
            "title": db_article.title,
            "category": db_article.category,
            "author": db_article.author,
            "author_role": db_article.author_role,
            "date": db_article.date,
            "read_time": db_article.read_time,
            "desc": db_article.desc,
            "image": db_article.image,
            "summary": db_article.summary,
            "content_markdown": db_article.content_markdown,
            "content_html": db_article.content_html,
            "sections": db_article.sections,
            "key_takeaways": db_article.key_takeaways,
        }
        db_related = KnowledgeArticle.objects.filter(
            status=KnowledgeArticle.STATUS_PUBLISHED
        ).exclude(pk=id).order_by("order")[:3]
        related_articles = [
            {"id": a.id, "title": a.title, "category": a.category, "image": a.image, "desc": a.desc}
            for a in db_related
        ]
    else:
        # fallback hardcoded
        article = next((item for item in ARTICLES if item["id"] == id), None)
        related_articles = [item for item in ARTICLES if item["id"] != id][:3]

    return render(
        request,
        "knowledge_detail.html",
        {
            "article": article,
            "related_articles": related_articles,
            "current_user": current_user(request),
        },
    )


# ─── Article CRUD (admin only) ───────────────────────────────────────────────

@require_POST
@staff_member_required(login_url="login")
def article_preview_view(request):
    raw_markdown = request.POST.get("content_markdown", "")
    html = render_article_markdown(raw_markdown)
    return JsonResponse({"html": html})


@require_POST
@staff_member_required(login_url="login")
def article_create_view(request):
    title = request.POST.get("title", "").strip()
    category = request.POST.get("category", "Security")
    author = request.POST.get("author", "PhishWise Team").strip()
    author_role = request.POST.get("author_role", "Cybersecurity Specialist").strip()
    date = request.POST.get("date", "").strip()
    read_time = request.POST.get("read_time", "").strip()
    desc = request.POST.get("desc", "").strip()
    image = request.POST.get("image", "").strip()
    summary = request.POST.get("summary", "").strip()
    content_raw = request.POST.get("content", "{}").strip()
    content_markdown = request.POST.get("content_markdown", "").strip()
    status_val = request.POST.get("status", KnowledgeArticle.STATUS_DRAFT)

    if not title or not desc:
        messages.error(request, "กรุณากรอกชื่อบทความและคำอธิบาย")
        return redirect(f"{reverse('admin')}#knowledge")

    try:
        content_data = json.loads(content_raw) if content_raw else {}
    except json.JSONDecodeError:
        content_data = {}

    content_html = render_article_markdown(content_markdown) if content_markdown else ""

    max_order = KnowledgeArticle.objects.count()
    KnowledgeArticle.objects.create(
        title=title,
        category=category,
        author=author,
        author_role=author_role,
        date=date,
        read_time=read_time,
        desc=desc,
        image=image,
        summary=summary,
        content=content_data,
        content_markdown=content_markdown,
        content_html=content_html,
        status=status_val,
        order=max_order,
    )
    messages.success(request, f"เพิ่มบทความ \"{title}\" เรียบร้อยแล้ว")
    return redirect(f"{reverse('admin')}#knowledge")


@require_POST
@staff_member_required(login_url="login")
def article_edit_view(request, pk):
    article = KnowledgeArticle.objects.filter(pk=pk).first()
    if not article:
        messages.error(request, "ไม่พบบทความที่ต้องการแก้ไข")
        return redirect(f"{reverse('admin')}#knowledge")

    article.title = request.POST.get("title", article.title).strip()
    article.category = request.POST.get("category", article.category)
    article.author = request.POST.get("author", article.author).strip()
    article.author_role = request.POST.get("author_role", article.author_role).strip()
    article.date = request.POST.get("date", article.date).strip()
    article.read_time = request.POST.get("read_time", article.read_time).strip()
    article.desc = request.POST.get("desc", article.desc).strip()
    article.image = request.POST.get("image", article.image).strip()
    article.summary = request.POST.get("summary", article.summary).strip()
    article.status = request.POST.get("status", article.status)

    if "content_markdown" in request.POST:
        content_markdown = request.POST.get("content_markdown", "").strip()
        article.content_markdown = content_markdown
        article.content_html = render_article_markdown(content_markdown)

    content_raw = request.POST.get("content", "").strip()
    if content_raw:
        try:
            article.content = json.loads(content_raw)
        except json.JSONDecodeError:
            pass

    article.save()
    messages.success(request, f"แก้ไขบทความ \"{article.title}\" เรียบร้อยแล้ว")
    return redirect(f"{reverse('admin')}#knowledge")


@require_POST
@staff_member_required(login_url="login")
def article_delete_view(request, pk):
    article = KnowledgeArticle.objects.filter(pk=pk).first()
    if article:
        title = article.title
        article.delete()
        messages.success(request, f"ลบบทความ \"{title}\" เรียบร้อยแล้ว")
    return redirect(f"{reverse('admin')}#knowledge")


@require_POST
@staff_member_required(login_url="login")
def article_toggle_status_view(request, pk):
    article = KnowledgeArticle.objects.filter(pk=pk).first()
    if article:
        if article.status == KnowledgeArticle.STATUS_PUBLISHED:
            article.status = KnowledgeArticle.STATUS_DRAFT
        else:
            article.status = KnowledgeArticle.STATUS_PUBLISHED
        article.save(update_fields=["status"])
    return redirect(f"{reverse('admin')}#knowledge")


@require_POST
@staff_member_required(login_url="login")
def article_upload_image_view(request):
    uploaded_file = request.FILES.get("image")
    if not uploaded_file:
        return JsonResponse({"success": False, "error": "กรุณาเลือกไฟล์รูปภาพ"}, status=400)

    allowed_extensions = {".jpg", ".jpeg", ".png", ".webp", ".gif"}
    ext = os.path.splitext(uploaded_file.name)[1].lower()
    if ext not in allowed_extensions:
        return JsonResponse({"success": False, "error": "รองรับเฉพาะไฟล์รูปภาพ .jpg, .png, .webp, .gif"}, status=400)

    if uploaded_file.size > 10 * 1024 * 1024:
        return JsonResponse({"success": False, "error": "ขนาดไฟล์ต้องไม่เกิน 10MB"}, status=400)

    articles_media_dir = Path(settings.MEDIA_ROOT) / "articles"
    articles_media_dir.mkdir(parents=True, exist_ok=True)

    unique_filename = f"art_{uuid.uuid4().hex[:12]}{ext}"
    target_path = articles_media_dir / unique_filename

    with open(target_path, "wb+") as destination:
        for chunk in uploaded_file.chunks():
            destination.write(chunk)

    image_url = f"{settings.MEDIA_URL}articles/{unique_filename}"
    return JsonResponse({
        "success": True,
        "url": image_url,
        "filename": uploaded_file.name,
        "size_kb": round(uploaded_file.size / 1024, 1),
    })




def scan_view(request):
    if request.method == "POST":
        url = request.POST.get("url", "").strip()
        uploaded_file = request.FILES.get("file")
        source_type = request.POST.get("source_type", "direct_url")
        if source_type not in {"direct_url", "camera_qr", "image_qr"}:
            source_type = "direct_url"

        if not url and uploaded_file:
            try:
                decoded_result, source_type = decode_image_url_or_qr(uploaded_file)
                all_urls = decoded_result if isinstance(decoded_result, list) else [decoded_result]
                if len(all_urls) == 1:
                    # URL เดียว → สแกนได้เลย
                    url = all_urls[0]
                elif len(all_urls) > 1:
                    # หลาย URL → เก็บใน Session แล้วกลับหน้าหลักให้ Modal ขึ้น
                    request.session["pending_ocr_urls"] = all_urls
                    request.session["pending_source_type"] = source_type
                    request.session.modified = True
                    return redirect("home")
                else:
                    raise ValueError("ไม่พบ QR Code หรือข้อความ URL ในรูปภาพที่อัปโหลด")
            except ValueError as exc:
                messages.error(request, str(exc))
                return redirect("home")

        if url:
            result = scan_url_logic(url)

            ScanHistory.objects.create(
                user=request.user if request.user.is_authenticated else None,
                source_type=source_type,
                url=result["url"],
                score=result["score"],
                status=result["status"],
                ai_risk_score=result["ai_risk_score"],
                ssl_title=result["ssl_title"],
                ssl_sub=result["ssl_sub"],
                domain_age=result["domain_age"],
                domain_sub=result["domain_sub"],
                is_blacklisted=result["is_blacklisted"],
                google_safe=result["google_safe"],
                location=result["location"],
                has_redirection=result["has_redirection"],
                timestamp=timezone.now(),
            )

            record_domain_scan(result["url"], request.user, status=result["status"], score=result["score"])

            request.session["last_scan_result"] = result
            request.session.modified = True

            return redirect("result")

        messages.error(request, "กรุณากรอก URL หรือเลือกภาพ QR Code")
        return redirect("home")

    return redirect("home")


def select_url_view(request):
    """หน้าให้ผู้ใช้เลือก URL เมื่อ OCR ตรวจพบหลายลิงก์ในภาพเดียวกัน"""
    if request.method == "POST":
        selected_url = request.POST.get("selected_url", "").strip()
        source_type = request.session.pop("pending_source_type", "image_ocr")
        request.session.pop("pending_ocr_urls", None)

        if not selected_url or selected_url == "__cancel__":
            return redirect("home")

        result = scan_url_logic(selected_url)

        ScanHistory.objects.create(
            user=request.user if request.user.is_authenticated else None,
            source_type=source_type,
            url=result["url"],
            score=result["score"],
            status=result["status"],
            ai_risk_score=result["ai_risk_score"],
            ssl_title=result["ssl_title"],
            ssl_sub=result["ssl_sub"],
            domain_age=result["domain_age"],
            domain_sub=result["domain_sub"],
            is_blacklisted=result["is_blacklisted"],
            google_safe=result["google_safe"],
            location=result["location"],
            has_redirection=result["has_redirection"],
            timestamp=timezone.now(),
        )

        record_domain_scan(result["url"], request.user, status=result["status"], score=result["score"])

        request.session["last_scan_result"] = result
        request.session.modified = True

        return redirect("result")

    # GET — แสดงหน้าเลือก URL
    pending_urls = request.session.get("pending_ocr_urls", [])
    if not pending_urls:
        messages.error(request, "ไม่พบรายการ URL กรุณาลองอัปโหลดภาพใหม่อีกครั้ง")
        return redirect("home")

    return render(request, "select_url.html", {
        "urls": pending_urls,
        "url_count": len(pending_urls),
        "current_user": current_user(request),
    })

