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
        "title": "How to Identify Phishing Links Like a Pro",
        "category": "Phishing",
        "author": "PhishWise Team",
        "author_role": "Cybersecurity Specialist",
        "date": "29 Jan 2026",
        "read_time": "4 min read",
        "desc": "In-depth techniques for inspecting suspicious URLs before clicking to avoid credential theft.",
        "image": "https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&q=80&w=1200",
        "summary": "Phishing remains the #1 cyber threat facing internet users today. Attackers clone legitimate bank or social media portals to steal passwords, financial credentials, and personal information.",
        "sections": [
            {
                "title": "1. Scrutinize the Domain Name Carefully",
                "text": "Cybercriminals often employ Typosquatting—registering domain names that look nearly identical to real brands (e.g. replacing 'l' with '1' or appending deceptive words after brand names).",
                "image": "https://images.unsplash.com/photo-1618060932014-4deda4932554?auto=format&fit=crop&q=80&w=1000",
                "caption": "Example of inspecting the exact domain in your browser's address bar",
                "examples": [
                    {
                        "label": "Legitimate URL",
                        "url": "https://www.scb.co.th",
                        "is_safe": True,
                    },
                    {
                        "label": "Fake URL (Misspelled)",
                        "url": "https://www.scb-verify-online.com",
                        "is_safe": False,
                    },
                    {
                        "label": "Fake URL (Number Substitution)",
                        "url": "http://www.g00gle.com",
                        "is_safe": False,
                    },
                ],
            },
            {
                "title": "2. Check SSL/TLS Encryption (https://)",
                "text": "If a website starts with http:// (without 's'), treat it with caution as traffic is unencrypted. Never enter sensitive passwords or credentials on such sites.",
                "callout": {
                    "type": "warning",
                    "title": "⚠️ Caution!",
                    "text": "A padlock icon 🔒 (https://) does NOT guarantee a site is safe! Anyone, including attackers, can obtain free SSL certificates. Always verify the domain name itself.",
                },
            },
            {
                "title": "3. Watch Out for Shortened URLs and Dynamic QR Codes",
                "text": "Attackers frequently hide real destinations behind URL shorteners like bit.ly or dynamic QR codes printed on flyers and sent via SMS to obscure fraudulent destinations.",
                "callout": {
                    "type": "tip",
                    "title": "💡 Pro Tip from PhishWise",
                    "text": "Whenever you encounter a shortened link or QR code, scan it through PhishWise first to inspect the destination domain before opening it.",
                },
            },
        ],
        "key_takeaways": [
            "Never hastily click links from unknown SMS messages or emails.",
            "Verify the primary domain name (the portion before .com / .org / .co.th) every time.",
            "When in doubt, open a fresh browser tab and manually type the official website address.",
        ],
    },
    {
        "id": 2,
        "title": "What Makes a Strong and Secure Password?",
        "category": "Security",
        "author": "PhishWise Team",
        "author_role": "Information Security Analyst",
        "date": "30 Jan 2026",
        "read_time": "3 min read",
        "desc": "Move beyond 123456 and adopt passphrases for maximum account protection.",
        "image": "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?auto=format&fit=crop&q=80&w=1200",
        "summary": "Passwords are your primary line of defense. Weak or reused passwords make account takeovers trivial for brute-force attacks and credential stuffing.",
        "sections": [
            {
                "title": "1. Upgrade from Passwords to Passphrases",
                "text": "Instead of short, hard-to-remember strings like P@ssw0rd!, use long passphrases combining multiple unrelated words, such as 'BlueElephantReadsCoffeeDaily2026!'.",
                "image": "https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?auto=format&fit=crop&q=80&w=1000",
                "caption": "Length provides exponentially greater entropy than complexity alone against brute-force attacks",
            },
            {
                "title": "2. Never Reuse Passwords Across Services",
                "text": "If one service suffers a data breach, attackers will immediately test leaked email-password combinations across other major services (Credential Stuffing).",
                "callout": {
                    "type": "tip",
                    "title": "🔒 Password Manager Recommendations",
                    "text": "Use a reputable Password Manager (such as Bitwarden or 1Password) to generate and store unique, high-entropy passwords for each service.",
                },
            },
        ],
        "key_takeaways": [
            "Password length should be at least 12-16 characters.",
            "Do not use personal details (birthdays, pet names, phone numbers) in passwords.",
            "Combine uppercase letters, lowercase letters, numbers, and symbols.",
        ],
    },
    {
        "id": 3,
        "title": "Alert: New Tactics Used by Call Center and Impersonation Gangs",
        "category": "Scams",
        "author": "Anti-Scam Unit",
        "author_role": "Fraud Investigation Specialist",
        "date": "02 Feb 2026",
        "read_time": "5 min read",
        "desc": "Understand psychological coercion and fake official credentials used by scammers.",
        "image": "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&q=80&w=1200",
        "summary": "Modern scam syndicates combine phone spoofing, forged arrest warrants, and video calls with fake police backgrounds to intimidate victims into liquidating their bank savings.",
        "sections": [
            {
                "title": "1. Common False Personas",
                "text": "Callers frequently claim to represent parcel courier services, the anti-money laundering office, taxation departments, or local law enforcement.",
            },
            {
                "title": "🚫 Golden Rule of Official Agencies",
                "text": "Legitimate government agencies and law enforcement NEVER contact citizens via Line or video call to demand money transfers for verification or asset freezing audits.",
            },
            {
                "title": "2. Hang Up and Verify Independently",
                "text": "If you receive a threatening call, hang up immediately. Look up the official hotline of the agency from their verified website and call them back directly.",
            },
        ],
        "key_takeaways": [
            "No state agency will ever ask you to transfer funds to a private account for verification.",
            "Do not add unknown callers on messaging apps or share bank OTPs.",
            "Always consult trusted family members or official hotlines before transferring money.",
        ],
    },
    {
        "id": 4,
        "title": "What is Ransomware? Understanding Extortion Malware",
        "category": "Malware",
        "author": "PhishWise Team",
        "author_role": "Malware Analyst",
        "date": "05 Feb 2026",
        "read_time": "5 min read",
        "desc": "How ransomware infiltrates systems and the essential 3-2-1 backup strategy.",
        "image": "https://images.unsplash.com/photo-1510511459019-5dda7724fd87?auto=format&fit=crop&q=80&w=1200",
        "summary": "Ransomware encrypts your documents and databases, rendering them completely inaccessible until an exorbitant ransom is paid in cryptocurrency.",
        "sections": [
            {
                "title": "1. Infection Vectors",
                "text": "Malicious email attachments (disguised as PDF invoices or Excel spreadsheets), pirated software cracks, and unpatched Remote Desktop Protocol (RDP) vulnerabilities are primary entryways.",
            },
            {
                "title": "2. The 3-2-1 Backup Strategy",
                "text": "Keep 3 total copies of critical files, across 2 different storage media types, with 1 copy completely offline (air-gapped) or in immutable cloud storage.",
            },
            {
                "title": "💡 Proactive Defense",
                "text": "Ensure automatic OS security updates are enabled and avoid executing unverified script files or cracked installers.",
            },
        ],
        "key_takeaways": [
            "Never pay ransoms—payment does not guarantee file recovery and funds criminal networks.",
            "Regular offline backups are your only reliable defense against data loss.",
            "Verify email attachments using PhishWise and endpoint anti-malware tools.",
        ],
    },
    {
        "id": 5,
        "title": "What is 2FA and Why Should You Enable It Immediately?",
        "category": "Security",
        "author": "SecOps Team",
        "author_role": "Identity & Access Architect",
        "date": "08 Feb 2026",
        "read_time": "4 min read",
        "desc": "Why passwords alone are insufficient and how multi-factor authentication stops 99% of automated attacks.",
        "image": "https://images.unsplash.com/photo-1563013544-824ae1b704d3?auto=format&fit=crop&q=80&w=1200",
        "summary": "Multi-Factor Authentication (MFA) requires two distinct verification factors before granting access. Even if an attacker steals your password via phishing, they cannot enter without the second factor.",
        "sections": [
            {
                "title": "1. Authentication Factors Explained",
                "text": "Authentication combines something you know (password), something you have (phone/token), and something you are (biometrics like fingerprints or FaceID).",
            },
            {
                "title": "2. Why Choose Authenticator Apps Over SMS OTP?",
                "text": "SMS messages can be intercepted through SIM swapping or telecom protocol flaws. Authenticator apps (Google Authenticator, Microsoft Authenticator) generate offline time-based codes (TOTP) that cannot be intercepted remotely.",
            },
            {
                "title": "💡 Don't Forget Backup Codes!",
                "text": "Always print or securely vault the one-time emergency backup recovery codes provided when setting up 2FA.",
            },
        ],
        "key_takeaways": [
            "Enable 2FA on primary email, financial apps, and social accounts.",
            "Prefer Authenticator apps over SMS OTP where possible.",
            "Never share 2FA OTP codes with anyone, under any circumstances.",
        ],
    },
    {
        "id": 6,
        "title": "How Risky is Public Wi-Fi? How to Stay Safe on Open Networks",
        "category": "Security",
        "author": "NetSec Specialist",
        "author_role": "Network Engineer",
        "date": "10 Feb 2026",
        "read_time": "4 min read",
        "desc": "Protect your personal traffic from snooping, packet sniffing, and evil twin hotspots.",
        "image": "https://images.unsplash.com/photo-1544197150-b99a580bb7a8?auto=format&fit=crop&q=80&w=1200",
        "summary": "Public Wi-Fi networks in coffee shops, transit stations, and hotels rarely isolate client traffic. Malicious actors on the same network can intercept unencrypted data packets.",
        "sections": [
            {
                "title": "1. Beware of 'Evil Twin' Rogue Hotspots",
                "text": "Attackers configure portable routers broadcasting identical SSID names (e.g. 'CoffeeShop_Free_WiFi') to trick devices into connecting and routing traffic through the attacker's proxy.",
            },
            {
                "title": "⚠️ Critical Restriction",
                "text": "Avoid accessing online banking or conducting e-commerce transactions while connected to public open Wi-Fi.",
            },
            {
                "title": "2. How to Protect Yourself When Connection is Necessary",
                "text": "Always activate a trustworthy Virtual Private Network (VPN) before browsing, or use cellular data (4G/5G) which provides carrier-grade link encryption.",
            },
        ],
        "key_takeaways": [
            "Turn off 'Auto-Connect to Open Wi-Fi' in phone settings.",
            "Use mobile cellular hotspot instead of untrusted public networks.",
            "Ensure HTTPS is strictly enforced on all websites you visit.",
        ],
    },
    {
        "id": 7,
        "title": "Deepfakes: The Silent Threat of AI Audio and Video Impersonation",
        "category": "Scams",
        "author": "AI Ethics Lab",
        "author_role": "AI Safety Researcher",
        "date": "12 Feb 2026",
        "read_time": "5 min read",
        "desc": "How generative AI voice clones are used in family emergency scams and how to spot them.",
        "image": "https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&q=80&w=1200",
        "summary": "With as little as 3 seconds of recorded audio sample from social media, modern AI can clone anyone's voice convincingly, leading to a surge in fake hostage and urgent financial request scams.",
        "sections": [
            {
                "title": "1. Spotting Video and Audio Deepfakes",
                "text": "Look for unnatural eye blinking patterns, audio-visual lip sync latency, strange boundary artifacts around teeth or ears, and monotonic emotional cadence.",
            },
            {
                "title": "2. Establishing Family 'Safe Words'",
                "text": "Establish a private code word among immediate family members. If you receive a distress call demanding immediate cash, ask for the code word to verify identity.",
            },
            {
                "title": "💡 Confirm via Alternate Channels",
                "text": "Always hang up and call back the person using their known telephone number or reach out to mutual contacts before sending any money.",
            },
        ],
        "key_takeaways": [
            "Establish a secret emergency passphrase with your loved ones.",
            "Do not trust audio or video alone in urgent financial situations.",
            "Limit public availability of high-definition voice recordings on social media.",
        ],
    },
    {
        "id": 8,
        "title": "How to Check if Your Data Has Leaked to the Dark Web",
        "category": "Privacy",
        "author": "Cyber Threat Intel",
        "author_role": "Data Breach Specialist",
        "date": "13 Feb 2026",
        "read_time": "4 min read",
        "desc": "Discover whether your email, passwords, or personal identity documents have been exposed.",
        "image": "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&q=80&w=1200",
        "summary": "Every year, thousands of corporate databases are breached, releasing billions of user credentials onto dark web forums where cybercriminals purchase them for targeted attacks.",
        "sections": [
            {
                "title": "1. How to Check for Compromised Credentials",
                "text": "Use reputable breach notification aggregators such as 'Have I Been Pwned' to safely check whether your email address has appeared in known public data leaks.",
            },
            {
                "title": "🚨 Immediate Actions If Compromised",
                "text": "If a leak is confirmed, immediately change passwords on the compromised service and any other accounts sharing similar passwords, and activate two-factor authentication.",
            },
        ],
        "key_takeaways": [
            "Regularly audit your email address against breach registries.",
            "Enable login notifications from unknown devices across all platforms.",
            "Replace passwords immediately whenever a breach alert is issued.",
        ],
    },
    {
        "id": 9,
        "title": "How Mobile Trojans Steal Funds and How to Shield Your Smartphone",
        "category": "Malware",
        "author": "Mobile Threat Team",
        "author_role": "Android Security Engineer",
        "date": "14 Feb 2026",
        "read_time": "5 min read",
        "desc": "Exposing deceptive sideloaded APKs and Android Accessibility Service abuse.",
        "image": "https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&q=80&w=1200",
        "summary": "Mobile banking malware does not hack bank servers directly; rather, it tricks victims into sideloading malicious .APK apps and granting Accessibility permissions to remotely control the screen.",
        "sections": [
            {
                "title": "1. Anatomy of the Attack",
                "text": "1. Attacker sends phishing SMS/call posing as government tax or utility department.\n2. Victim is guided to install a malicious .APK file.\n3. App prompts user to enable Accessibility Service permissions.\n4. Screen freezes or goes dark while the attacker remotely transfers funds.",
            },
            {
                "title": "⛔ Strict Prohibition",
                "text": "Never download or install .APK files from links sent via messaging apps or external websites outside Google Play Store or Apple App Store.",
            },
        ],
        "key_takeaways": [
            "Download applications exclusively from verified official app stores.",
            "Never grant Accessibility Service permissions to unverified applications.",
            "If your screen freezes unexpectedly and you suspect unauthorized access, immediately shut down the device or toggle Airplane Mode.",
        ],
    },
    {
        "id": 10,
        "title": "Understanding Social Engineering: The Psychology of Deception",
        "category": "Scams",
        "author": "PsychSec Research",
        "author_role": "Human Factors Analyst",
        "date": "14 Feb 2026",
        "read_time": "4 min read",
        "desc": "Mastering the defense against cyber attacks targeting human emotions rather than software flaws.",
        "image": "https://images.unsplash.com/photo-1509062522246-3755977927d7?auto=format&fit=crop&q=80&w=1200",
        "summary": "Social engineering targets cognitive vulnerabilities—fear, greed, empathy, or artificial urgency—to manipulate victims into bypassing their own security guidelines.",
        "sections": [
            {
                "title": "1. Emotional Levers Exploited by Scammers",
                "text": "• Urgency: 'Your account will be terminated in 2 hours!'\n• Greed: 'Congratulations! You won a $10,000 lottery!'\n• Fear: 'You are implicated in a federal money laundering warrant!'",
            },
            {
                "title": "💡 The 10-Second Pause Rule",
                "text": "Whenever an incoming message creates acute anxiety, excessive excitement, or frantic haste, deliberately pause for 10 seconds to evaluate the request logically.",
            },
        ],
        "key_takeaways": [
            "Maintain situational awareness whenever emotion-triggering messages arrive.",
            "Never share credentials or OTPs with unknown contacts online.",
            "Independently cross-check claims with official published channels.",
        ],
    },
    {
        "id": 11,
        "title": "Safe Online Shopping: How to Avoid Fake Merchant Scams",
        "category": "Privacy",
        "author": "Consumer Cyber Defense",
        "author_role": "E-Commerce Security Analyst",
        "date": "14 Feb 2026",
        "read_time": "3 min read",
        "desc": "Essential verification tips before making payments to online vendors.",
        "image": "https://images.unsplash.com/photo-1556742049-0a67c5574f73?auto=format&fit=crop&q=80&w=1200",
        "summary": "While online shopping offers immense convenience, fraudsters frequently erect cloned store pages and social commerce profiles to harvest payment cards or vanish after receiving direct transfers.",
        "sections": [
            {
                "title": "1. Scrutinize Seller Credibility",
                "text": "Inspect page rename history, follower count quality, page creation date, and verify the seller's account details against merchant fraud databases before sending money.",
            },
            {
                "title": "🛒 Secure Payment Channels",
                "text": "Opt for escrow-protected platforms (e.g. Amazon, Shopee, Lazada) offering buyer protection guarantees or select Cash on Delivery where feasible.",
            },
        ],
        "key_takeaways": [
            "Be skeptical of prices that are drastically lower than market rates.",
            "Verify seller name and bank account against consumer scam registries.",
            "Avoid private wire transfers outside established shopping platforms.",
        ],
    },
    {
        "id": 12,
        "title": "Managing Browser Cookies for Maximum Privacy",
        "category": "Privacy",
        "author": "DataGuard",
        "author_role": "Privacy Engineer",
        "date": "15 Feb 2026",
        "read_time": "3 min read",
        "desc": "Understand how browser cookies function and how clearing them prevents unwanted tracking.",
        "image": "https://images.unsplash.com/photo-1516321497487-e288fb19713f?auto=format&fit=crop&q=80&w=1200",
        "summary": "Cookies are small files stored on your device by websites. While essential for maintaining login sessions, third-party cookies are extensively used to track user behavior across the web for targeted advertising.",
        "sections": [
            {
                "title": "1. Regularly Clear Cookies and Cache",
                "text": "Clearing cookies, using Incognito/Private browsing, and utilizing privacy extensions minimizes the risk of session hijacking and persistent tracking across sites.",
                "callout": {
                    "type": "tip",
                    "title": "💡 Privacy-First Browsers",
                    "text": "Consider privacy-oriented browsers such as Brave or Firefox to automatically block tracking scripts and fingerprinting.",
                },
            }
        ],
        "key_takeaways": [
            "Opt for essential cookies only when cookie consent banners appear.",
            "Periodically clear browsing history and cached data.",
            "Enable third-party cookie blocking in your browser settings.",
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
    
    # 1. Fix commas in IP address from OCR errors (e.g. 105,186.250,56:38301 -> 105.186.250.56:38301)
    cleaned = re.sub(r'(\d{1,3})\s*,\s*(\d{1,3})', r'\1.\2', text)
    
    # 2. Search text fragments that look like URLs
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
            
        # Normalize protocol scheme
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
            
        # Separate domain and path
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
                
        # Domain part: spaces, commas, or semicolons -> dot '.'
        domain_part = re.sub(r'[\s,;]+', '.', domain_part).strip('.')
        domain_part = re.sub(r'\.+', '.', domain_part)
        
        # In Path component:
        if path_part:
            path_part = re.sub(r'\s*([.:/?=&%#_~-])\s*', r'\1', path_part)
            path_part = re.sub(rf'/([^\s/]+)\s+({exts})(?=[\s?#]|$)', r'/\1.\2', path_part, flags=re.IGNORECASE)
            path_part = re.sub(rf'\s+({exts})(?=[\s?#]|$)', r'.\1', path_part, flags=re.IGNORECASE)
            
            # Terminate at other table columns (e.g. file extension followed by space)
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
        raise ValueError("Only image files are supported (.jpg, .png, .webp)")
    if uploaded_file.size > MAX_QR_IMAGE_BYTES:
        raise ValueError("Image file size must not exceed 10 MB")

    file_bytes = np.frombuffer(uploaded_file.read(), dtype=np.uint8)
    image = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("Unable to open image file")

    # 1. Check QR Code via OpenCV
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

    # 2. Fallback: OCR text extraction from image (Enhanced 5-layer OCR Pipeline)
    try:
        from detector.ocr_pipeline import extract_urls_from_image_pipeline
        pipeline_urls = extract_urls_from_image_pipeline(image)
        if pipeline_urls:
            print(f"[OCR Pipeline] Extracted {len(pipeline_urls)} URL(s): {pipeline_urls}")
            return (pipeline_urls if len(pipeline_urls) > 1 else pipeline_urls[0]), "image_ocr"
    except Exception as e:
        print(f"[OCR Pipeline Warning] OCR Pipeline fallback triggered: {e}")

    try:
        reader = get_easyocr_reader()
        # Pass 1: Original image, refined threshold for dots and punctuation
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
        print(f"[EasyOCR Pass 1] Detected text: '{full_text}'")
        urls = extract_urls_from_text(full_text)
        if urls:
            print(f"[EasyOCR] Extracted URL: {urls[0]}")
            return (urls if len(urls) > 1 else urls[0]), "image_ocr"

        # Pass 2: Super-Resolution (2.5x Lanczos4) + Grayscale + Sharpening
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
        print(f"[EasyOCR Pass 2] Enhanced text: '{full_text_2}'")
        urls_2 = extract_urls_from_text(full_text_2)
        if urls_2:
            print(f"[EasyOCR] Extracted URL (Pass 2): {urls_2[0]}")
            return (urls_2 if len(urls_2) > 1 else urls_2[0]), "image_ocr"
    except Exception as e:
        print(f"[EasyOCR Error] OCR error: {e}")

    raise ValueError("No QR Code or URL text detected in the uploaded image")


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
        error = "Invalid email or password"
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
            error = "Please fill in all required fields"
        elif password != password_confirm:
            error = "Passwords do not match"
        elif len(password) < 8:
            error = "Password must be at least 8 characters long"
        elif User.objects.filter(username=email).exists():
            error = "This email is already registered"
        else:
            first_name, _, last_name = name.partition(" ")
            User.objects.create_user(
                username=email,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
            )
            messages.success(request, "Registration successful! Please log in.")
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
    period_labels = {"7": "Last 7 Days", "30": "Last 30 Days", "all": "All Time"}
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
            trend_labels.append(f"Week {5 - index}")
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
    user_display_name = (active_user or {}).get("name", "System User")
    user_email = (active_user or {}).get("email", "")
    if is_admin_report:
        prepared_by = "PhishWise Administrator"
        report_number = f"PW-STAT-{timezone.now().strftime('%Y-%m')}"
    else:
        prepared_by = f"{user_display_name} ({user_email})" if user_email else user_display_name
        report_number = f"PW-USR-{timezone.now().strftime('%Y-%m')}"

    five_levels = [
        {
            "key": "safe",
            "name": "Safe",
            "color": "#059669",
            "score_range": "0 - 20",
            "count": safe_exact_count,
            "percentage": round(safe_exact_count * 100 / total_scans, 1) if total_scans else 0,
            "action": "Safe to browse, but always verify domain name",
        },
        {
            "key": "mostly_safe",
            "name": "Mostly Safe",
            "color": "#0d9488",
            "score_range": "21 - 40",
            "count": mostly_safe_count,
            "percentage": round(mostly_safe_count * 100 / total_scans, 1) if total_scans else 0,
            "action": "Verify source before entering sensitive information",
        },
        {
            "key": "warning",
            "name": "Caution",
            "color": "#d97706",
            "score_range": "41 - 60",
            "count": warning_count,
            "percentage": round(warning_count * 100 / total_scans, 1) if total_scans else 0,
            "action": "Avoid submitting sensitive personal credentials",
        },
        {
            "key": "mostly_danger",
            "name": "High Risk",
            "color": "#ea580c",
            "score_range": "61 - 80",
            "count": mostly_danger_count,
            "percentage": round(mostly_danger_count * 100 / total_scans, 1) if total_scans else 0,
            "action": "Do not open link or download files from this site",
        },
        {
            "key": "danger",
            "name": "Dangerous",
            "color": "#e11d48",
            "score_range": "81 - 100",
            "count": danger_exact_count,
            "percentage": round(danger_exact_count * 100 / total_scans, 1) if total_scans else 0,
            "action": "Halt usage immediately and do not download files",
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
        "source_labels": ["Direct Link", "Camera QR Code", "Image QR Code", "Image OCR Text"],
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
    ssl_sub = source.get("ssl_sub") or "No certificate details found"
    domain_age = source.get("domain_age") or "No data"
    domain_sub = source.get("domain_sub") or "No domain registration records found"
    location = source.get("location") or "Unknown"
    # Classify domain age category from scan_url_logic results
    # Use domain_age_days (int) if available, otherwise fallback from domain_sub text
    _age_days = source.get("domain_age_days")
    if _age_days is not None:
        _age_days = int(_age_days)
        if _age_days <= 30:
            domain_age_category = "new"          # Risky - newly registered domain
        elif _age_days <= 180:
            domain_age_category = "recent"       # Caution - relatively new domain
        else:
            domain_age_category = "established"  # Established domain
    elif domain_age in ("Not Available", "No data", ""):
        domain_age_category = "unknown"
    elif "newly" in str(domain_sub).lower() or "day" in str(domain_sub).lower():
        domain_age_category = "new"
    elif "established" in str(domain_sub).lower():
        domain_age_category = "established"
    else:
        domain_age_category = "unknown"
    has_redirection = bool(source.get("has_redirection"))
    is_blacklisted = bool(source.get("is_blacklisted"))
    google_safe = bool(source.get("google_safe", True))
    url = source.get("url") or "URL not specified"

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
                "label": "Cannot inspect",
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
        confidence_text = "High Confidence"
    elif url_model_result.get("available"):
        confidence_text = "Moderate Confidence"
    else:
        confidence_text = "Preliminary Assessment"

    if latest_scan and latest_scan.timestamp:
        scan_time_text = timezone.localtime(latest_scan.timestamp).strftime("%H:%M:%S")
    else:
        scan_time_text = timezone.localtime(timezone.now()).strftime("%H:%M:%S")

    risk_guidelines = {
        "safe": {
            "summary": "No prominent malicious indicators detected at this time",
            "action": "Ensure the domain matches the official service before entering credentials",
        },
        "mostly_safe": {
            "summary": "Low risk detected; URL and server structure appear mostly standard",
            "action": "Confirm the link source before proceeding with transactions",
        },
        "warning": {
            "summary": "Some suspicious indicators detected that require caution",
            "action": "Avoid submitting credentials or passwords until further verified",
        },
        "mostly_danger": {
            "summary": "Multiple risk indicators detected strongly pointing to malicious intent",
            "action": "Do not disclose personal data or download files from this website",
        },
        "danger": {
            "summary": "Clear threat patterns or active phishing/malware behavior identified",
            "action": "Stop using this link immediately. Do not browse or download files",
        },
    }
    guideline = risk_guidelines.get(status_key, risk_guidelines["danger"])
    result_summary = guideline["summary"]
    action_text = guideline["action"]

    # System history data (DomainStatistic and ScanHistory)
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
        ("safe", "Safe", "bg-emerald-100 text-emerald-700 border-emerald-200", "fa-solid fa-circle-check text-emerald-500"),
        ("mostly_safe", "Mostly Safe", "bg-teal-100 text-teal-700 border-teal-200", "fa-solid fa-circle-check text-teal-500"),
        ("warning", "Caution", "bg-amber-100 text-amber-700 border-amber-200", "fa-solid fa-triangle-exclamation text-amber-500"),
        ("mostly_danger", "High Risk", "bg-orange-100 text-orange-700 border-orange-200", "fa-solid fa-circle-xmark text-orange-500"),
        ("danger", "Dangerous", "bg-rose-100 text-rose-700 border-rose-200", "fa-solid fa-circle-xmark text-rose-500"),
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
                parts.append(f"{item['label']} {item['count']} time(s)")
        if domain_statistic and domain_statistic.approved_report_count > 0:
            parts.append(f"({domain_statistic.approved_report_count} reports approved)")
        domain_history_text = " ".join(parts) if parts else "No scan history recorded in system"
    else:
        domain_history_text = "No scan history recorded in system"

    if domain_statistic and domain_statistic.approved_report_count >= 3:
        phishwise_db = {
            "status": "danger",
            "label": "Risk History Detected",
            "desc": domain_history_text,
            "badge_class": "bg-rose-100 text-rose-700 border-rose-200",
            "icon_class": "fa-solid fa-circle-xmark text-red-500 text-[22px]",
        }
    elif status_counts.get("danger", 0) > 0 or status_counts.get("mostly_danger", 0) > 0 or (domain_statistic and domain_statistic.last_status in {"danger", "mostly_danger"}):
        phishwise_db = {
            "status": "danger",
            "label": "Risk History Detected",
            "desc": domain_history_text,
            "badge_class": "bg-rose-100 text-rose-700 border-rose-200",
            "icon_class": "fa-solid fa-circle-xmark text-red-500 text-[22px]",
        }
    elif status_counts.get("warning", 0) > 0 or (domain_statistic and domain_statistic.last_status == "warning"):
        phishwise_db = {
            "status": "warning",
            "label": "Caution",
            "desc": domain_history_text,
            "badge_class": "bg-amber-100 text-amber-700 border-amber-200",
            "icon_class": "fa-solid fa-triangle-exclamation text-amber-500 text-[22px]",
        }
    elif total_scans > 0:
        phishwise_db = {
            "status": "safe",
            "label": "Safe",
            "desc": domain_history_text,
            "badge_class": "bg-green-100 text-green-700 border-green-200",
            "icon_class": "fa-solid fa-circle-check text-green-500 text-[22px]",
        }
    else:
        phishwise_db = {
            "status": "neutral",
            "label": "First Scan",
            "desc": "No prior scan history recorded in system",
            "badge_class": "bg-slate-100 text-slate-600 border-slate-200",
            "icon_class": "fa-solid fa-circle-info text-blue-500 text-[22px]",
        }

    # Redirection data
    redirect_count = int(source.get("redirect_count", 1 if has_redirection else 0))
    redirect_chain = source.get("redirect_chain") or ([url] if not has_redirection else [url, url])
    if redirect_count > 0:
        redirect_desc = f"This link redirects through {redirect_count} intermediate hop(s) before reaching the destination, a technique frequently used to evade detection."
    else:
        redirect_desc = "This link navigates directly to the destination without redirection."

    # 11 URL Structure Features
    from detector.services import extract_url_features
    features_dict = source.get("url_features") or extract_url_features(url)
    url_len = features_dict.get("url_length", len(url))
    url_features_details = [
        {
            "name": "url_length",
            "label": "URL Length",
            "value": f"{url_len} characters",
            "is_risky": url_len > 75,
            "desc": "Unusually long URL, often used to conceal the actual destination" if url_len > 75 else "URL length is within standard range",
        },
        {
            "name": "is_ip_address",
            "label": "IP Address as Hostname",
            "value": "Direct IP used" if features_dict.get("is_ip_address") else "Not detected (Standard domain)",
            "is_risky": bool(features_dict.get("is_ip_address")),
            "desc": "Direct IP address used instead of domain, often found on malicious servers" if features_dict.get("is_ip_address") else "Standard domain name used without direct IP",
        },
        {
            "name": "count_dots",
            "label": "Dot Count (.)",
            "value": f"{features_dict.get('count_dots', 0)} dot(s)",
            "is_risky": features_dict.get("count_dots", 0) > 3,
            "desc": "Multiple dots detected, possible complex subdomain spoofing" if features_dict.get("count_dots", 0) > 3 else "Dot count is within normal range",
        },
        {
            "name": "count_hyphens",
            "label": "Hyphen Count (-)",
            "value": f"{features_dict.get('count_hyphens', 0)} hyphen(s)",
            "is_risky": features_dict.get("count_hyphens", 0) > 2,
            "desc": "Multiple hyphens detected, commonly used in brand impersonation" if features_dict.get("count_hyphens", 0) > 2 else "Hyphen count is within normal range",
        },
        {
            "name": "count_at",
            "label": "At Symbol (@)",
            "value": f"Found {features_dict.get('count_at', 0)}" if features_dict.get("count_at", 0) > 0 else "None",
            "is_risky": features_dict.get("count_at", 0) > 0,
            "desc": "Contains @ symbol, which may cause browsers to ignore preceding text" if features_dict.get("count_at", 0) > 0 else "No @ symbol present in URL",
        },
        {
            "name": "count_question",
            "label": "Question Mark Count (?)",
            "value": f"{features_dict.get('count_question', 0)}",
            "is_risky": features_dict.get("count_question", 0) > 1,
            "desc": "Multiple query parameters detected" if features_dict.get("count_question", 0) > 1 else "Normal query parameter structure",
        },
        {
            "name": "count_equal",
            "label": "Equal Sign Count (=)",
            "value": f"{features_dict.get('count_equal', 0)}",
            "is_risky": features_dict.get("count_equal", 0) > 3,
            "desc": "Excessive parameter assignments detected" if features_dict.get("count_equal", 0) > 3 else "Normal parameter assignments",
        },
        {
            "name": "count_slash",
            "label": "Slash Count (/)",
            "value": f"{features_dict.get('count_slash', 0)}",
            "is_risky": features_dict.get("count_slash", 0) > 5,
            "desc": "Unusually deep path directory depth" if features_dict.get("count_slash", 0) > 5 else "Standard folder path structure",
        },
        {
            "name": "has_suspicious_keyword",
            "label": "Suspicious Keywords",
            "value": "Keywords detected" if features_dict.get("has_suspicious_keyword") else "No suspicious keywords",
            "is_risky": bool(features_dict.get("has_suspicious_keyword")),
            "desc": "Contains keywords like login, verify, account, update in URL" if features_dict.get("has_suspicious_keyword") else "No common phishing keywords detected",
        },
        {
            "name": "has_executable_extension",
            "label": "Dangerous File Extension",
            "value": "Dangerous extension detected" if features_dict.get("has_executable_extension") else "No dangerous extension",
            "is_risky": bool(features_dict.get("has_executable_extension")),
            "desc": "Points to executable or script files (.exe, .sh, .apk, etc.)" if features_dict.get("has_executable_extension") else "Standard web file extension",
        },
        {
            "name": "is_https",
            "label": "HTTPS Encryption",
            "value": "HTTPS Enabled (Encrypted)" if features_dict.get("is_https") else "HTTPS Not Used (Unencrypted)",
            "is_risky": not bool(features_dict.get("is_https")),
            "desc": "Connection is securely encrypted" if features_dict.get("is_https") else "Unencrypted connection, data can be intercepted",
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
            messages.error(request, "Please select a reason for the report.")
        else:
            try:
                create_site_report(user=request.user, url=url, reason=reason, details=details)
                messages.success(request, "Report submitted successfully and is pending administrator review.")
                return redirect("report")
            except ValueError as exc:
                messages.error(request, str(exc))
    return render(request, "report.html", {"current_user": current_user(request), "reasons": SuspiciousSiteReport.REASON_CHOICES, "my_reports": SuspiciousSiteReport.objects.filter(user=request.user)[:10]})


@require_POST
@staff_member_required(login_url="login")
def admin_review_report(request, report_id):
    report = SuspiciousSiteReport.objects.filter(pk=report_id).first()
    if not report:
        messages.error(request, "Report not found.")
    else:
        try:
            review_site_report(report, status=request.POST.get("status"), reviewer=request.user)
            messages.success(request, "Report status updated successfully.")
        except ValueError as exc:
            messages.error(request, str(exc))
    return redirect(f"{reverse('admin')}#reports")

def history_view(request):
    my_reports = [
        {
            "id": 1,
            "url": "http://scb-verify-login.com",
            "type": "Phishing",
            "date": "12 Feb 2026",
            "status": "Pending",
        },
        {
            "id": 2,
            "url": "https://free-iphone-15.net",
            "type": "Scam",
            "date": "10 Feb 2026",
            "status": "Verified",
        },
        {
            "id": 3,
            "url": "https://www.google.com",
            "type": "Other",
            "date": "05 Feb 2026",
            "status": "Rejected",
        },
        {
            "id": 4,
            "url": "http://bit.ly/fake-bank",
            "type": "Phishing",
            "date": "04 Feb 2026",
            "status": "Pending",
        },
        {
            "id": 5,
            "url": "https://secure-pay-web.com",
            "type": "Scam",
            "date": "03 Feb 2026",
            "status": "Verified",
        },
        {
            "id": 6,
            "url": "http://malware-site.net",
            "type": "Malware",
            "date": "02 Feb 2026",
            "status": "Pending",
        },
        {
            "id": 7,
            "url": "https://verify-account.io",
            "type": "Phishing",
            "date": "01 Feb 2026",
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
    # Fetch from DB first; fallback to ARTICLES list if empty
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
    # Try fetching from DB first
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
        messages.error(request, "Please enter both an article title and a description.")
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
    messages.success(request, f'Article "{title}" published successfully.')
    return redirect(f"{reverse('admin')}#knowledge")


@require_POST
@staff_member_required(login_url="login")
def article_edit_view(request, pk):
    article = KnowledgeArticle.objects.filter(pk=pk).first()
    if not article:
        messages.error(request, "Article not found.")
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
    messages.success(request, f'Article "{article.title}" updated successfully.')
    return redirect(f"{reverse('admin')}#knowledge")


@require_POST
@staff_member_required(login_url="login")
def article_delete_view(request, pk):
    article = KnowledgeArticle.objects.filter(pk=pk).first()
    if article:
        title = article.title
        article.delete()
        messages.success(request, f'Article "{title}" deleted successfully.')
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
        return JsonResponse({"success": False, "error": "Please select an image file."}, status=400)

    allowed_extensions = {".jpg", ".jpeg", ".png", ".webp", ".gif"}
    ext = os.path.splitext(uploaded_file.name)[1].lower()
    if ext not in allowed_extensions:
        return JsonResponse({"success": False, "error": "Only image formats (.jpg, .png, .webp, .gif) are supported."}, status=400)

    if uploaded_file.size > 10 * 1024 * 1024:
        return JsonResponse({"success": False, "error": "File size must not exceed 10MB."}, status=400)

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
                    # Single URL -> Scan immediately
                    url = all_urls[0]
                elif len(all_urls) > 1:
                    # Multiple URLs -> Store in session and show selection modal
                    request.session["pending_ocr_urls"] = all_urls
                    request.session["pending_source_type"] = source_type
                    request.session.modified = True
                    return redirect("home")
                else:
                    raise ValueError("No QR Code or URL text detected in the uploaded image")
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

        messages.error(request, "Please enter a URL or upload a QR Code image.")
        return redirect("home")

    return redirect("home")


def select_url_view(request):
    """View allowing user to select a URL when OCR detects multiple links in an image."""
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

    # GET - Display URL selection view
    pending_urls = request.session.get("pending_ocr_urls", [])
    if not pending_urls:
        messages.error(request, "No URL list found. Please try uploading the image again.")
        return redirect("home")

    return render(request, "select_url.html", {
        "urls": pending_urls,
        "url_count": len(pending_urls),
        "current_user": current_user(request),
    })

