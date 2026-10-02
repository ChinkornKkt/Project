import hashlib
import time

import requests
from django.conf import settings

VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_TIMEOUT = 15


def _empty_result(status="unavailable", message="VirusTotal is not configured"):
    return {
        "status": status,
        "message": message,
        "risk_score": None,
        "community_score": None,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "total_engines": 0,
        "sha256": "",
        "file_name": "",
    }


def _headers():
    return {"x-apikey": settings.VIRUSTOTAL_API_KEY}


def _stats_result(stats, sha256, file_name, community_score=None):
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    total = sum(int(value) for value in stats.values())

    if malicious >= 3:
        status, risk = "danger", 100
        message = f"VirusTotal detected this as malicious by {malicious} security vendors"
    elif malicious:
        status, risk = "high_risk", 75
        message = f"VirusTotal detected this as malicious by {malicious} security vendors"
    elif suspicious:
        status, risk, message = (
            "suspicious",
            40,
            f"VirusTotal marked this suspicious by {suspicious} security vendors",
        )
    elif total:
        status, risk, message = (
            "clean",
            0,
            "No VirusTotal security vendor detected this as malicious",
        )
    else:
        status, risk, message = (
            "pending",
            None,
            "VirusTotal analysis has not produced a verdict yet",
        )

    return {
        "status": status,
        "message": message,
        "risk_score": risk,
        "community_score": community_score,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": total,
        "sha256": sha256,
        "file_name": file_name,
    }


def _get_url_report(url):
    """ดึงข้อมูล Community Score และ Stats จาก URL บน VirusTotal (ถ้ามี)"""
    if not url or not settings.VIRUSTOTAL_API_KEY:
        return None, None
    import base64
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(
            f"{VT_API_BASE}/urls/{url_id}",
            headers=_headers(),
            timeout=VT_TIMEOUT,
        )
        if response.status_code == 200:
            attributes = response.json().get("data", {}).get("attributes", {})
            return attributes.get("reputation", None), attributes.get("last_analysis_stats", {})
    except Exception:
        pass
    return None, None


def _get_file_report(sha256, file_name, url=None):
    response = requests.get(
        f"{VT_API_BASE}/files/{sha256}",
        headers=_headers(),
        timeout=VT_TIMEOUT,
    )
    if response.status_code == 404:
        # หากไม่พบไฟล์ แต่มี URL ลองดึงผลของ URL
        if url:
            url_reputation, url_stats = _get_url_report(url)
            if url_stats:
                return _stats_result(url_stats, sha256, file_name, community_score=url_reputation)
        return None
    response.raise_for_status()
    attributes = response.json().get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    community_score = attributes.get("reputation", None)
    if url:
        url_reputation, url_stats = _get_url_report(url)
        if community_score is None and url_reputation is not None:
            community_score = url_reputation
        # หากผลสแกน URL บน VirusTotal พบว่าอันตรายมากกว่า ให้ใช้ผลสแกนที่ครอบคลุมกว่า
        if url_stats and url_stats.get("malicious", 0) > stats.get("malicious", 0):
            stats = url_stats
            if url_reputation is not None:
                community_score = url_reputation
    return _stats_result(stats, sha256, file_name, community_score=community_score)


def _upload_and_wait(file_bytes, file_name, sha256):
    response = requests.post(
        f"{VT_API_BASE}/files",
        headers=_headers(),
        files={"file": (file_name, file_bytes)},
        timeout=VT_TIMEOUT,
    )
    response.raise_for_status()
    analysis_id = response.json()["data"]["id"]

    for _ in range(settings.VIRUSTOTAL_POLL_ATTEMPTS):
        time.sleep(settings.VIRUSTOTAL_POLL_SECONDS)
        analysis = requests.get(
            f"{VT_API_BASE}/analyses/{analysis_id}",
            headers=_headers(),
            timeout=VT_TIMEOUT,
        )
        analysis.raise_for_status()
        attributes = analysis.json()["data"]["attributes"]
        if attributes.get("status") == "completed":
            community_score = attributes.get("reputation", None)
            return _stats_result(
                attributes.get("stats", {}), sha256, file_name, community_score=community_score
            )

    result = _empty_result(
        "pending",
        "The file was submitted to VirusTotal and is still being analysed",
    )
    result.update({"sha256": sha256, "file_name": file_name})
    return result


def analyse_file_bytes(file_bytes, file_name, url=None):
    if not settings.VIRUSTOTAL_API_KEY:
        result = _empty_result(
            "not_configured",
            "Set VIRUSTOTAL_API_KEY to enable external file scanning",
        )
        result["file_name"] = file_name
        return result

    sha256 = hashlib.sha256(file_bytes).hexdigest()
    try:
        existing = _get_file_report(sha256, file_name, url=url)
        if existing is not None:
            return existing
        if not settings.VIRUSTOTAL_UPLOAD_UNKNOWN_FILES:
            result = _empty_result(
                "unknown",
                "VirusTotal has no report for this hash; automatic upload is disabled",
            )
            result.update({"sha256": sha256, "file_name": file_name})
            return result
        return _upload_and_wait(file_bytes, file_name, sha256)
    except (requests.RequestException, KeyError, TypeError, ValueError) as exc:
        result = _empty_result(
            "error", f"VirusTotal request failed: {exc}"
        )
        result.update({"sha256": sha256, "file_name": file_name})
        return result
