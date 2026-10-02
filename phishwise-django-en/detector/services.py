import ipaddress
import logging
import pickle
import re
import socket
import ssl
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import pandas as pd
import requests
import torch
import torch.nn as nn
import whois
from django.conf import settings

from .risk_levels import classify_risk
from .virustotal import analyse_file_bytes

LOGGER = logging.getLogger(__name__)
ML_MODELS_DIR = Path(settings.BASE_DIR) / "detector" / "ml_models"
REQUEST_HEADERS = {"User-Agent": "PhishWise-Education/1.0"}
MAX_REDIRECTS = 5
MAX_HTML_BYTES = 2 * 1024 * 1024
MAX_VT_FILE_BYTES = 32 * 1024 * 1024
HTML_SEQUENCE_LENGTH = 250
RF_FEATURE_NAMES = [
    "url_length",
    "is_ip_address",
    "count_dots",
    "count_hyphens",
    "count_at",
    "count_question",
    "count_equal",
    "count_slash",
    "has_suspicious_keyword",
    "has_executable_extension",
    "is_https",
]

vocab = {"<PAD>": 0, "<UNK>": 1}
url_rf_model = None
bilstm_model = None
resources_loaded = False


class PhishingBiLSTM(nn.Module):
    def __init__(
        self, vocab_size=15000, embedding_dim=64, hidden_dim=128, output_dim=2
    ):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        self.lstm = nn.LSTM(
            embedding_dim,
            hidden_dim,
            num_layers=2,
            bidirectional=True,
            batch_first=True,
            dropout=0.3,
        )
        self.fc = nn.Linear(hidden_dim * 2, output_dim)

    def forward(self, text):
        embedded = self.embedding(text)
        lstm_out, _ = self.lstm(embedded)
        # Must match the global-average pooling used during Colab training.
        pooled = torch.mean(lstm_out, dim=1)
        return self.fc(pooled)


def load_resources():
    global vocab, url_rf_model, bilstm_model, resources_loaded
    if resources_loaded:
        return

    try:
        with open(ML_MODELS_DIR / "vocab_final.pkl", "rb") as file:
            vocab = pickle.load(file)
    except Exception:
        LOGGER.exception("Unable to load the HTML vocabulary")
        vocab = {"<PAD>": 0, "<UNK>": 1}

    try:
        with open(ML_MODELS_DIR / "url_random_forest_model.pt", "rb") as file:
            url_rf_model = pickle.load(file)
        trained_features = list(getattr(url_rf_model, "feature_names_in_", []))
        if trained_features and trained_features != RF_FEATURE_NAMES:
            raise ValueError(
                f"Random Forest expects {trained_features}, not {RF_FEATURE_NAMES}"
            )
    except Exception:
        LOGGER.exception("Unable to load the URL Random Forest model")
        url_rf_model = None

    try:
        weights = torch.load(
            ML_MODELS_DIR / "advanced_model_bi_lstm.pt",
            map_location=torch.device("cpu"),
            weights_only=True,
        )
        state_dict = (
            weights
            if "embedding.weight" in weights
            else weights.get("state_dict", weights)
        )
        bilstm_model = PhishingBiLSTM(
            vocab_size=state_dict["embedding.weight"].shape[0],
            embedding_dim=state_dict["embedding.weight"].shape[1],
            output_dim=state_dict["fc.weight"].shape[0],
        )
        bilstm_model.load_state_dict(state_dict, strict=True)
        bilstm_model.eval()
    except Exception:
        LOGGER.exception("Unable to load the HTML BiLSTM model")
        bilstm_model = None
    finally:
        resources_loaded = True


def normalize_url(url):
    normalized = str(url or "").strip()
    if not normalized:
        raise ValueError("URL is required")
    if not normalized.lower().startswith(("http://", "https://")):
        normalized = "http://" + normalized
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only valid HTTP and HTTPS URLs are supported")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not supported")
    return normalized


def _assert_public_destination(url):
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError("URL has no hostname")
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(
                parsed.hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
            )
        }
    except socket.gaierror as exc:
        raise ValueError("The hostname could not be resolved") from exc
    if any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("Private or non-public network destinations are blocked")


def _safe_get(url, timeout=5, stream=False):
    current_url = normalize_url(url)
    chain = [current_url]
    for _ in range(MAX_REDIRECTS + 1):
        _assert_public_destination(current_url)
        response = requests.get(
            current_url,
            allow_redirects=False,
            timeout=timeout,
            headers=REQUEST_HEADERS,
            stream=stream,
        )
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            if not location:
                return response, current_url, chain
            current_url = normalize_url(urljoin(current_url, location))
            chain.append(current_url)
            continue
        return response, current_url, chain
    raise ValueError("The URL redirects too many times")


def resolve_final_url(initial_url, return_details=False):
    initial_url = normalize_url(initial_url)
    try:
        response, final_url, chain = _safe_get(initial_url, stream=True)
        response.close()
        redirect_count = max(0, len(chain) - 1)
        has_redirection = redirect_count > 0
        if return_details:
            return final_url, has_redirection, redirect_count, chain
        return final_url, has_redirection
    except (requests.RequestException, ValueError) as exc:
        LOGGER.warning("Unable to resolve %s: %s", initial_url, exc)
        if return_details:
            return initial_url, False, 0, [initial_url]
        return initial_url, False


def _hostname(url):
    return urlparse(url).hostname or ""


def fetch_domain_age_days(url):
    try:
        domain = _hostname(url).lower()
        if domain.startswith("www."):
            domain = domain[4:]
        record = whois.whois(domain)
        creation_date = record.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.now() - creation_date.replace(tzinfo=None)).days
            if age_days < 180:
                return (
                    age_days,
                    f"{age_days} days",
                    f"⚠️ Newly registered domain ({age_days} days old)",
                )
            return (
                age_days,
                f"{age_days // 365} yr {(age_days % 365) // 30} mo",
                "🟢 Established domain with active history",
            )
    except Exception:
        pass
    return None, "Not Available", "No domain registration history found"


def fetch_ssl_status(url):
    if urlparse(url).scheme != "https":
        return False, "Not Secure", "❌ URL does not use HTTPS"
    try:
        hostname = _hostname(url)
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
                issuer = dict(x[0] for x in cert["issuer"]).get(
                    "commonName", "Unknown CA"
                )
                return True, issuer, "🔒 HTTPS Certificate Verified"
    except Exception:
        return False, "Not Secure", "❌ Unable to verify HTTPS certificate"


def fetch_ip_location(url):
    try:
        ip_address = socket.gethostbyname(_hostname(url))
        response = requests.get(
            f"https://ipapi.co/{ip_address}/json/",
            timeout=3,
            headers=REQUEST_HEADERS,
        )
        response.raise_for_status()
        data = response.json()
        return f"{data.get('city', 'Unknown')}, {data.get('country_name', 'Unknown')}"
    except Exception:
        return "Unknown Location"


def extract_url_features(url):
    url = str(url).strip()
    lowered = url.lower()
    ip_pattern = re.search(
        r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}"
        r"([01]?\d\d?|2[0-4]\d|25[0-5])",
        url,
    )
    suspicious_keywords = [
        "login",
        "secure",
        "update",
        "banking",
        "account",
        "verify",
        "free",
        "webscr",
        "ebayisapi",
    ]
    executable_extensions = [
        ".sh",
        ".exe",
        ".arm7",
        ".bin",
        ".zip",
        ".rar",
        ".elf",
        ".apk",
    ]
    return {
        "url_length": len(url),
        "is_ip_address": int(bool(ip_pattern)),
        "count_dots": url.count("."),
        "count_hyphens": url.count("-"),
        "count_at": url.count("@"),
        "count_question": url.count("?"),
        "count_equal": url.count("="),
        "count_slash": url.count("/"),
        "has_suspicious_keyword": int(
            any(keyword in lowered for keyword in suspicious_keywords)
        ),
        "has_executable_extension": int(
            any(extension in lowered for extension in executable_extensions)
        ),
        "is_https": int(lowered.startswith("https")),
    }


def tokenize_html(html_code, max_len=HTML_SEQUENCE_LENGTH):
    cleaned = re.sub(r"""[<>/\\{}()='"]""", " ", html_code)
    tokens = cleaned.lower().split()
    tokens = [
        token for token in tokens if token.isalpha() and 2 <= len(token) <= 20
    ][:max_len]
    if not tokens:
        return None
    unknown_id = vocab.get("<UNK>", 1)
    pad_id = vocab.get("<PAD>", 0)
    numerical = [vocab.get(token, unknown_id) for token in tokens]
    numerical.extend([pad_id] * (max_len - len(numerical)))
    return torch.tensor([numerical], dtype=torch.long)


def process_html_content(url, max_len=HTML_SEQUENCE_LENGTH):
    try:
        res = _safe_get(url)
        response = res[0] if isinstance(res, (tuple, list)) else res
        if response.status_code != 200:
            return None
        content_type = response.headers.get("Content-Type", "").lower()
        if content_type and "html" not in content_type:
            return None
        if len(response.content) > MAX_HTML_BYTES:
            return None
        return tokenize_html(response.text, max_len=max_len)
    except (requests.RequestException, ValueError):
        return None


def inspect_download_with_virustotal(url):
    result = {
        "download_detected": False,
        "download_name": "",
        "download_size": 0,
        "status": "not_applicable",
        "message": "The destination is a web page, not a downloadable file",
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
    response = None
    try:
        response, final_url, _ = _safe_get(url, timeout=10, stream=True)
        if response.status_code != 200:
            return result

        content_type = response.headers.get("Content-Type", "").split(";")[0].lower()
        disposition = response.headers.get("Content-Disposition", "").lower()
        path_name = Path(urlparse(final_url).path).name
        extension = Path(path_name).suffix.lower()
        file_extensions = {
            ".exe", ".dll", ".msi", ".apk", ".jar", ".zip", ".rar", ".7z",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".scr", ".bat", ".cmd", ".ps1", ".sh", ".bin", ".elf", ".arm7",
            ".js", ".vbs",
        }
        is_download = (
            "attachment" in disposition
            or extension in file_extensions
            or (
                content_type
                and content_type not in {"text/html", "application/xhtml+xml"}
                and not content_type.startswith("image/")
            )
        )
        if not is_download:
            return result

        result["download_detected"] = True
        result["download_name"] = path_name or "downloaded-file"
        declared_size = int(response.headers.get("Content-Length", 0) or 0)
        if declared_size > MAX_VT_FILE_BYTES:
            result.update(
                {
                    "status": "too_large",
                    "message": "The downloaded file is larger than the 32 MB scan limit",
                    "download_size": declared_size,
                }
            )
            return result

        chunks = []
        downloaded = 0
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            downloaded += len(chunk)
            if downloaded > MAX_VT_FILE_BYTES:
                result.update(
                    {
                        "status": "too_large",
                        "message": "The downloaded file is larger than the 32 MB scan limit",
                        "download_size": downloaded,
                    }
                )
                return result
            chunks.append(chunk)

        vt_result = analyse_file_bytes(b"".join(chunks), result["download_name"], url=final_url)
        result.update(vt_result)
        result["download_detected"] = True
        result["download_name"] = vt_result.get("file_name") or result["download_name"]
        result["download_size"] = downloaded
        return result
    except (requests.RequestException, ValueError, OSError) as exc:
        # Domain and SSL verification logic
        # Domain and SSL verification logic
        try:
            from .virustotal import _get_url_report, _stats_result
            path_name = Path(urlparse(url).path).name
            extension = Path(path_name).suffix.lower()
            if extension in {".exe", ".dll", ".apk", ".zip", ".rar", ".sh", ".bin", ".js", ".vbs", ".scr"}:
                url_rep, url_stats = _get_url_report(url)
                if url_stats:
                    vt_result = _stats_result(url_stats, "", path_name, community_score=url_rep)
                    result.update(vt_result)
                    result["download_detected"] = True
                    result["download_name"] = path_name
                    return result
        except Exception:
            pass

        if result["download_detected"]:
            result.update(
                {"status": "error", "message": f"Unable to inspect download: {exc}"}
            )
        return result
    finally:
        if response is not None:
            response.close()


def _predict_model_risks(url, include_details=False):
    risks = []
    details = {
        "url_model": {"available": False, "risk_score": None},
        "content_model": {"available": False, "risk_score": None},
    }
    if url_rf_model is not None:
        try:
            features = pd.DataFrame(
                [extract_url_features(url)], columns=RF_FEATURE_NAMES
            )
            risk = float(url_rf_model.predict_proba(features)[0][1])
            risks.append(risk)
            details["url_model"] = {"available": True, "risk_score": risk}
        except Exception:
            LOGGER.exception("Random Forest inference failed for %s", url)

    html_tensor = process_html_content(url)
    if html_tensor is not None and bilstm_model is not None:
        try:
            with torch.no_grad():
                probabilities = torch.softmax(bilstm_model(html_tensor), dim=1)[0]
            risk = float(probabilities[1].item())
            risks.append(risk)
            details["content_model"] = {"available": True, "risk_score": risk}
        except Exception:
            LOGGER.exception("BiLSTM inference failed for %s", url)
    if include_details:
        return {"risks": risks, **details}
    return risks


def scan_url_logic(url):
    load_resources()
    resolved = resolve_final_url(url, return_details=True)
    if isinstance(resolved, tuple) and len(resolved) == 4:
        target_url, has_redirection, redirect_count, redirect_chain = resolved
    elif isinstance(resolved, tuple) and len(resolved) >= 2:
        target_url, has_redirection = resolved[0], resolved[1]
        redirect_count = 1 if has_redirection else 0
        redirect_chain = [url, target_url] if has_redirection else [url]
    else:
        target_url = str(resolved)
        has_redirection = False
        redirect_count = 0
        redirect_chain = [target_url]

    age_days, domain_age, domain_sub = fetch_domain_age_days(target_url)
    has_ssl, ssl_title, ssl_sub = fetch_ssl_status(target_url)
    location = fetch_ip_location(target_url)
    vt_result = inspect_download_with_virustotal(target_url)

    model_prediction = _predict_model_risks(target_url, include_details=True)
    # Domain and SSL verification logic
    if isinstance(model_prediction, dict):
        risks = model_prediction["risks"]
        model_results = {
            "url_model": model_prediction["url_model"],
            "content_model": model_prediction["content_model"],
        }
    else:
        risks = model_prediction
        model_results = {
            "url_model": {
                "available": len(risks) >= 1,
                "risk_score": risks[0] if risks else None,
            },
            "content_model": {
                "available": len(risks) >= 2,
                "risk_score": risks[1] if len(risks) >= 2 else None,
            },
        }
    # Unknown is deliberately neutral, not silently classified as safe.
    accumulated_risk = round(sum(risks) / len(risks) * 100) if risks else 50
    url_features = extract_url_features(target_url)

    # High-confidence rules from the final Colab pipeline protect obvious cases
    # that the small URL model does not score strongly enough on its own.
    if (
        url_features["is_ip_address"]
        and url_features["has_executable_extension"]
    ):
        accumulated_risk = max(accumulated_risk, 100)
    elif (
        url_features["has_suspicious_keyword"]
        and not url_features["is_https"]
    ):
        accumulated_risk = max(accumulated_risk, 95)

    if age_days is not None and age_days <= 30:
        accumulated_risk += 40
    elif age_days is not None and age_days <= 180:
        accumulated_risk += 20
    if not has_ssl:
        accumulated_risk += 30
    if url_features["has_executable_extension"] or ".scr" in target_url.lower():
        accumulated_risk += 20
    if vt_result["risk_score"] is not None:
        accumulated_risk = max(accumulated_risk, vt_result["risk_score"])
    accumulated_risk = min(100, accumulated_risk)

    safe_score = 100 - accumulated_risk
    status = classify_risk(accumulated_risk)["key"]
    return {
        "url": target_url,
        "score": safe_score,
        "status": status,
        "ssl_title": ssl_title,
        "ssl_sub": ssl_sub,
        "domain_age": domain_age,
        "domain_age_days": age_days,  # Domain and SSL verification logic
        "domain_sub": domain_sub,
        "ai_risk_score": accumulated_risk,
        "model_results": model_results,
        "url_features": url_features,
        # These are local assessment fields, not external blacklist/API results.
        "is_blacklisted": vt_result["status"] in {"danger", "high_risk"},
        "google_safe": status != "danger",
        "location": location,
        "has_redirection": has_redirection,
        "redirect_count": redirect_count,
        "redirect_chain": redirect_chain,
        "download_detected": vt_result["download_detected"],
        "download_name": vt_result["download_name"],
        "download_size": vt_result["download_size"],
        "virustotal": vt_result,
    }
