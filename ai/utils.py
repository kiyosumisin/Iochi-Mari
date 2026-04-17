from urllib.parse import urlparse
import re

SUSPICIOUS_TLDS = {
    "xyz", "top", "vip", "bet", "casino", "site", "online", "club",
    "tk", "ml", "ga", "cf", "pw", "gq", "cfd", "sbs", "cyou", "icu",
    "monster", "digital", "rest", "cam", "beauty", "hair", "buzz",
}


def parse_domain(url: str):
    """
    Trả về (hostname, tld, subdomain_count).
    Dùng parsed.hostname thay vì netloc để loại bỏ port.
    """
    try:
        parsed = urlparse(url)
        
        hostname = (parsed.hostname or "").lower()
        parts = hostname.split(".")
        tld = parts[-1] if len(parts) > 1 else ""
        subdomains = max(len(parts) - 2, 0)
        return hostname, tld, subdomains
    except Exception:
        return "", "", 0


def is_ip_address(url: str) -> bool:
    """Kiểm tra URL dùng IP thay vì domain name."""
    try:
        hostname = urlparse(url).hostname or ""
        # IPv4
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname):
            return True
        # IPv6 
        if ":" in hostname:
            return True
    except Exception:
        pass
    return False


def count_digits(text: str) -> int:
    return sum(c.isdigit() for c in text)


def count_special(text: str) -> int:
    """
    Đếm ký tự đặc biệt liên quan đến phishing:
    - Ký tự gốc: - _ @
    - Thêm: % (URL encoding), = (key=value), ~ ! các dấu hiệu bất thường
    """
    return len(re.findall(r"[-_@%=~!]", text))


def count_url_encoded(text: str) -> int:
    """Đếm số lần xuất hiện URL encoding (%XX) — dấu hiệu obfuscation."""
    return len(re.findall(r"%[0-9a-fA-F]{2}", text))