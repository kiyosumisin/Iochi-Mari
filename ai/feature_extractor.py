from urllib.parse import urlparse, unquote, parse_qs
from ai.entropy import shannon_entropy
from ai.utils import parse_domain, count_digits, count_special, count_url_encoded, is_ip_address, SUSPICIOUS_TLDS


def extract_features(url: str, include_page: bool = False) -> dict:
    """
    Trích xuất feature từ URL.

    Args:
        url          : URL cần phân tích.
        include_page : Nếu True, fetch trang và thêm feature nội dung HTML.
                       Chậm hơn (~vài giây) nhưng chính xác hơn đáng kể.
    """
    if not url or not isinstance(url, str):
        raise ValueError(f"URL không hợp lệ: {url!r}")

    url = url.strip()
    parsed = urlparse(url)
    decoded = unquote(url)

    domain, tld, subdomains = parse_domain(url)

    try:
        num_params = len(parse_qs(parsed.query)) if parsed.query else 0
    except Exception:
        num_params = 0

    features = {
        # URL features
        "url_length": len(url),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
        "num_params": num_params,
        "has_https": int(parsed.scheme == "https"),

        # Domain features
        "domain_length": len(domain),
        "subdomain_depth": subdomains,
        "tld_suspicious": int(tld in SUSPICIOUS_TLDS),

        # Character features
        "num_digits": count_digits(decoded),
        "num_special": count_special(decoded),
        "num_url_encoded": count_url_encoded(url),
        "entropy": shannon_entropy(domain),

        # Structural
        "path_depth": parsed.path.count("/"),
        "is_ip_address": int(is_ip_address(url)),
    }

    if include_page:
        from ai.page_analyzer import analyze_page
        page_features = analyze_page(url)
        features.update(page_features)

    return features