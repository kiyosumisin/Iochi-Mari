"""
page_analyzer.py
----------------
Fetch page content and extract additional features for phishing / malicious URL detection.

Features returned:
  fetch_success       : 1 if fetch succeeded, 0 on error/timeout
  redirect_count      : number of redirects followed
  domain_changed      : 1 if final domain differs from original (suspicious redirect)
  has_password_input  : 1 if page contains <input type="password">
  has_login_form      : 1 if a form contains a password input
  external_form_action: 1 if a form submits to a different domain
  external_link_ratio : ratio of external links to total links
  hidden_iframe_count : number of hidden iframes (display:none / visibility:hidden)
  script_count        : number of <script> tags
  meta_refresh        : 1 if page has a meta refresh (auto-redirect)
  title_domain_match  : 1 if the domain appears in <title>
  favicon_external    : 1 if favicon is loaded from a different domain
  copyright_mismatch  : 1 if footer copyright mentions a brand not in the domain
"""

import json
import logging
import logging.handlers
import re
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Page content logger — writes one JSON record per fetched page
# ---------------------------------------------------------------------------
_PAGE_LOG_PATH = Path(__file__).resolve().parent / "logs" / "page_content.log"
_page_logger: logging.Logger | None = None


def _get_page_logger() -> logging.Logger:
    """
    Returns a dedicated logger that writes structured JSON records to
    logs/page_content.log (rotating at 10 MB, keeping 5 backups).
    Created once, reused on subsequent calls.
    """
    global _page_logger
    if _page_logger is not None:
        return _page_logger

    _PAGE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    pl = logging.getLogger("ai.page_content")
    pl.setLevel(logging.INFO)
    pl.propagate = False  # don't bubble up to root logger

    handler = logging.handlers.RotatingFileHandler(
        _PAGE_LOG_PATH,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(message)s"))  # raw JSON lines
    pl.addHandler(handler)

    _page_logger = pl
    return _page_logger


def _log_page(
    url: str,
    final_url: str,
    status_code: int,
    title: str,
    text_snippet: str,
    features: dict,
) -> None:
    """Write one JSON record to page_content.log."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "url": url,
        "final_url": final_url,
        "status_code": status_code,
        "title": title,
        # First 500 chars of visible text — enough context without flooding disk
        "text_snippet": textwrap.shorten(text_snippet, width=500, placeholder="..."),
        "features": features,
    }
    _get_page_logger().info(json.dumps(record, ensure_ascii=False))


# ---------------------------------------------------------------------------

# Fetch timeout (seconds)
_FETCH_TIMEOUT = 8

# Browser-like headers to avoid being blocked
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

# Default features returned when fetch fails
_DEFAULT_FEATURES: dict = {
    "fetch_success": 0,
    "redirect_count": 0,
    "domain_changed": 0,
    "has_password_input": 0,
    "has_login_form": 0,
    "external_form_action": 0,
    "external_link_ratio": 0.0,
    "hidden_iframe_count": 0,
    "script_count": 0,
    "meta_refresh": 0,
    "title_domain_match": 0,
    "favicon_external": 0,
    "copyright_mismatch": 0,
}


def _hostname(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _is_hidden(tag) -> bool:
    style = (tag.get("style") or "").replace(" ", "").lower()
    return "display:none" in style or "visibility:hidden" in style


def analyze_page(url: str) -> dict:
    """
    Fetch the page and return a dict of content features.
    If fetch fails for any reason, returns _DEFAULT_FEATURES (fetch_success=0)
    so the pipeline can continue without crashing.
    """
    origin_host = _hostname(url)
    features = _DEFAULT_FEATURES.copy()

    try:
        session = requests.Session()
        resp = session.get(
            url,
            timeout=_FETCH_TIMEOUT,
            headers=_HEADERS,
            allow_redirects=True,
        )
    except requests.exceptions.Timeout:
        logger.warning(f"Fetch timeout: {url}")
        return features
    except requests.exceptions.TooManyRedirects:
        logger.warning(f"Too many redirects: {url}")
        features["redirect_count"] = 20
        return features
    except Exception as e:
        logger.warning(f"Fetch failed ({url}): {e}")
        return features

    # ── Redirect info ──────────────────────────────────────────────
    redirect_count = len(resp.history)
    final_host = _hostname(resp.url)
    domain_changed = int(origin_host != final_host and bool(final_host))

    # ── Parse HTML ─────────────────────────────────────────────────
    try:
        soup = BeautifulSoup(resp.text, "lxml")
    except Exception as e:
        logger.warning(f"HTML parse failed ({url}): {e}")
        features["fetch_success"] = 1
        features["redirect_count"] = redirect_count
        features["domain_changed"] = domain_changed
        return features

    active_host = final_host or origin_host

    # ── Password / login form ───────────────────────────────────────
    pwd_inputs = soup.find_all("input", {"type": re.compile(r"^password$", re.I)})
    has_password_input = int(bool(pwd_inputs))

    has_login_form = 0
    external_form_action = 0
    for form in soup.find_all("form"):
        if form.find("input", {"type": re.compile(r"^password$", re.I)}):
            has_login_form = 1
            action = form.get("action", "")
            if action:
                action_url = urljoin(resp.url, action)
                action_host = _hostname(action_url)
                if action_host and action_host != active_host:
                    external_form_action = 1

    # ── Links ───────────────────────────────────────────────────────
    all_links = [a.get("href", "") for a in soup.find_all("a", href=True)]
    total_links = len(all_links)
    external_links = [
        l for l in all_links
        if l.startswith("http") and _hostname(l) != active_host
    ]
    external_link_ratio = (
        round(len(external_links) / total_links, 4) if total_links > 0 else 0.0
    )

    # ── Hidden iframes ──────────────────────────────────────────────
    hidden_iframe_count = sum(
        1 for iframe in soup.find_all("iframe") if _is_hidden(iframe)
    )

    # ── Script tags ─────────────────────────────────────────────────
    script_count = len(soup.find_all("script"))

    # ── Meta refresh ────────────────────────────────────────────────
    meta_refresh = int(bool(
        soup.find("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)})
    ))

    # ── Title vs domain ─────────────────────────────────────────────
    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
    host_parts = active_host.split(".")
    registered = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else active_host
    title_domain_match = int(registered in title.lower())

    # ── Favicon from external domain ────────────────────────────────
    favicon_external = 0
    for link_tag in soup.find_all("link", rel=re.compile(r"icon", re.I)):
        href = link_tag.get("href", "")
        if href.startswith("http") and _hostname(href) != active_host:
            favicon_external = 1
            break

    # ── Copyright mismatch ──────────────────────────────────────────
    copyright_mismatch = 0
    footer = soup.find("footer") or soup.find(id=re.compile(r"footer", re.I))
    if footer:
        footer_text = footer.get_text(" ", strip=True).lower()
        copy_match = re.search(r"©|copyright|\(c\)", footer_text)
        if copy_match:
            excerpt = footer_text[copy_match.end():copy_match.end() + 50]
            words = re.findall(r"[a-z]+", excerpt)
            domain_words = set(re.findall(r"[a-z]+", active_host))
            if words and not any(w in domain_words for w in words[:3]):
                copyright_mismatch = 1

    # ── Visible text snippet for logging ────────────────────────────
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    visible_text = soup.get_text(" ", strip=True)

    result = {
        "fetch_success": 1,
        "redirect_count": redirect_count,
        "domain_changed": domain_changed,
        "has_password_input": has_password_input,
        "has_login_form": has_login_form,
        "external_form_action": external_form_action,
        "external_link_ratio": external_link_ratio,
        "hidden_iframe_count": hidden_iframe_count,
        "script_count": script_count,
        "meta_refresh": meta_refresh,
        "title_domain_match": title_domain_match,
        "favicon_external": favicon_external,
        "copyright_mismatch": copyright_mismatch,
    }

    # ── Write to page content log ────────────────────────────────────
    _log_page(
        url=url,
        final_url=resp.url,
        status_code=resp.status_code,
        title=title,
        text_snippet=visible_text,
        features=result,
    )

    return result