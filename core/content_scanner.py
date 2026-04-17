import logging
from urllib.parse import urlparse, urljoin
from core.url_utils import URLUtils

import aiohttp
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class ContentScanner:
    PHISHING_KEYWORDS = [
        "verify", "verification", "login", "sign in", "password",
        "account", "update", "security", "unlock", "confirm",
        "bank", "wallet", "crypto", "payment", "billing",
    ]

    SCAM_KEYWORDS = [
        "free", "gift", "claim", "bonus", "airdrop", "limited",
        "urgent", "exclusive", "win", "giveaway",
    ]

    # Domains that are always safe to skip content scanning
    SAFE_CONTENT_DOMAINS = {
        "discord.com", "discord.gg",
        "youtube.com", "www.youtube.com", "youtu.be",
        "facebook.com", "www.facebook.com",
        "google.com", "www.google.com",
        "github.com", "www.github.com",
        "twitter.com", "www.twitter.com", "x.com",
        "reddit.com", "www.reddit.com",
        "instagram.com", "www.instagram.com",
        "wikipedia.org", "www.wikipedia.org",
        "microsoft.com", "www.microsoft.com",
        "apple.com", "www.apple.com",
        "amazon.com", "www.amazon.com",
        "linkedin.com", "www.linkedin.com",
        "twitch.tv", "www.twitch.tv",
        "tiktok.com", "www.tiktok.com",
        "stackoverflow.com",
        "npmjs.com", "pypi.org",
    }

    # Minimum score to flag as scam or phishing
    _PHISHING_THRESHOLD = 7
    _SCAM_THRESHOLD = 4

    @classmethod
    def _extract_body_text(cls, soup: BeautifulSoup, max_chars: int = 5000) -> str:
        """Extract visible text from <body> only, ignoring scripts and styles."""
        body = soup.find("body")
        if not body:
            return ""
        for tag in body(["script", "style", "noscript", "head"]):
            tag.decompose()
        return " ".join(body.stripped_strings)[:max_chars].lower()

    @classmethod
    def _form_action_mismatch(cls, forms, page_domain: str, base_url: str) -> bool:
        """Return True if any form submits to a different domain than the page."""
        for form in forms:
            action = (form.get("action") or "").strip()
            if not action:
                continue
            # Resolve relative URLs before checking domain
            action_full = urljoin(base_url, action)
            action_domain = urlparse(action_full).netloc.lower()
            if action_domain and action_domain != page_domain:
                return True
        return False

    @classmethod
    async def scan(cls, url: str):
        try:
            domain = URLUtils.get_domain(url)
            if domain in cls.SAFE_CONTENT_DOMAINS:
                return None

            # Fix: use aiohttp.ClientTimeout instead of raw int
            timeout = aiohttp.ClientTimeout(total=10)
            headers = {"User-Agent": "Mozilla/5.0 (compatible; mari-bot/2.1)"}

            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                async with session.get(url, allow_redirects=True) as resp:
                    # Only scan HTML pages, skip binary/media responses
                    content_type = resp.headers.get("Content-Type", "")
                    if "text/html" not in content_type:
                        return None
                    html = await resp.text(errors="ignore")
                    final_url = str(resp.url)

            soup = BeautifulSoup(html, "html.parser")

            title = (soup.title.string if soup.title else "").lower()
            body_text = cls._extract_body_text(soup)
            sample = f"{title} {body_text}"

            forms   = soup.find_all("form")
            inputs  = soup.find_all("input")
            iframes = soup.find_all("iframe")
            scripts = soup.find_all("script", src=True)

            has_password = any(i.get("type", "").lower() == "password" for i in inputs)
            has_email    = any(i.get("type", "").lower() == "email"    for i in inputs)

            phishing_hits = sum(1 for k in cls.PHISHING_KEYWORDS if k in sample)
            scam_hits     = sum(1 for k in cls.SCAM_KEYWORDS     if k in sample)

            parsed_final = urlparse(final_url)
            page_domain  = parsed_final.netloc.lower()

            score = 0

            # --- Phishing signals ---
            # Password field is a strong signal but not conclusive alone
            if has_password:
                score += 2
            if has_email:
                score += 1
            # Only add phishing keyword score if there is a form present
            # to avoid flagging informational pages that mention these words
            if forms and phishing_hits >= 3:
                score += 3
            elif forms and phishing_hits >= 1:
                score += 1
            if len(forms) >= 1:
                score += 1
            if cls._form_action_mismatch(forms, page_domain, final_url):
                score += 3  # strong signal: form submits to external domain
            if len(iframes) >= 2:
                score += 1
            if len(scripts) >= 10:
                score += 1

            # --- Scam signals (evaluated separately) ---
            scam_score = 0
            if scam_hits >= 3:
                scam_score += 3
            elif scam_hits >= 1:
                scam_score += 1
            # Scam pages rarely have login forms
            if scam_hits >= 2 and not has_password:
                scam_score += 1

            # --- Final verdict ---
            # Check phishing first (higher severity), then scam
            if score >= cls._PHISHING_THRESHOLD:
                logger.debug(
                    "Content scan phishing | url=%s | score=%d | pw=%s | forms=%d | mismatch=%s",
                    url, score, has_password, len(forms),
                    cls._form_action_mismatch(forms, page_domain, final_url),
                )
                return "phishing"

            if scam_score >= cls._SCAM_THRESHOLD or (score >= cls._SCAM_THRESHOLD and scam_hits >= 1):
                logger.debug("Content scan scam | url=%s | scam_score=%d | score=%d", url, scam_score, score)
                return "scam"

            return None

        except aiohttp.ClientError as exc:
            logger.debug("Content scan network error | url=%s | error=%s", url, exc)
            return None
        except Exception as exc:
            logger.debug("Content scan failed | url=%s | error=%s", url, exc)
            return None