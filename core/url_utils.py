import re
from urllib.parse import urlparse
import aiohttp

SHORTENER_DOMAINS = {
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "rebrand.ly",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
    "ow.ly",
    "buff.ly",
    "tiny.cc",
    "rb.gy",
    "lnk.to",
    "s.id",
    "shorte.st",
    "adf.ly",
}

class URLUtils:
    URL_REGEX = re.compile(r"(https?://[^\s]+)")

    @staticmethod
    def extract_urls(text: str):
        return URLUtils.URL_REGEX.findall(text)

    @staticmethod
    def get_domain(url: str):
        # .hostname (not .netloc) drops "user@" and ":port", so the classic trick
        # https://discord.com@evil.com/ resolves to evil.com, the real destination.
        try:
            host = (urlparse(url).hostname or "").lower()
            return (host[4:] if host.startswith("www.") else host) or "unknown-domain"
        except Exception:
            return "unknown-domain"

    @staticmethod
    def domain_in(domain: str, domains) -> bool:
        """True if `domain` is in `domains` or is a subdomain of one of them.
        One set lookup per label, so it stays fast against large sets."""
        parts = domain.lower().split(".")
        return any(".".join(parts[i:]) in domains for i in range(len(parts)))

    @staticmethod
    async def resolve_short_url(url: str):
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(url, allow_redirects=True, timeout=10) as r:
                    return str(r.url)
        except Exception:
            return None
