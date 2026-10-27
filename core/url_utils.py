import asyncio
import ipaddress
import re
import socket
from contextlib import asynccontextmanager
from urllib.parse import urljoin, urlparse

import aiohttp

# Invisible characters scammers slip into links to dodge lists (zero-width
# space/joiners, word joiner, BOM, soft hyphen).
_INVISIBLE = re.compile("[\u00ad\u200b-\u200f\u2060\ufeff]")
MAX_REDIRECTS = 5


class BlockedURL(Exception):
    """A link Mari will not open: not http(s), or pointing inside a private network."""


async def _is_public(url: str) -> bool:
    """http(s) to a host whose every address is on the public internet. Stops
    links like http://127.0.0.1/, http://192.168.x.x/ or http://169.254.169.254/
    from making Mari probe the VPS or its network (SSRF)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(parsed.hostname, parsed.port or 443)
    except (socket.gaierror, UnicodeError):
        return False
    ips = {ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos}
    return bool(ips) and all(ip.is_global and not ip.is_multicast for ip in ips)


@asynccontextmanager
async def get_public(session: aiohttp.ClientSession, url: str):
    """session.get that only ever talks to public addresses: redirects are
    followed by hand (at most MAX_REDIRECTS) so every hop is checked too.
    ponytail: DNS could still change between the check and the request
    (rebinding); pin the checked IP in a custom resolver if that ever matters."""
    for _ in range(MAX_REDIRECTS + 1):
        if not await _is_public(url):
            raise BlockedURL(url)
        resp = await session.get(url, allow_redirects=False)
        if resp.status in (301, 302, 303, 307, 308) and resp.headers.get("Location"):
            url = urljoin(str(resp.url), resp.headers["Location"])
            resp.release()
            continue
        try:
            yield resp
        finally:
            resp.release()
        return
    raise BlockedURL(f"more than {MAX_REDIRECTS} redirects")

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
    # A link stops at Discord markdown around it (<no embed>, ||spoiler||, **bold**,
    # (brackets), `code`), so "<https://scam.gift>" is read as scam.gift, not "scam.gift>".
    URL_REGEX = re.compile(r"https?://[^\s<>|*()\[\]{}\"'`]+", re.IGNORECASE)

    @staticmethod
    def extract_urls(text: str):
        # Punctuation ending a sentence ("scam.gift, nhanh!") or __underline__/~~strike~~.
        return [u.rstrip(".,!?:;_~") for u in URLUtils.URL_REGEX.findall(text)]

    @staticmethod
    def get_domain(url: str):
        # .hostname (not .netloc) drops "user@" and ":port", so the classic trick
        # https://discord.com@evil.com/ resolves to evil.com, the real destination.
        # Invisible characters and a trailing dot are dropped and Unicode names
        # become punycode, so "disc\u200bord.gift." or a look-alike in another
        # alphabet is compared with the scam lists in one canonical form.
        try:
            host = _INVISIBLE.sub("", urlparse(_INVISIBLE.sub("", url)).hostname or "").lower().rstrip(".")
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError:
                pass
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
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                async with get_public(s, url) as r:
                    return str(r.url)
        except Exception:  # includes BlockedURL: a shortener pointing inside is not followed
            return None
