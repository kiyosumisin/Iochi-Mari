"""Community-maintained lists of known Discord scam/phishing domains.

The lists are third-party data and a match leads to a ban, so they are
guarded: nothing on or under a well-known legitimate site (or the whitelist) is
ever treated as a scam, hosting platforms themselves can't be listed (only
individual sites on them), and a refresh that suddenly shrinks the list is
rejected in favour of the last good copy.
"""

import json
import logging
from pathlib import Path

import aiohttp

from core.guild_settings import atomic_write
from core.url_utils import URLUtils

logger = logging.getLogger(__name__)

SOURCES = [
    "https://raw.githubusercontent.com/Discord-AntiScam/scam-links/main/list.json",
    "https://raw.githubusercontent.com/DevSpen/scam-links/master/src/links.txt",
    "https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/domain-list.json",
]
CACHE = Path(__file__).resolve().parent.parent / "log" / "scam_domains.json"

# Company-owned sites: nothing on or under these is ever a scam domain.
OWNED = {
    "discord.com", "discord.gg", "discord.gift", "discordapp.com", "discordapp.net",
    "discord.media", "discord.new", "google.com", "youtube.com", "youtu.be",
    "github.com", "microsoft.com", "live.com", "apple.com", "amazon.com",
    "steampowered.com", "steamcommunity.com", "twitch.tv", "twitter.com", "x.com",
    "facebook.com", "instagram.com", "reddit.com", "tiktok.com", "spotify.com",
    "cloudflare.com", "hoyoverse.com", "hoyolab.com", "mihoyo.com", "wikipedia.org",
}
# Hosting platforms: a site *on* them can be a scam, the platform itself can't.
PLATFORMS = {
    "github.io", "vercel.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com",
    "netlify.app", "herokuapp.com", "glitch.me", "repl.co", "azurewebsites.net",
    "blogspot.com", "wixsite.com", "weebly.com", "carrd.co", "000webhostapp.com",
}


def parse_domains(text: str) -> set[str]:
    """Domains from a JSON list, a {"domains": [...]} object, or one per line."""
    try:
        data = json.loads(text)
        items = data.get("domains", []) if isinstance(data, dict) else data
    except ValueError:
        items = text.splitlines()
    out = set()
    for x in items:
        x = str(x).strip().lower()
        if x and not x.startswith("#"):
            d = URLUtils.get_domain(x if "://" in x else "http://" + x)
            if "." in d:
                out.add(d)
    return out


class ScamDomainList:
    def __init__(self, protected_extra=()):
        self.protected = OWNED | {d.lower() for d in protected_extra}
        try:
            self.domains = set(json.loads(CACHE.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            self.domains = set()

    def is_protected(self, domain: str) -> bool:
        return (
            URLUtils.domain_in(domain, self.protected)
            or domain in PLATFORMS
            # a listed parent like "vercel.app" or "com" would sweep in everything below it
            or any(p.endswith("." + domain) for p in self.protected | PLATFORMS)
        )

    def contains(self, domain: str) -> bool:
        if self.is_protected(domain):
            return False
        parts = domain.lower().split(".")
        # The matching list entry must itself be unprotected, so a bad parent entry
        # (e.g. "vercel.app" in an old cache) can't sweep in every site below it.
        return any(
            (entry := ".".join(parts[i:])) in self.domains and not self.is_protected(entry)
            for i in range(len(parts))
        )

    async def refresh(self):
        fetched, ok = set(), 0
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as s:
            for url in SOURCES:
                try:
                    async with s.get(url) as r:
                        if r.status == 200:
                            fetched |= parse_domains(await r.text())
                            ok += 1
                        else:
                            logger.warning("Scam list source %s returned %s", url, r.status)
                except Exception as exc:
                    logger.warning("Scam list source %s failed: %s", url, exc)

        fresh = {d for d in fetched if not self.is_protected(d)}
        if not ok or len(fresh) < len(self.domains) * 0.5:
            logger.warning(
                "Scam list refresh rejected (%d sources ok, %d -> %d domains); keeping the last good copy",
                ok, len(self.domains), len(fresh),
            )
            return
        self.domains = fresh
        atomic_write(CACHE, json.dumps(sorted(fresh)))
        logger.info("Scam domain list refreshed: %d domains from %d sources", len(fresh), ok)
