"""Well-known sites, from the Tranco top list (tranco-list.eu).

The URL model learned from data where long, messy URLs meant phishing, so it
misfires on Discord's everyday links (gif and image CDNs, game event pages).
For a popular site its guess, and the keyword heuristics', is ignored: only the
scam lists and Google Safe Browsing count. Sites where anyone can publish a page
(hosting platforms, Google Docs/Forms, file shares) stay fully checked, since
scams live there too.
"""

import asyncio
import csv
import io
import logging
import time
import zipfile
from pathlib import Path

import aiohttp

from core.guild_settings import atomic_write
from core.scam_list import PLATFORMS

logger = logging.getLogger(__name__)

SOURCE = "https://tranco-list.eu/top-1m.csv.zip"
CACHE = Path(__file__).resolve().parent.parent / "log" / "popular_domains.txt"
TOP_N = 200_000          # ~20 MB in memory; covers the gif/CDN/game sites seen on Discord
MAX_AGE = 30 * 86400     # refresh the cached list monthly
# Popular, but anyone can put a page there: never trusted just for being popular.
SHARED = PLATFORMS | {
    "google.com", "forms.gle", "sharepoint.com", "1drv.ms", "onedrive.live.com", "live.com",
    "dropbox.com", "notion.site", "wordpress.com", "medium.com", "webflow.io", "framer.website",
    "gitbook.io", "linktr.ee", "typeform.com", "jotform.com", "mediafire.com", "mega.nz",
    "wix.com", "square.site", "godaddysites.com", "myshopify.com", "translate.goog",
}


def _top_domains(data: bytes, n: int) -> list[str]:
    """The first n domains of a Tranco zip ("rank,domain" rows)."""
    with zipfile.ZipFile(io.BytesIO(data)) as z, z.open(z.namelist()[0]) as f:
        rows = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
        return [row[1].strip().lower() for _, row in zip(range(n), rows) if len(row) > 1]


class PopularDomains:
    def __init__(self):
        try:
            self.domains = set(CACHE.read_text(encoding="utf-8").split())
        except OSError:
            self.domains = set()

    def contains(self, domain: str) -> bool:
        """True if the host, or a site it belongs to, is popular and not shared."""
        parts = domain.lower().split(".")
        suffixes = [".".join(parts[i:]) for i in range(len(parts) - 1)]
        if any(s in SHARED for s in suffixes):
            return False
        return any(s in self.domains for s in suffixes)

    async def refresh(self):
        """Download the list when the cached copy is missing or a month old."""
        if self.domains and CACHE.exists() and time.time() - CACHE.stat().st_mtime < MAX_AGE:
            return
        async with aiohttp.ClientSession() as s:
            async with s.get(SOURCE, timeout=aiohttp.ClientTimeout(total=120)) as r:
                r.raise_for_status()
                data = await r.read()
        domains = await asyncio.to_thread(_top_domains, data, TOP_N)
        if len(domains) < TOP_N // 2:  # a broken download: keep what we have
            logger.warning("Popular list refresh rejected: only %d domains", len(domains))
            return
        atomic_write(CACHE, "\n".join(domains))
        self.domains = set(domains)
        logger.info("Popular domain list refreshed: %d domains", len(self.domains))
