import aiohttp
from bs4 import BeautifulSoup
from core.heuristic_scanner import HeuristicScanner
from core.url_utils import URLUtils

SAFE_PAGE_SCAN_DOMAINS = {
    "discord.com",
    "discord.gg",
    "youtube.com",
    "www.youtube.com",
    "facebook.com",
    "www.facebook.com",
}

class ExternalScanners:
    def __init__(self, config):
        self.config = config

    async def google_safe_browsing(self, url):
        if not self.config.GOOGLE_API_KEY:
            return None

        api = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.config.GOOGLE_API_KEY}"
        payload = {
            "client": {"clientId": "mari-bot", "clientVersion": "2.1"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            async with aiohttp.ClientSession() as s:
                async with s.post(api, json=payload, timeout=10) as r:
                    data = await r.json()
                    return "malware" if data.get("matches") else None
        except Exception:
            return None

    async def virustotal(self, url):
        if not self.config.VIRUSTOTAL_API_KEY:
            return None

        try:
            async with aiohttp.ClientSession(
                headers={"x-apikey": self.config.VIRUSTOTAL_API_KEY}
            ) as s:
                async with s.post(
                    "https://www.virustotal.com/api/v3/urls",
                    data={"url": url},
                    timeout=10,
                ) as r:
                    data = await r.json()
                    vid = data.get("data", {}).get("id")

                if not vid:
                    return None

                async with s.get(f"https://www.virustotal.com/api/v3/urls/{vid}") as r2:
                    info = await r2.json()
                    stats = info["data"]["attributes"]["last_analysis_stats"]
                    if stats.get("malicious", 0) + stats.get("suspicious", 0) > 0:
                        return "malware"
        except Exception:
            return None

    async def page_scan(self, url):
        try:
            domain = URLUtils.get_domain(url)
            if domain in SAFE_PAGE_SCAN_DOMAINS:
                return None

            async with aiohttp.ClientSession() as s:
                async with s.get(url, timeout=10) as r:
                    html = await r.text(errors="ignore")
                    soup = BeautifulSoup(html, "html.parser")
                    content = (soup.title.string if soup.title else "") + html[:3000]
                    text = content.lower()

                    if any(k in text for k in HeuristicScanner.ADULT):
                        return "adult"
                    if any(k in text for k in HeuristicScanner.GAMBLING):
                        return "gambling"
                    if any(k in text for k in HeuristicScanner.SCAM):
                        return "scam"
        except Exception:
            return None
