import base64
import logging

import aiohttp

logger = logging.getLogger(__name__)


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
                    if r.status != 200:
                        logger.warning("Safe Browsing error %s: %s", r.status, data.get("error"))
                        return None
                    return "malware" if data.get("matches") else None
        except Exception as exc:
            logger.warning("Safe Browsing failed: %s", exc)
            return None

    async def virustotal(self, url):
        """VirusTotal's last analysis of this URL. A URL it has never seen (404)
        counts as no finding; it is not submitted, which would cost a second
        request of the small free quota for an answer that comes later."""
        if not self.config.VIRUSTOTAL_API_KEY:
            return None

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        try:
            async with aiohttp.ClientSession(
                headers={"x-apikey": self.config.VIRUSTOTAL_API_KEY}
            ) as s:
                async with s.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", timeout=10) as r:
                    if r.status == 404:
                        return None
                    info = await r.json()
                    if r.status != 200:
                        logger.warning("VirusTotal error %s: %s", r.status, info.get("error"))
                        return None
                    stats = info["data"]["attributes"]["last_analysis_stats"]
                    if stats.get("malicious", 0) + stats.get("suspicious", 0) > 0:
                        return "malware"
                    return None
        except Exception as exc:
            logger.warning("VirusTotal failed: %s", exc)
            return None
