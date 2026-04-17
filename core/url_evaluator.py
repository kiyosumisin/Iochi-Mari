import time
import asyncio
import os
import json
import logging
from pathlib import Path
from core.heuristic_scanner import HeuristicScanner
from core.content_scanner import ContentScanner
from core.url_utils import URLUtils, SHORTENER_DOMAINS
from ai.predict import predict_url

logger = logging.getLogger(__name__)


class URLEvaluator:
    CACHE_TTL = 3600

    def __init__(self, scanners):
        self.scanners = scanners
        self.cache = {}
        self.whitelist = self._load_list("whitelist.json")
        self.blacklist = self._load_list("blacklist.json")

    def _load_list(self, filename: str):
        try:
            base_dir = Path(__file__).resolve().parent.parent
            path = base_dir / "data" / filename
            if not path.exists():
                return []
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return [str(x).lower() for x in data]
        except Exception as exc:
            logger.warning("Failed to load %s: %s", filename, exc)
        return []

    def _is_listed(self, domain: str, items: list[str]):
        domain = domain.lower()
        for d in items:
            if domain == d or domain.endswith("." + d):
                return True
        return False

    async def evaluate(self, url: str):
        now = time.time()

        original_url = url

        if url in self.cache and now - self.cache[url]["time"] < self.CACHE_TTL:
            return self.cache[url]["verdict"]

        verdicts = []
        sources = []

        domain = URLUtils.get_domain(url)
        if domain in SHORTENER_DOMAINS:
            resolved = await URLUtils.resolve_short_url(url)
            if resolved and resolved != url:
                sources.append(f"shortener:resolved:{domain}")
                url = resolved

        domain = URLUtils.get_domain(url)
        if self._is_listed(domain, self.whitelist):
            self.cache[url] = {"time": now, "verdict": "safe"}
            logger.info("URL whitelisted | url=%s | domain=%s", url, domain)
            return "safe"

        if self._is_listed(domain, self.blacklist):
            self.cache[url] = {"time": now, "verdict": "malware"}
            logger.info("URL blacklisted | url=%s | domain=%s", url, domain)
            return "malware"

        heur = HeuristicScanner.scan(url)
        if heur:
            verdicts.append(heur)
            sources.append(f"heuristic:{heur}")
        has_soft_category = heur in ("adult", "gambling")

        try:
            prob, is_malicious = predict_url(url)
            override_threshold = float(os.getenv("AI_OVERRIDE_THRESHOLD", "0.9"))
            if is_malicious:
                if (not has_soft_category) or prob >= override_threshold:
                    verdicts.append("phishing")
                    sources.append(f"ai:phishing:{prob:.4f}")
            else:
                scam_threshold = float(os.getenv("AI_SCAM_THRESHOLD", "0.3"))
                if (not has_soft_category) and prob >= scam_threshold:
                    verdicts.append("scam")
                    sources.append(f"ai:scam:{prob:.4f}")
        except Exception as exc:
            logger.warning("AI prediction failed: %s", exc)

        tasks = [
            ContentScanner.scan(url),
            self.scanners.google_safe_browsing(url),
            self.scanners.virustotal(url),
            self.scanners.page_scan(url),
        ]

        results = await asyncio.gather(*tasks)
        for v in results:
            if v:
                verdicts.append(v)
                sources.append(f"scanner:{v}")

        final = "safe"
        for v in verdicts:
            if v in ("malware", "phishing"):
                final = v
                break
            if v in ("adult", "gambling", "scam"):
                final = v

        self.cache[original_url] = {"time": now, "verdict": final}
        logger.info(
            "URL final verdict | url=%s | verdict=%s | sources=%s",
            original_url,
            final,
            ";".join(sources) if sources else "none",
        )
        return final