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

    @staticmethod
    def _cache_key(url: str, threshold: float | None) -> str:
        """Verdicts depend on the decision threshold, so it is part of the key."""
        return f"{threshold}|{url}"

    def _cache_detail(self, cache_key, now, verdict, probability, is_malicious, top_features, sources):
        detail = {
            "verdict": verdict,
            "probability": probability,
            "is_malicious": is_malicious,
            "top_features": top_features,
            "sources": sources,
        }
        self.cache[cache_key] = {"time": now, "detail": detail}
        return detail

    async def evaluate(self, url: str, threshold: float | None = None) -> str:
        """Backward-compatible: return just the verdict string."""
        detail = await self.evaluate_detailed(url, threshold)
        return detail["verdict"]

    async def evaluate_detailed(self, url: str, threshold: float | None = None) -> dict:
        """
        Full evaluation result: verdict + AI probability + is_malicious + SHAP
        top features + the list of contributing sources. Used by the agent layer
        to detect borderline cases.
        """
        now = time.time()

        original_url = url
        cache_key = self._cache_key(original_url, threshold)

        cached = self.cache.get(cache_key)
        if cached and now - cached["time"] < self.CACHE_TTL:
            return cached["detail"]

        verdicts = []
        sources = []
        probability = None
        is_malicious = False
        top_features = []

        domain = URLUtils.get_domain(url)
        if domain in SHORTENER_DOMAINS:
            resolved = await URLUtils.resolve_short_url(url)
            if resolved and resolved != url:
                sources.append(f"shortener:resolved:{domain}")
                url = resolved

        domain = URLUtils.get_domain(url)
        if self._is_listed(domain, self.whitelist):
            logger.info("URL whitelisted | url=%s | domain=%s", url, domain)
            return self._cache_detail(cache_key, now, "safe", None, False, [], ["whitelist"])

        if self._is_listed(domain, self.blacklist):
            logger.info("URL blacklisted | url=%s | domain=%s", url, domain)
            return self._cache_detail(cache_key, now, "malware", 1.0, True, [], ["blacklist"])

        heur = HeuristicScanner.scan(url)
        if heur:
            verdicts.append(heur)
            sources.append(f"heuristic:{heur}")
        has_soft_category = heur in ("adult", "gambling")

        try:
            prediction = await asyncio.to_thread(predict_url, url, threshold=threshold)
            probability = prediction.probability
            is_malicious = prediction.is_malicious
            top_features = [
                {"feature": f.feature, "value": f.value, "shap": f.shap_value}
                for f in prediction.top_features
            ]
            override_threshold = float(os.getenv("AI_OVERRIDE_THRESHOLD", "0.9"))
            if is_malicious:
                if (not has_soft_category) or probability >= override_threshold:
                    verdicts.append("phishing")
                    sources.append(f"ai:phishing:{probability:.4f}")
            else:
                scam_threshold = float(os.getenv("AI_SCAM_THRESHOLD", "0.3"))
                if (not has_soft_category) and probability >= scam_threshold:
                    verdicts.append("scam")
                    sources.append(f"ai:scam:{probability:.4f}")
        except Exception as exc:
            logger.warning("AI prediction failed: %s", exc)

        # Short-circuit the external scanners to save latency and API quota.
        # Google Safe Browsing is cheap (high quota) so it always runs as an
        # independent safety net. The rate-limited VirusTotal and the page-fetch
        # content scan only run when the local classifiers are NOT already
        # confident — so clearly-safe and clearly-malicious URLs skip them.
        # (page_scan is dropped entirely: it duplicated ContentScanner's fetch.)
        ovr = float(os.getenv("AI_OVERRIDE_THRESHOLD", "0.9"))
        safe = float(os.getenv("AI_SAFE_THRESHOLD", "0.15"))
        confident_malicious = probability is not None and probability >= ovr
        confident_safe = probability is not None and probability <= safe and not heur
        uncertain = probability is None or not (confident_malicious or confident_safe)

        tasks = [self.scanners.google_safe_browsing(url)]
        if uncertain:
            tasks.append(ContentScanner.scan(url))
            tasks.append(self.scanners.virustotal(url))

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

        logger.info(
            "URL final verdict | url=%s | verdict=%s | sources=%s",
            original_url,
            final,
            ";".join(sources) if sources else "none",
        )
        return self._cache_detail(cache_key, now, final, probability, is_malicious, top_features, sources)