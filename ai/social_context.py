"""
social_context.py
-----------------
Phân tích nội dung text từ Discord message và Twitter/X post
để phát hiện dấu hiệu scam/phishing.

Sử dụng:
    from ai.social_context import analyze_social_context, SocialRisk
    result = await analyze_social_context(text="...", image_texts=["..."])
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Keyword banks — có trọng số theo mức độ nguy hiểm
# ---------------------------------------------------------------------------

# Điểm cao = nguy hiểm rõ ràng
HIGH_RISK_KEYWORDS: dict[str, float] = {
    # Crypto scam cổ điển
    "giving away":       3.0,
    "giveaway":          2.5,
    "airdrop":           2.0,
    "free crypto":       3.0,
    "free bitcoin":      3.0,
    "free usdt":         3.0,
    "free eth":          2.5,
    "claim your":        2.5,
    "claim now":         2.5,
    "send crypto":       3.0,
    "double your":       3.5,
    "multiply your":     3.0,
    "withdrawal success":3.5,
    "withdraw instantly":3.0,
    "instant withdraw":  3.0,

    # Fake celebrity
    "elon musk":         1.5,
    "mrbeast":           1.5,
    "i am giving":       2.0,
    "i'm giving":        2.0,
    "launch of my":      1.5,
    "my own crypto":     2.5,
    "my own casino":     2.5,

    # Promo scam
    "promo code":        1.5,
    "promocode":         1.5,
    "special promo":     1.5,
    "bonus code":        1.5,
    "enter code":        1.5,
    "use code":          1.0,
    "coupon code":       1.0,

    # Urgency tactics
    "will be deleted":   2.0,
    "deleted in":        2.0,
    "limited time":      1.5,
    "don't miss":        1.0,
    "act now":           1.5,
    "expires soon":      1.5,
    "only today":        1.5,
    "last chance":       1.5,

    # Fake rewards
    "bonus credited":    2.5,
    "prize credited":    2.5,
    "reward credited":   2.5,
    "has been credited": 2.0,
    "successfully credited": 2.0,
    "vip club":          1.0,
    "vip-club":          1.0,

    # Casino / gambling scam
    "crypto casino":     2.5,
    "online casino":     1.5,
    "slots":             0.8,
    "play or withdraw":  2.5,
    "rakeback":          1.5,

    # Phishing verbs
    "verify your":       1.5,
    "confirm your":      1.5,
    "update your":       1.5,
    "suspended":         1.5,
    "account locked":    2.0,
    "unusual activity":  1.5,
}

MEDIUM_RISK_KEYWORDS: dict[str, float] = {
    "register now":      1.0,
    "sign up":           0.5,
    "click here":        0.8,
    "visit":             0.3,
    "go to":             0.5,
    "contact support":   0.5,
    "investment":        0.8,
    "profit":            0.8,
    "passive income":    1.0,
    "no risk":           1.0,
    "guaranteed":        1.2,
    "100%":              0.5,
    "official":          0.3,
    "exclusive":         0.5,
}

# Dấu hiệu giả mạo người nổi tiếng
IMPERSONATION_PATTERNS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r'\bi\s+(am|m)\s+(giving|excited|pleased|happy)\b', re.I), 2.0,
     "First-person celebrity announcement"),
    (re.compile(r'announce\s+the\s+launch\s+of\s+my', re.I), 2.5,
     "Fake product launch announcement"),
    (re.compile(r'to\s+celebrate\s+.{0,40}giving\s+away', re.I), 2.5,
     "Celebration giveaway pattern"),
    (re.compile(r'this\s+post\s+will\s+be\s+deleted', re.I), 2.0,
     "Artificial urgency — post deletion threat"),
    (re.compile(r'only\s+the\s+fastest\s+will', re.I), 1.5,
     "Artificial scarcity — speed pressure"),
    (re.compile(r'\$\s*\d{3,6}\s*(bonus|reward|prize|usdt|btc|eth)', re.I), 2.0,
     "Large crypto/cash reward claim"),
    (re.compile(r'(register|sign\s*up).{0,60}(bonus|reward|withdraw)', re.I), 2.5,
     "Register-to-claim scam pattern"),
    (re.compile(r'withdrawal\s+of\s+\$[\d,]+\s+was\s+success', re.I), 3.5,
     "Fake withdrawal success screenshot"),
    (re.compile(r'(rackswin|vanedex|binance-free|crypto-gift)', re.I), 3.0,
     "Known scam domain mentioned in text"),
]

# Ngưỡng điểm
RISK_THRESHOLD_HIGH   = 5.0
RISK_THRESHOLD_MEDIUM = 2.5


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class KeywordHit:
    keyword: str
    score: float
    context: str          # đoạn văn xung quanh keyword


@dataclass
class PatternHit:
    pattern_desc: str
    score: float
    matched_text: str


@dataclass
class SocialRisk:
    total_score: float
    risk_level: str                          # "HIGH" | "MEDIUM" | "LOW"
    keyword_hits: list[KeywordHit] = field(default_factory=list)
    pattern_hits: list[PatternHit] = field(default_factory=list)
    summary: str = ""
    raw_text_analyzed: str = ""

    @property
    def is_suspicious(self) -> bool:
        return self.risk_level in ("HIGH", "MEDIUM")


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------
def _extract_context(text: str, keyword: str, window: int = 40) -> str:
    """Lấy đoạn văn ±window ký tự xung quanh keyword."""
    idx = text.lower().find(keyword.lower())
    if idx == -1:
        return ""
    start = max(0, idx - window)
    end   = min(len(text), idx + len(keyword) + window)
    snippet = text[start:end].replace("\n", " ").strip()
    return f"...{snippet}..."


def _score_keywords(text: str) -> tuple[float, list[KeywordHit]]:
    text_lower = text.lower()
    total = 0.0
    hits: list[KeywordHit] = []

    for kw, score in {**HIGH_RISK_KEYWORDS, **MEDIUM_RISK_KEYWORDS}.items():
        if kw in text_lower:
            ctx = _extract_context(text, kw)
            hits.append(KeywordHit(keyword=kw, score=score, context=ctx))
            total += score

    return total, hits


def _score_patterns(text: str) -> tuple[float, list[PatternHit]]:
    total = 0.0
    hits: list[PatternHit] = []

    for pattern, score, desc in IMPERSONATION_PATTERNS:
        match = pattern.search(text)
        if match:
            hits.append(PatternHit(
                pattern_desc=desc,
                score=score,
                matched_text=match.group(0)[:80],
            ))
            total += score

    return total, hits


def _build_summary(
    score: float,
    level: str,
    kw_hits: list[KeywordHit],
    pat_hits: list[PatternHit],
) -> str:
    if level == "LOW":
        return "No significant scam indicators detected in text."

    parts = [f"Risk level: {level} (score={score:.1f})"]

    if pat_hits:
        parts.append("Patterns detected:")
        for h in pat_hits[:3]:
            parts.append(f'  • {h.pattern_desc} → "{h.matched_text}"')

    if kw_hits:
        top = sorted(kw_hits, key=lambda x: x.score, reverse=True)[:5]
        parts.append("Top keywords:")
        for h in top:
            parts.append(f'  • "{h.keyword}" (score={h.score}) {h.context}')

    return "\n".join(parts)


def analyze_social_context(
    text: str,
    image_texts: Optional[list[str]] = None,
) -> SocialRisk:
    """
    Phân tích text từ Discord message và/hoặc text extract từ ảnh (OCR).

    Args:
        text        : Nội dung text của Discord message.
        image_texts : Danh sách text đã OCR từ các ảnh đính kèm.

    Returns:
        SocialRisk với score, level, và chi tiết các hits.
    """
    # Gộp tất cả text lại để phân tích
    combined = text or ""
    if image_texts:
        combined += "\n" + "\n".join(image_texts)

    if not combined.strip():
        return SocialRisk(
            total_score=0.0,
            risk_level="LOW",
            summary="No text to analyze.",
        )

    kw_score,  kw_hits  = _score_keywords(combined)
    pat_score, pat_hits = _score_patterns(combined)
    total = kw_score + pat_score

    if total >= RISK_THRESHOLD_HIGH:
        level = "HIGH"
    elif total >= RISK_THRESHOLD_MEDIUM:
        level = "MEDIUM"
    else:
        level = "LOW"

    summary = _build_summary(total, level, kw_hits, pat_hits)

    logger.info(
        "Social context analysis: score=%.1f level=%s kw_hits=%d pat_hits=%d",
        total, level, len(kw_hits), len(pat_hits),
    )

    return SocialRisk(
        total_score=round(total, 2),
        risk_level=level,
        keyword_hits=kw_hits,
        pattern_hits=pat_hits,
        summary=summary,
        raw_text_analyzed=combined[:500],
    )