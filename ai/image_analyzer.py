"""
image_analyzer.py
-----------------
OCR ảnh đính kèm từ Discord, extract text, phân tích dấu hiệu scam.

Yêu cầu:
    pip install pytesseract Pillow aiohttp
    Tesseract-OCR cài trên hệ thống (https://github.com/UB-Mannheim/tesseract/wiki)

Sử dụng:
    from ai.image_analyzer import analyze_image_url, analyze_image_bytes, ImageRisk
    result = await analyze_image_url("https://cdn.discordapp.com/...")
    result = await analyze_image_bytes(raw_bytes)
"""

from __future__ import annotations

import asyncio
import io
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tesseract path — Windows cần set thủ công nếu chưa vào PATH
# ---------------------------------------------------------------------------
_TESSERACT_CMD = os.getenv(
    "TESSERACT_CMD",
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
)

# ---------------------------------------------------------------------------
# Scam indicators trong ảnh (thường là screenshot)
# ---------------------------------------------------------------------------
IMAGE_SCAM_PATTERNS: list[tuple[re.Pattern, float, str]] = [
    # Fake withdrawal / transaction
    (re.compile(r'withdrawal\s+success', re.I),        4.0, "Fake withdrawal success UI"),
    (re.compile(r'your\s+withdrawal\s+of\s+\$', re.I), 4.0, "Fake withdrawal amount"),
    (re.compile(r'was\s+successful', re.I),             2.0, "Success confirmation text"),
    (re.compile(r'\+\s*\d{3,6}\s*usdt', re.I),         3.5, "Fake USDT transfer amount"),
    (re.compile(r'\+\s*\d{3,6}\s*(btc|eth|bnb|trx)', re.I), 3.0, "Fake crypto transfer"),
    (re.compile(r'transfer\b.{0,30}\bcompleted', re.I), 2.5, "Fake transfer completed"),

    # Casino / bonus UI
    (re.compile(r'vip[\s\-]?club', re.I),              1.5, "VIP Club UI element"),
    (re.compile(r'activate\s+code\s+for\s+bonus', re.I), 2.5, "Bonus activation UI"),
    (re.compile(r'special\s+promo\s*code', re.I),       2.0, "Promo code UI"),
    (re.compile(r'rakeback', re.I),                     1.5, "Rakeback casino element"),
    (re.compile(r'(deposit|withdraw)\b', re.I),         1.0, "Deposit/withdraw UI"),

    # Fake Twitter / social post screenshot
    (re.compile(r'giving\s+away\s+\$', re.I),           3.5, "Giveaway claim in screenshot"),
    (re.compile(r'promo\s+code\s*[:\-]?\s*\w+', re.I), 2.0, "Promo code in screenshot"),
    (re.compile(r'this\s+post\s+will\s+be\s+deleted', re.I), 2.5, "Post deletion urgency"),
    (re.compile(r'(vanedex|rackswin|cryptogive|btcgift)', re.I), 4.0, "Known scam domain in image"),

    # Generic phishing
    (re.compile(r'verify\s+your\s+(account|wallet|identity)', re.I), 2.0, "Account verification prompt"),
    (re.compile(r'enter\s+(your\s+)?(seed|private\s+key|mnemonic)', re.I), 5.0, "Seed phrase request — critical"),
    (re.compile(r'connect\s+wallet', re.I),             2.0, "Wallet connection prompt"),
]

IMAGE_RISK_THRESHOLD_HIGH   = 4.0
IMAGE_RISK_THRESHOLD_MEDIUM = 2.0


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class ImageHit:
    pattern_desc: str
    score: float
    matched_text: str


@dataclass
class ImageRisk:
    extracted_text: str
    total_score: float
    risk_level: str                    # "HIGH" | "MEDIUM" | "LOW" | "UNREADABLE"
    hits: list[ImageHit] = field(default_factory=list)
    summary: str = ""
    ocr_confidence: float = 0.0       # 0–100, -1 = tesseract không available

    @property
    def is_suspicious(self) -> bool:
        return self.risk_level in ("HIGH", "MEDIUM")


# ---------------------------------------------------------------------------
# OCR helper
# ---------------------------------------------------------------------------
def _ocr_image_bytes(raw: bytes) -> tuple[str, float]:
    """
    Chạy Tesseract OCR trên raw image bytes.
    Returns (extracted_text, confidence_0_to_100).
    Raises ImportError nếu pytesseract chưa cài.
    Raises FileNotFoundError nếu Tesseract binary không tìm thấy.
    """
    try:
        import pytesseract
        from PIL import Image, ImageEnhance, ImageFilter
    except ImportError as exc:
        raise ImportError(
            "pytesseract hoặc Pillow chưa cài. Chạy: pip install pytesseract Pillow"
        ) from exc

    # Trỏ đến Tesseract binary (cần thiết trên Windows)
    if os.path.exists(_TESSERACT_CMD):
        pytesseract.pytesseract.tesseract_cmd = _TESSERACT_CMD

    img = Image.open(io.BytesIO(raw)).convert("RGB")

    # Pre-processing: tăng contrast và sharpen để OCR chính xác hơn
    img = ImageEnhance.Contrast(img).enhance(2.0)
    img = ImageEnhance.Sharpness(img).enhance(2.0)
    img = img.filter(ImageFilter.SHARPEN)

    # OCR với data về confidence
    try:
        data = pytesseract.image_to_data(
            img,
            output_type=pytesseract.Output.DICT,
            config="--psm 3",          # Auto page segmentation
        )
        words      = [w for w in data["text"]  if w.strip()]
        confs      = [c for c, w in zip(data["conf"], data["text"]) if w.strip() and c > 0]
        full_text  = " ".join(words)
        confidence = sum(confs) / len(confs) if confs else 0.0
    except Exception as exc:
        logger.warning("OCR data extraction failed, falling back to simple string: %s", exc)
        full_text  = pytesseract.image_to_string(img)
        confidence = -1.0

    return full_text.strip(), confidence


def _analyze_text(text: str) -> tuple[float, list[ImageHit]]:
    """Quét text OCR theo IMAGE_SCAM_PATTERNS."""
    total = 0.0
    hits: list[ImageHit] = []

    for pattern, score, desc in IMAGE_SCAM_PATTERNS:
        match = pattern.search(text)
        if match:
            hits.append(ImageHit(
                pattern_desc=desc,
                score=score,
                matched_text=match.group(0)[:80],
            ))
            total += score

    return total, hits


def _build_summary(
    text: str,
    score: float,
    level: str,
    hits: list[ImageHit],
    confidence: float,
) -> str:
    if level == "UNREADABLE":
        return "Image could not be read by OCR (low confidence or non-text image)."
    if level == "LOW":
        conf_note = f" (OCR confidence: {confidence:.0f}%)" if confidence >= 0 else ""
        return f"No scam indicators found in image text{conf_note}."

    parts = [f"⚠ Image risk: {level} (score={score:.1f})"]
    if confidence >= 0:
        parts[0] += f" | OCR confidence: {confidence:.0f}%"

    for h in sorted(hits, key=lambda x: x.score, reverse=True)[:5]:
        parts.append(f'  • {h.pattern_desc} → "{h.matched_text}"')

    if text:
        preview = text[:200].replace("\n", " ")
        parts.append(f'\nExtracted text preview: "{preview}..."')

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def analyze_image_bytes(raw: bytes) -> ImageRisk:
    """
    Phân tích ảnh từ raw bytes (dùng khi đã download ảnh về).

    Args:
        raw: Raw image bytes (PNG, JPEG, WEBP, ...)

    Returns:
        ImageRisk với extracted text, score, level, và hits.
    """
    if not raw:
        return ImageRisk(
            extracted_text="",
            total_score=0.0,
            risk_level="LOW",
            summary="Empty image data.",
        )

    try:
        text, confidence = _ocr_image_bytes(raw)
    except ImportError as exc:
        logger.error("OCR dependencies missing: %s", exc)
        return ImageRisk(
            extracted_text="",
            total_score=0.0,
            risk_level="LOW",
            summary=str(exc),
            ocr_confidence=-1.0,
        )
    except Exception as exc:
        logger.warning("OCR failed: %s", exc)
        return ImageRisk(
            extracted_text="",
            total_score=0.0,
            risk_level="LOW",
            summary=f"OCR error: {exc}",
            ocr_confidence=-1.0,
        )

    # Nếu text quá ngắn hoặc confidence thấp → ảnh không đọc được
    if len(text.strip()) < 10 or (confidence >= 0 and confidence < 20):
        return ImageRisk(
            extracted_text=text,
            total_score=0.0,
            risk_level="UNREADABLE",
            summary="Image could not be read by OCR (low confidence or non-text image).",
            ocr_confidence=confidence,
        )

    score, hits = _analyze_text(text)

    if score >= IMAGE_RISK_THRESHOLD_HIGH:
        level = "HIGH"
    elif score >= IMAGE_RISK_THRESHOLD_MEDIUM:
        level = "MEDIUM"
    else:
        level = "LOW"

    summary = _build_summary(text, score, level, hits, confidence)

    logger.info(
        "Image analysis: score=%.1f level=%s hits=%d confidence=%.0f text_len=%d",
        score, level, len(hits), confidence, len(text),
    )

    return ImageRisk(
        extracted_text=text,
        total_score=round(score, 2),
        risk_level=level,
        hits=hits,
        summary=summary,
        ocr_confidence=round(confidence, 1),
    )


async def analyze_image_url(url: str, timeout: int = 10) -> ImageRisk:
    """
    Download ảnh từ URL (Discord CDN, Twitter CDN...) rồi phân tích.

    Args:
        url    : URL của ảnh.
        timeout: Timeout download (giây).

    Returns:
        ImageRisk — trả về level=LOW nếu download thất bại.
    """
    try:
        import aiohttp
    except ImportError:
        logger.error("aiohttp chưa cài. Chạy: pip install aiohttp")
        return ImageRisk("", 0.0, "LOW", summary="aiohttp not installed.")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status != 200:
                    logger.warning("Image download failed: HTTP %d for %s", resp.status, url)
                    return ImageRisk("", 0.0, "LOW", summary=f"HTTP {resp.status}")
                raw = await resp.read()
    except asyncio.TimeoutError:
        logger.warning("Image download timeout: %s", url)
        return ImageRisk("", 0.0, "LOW", summary="Download timeout.")
    except Exception as exc:
        logger.warning("Image download error for %s: %s", url, exc)
        return ImageRisk("", 0.0, "LOW", summary=str(exc))

    return analyze_image_bytes(raw)