import io
import os
import logging
from pathlib import Path

try:
    from PIL import Image, ImageOps
    import pytesseract
except Exception:  # pragma: no cover
    Image = None
    ImageOps = None
    pytesseract = None

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tesseract binary resolution
# On Windows the binary is frequently not on PATH; point pytesseract at it.
# Override with the TESSERACT_CMD env var if installed somewhere custom.
# ---------------------------------------------------------------------------
def _configure_tesseract() -> None:
    if pytesseract is None:
        return
    candidates = [
        os.getenv("TESSERACT_CMD"),
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
    ]
    for c in candidates:
        if c and os.path.exists(c):
            pytesseract.pytesseract.tesseract_cmd = c
            return
    # Otherwise rely on PATH (pytesseract's default).


_configure_tesseract()

# Language(s) passed to Tesseract, e.g. "eng", "vie", or "vie+eng".
# Vietnamese needs the `vie` traineddata installed in Tesseract's tessdata dir.
OCR_LANG = os.getenv("OCR_LANG", "eng")

SCAM_KEYWORDS = [
    "free nitro",
    "nitro gift",
    "free gift",
    "gift card",
    "claim",
    "giveaway",
    "airdrop",
    "bonus",
    "urgent",
    "limited time",
    "verify",
    "login",
    "password",
    "wallet",
    "crypto",
    "bitcoin",
    "eth",
    "usdt",
]


def _preprocess(img: "Image.Image") -> "Image.Image":
    """
    Normalise an image for OCR: flatten transparency onto white, convert to
    grayscale, upscale small images (Tesseract needs a decent x-height), and
    stretch contrast. Greatly improves recognition on screenshots/scam images.
    """
    if img.mode in ("RGBA", "LA", "P"):
        img = img.convert("RGBA")
        bg = Image.new("RGBA", img.size, (255, 255, 255, 255))
        img = Image.alpha_composite(bg, img)
    img = img.convert("L")
    if img.width and img.width < 1200:
        scale = min(4, max(2, 1200 // img.width))
        img = img.resize((img.width * scale, img.height * scale))
    return ImageOps.autocontrast(img)


def _run_ocr(img: "Image.Image", lang: str) -> str | None:
    """
    Run Tesseract trying a couple of page-segmentation modes, keeping the
    longest result. Returns None if the language pack is unavailable (so the
    caller can fall back), or the extracted text otherwise (possibly empty).
    """
    best = ""
    for psm in (6, 3):
        try:
            text = pytesseract.image_to_string(img, lang=lang, config=f"--psm {psm}")
        except Exception as exc:
            logger.warning("OCR failed (lang=%s psm=%s): %s", lang, psm, exc)
            return None
        if len(text.strip()) > len(best.strip()):
            best = text
    return best


def ocr_image_bytes(data: bytes) -> str:
    if Image is None or pytesseract is None:
        raise RuntimeError("OCR dependencies not installed (pillow, pytesseract)")

    with Image.open(io.BytesIO(data)) as raw:
        img = _preprocess(raw)

    text = _run_ocr(img, OCR_LANG)
    # Fall back to English if the configured language pack isn't installed.
    if text is None and OCR_LANG != "eng":
        logger.warning("OCR lang %r unavailable — falling back to eng", OCR_LANG)
        text = _run_ocr(img, "eng")
    return text or ""


def append_ocr_log(text: str, source: str, verdict: str | None = None):
    log_dir = Path(__file__).resolve().parent.parent / "log"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "ocr.log"
    with log_file.open("a", encoding="utf-8") as f:
        if verdict:
            f.write(f"SOURCE: {source} | VERDICT: {verdict}\n")
        else:
            f.write(f"SOURCE: {source}\n")
        f.write(f"{text.strip()}\n---\n")


def scan_ocr_text(text: str) -> str | None:
    lowered = text.lower()
    hits = [k for k in SCAM_KEYWORDS if k in lowered]
    if len(hits) >= 2:
        return "scam"
    if len(hits) == 1:
        return "suspected"
    return None
