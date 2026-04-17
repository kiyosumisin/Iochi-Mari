import io
import logging
from pathlib import Path

try:
    from PIL import Image
    import pytesseract
except Exception:  # pragma: no cover
    Image = None
    pytesseract = None

logger = logging.getLogger(__name__)

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


def ocr_image_bytes(data: bytes) -> str:
    if Image is None or pytesseract is None:
        raise RuntimeError("OCR dependencies not installed (pillow, pytesseract)")

    with Image.open(io.BytesIO(data)) as img:
        return pytesseract.image_to_string(img)


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