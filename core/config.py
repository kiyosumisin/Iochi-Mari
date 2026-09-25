import os

from dotenv import load_dotenv


def _flag(name: str, default: str) -> bool:
    return os.getenv(name, default).lower() in ("1", "true", "yes")


class Config:
    """Every runtime setting the bot reads, in one place (loaded from .env).

    The standalone ML tools (ai/predict.py, ai/train.py, app.py) keep reading
    their own AI_* variables so they still work without the bot.
    """

    def __init__(self):
        load_dotenv()

        # -- Discord ---------------------------------------------------------
        self.TOKEN = os.getenv("DISCORD_TOKEN")
        # Owner-only commands (/check img, /text). Override with OWNER_ID if needed.
        self.OWNER_ID = int(os.getenv("OWNER_ID", "849917651786268703") or "0")
        self.GUILD_ID = int(os.getenv("GUILD_ID", "0") or "0")  # 0 = global command sync
        # Fallbacks only; the per-server slash commands take precedence.
        self.LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID", "0") or "0")
        self.HONEYPOT_CHANNEL_ID = int(os.getenv("HONEYPOT_CHANNEL_ID", "0") or "0")

        # -- External scanners -----------------------------------------------
        self.GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
        self.VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

        # -- URL verdicts ----------------------------------------------------
        # At or above this, an AI phishing verdict is acted on without review.
        self.AI_OVERRIDE_THRESHOLD = float(os.getenv("AI_OVERRIDE_THRESHOLD", "0.9") or "0.9")
        # At or below this (and no heuristic hit) a URL skips the slow scanners.
        self.AI_SAFE_THRESHOLD = float(os.getenv("AI_SAFE_THRESHOLD", "0.15") or "0.15")
        # An AI-only phishing verdict (no blacklist/scanner evidence) in this
        # band goes to the Gemini agent for review instead of an automatic ban.
        self.AI_BORDERLINE_LOW = float(os.getenv("AI_BORDERLINE_LOW", "0.0") or "0.0")
        self.AI_BORDERLINE_HIGH = float(os.getenv("AI_BORDERLINE_HIGH") or self.AI_OVERRIDE_THRESHOLD)

        # -- Moderation ------------------------------------------------------
        self.TIMEOUT_DURATIONS = [
            d.strip() for d in os.getenv("TIMEOUT_DURATIONS", "10m,1h,6h,1d,3d").split(",") if d.strip()
        ]
        self.HONEYPOT_WARN_LIMIT = int(os.getenv("HONEYPOT_WARN_LIMIT", "3") or "3")
        self.OCR_ENABLED = _flag("OCR_ENABLED", "true")

        # -- Gemini agent ----------------------------------------------------
        self.GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
        self.GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
        self.AGENT_ENABLED = _flag("AGENT_ENABLED", "true")
        self.GEMINI_RPM = int(os.getenv("GEMINI_RPM", "15") or "15")    # flash-lite free tier
        self.GEMINI_RPD = int(os.getenv("GEMINI_RPD", "500") or "500")
        self.GEMINI_TIMEOUT = float(os.getenv("GEMINI_TIMEOUT", "8") or "8")
        # Optional relay (relay/, on Vercel) for hosts Google geo-blocks.
        self.GEMINI_BASE_URL = os.getenv("GEMINI_BASE_URL") or None
        self.GEMINI_RELAY_TOKEN = os.getenv("GEMINI_RELAY_TOKEN", "")

        if not self.TOKEN:
            raise RuntimeError("DISCORD_TOKEN is missing")
