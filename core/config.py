import os
from dotenv import load_dotenv

class Config:
    def __init__(self):
        load_dotenv()

        self.TOKEN = os.getenv("DISCORD_TOKEN")
        self.GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
        self.VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
        self.URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
        self.ADMIN_ROLE_ID = int(os.getenv("ADMIN_ROLE_ID", "0"))
        # The sole owner who may use owner-only commands (/checkimg, /text).
        # Defaults to the bot keeper; override with OWNER_ID in .env if needed.
        self.OWNER_ID = int(os.getenv("OWNER_ID", "849917651786268703") or "0")
        self.GUILD_ID = int(os.getenv("GUILD_ID", "0"))
        self.LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID", "0"))
        self.HONEYPOT_CHANNEL_ID = int(os.getenv("HONEYPOT_CHANNEL_ID", "0") or "0")

        # Gemini agent layer (borderline-case analysis)
        self.GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
        self.GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
        self.AGENT_ENABLED = os.getenv("AGENT_ENABLED", "true").lower() in ("1", "true", "yes")
        # An AI-only phishing verdict (no blacklist/scanner evidence) below HIGH is
        # sent to the Gemini agent for review instead of an automatic ban; at or
        # above HIGH (= AI_OVERRIDE_THRESHOLD by default) the model is confident.
        self.AI_BORDERLINE_LOW = float(os.getenv("AI_BORDERLINE_LOW", "0.0") or "0.0")
        self.AI_BORDERLINE_HIGH = float(
            os.getenv("AI_BORDERLINE_HIGH", os.getenv("AI_OVERRIDE_THRESHOLD", "0.9")) or "0.9"
        )

        if not self.TOKEN:
            raise RuntimeError("DISCORD_TOKEN is missing")