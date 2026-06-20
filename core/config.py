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
        self.GUILD_ID = int(os.getenv("GUILD_ID", "0"))
        self.LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID", "0"))
        self.HONEYPOT_CHANNEL_ID = int(os.getenv("HONEYPOT_CHANNEL_ID", "0") or "0")

        # Gemini agent layer (borderline-case analysis)
        self.GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
        self.GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        self.AGENT_ENABLED = os.getenv("AGENT_ENABLED", "true").lower() in ("1", "true", "yes")
        self.AI_BORDERLINE_LOW = float(os.getenv("AI_BORDERLINE_LOW", "0.4") or "0.4")
        self.AI_BORDERLINE_HIGH = float(os.getenv("AI_BORDERLINE_HIGH", "0.7") or "0.7")
        raw_adult_channels = os.getenv("ADULT_CHANNEL_IDS", "").strip()
        self.ADULT_CHANNEL_IDS = [
            int(x) for x in raw_adult_channels.split(",") if x.strip().isdigit()
        ]

        if not self.TOKEN:
            raise RuntimeError("DISCORD_TOKEN is missing")