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
        raw_adult_channels = os.getenv("ADULT_CHANNEL_IDS", "").strip()
        self.ADULT_CHANNEL_IDS = [
            int(x) for x in raw_adult_channels.split(",") if x.strip().isdigit()
        ]

        if not self.TOKEN:
            raise RuntimeError("DISCORD_TOKEN is missing")
