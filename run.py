import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

from dotenv import load_dotenv

# Load .env before importing the bot: some modules read settings at import time
# (e.g. OCR_LANG in core/image_scanner.py), before Config() would load it.
load_dotenv()

from bot.mari_bot import MariBot  # noqa: E402


def setup_logging():
    log_dir = Path(__file__).resolve().parent / "log"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "mari.log"

    handler = TimedRotatingFileHandler(
        log_file,
        when="W0",
        interval=1,
        backupCount=4,
        encoding="utf-8",
    )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        # stdout too, so `journalctl -u mari` shows the bot's own logs on the VPS.
        handlers=[handler, logging.StreamHandler()],
    )

if __name__ == "__main__":
    setup_logging()
    bot = MariBot()
    # log_handler=None: our root handlers above already cover discord.py's logs.
    bot.run(bot.config.TOKEN, log_handler=None)
 