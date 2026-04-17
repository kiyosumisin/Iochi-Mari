import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

from bot.mari_bot import MariBot


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
        handlers=[handler],
    )

if __name__ == "__main__":
    setup_logging()
    bot = MariBot()
    bot.run(bot.config.TOKEN)
