"""Delete stored records that contain users' message content or activity once
they are older than RETENTION_DAYS. Daily backups are kept 7 days on top, so no
such record outlives 30 days (promised in PRIVACY.md).

Kept, because they identify no one: image fingerprints of confirmed scams
(data/image_hashes.json) and moderator-labelled links for retraining
(ai/feedback.csv, no user IDs)."""

import csv
import io
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.guild_settings import atomic_write

logger = logging.getLogger(__name__)

RETENTION_DAYS = 23  # + 7 days of backups = 30
LOG_DIR = Path(__file__).resolve().parent.parent / "log"
AGENT_LOG = LOG_DIR / "agent_calls.jsonl"
CATCH_LOG = LOG_DIR / "scam_catches.csv"


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def purge_agent_log(path: Path, before: datetime) -> int:
    """Gemini case log (message text, recent messages): one JSON object per line."""
    if not path.exists():
        return 0
    lines = path.read_text(encoding="utf-8").splitlines()
    kept = []
    for line in lines:
        try:
            if _utc(datetime.fromisoformat(json.loads(line)["ts"])) >= before:
                kept.append(line)
        except (ValueError, KeyError, TypeError):
            pass  # unreadable: drop it rather than keep it forever
    if len(kept) != len(lines):
        atomic_write(path, "".join(line + "\n" for line in kept))
    return len(lines) - len(kept)


def purge_catch_log(path: Path, before: datetime) -> int:
    """Scam catch evidence log (/scamlog)."""
    if not path.exists():
        return 0
    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    if not rows:
        return 0
    header, body = rows[0], rows[1:]
    col = header.index("timestamp_utc")

    def recent(row):
        try:
            return _utc(datetime.strptime(row[col], "%Y-%m-%d %H:%M:%S")) >= before
        except (IndexError, ValueError):
            return False

    kept = [r for r in body if recent(r)]
    if len(kept) != len(body):
        buf = io.StringIO()
        csv.writer(buf, lineterminator="\n").writerows([header] + kept)
        atomic_write(path, buf.getvalue())
    return len(body) - len(kept)


def purge_all(guild_settings, feedback) -> dict:
    """Run every purge; returns how many records each one dropped."""
    before = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
    dropped = {
        "agent_calls": purge_agent_log(AGENT_LOG, before),
        "scam_catches": purge_catch_log(CATCH_LOG, before),
        "violations": guild_settings.purge_violations(before),
        "review_cases": feedback.purge(time.time() - RETENTION_DAYS * 86400),
    }
    logger.info("Retention purge (older than %d days): %s", RETENTION_DAYS, dropped)
    return dropped
