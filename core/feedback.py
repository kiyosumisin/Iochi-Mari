"""Moderator feedback on Mari's decisions.

Every case Mari acts on (or sends for review) gets a short id, remembered on
disk so the buttons under its notice keep working after a restart. When a
moderator answers, the verdict is recorded:
  - links  -> ai/feedback.csv, read by `python -m ai.train --feedback`
  - images -> fingerprints of confirmed scam images (caught again anywhere on
              sight) and of images confirmed safe (never punished again)
"""

import csv
import json
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

from core.guild_settings import atomic_write
from core.image_scanner import hash_distance

ROOT = Path(__file__).resolve().parent.parent
CASES_FILE = ROOT / "data" / "feedback_cases.json"
HASHES_FILE = ROOT / "data" / "image_hashes.json"
FEEDBACK_CSV = ROOT / "ai" / "feedback.csv"

MALICIOUS_LABEL = 0   # same convention as ai/data/urls.csv (0 = malicious, 1 = benign)
MAX_CASES = 2000      # oldest cases are forgotten beyond this
MATCH_DISTANCE = 6    # images whose fingerprints differ in <= 6 of 64 bits are "the same"


def _load(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


class FeedbackStore:
    def __init__(self):
        self.cases: dict[str, dict] = _load(CASES_FILE, {})
        hashes = _load(HASHES_FILE, {})
        self.scam_hashes = [int(h, 16) for h in hashes.get("scam", [])]
        self.safe_hashes = [int(h, 16) for h in hashes.get("safe", [])]

    # -- cases -------------------------------------------------------------
    def new_case(self, kind: str, guild_id: int, user_id: int, *, verdict: str = "",
                 url: str | None = None, image_hash: int | None = None) -> str:
        """kind: "actioned" (Mari already acted) or "review" (waiting for a moderator)."""
        case_id = secrets.token_hex(4)
        self.cases[case_id] = {
            "kind": kind, "guild_id": guild_id, "user_id": user_id, "verdict": verdict,
            "url": url, "image_hash": f"{image_hash:016x}" if image_hash is not None else None,
            "created": time.time(), "resolved": None,
        }
        if len(self.cases) > MAX_CASES:
            for old in sorted(self.cases, key=lambda c: self.cases[c]["created"])[: len(self.cases) - MAX_CASES]:
                del self.cases[old]
        self._save_cases()
        return case_id

    def resolve(self, case_id: str, malicious: bool, by: str) -> dict | None:
        """Record a moderator's answer (once). Returns the case, or None if unknown."""
        case = self.cases.get(case_id)
        if case is None or case["resolved"]:
            return case
        case["resolved"] = {"malicious": malicious, "by": by,
                            "at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
        if case.get("url"):
            self._append_url_label(case["url"], malicious)
        if case.get("image_hash"):
            h = int(case["image_hash"], 16)
            self.add_scam_hash(h) if malicious else self.add_safe_hash(h)
        self._save_cases()
        return case

    # -- image fingerprints ------------------------------------------------
    def is_known_scam(self, h: int) -> bool:
        return (any(hash_distance(h, s) <= MATCH_DISTANCE for s in self.scam_hashes)
                and not any(hash_distance(h, s) <= MATCH_DISTANCE for s in self.safe_hashes))

    def add_scam_hash(self, h: int):
        # A blank or plain-gradient picture hashes to (almost) all 0s or all 1s and
        # would "match" every other blank screenshot: too little detail to ban on.
        if not 8 <= bin(h).count("1") <= 56:
            return
        if not any(hash_distance(h, s) <= MATCH_DISTANCE for s in self.scam_hashes):
            self.scam_hashes.append(h)
            self._save_hashes()

    def add_safe_hash(self, h: int):
        # A moderator said this picture is fine: forget any scam fingerprint for it.
        self.scam_hashes = [s for s in self.scam_hashes if hash_distance(h, s) > MATCH_DISTANCE]
        if not any(hash_distance(h, s) <= MATCH_DISTANCE for s in self.safe_hashes):
            self.safe_hashes.append(h)
        self._save_hashes()

    # -- persistence -------------------------------------------------------
    def _save_cases(self):
        atomic_write(CASES_FILE, json.dumps(self.cases, ensure_ascii=False))

    def _save_hashes(self):
        atomic_write(HASHES_FILE, json.dumps({
            "scam": [f"{h:016x}" for h in self.scam_hashes],
            "safe": [f"{h:016x}" for h in self.safe_hashes],
        }))

    @staticmethod
    def _append_url_label(url: str, malicious: bool):
        # Same columns, same order as app.py's /feedback, which writes this file too.
        new = not FEEDBACK_CSV.exists() or FEEDBACK_CSV.stat().st_size == 0
        FEEDBACK_CSV.parent.mkdir(parents=True, exist_ok=True)
        with FEEDBACK_CSV.open("a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["timestamp", "url", "label"])
            w.writerow([datetime.now(timezone.utc).isoformat(timespec="seconds"), url,
                        MALICIOUS_LABEL if malicious else 1 - MALICIOUS_LABEL])
