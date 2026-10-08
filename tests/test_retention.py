"""Old records holding message content are deleted. Run: python tests/test_retention.py"""

import csv
import json
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.feedback as fb  # noqa: E402
import core.retention as rt  # noqa: E402
from core.guild_settings import GuildSettings  # noqa: E402

NOW = datetime.now(timezone.utc)
OLD = NOW - timedelta(days=rt.RETENTION_DAYS + 1)
NEW = NOW - timedelta(days=1)


def test_old_records_are_purged_and_new_ones_kept():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        rt.AGENT_LOG, rt.CATCH_LOG = tmp / "agent_calls.jsonl", tmp / "scam_catches.csv"
        fb.CASES_FILE, fb.HASHES_FILE = tmp / "cases.json", tmp / "hashes.json"

        rt.AGENT_LOG.write_text(
            json.dumps({"ts": OLD.isoformat(), "input": {"message_text": "old"}}) + "\n"
            + json.dumps({"ts": NEW.isoformat(), "input": {"message_text": "new"}}) + "\n"
            + "not json\n",
            encoding="utf-8")
        with rt.CATCH_LOG.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["timestamp_utc", "server", "channel", "user", "user_id", "category", "detail", "action"])
            for when, detail in ((OLD, "old"), (NEW, "new")):
                w.writerow([when.strftime("%Y-%m-%d %H:%M:%S"), "s", "c", "u", 1, "url", detail, "banned"])

        gs = GuildSettings()
        gs.path = tmp / "guild_settings.json"
        gs.data = {"1": {"violations": {
            "10": [{"timestamp": OLD.strftime("%Y-%m-%d %H:%M UTC"), "url": "old"}],
            "11": [{"timestamp": OLD.strftime("%Y-%m-%d %H:%M UTC"), "url": "old"},
                   {"timestamp": NEW.strftime("%Y-%m-%d %H:%M UTC"), "url": "new"}],
        }}}
        store = fb.FeedbackStore()
        old_case = store.new_case("review", 1, 10, url="https://old.example/")
        store.cases[old_case]["created"] = time.time() - (rt.RETENTION_DAYS + 1) * 86400
        new_case = store.new_case("review", 1, 11, url="https://new.example/")

        dropped = rt.purge_all(gs, store)

        assert dropped == {"agent_calls": 2, "scam_catches": 1, "violations": 2, "review_cases": 1}, dropped
        assert [json.loads(l)["input"]["message_text"] for l in rt.AGENT_LOG.read_text(encoding="utf-8").splitlines()] == ["new"]
        assert [r["detail"] for r in csv.DictReader(rt.CATCH_LOG.open(encoding="utf-8"))] == ["new"]
        assert gs.data["1"]["violations"] == {"11": [{"timestamp": NEW.strftime("%Y-%m-%d %H:%M UTC"), "url": "new"}]}
        assert list(store.cases) == [new_case]
        assert rt.purge_all(gs, store) == {"agent_calls": 0, "scam_catches": 0, "violations": 0, "review_cases": 0}


if __name__ == "__main__":
    tests = [f for name, f in dict(globals()).items() if name.startswith("test_")]
    for t in tests:
        t()
        print("ok  ", t.__name__)
    print(f"{len(tests)} passed")
