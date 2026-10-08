"""Known scams (listed links, fingerprinted images) outside the honeypot: warn a
lone post, ban a scam bot. Run: python tests/test_known_scams.py"""

import asyncio
import io
import sys
import tempfile
import types as T
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PIL import Image, ImageDraw  # noqa: E402

import core.feedback as fb  # noqa: E402
from bot.events import MessageHandler  # noqa: E402
from core.image_scanner import dhash  # noqa: E402

HONEYPOT, GENERAL = 100, 1
SCAM = "https://d-giftnitro.com/claim"


def _png() -> bytes:
    im = Image.new("RGB", (300, 200), (30, 30, 60))
    ImageDraw.Draw(im).rectangle((20, 20, 200, 120), fill=(200, 60, 60))
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


IMG = _png()


class World:
    """A fake guild that records every action Mari takes."""

    def __init__(self, honeypot=True, whitelist=()):
        tmp = Path(tempfile.mkdtemp())
        fb.CASES_FILE, fb.HASHES_FILE, fb.FEEDBACK_CSV = tmp / "c.json", tmp / "h.json", tmp / "f.csv"
        self.feedback = fb.FeedbackStore()
        self.feedback.add_scam_hash(dhash(IMG))
        self.log = []
        log = self.log

        class Guild:
            id = 7

            def get_channel(self, cid):
                return None

            async def ban(self, user, reason, delete_message_days):
                log.append(("ban", user.id, reason))

        self.guild = Guild()
        gs = T.SimpleNamespace(
            get_honeypot_channel=lambda g: HONEYPOT if honeypot else 0,
            get_log_channel=lambda g: None, get_threshold=lambda g: None,
            get_whitelist=lambda g: set(whitelist), increment_stat=lambda *a, **k: None,
            record_violation=lambda *a, **k: None,
        )
        evaluator = T.SimpleNamespace(is_known_scam=lambda d: d == "d-giftnitro.com")
        cfg = T.SimpleNamespace(TIMEOUT_DURATIONS=["10m"], HONEYPOT_WARN_LIMIT=3, OCR_ENABLED=False,
                                HONEYPOT_CHANNEL_ID=0, LOG_CHANNEL_ID=0)
        self.handler = MessageHandler(evaluator, cfg, gs, None, self.feedback)
        self.handler.warn_file = tmp / "warnings.json"
        self.handler.warns = {}
        self.handler._log_catch = lambda *a, **k: None

    def post(self, channel_id, content="", image=False, user=42, admin=False):
        log = self.log

        class Channel:
            id, name = channel_id, f"ch{channel_id}"

            async def send(self, text, view=None, **kw):
                log.append(("send", text, view))

        class Att:
            filename, content_type, size = "a.png", "image/png", len(IMG)

            async def read(self):
                return IMG

        async def delete():
            log.append(("delete",))

        author = T.SimpleNamespace(id=user, bot=False, mention=f"<@{user}>",
                                   guild_permissions=T.SimpleNamespace(administrator=admin))
        msg = T.SimpleNamespace(author=author, guild=self.guild, channel=Channel(), content=content,
                                attachments=[Att()] if image else [], delete=delete)
        asyncio.run(self.handler.handle(msg))

    def kinds(self):
        return [e[0] for e in self.log]


def test_lone_known_scam_link_outside_honeypot_is_warned_not_banned():
    w = World()
    w.post(GENERAL, f"careful, this is a scam: {SCAM}")
    assert w.kinds().count("ban") == 0 and "delete" in w.kinds(), w.log
    notices = [e for e in w.log if e[0] == "send" and e[2] is not None]
    assert len(notices) == 1 and "Link: `" + SCAM in notices[0][1]
    assert [c.item.label for c in notices[0][2].children] == ["Ban", "Dismiss"]
    # The review case teaches nothing: dismissing it must not mark the scam safe.
    case = next(iter(w.feedback.cases.values()))
    assert case["url"] is None and case["image_hash"] is None


def test_scam_bot_burst_across_channels_is_banned():
    w = World()
    for ch in (1, 2, 3):
        w.post(ch, f"free nitro {SCAM}")
    assert w.kinds().count("ban") == 1, w.log


def test_known_scam_in_honeypot_is_banned_at_once():
    w = World()
    w.post(HONEYPOT, SCAM)
    assert ("ban", 42, "Known scam link") in w.log


def test_known_image_outside_honeypot_is_warned_even_in_normal_mode():
    w = World(honeypot=False)
    w.post(GENERAL, image=True)
    assert "ban" not in w.kinds() and "delete" in w.kinds()


def test_repeat_offender_is_banned_after_the_warning_limit():
    w = World()
    for _ in range(4):
        w.handler._media_posts.clear()  # separate posts, not one burst
        w.post(GENERAL, SCAM)
    assert w.kinds().count("ban") == 1 and w.log[-1][0] == "send"


def test_unlisted_links_admins_and_trusted_domains_are_left_alone():
    w = World(whitelist={"d-giftnitro.com"})
    w.post(GENERAL, SCAM)
    w2 = World()
    w2.post(GENERAL, "https://example.com/")
    w2.post(GENERAL, SCAM, admin=True, user=9)
    assert w.log == [] and w2.log == [], (w.log, w2.log)


if __name__ == "__main__":
    tests = [f for name, f in dict(globals()).items() if name.startswith("test_")]
    for t in tests:
        t()
        print("ok  ", t.__name__)
    print(f"{len(tests)} passed")
