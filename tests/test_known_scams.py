"""Known scams (listed links, fingerprinted images) outside the honeypot: warn a
lone post, ban a scam bot. Run: python tests/test_known_scams.py"""

import asyncio
import io
import itertools
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
_ids = itertools.count(1)


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
        self.verdicts = {}  # url -> evaluate_detailed() answer for the watch mode; default safe

        async def evaluate_detailed(url, threshold=None):
            return self.verdicts.get(url, {"verdict": "safe", "probability": 0.01, "sources": []})

        evaluator = T.SimpleNamespace(is_known_scam=lambda d: d == "d-giftnitro.com",
                                      evaluate_detailed=evaluate_detailed)
        cfg = T.SimpleNamespace(HONEYPOT_WARN_LIMIT=3, OCR_ENABLED=False,
                                HONEYPOT_CHANNEL_ID=0, LOG_CHANNEL_ID=0, AI_OVERRIDE_THRESHOLD=0.9,
                                OWNER_ID=1)
        self.handler = MessageHandler(evaluator, cfg, gs, None, self.feedback)
        self.handler.warn_file = tmp / "warnings.json"
        self.handler.warns = {}
        self.handler._log_catch = lambda *a, **k: None

    def post(self, channel_id, content="", image=False, user=42, admin=False):
        log = self.log

        class Channel:
            id, name = channel_id, f"ch{channel_id}"

            async def send(self, text, view=None, **kw):
                pinged = [u.id for u in getattr(kw.get("allowed_mentions"), "users", None) or []]
                log.append(("send", text, view, pinged))
                n = len(log)

                async def unsend():
                    log.append(("unsend", n))
                return T.SimpleNamespace(delete=unsend)

        class Att:
            filename, content_type, size, id = "a.png", "image/png", len(IMG), next(_ids)

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
    assert len(notices) == 1 and "Liên kết: `" + SCAM in notices[0][1]
    assert [c.item.label for c in notices[0][2].children] == ["Ban", "Bỏ qua"]
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
    assert ("ban", 42, "Scam đã biết (liên kết)") in w.log


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


def test_strong_suspicion_is_hidden_and_sensei_asked_in_that_channel():
    w = World()
    w.verdicts["https://evil.example/login"] = {"verdict": "phishing", "probability": 0.4,
                                                "sources": ["scanner:phishing"]}
    w.post(GENERAL, "https://evil.example/login")
    sends = [e for e in w.log if e[0] == "send"]
    assert "ban" not in w.kinds() and "delete" in w.kinds(), w.log
    assert len(sends) == 1 and sends[0][3] == [1] and "Sensei ơi" in sends[0][1]
    assert [c.item.label for c in sends[0][2].children] == ["Ban", "Bỏ qua"]
    case = next(iter(w.feedback.cases.values()))
    assert case["url"] == "https://evil.example/login"  # "Bỏ qua" teaches Mari this link is fine


def test_weak_suspicion_leaves_the_post_and_pings_no_one():
    w = World()
    w.verdicts["https://odd.example/"] = {"verdict": "phishing", "probability": 0.6, "sources": ["ai:phishing:0.6"]}
    w.post(GENERAL, "https://odd.example/")
    sends = [e for e in w.log if e[0] == "send"]
    assert "delete" not in w.kinds() and "ban" not in w.kinds()
    assert len(sends) == 1 and "hơi nghi" in sends[0][1] and sends[0][3] == []


def test_sensei_is_pinged_at_most_every_ten_minutes():
    w = World()
    for n in (1, 2):
        w.verdicts[f"https://evil{n}.example/"] = {"verdict": "malware", "probability": 0.95, "sources": []}
        w.post(GENERAL, f"https://evil{n}.example/", user=40 + n)
    pings = [e[3] for e in w.log if e[0] == "send"]
    assert pings == [[1], []], pings


def test_late_posts_of_a_banned_spammer_are_deleted_quietly():
    w = World()
    for ch in (1, 2, 3, 4):
        w.post(ch, f"free nitro {SCAM}")
    # The first two posts (not yet a burst) asked Sensei; the ban takes those questions
    # back, and the late fourth post is just deleted.
    assert w.kinds().count("ban") == 1 and w.kinds().count("unsend") == 2, w.log
    assert w.kinds()[-1] == "delete" and w.kinds().count("send") == 3
    w.handler.forgive(7, 42)  # e.g. "Sai - gỡ ban": judged normally again
    w.handler._media_posts.clear()
    before = len(w.log)
    w.post(GENERAL, "hello again")
    assert len(w.log) == before  # a harmless post is left alone, not deleted


def test_images_need_two_phrases_and_gemini_before_being_hidden():
    import bot.events as ev
    w = World(honeypot=True)
    w.handler.config.OCR_ENABLED = True
    w.feedback.scam_hashes.clear()  # not a known scam image: only the watch looks at it
    verdict = {"res": None}

    async def classify(image):
        return verdict["res"]
    w.handler.agent = T.SimpleNamespace(enabled=True, classify_scam_image=classify)
    ocr = {"text": "1st Anniversary Celebration Rewards, claim rewards"}
    old = ev.ocr_image_bytes
    ev.ocr_image_bytes = lambda data: ocr["text"]
    try:
        w.post(GENERAL, image=True)                      # one phrase: a game banner, ignored
        ocr["text"] = "FREE NITRO giveaway - claim now! scan the qr code"
        verdict["res"] = {"scam": False, "confidence": 0.9}
        w.post(GENERAL, image=True, user=43)            # two phrases, Gemini disagrees: ignored
        assert w.log == [], w.log
        verdict["res"] = {"scam": True, "confidence": 0.95, "reason": "fake nitro"}
        w.post(GENERAL, image=True, user=44)            # Gemini agrees: hidden, Sensei asked
        assert "delete" in w.kinds() and any(e[0] == "send" and e[3] == [1] for e in w.log), w.log
    finally:
        ev.ocr_image_bytes = old


def test_a_server_without_honeypot_never_bans_on_a_guess():
    w = World(honeypot=False)
    w.verdicts["https://evil.example/login"] = {"verdict": "phishing", "probability": 0.97, "sources": []}
    w.post(GENERAL, "https://evil.example/login")
    assert "ban" not in w.kinds() and "delete" in w.kinds(), w.log
    assert any(e[0] == "send" and "Sensei ơi" in e[1] for e in w.log)
    w.post(GENERAL, f"<{SCAM}>", user=43)            # a listed scam, even wrapped in <...>
    assert "ban" not in w.kinds() and "Liên kết: `" + SCAM in w.log[-1][1], w.log


def test_a_ban_in_one_server_does_not_touch_another():
    w = World()
    for ch in (1, 2, 3):
        w.post(ch, f"free nitro {SCAM}")
    assert w.kinds().count("ban") == 1
    w.guild.id = 8  # same person, another server: judged on its own
    before = len(w.log)
    w.post(GENERAL, "hello")
    assert len(w.log) == before, w.log[before:]


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
