"""Image fingerprints and moderator feedback. Run: python tests/test_feedback.py"""

import csv
import io
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PIL import Image, ImageDraw  # noqa: E402

import core.feedback as fb  # noqa: E402
from core.image_scanner import dhash, hash_distance  # noqa: E402


def _poster(text: str, size=(800, 600), fmt="PNG", quality=95) -> bytes:
    im = Image.new("RGB", (400, 300), (30, 30, 60))
    d = ImageDraw.Draw(im)
    d.rectangle((20, 20, 380, 120), fill=(200, 60, 60))
    d.ellipse((250, 150, 380, 280), fill=(240, 220, 90))
    d.text((40, 200), text, fill=(255, 255, 255))
    im = im.resize(size)
    buf = io.BytesIO()
    im.save(buf, fmt, quality=quality)
    return buf.getvalue()


def test_fingerprint_survives_resize_and_recompress():
    a = dhash(_poster("FREE NITRO"))
    b = dhash(_poster("FREE NITRO", size=(400, 300), fmt="JPEG", quality=40))
    assert hash_distance(a, b) <= fb.MATCH_DISTANCE, hash_distance(a, b)


def test_different_pictures_do_not_match():
    im = Image.new("RGB", (400, 300), (255, 255, 255))
    ImageDraw.Draw(im).rectangle((0, 150, 400, 300), fill=(0, 0, 0))
    buf = io.BytesIO(); im.save(buf, "PNG")
    assert hash_distance(dhash(_poster("x")), dhash(buf.getvalue())) > fb.MATCH_DISTANCE


def test_blank_pictures_are_never_remembered_as_scams():
    with tempfile.TemporaryDirectory() as tmp:
        fb.HASHES_FILE = Path(tmp) / "h.json"
        store = fb.FeedbackStore()
        buf = io.BytesIO(); Image.new("RGB", (300, 300), (0, 0, 0)).save(buf, "PNG")
        store.add_scam_hash(dhash(buf.getvalue()))
        assert store.scam_hashes == []


def test_moderator_answers_are_recorded():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        fb.CASES_FILE, fb.HASHES_FILE, fb.FEEDBACK_CSV = tmp / "c.json", tmp / "h.json", tmp / "f.csv"
        h = dhash(_poster("FREE NITRO"))
        store = fb.FeedbackStore()

        # Confirmed scam: the image is now caught anywhere, the link is labelled malicious.
        c = store.new_case("review", 1, 2, url="https://nitro-gift.example/", image_hash=h)
        store.resolve(c, True, "mod")
        assert store.is_known_scam(h ^ 0b11)             # a couple of bits off still matches
        store.resolve(c, False, "other")                 # answered once only
        assert store.is_known_scam(h)

        # Survives a restart.
        store = fb.FeedbackStore()
        assert store.is_known_scam(h) and store.cases[c]["resolved"]["by"] == "mod"

        # Overturned: the fingerprint is forgotten and never punished again.
        c2 = store.new_case("actioned", 1, 3, url="https://docs.google.com/x", image_hash=h)
        store.resolve(c2, False, "mod")
        assert not store.is_known_scam(h)
        store.add_scam_hash(h)
        assert not store.is_known_scam(h)                # the safe list wins

        rows = list(csv.DictReader(fb.FEEDBACK_CSV.open(encoding="utf-8")))
        assert [(r["url"], r["label"]) for r in rows] == [
            ("https://nitro-gift.example/", str(fb.MALICIOUS_LABEL)),
            ("https://docs.google.com/x", str(1 - fb.MALICIOUS_LABEL)),
        ]


if __name__ == "__main__":
    tests = [f for name, f in dict(globals()).items() if name.startswith("test_")]
    for t in tests:
        t()
        print("ok  ", t.__name__)
    print(f"{len(tests)} passed")
