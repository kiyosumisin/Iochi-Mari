"""Mari addresses her owner as a student addresses Sensei. Run: python tests/test_voice.py"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bot.voice import to_reader  # noqa: E402


def test_owner_is_sensei_and_mari_says_em():
    assert to_reader("Mari có thể giúp gì cho bạn? Cứ gọi Mari nhé.", True) == \
        "Em có thể giúp gì cho Sensei? Cứ gọi em nhé."
    assert to_reader("Xong rồi ạ, Mari đã dọn 3 tin.\nMari đi nghỉ đây.", True) == \
        "Xong rồi ạ, em đã dọn 3 tin.\nEm đi nghỉ đây."


def test_code_and_other_readers_are_left_alone():
    assert to_reader("`Mari ơi` — Gọi xem Mari có ở đây không", True) == \
        "`Mari ơi` — Gọi xem em có ở đây không"
    text = "Mari có thể giúp gì cho bạn?"
    assert to_reader(text, False) == text
    assert to_reader("bạnbè", True) == "bạnbè"


if __name__ == "__main__":
    tests = [f for name, f in dict(globals()).items() if name.startswith("test_")]
    for t in tests:
        t()
        print("ok  ", t.__name__)
    print(f"{len(tests)} passed")
