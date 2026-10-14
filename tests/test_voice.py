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


def test_calling_mari_versus_talking_about_her():
    from bot.voice import CALL as _CALL
    for call in ["Mari ơi", "Mari à, giúp anh", "Mari ạ", "Mari nè", "Mari", "Mari!", "Mari, hình này là gì", "ê Mari ơi"]:
        assert _CALL.match(call), call
    for talk in ["Mari bắt scam giỏi ghê", "Marina", "Mari an toàn không", "hello Mari ơi"]:
        assert not _CALL.match(talk), talk


def test_deleting_our_chat_spares_everyone_else():
    import types as T
    from bot.commands.actions import _our_chat
    SENSEI, MARI, FRIEND = 1, 999, 42
    msgs = {}

    def m(i, who, text, reply_to=None):
        ref = T.SimpleNamespace(resolved=msgs[reply_to]) if reply_to else None
        msgs[i] = T.SimpleNamespace(id=i, author=T.SimpleNamespace(id=who), content=text, reference=ref)

    for args in [(1, SENSEI, "Mari ơi, hôm nay thế nào?"), (2, MARI, "Dạ em ổn ạ", 1), (3, FRIEND, "đi ăn không"),
                 (4, SENSEI, "đi luôn"), (5, FRIEND, "Mari ơi"), (6, MARI, "Vâng, Mari đây ạ", 5),
                 (7, SENSEI, "kể tiếp đi em", 2), (8, MARI, "Dạ...", 7)]:
        m(*args)
    match = _our_chat(T.SimpleNamespace(user=T.SimpleNamespace(id=MARI)), SENSEI)
    assert [i for i, x in msgs.items() if match(x)] == [1, 2, 7, 8]


if __name__ == "__main__":
    tests = [f for name, f in dict(globals()).items() if name.startswith("test_")]
    for t in tests:
        t()
        print("ok  ", t.__name__)
    print(f"{len(tests)} passed")
