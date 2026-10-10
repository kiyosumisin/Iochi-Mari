"""How Mari speaks: the words she uses for verdicts, and how she addresses
people. To everyone she is "Mari" and they are "bạn"; with her owner, as a
student with her Sensei in Blue Archive, she is "em" and the owner is "Sensei"."""

import re

VERDICT_VI = {"phishing": "lừa đảo đánh cắp tài khoản", "malware": "mã độc",
              "scam": "lừa đảo", "gambling": "cờ bạc"}
KIND_VI = {"link": "liên kết", "image": "hình ảnh"}
SUSPICION_VI = {"low": "thấp", "medium": "trung bình", "high": "cao"}

_YOU = re.compile(r"\b[Bb]ạn\b")
_SELF_START = re.compile(r"(^|[.!?]\s+|\n\s*)Mari\b")  # "Mari" opening a sentence
_SELF = re.compile(r"\bMari\b")
_CODE = re.compile(r"(`[^`]*`)")


async def is_sensei(client, user) -> bool:
    """True only for the configured OWNER_ID or the bot's application owner."""
    owner_id = getattr(getattr(client, "config", None), "OWNER_ID", 0)
    if owner_id and user.id == owner_id:
        return True
    try:
        return await client.is_owner(user)
    except Exception:
        return False


def to_reader(text: str, sensei: bool) -> str:
    """Speak to the reader. Replies are written for members ("Mari" ... "bạn",
    where "bạn" always means the reader); for her owner they become "em" ...
    "Sensei". Text in `code` (command names such as `Mari ơi`) is left alone."""
    if not sensei:
        return text
    parts = _CODE.split(text)
    for i in range(0, len(parts), 2):  # even parts are outside `code`
        p = _YOU.sub("Sensei", parts[i])
        p = _SELF_START.sub(lambda m: m.group(1) + "Em", p)
        parts[i] = _SELF.sub("em", p)
    return "".join(parts)
