"""How Mari speaks: the words she uses for verdicts, and how she addresses
people (her owner is "Sensei", as in Blue Archive; everyone else "bạn")."""

import re

VERDICT_VI = {"phishing": "lừa đảo đánh cắp tài khoản", "malware": "mã độc",
              "scam": "lừa đảo", "gambling": "cờ bạc"}
KIND_VI = {"link": "liên kết", "image": "hình ảnh"}
SUSPICION_VI = {"low": "thấp", "medium": "trung bình", "high": "cao"}

_YOU = re.compile(r"\b[Bb]ạn\b")


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
    """Address the reader: every "bạn" in Mari's replies means the person she is
    answering, so for her owner it becomes "Sensei"."""
    return _YOU.sub("Sensei", text) if sensei else text
