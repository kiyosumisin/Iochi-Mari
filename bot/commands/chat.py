"""Talking to Mari. Anyone can call "Mari ơi" to see she is there; her owner
can also chat with her (Gemini): "Mari ơi, <anything>", or reply to her answer.
Pictures attached to Sensei's message, or in the message Sensei replies to with
"Mari ơi ...", are shown to her too. Sensei can also ask her to delete messages
("Mari, xóa giúp Sensei 10 tin của X"); nothing is deleted until Sensei presses
the confirm button under her answer."""

import re
import time
from collections import deque
from datetime import datetime, timedelta, timezone

import discord
from discord.ext import commands

from bot.voice import VERDICT_VI, is_sensei, to_reader
from .common import MariCog
from .moderation import SCAN_LIMIT, delete_latest, purge_scope
from .reports import load_catches
from .translate import message_images, split_text

# Calling Mari at the start of a message: "Mari ơi", "Mari à", "Mari ạ", "Mari này",
# "Mari nè", "Mari ới", "Mari, ...", "Mari!" or just "Mari", optionally after
# "này" / "ê" / "hey" / "chào". "Mari bắt scam giỏi ghê" only talks about her.
_CALL = re.compile(
    r"\s*(?:(?:này|nè|ê|hey|hi|chào)\s+)?mari"
    r"(?:\s+(?:[oơ]i+|ới|[aàạ]|này|nay|nè|ne)\b|(?=\s*(?:[,.!?…:]|$)))[\s,.!?…:]*",
    re.IGNORECASE,
)
HISTORY_TURNS = 12   # messages (Sensei's and Mari's) remembered per channel
FORGET_AFTER = 1800  # seconds of silence before Mari starts a fresh conversation
MAX_IMAGES = 3      # pictures per message (the Gemini relay caps a request at 4.5 MB)
VN_TIME = timezone(timedelta(hours=7))  # Sensei's "hôm nay" (Vietnam has no DST)
CLEANUP_AFTER = 8   # seconds before Sensei's request and Mari's "done" answer are deleted


def _catch_reason(row: dict) -> str:
    kind, _, verdict = (row.get("category") or "").partition(":")
    detail = (row.get("detail") or "")[:80]
    if kind in ("url", "link"):
        return f"liên kết {VERDICT_VI.get(verdict, 'scam')} `{detail}`"
    if kind == "image":
        return "ảnh scam đã biết" if verdict == "known" else "ảnh scam"
    if kind == "spread":
        return f"rải tin hàng loạt (`{detail}`)"
    return f"`{row.get('category')}`"


def catches_report(guild_name: str, days: int) -> str:
    """Who Mari caught in this server today (days=0) or in the last `days` days,
    read from the real catch log, never from the model's imagination."""
    now = datetime.now(VN_TIME)
    since = now.replace(hour=0, minute=0, second=0, microsecond=0) if days == 0 else now - timedelta(days=days)
    caught = []
    for row in load_catches():
        try:
            ts = datetime.strptime(row["timestamp_utc"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        if row.get("server") == guild_name and ts >= since:
            caught.append((ts.astimezone(VN_TIME), row))
    when = "Hôm nay" if days == 0 else f"Trong {days} ngày qua"
    if not caught:
        return f"{when} chưa có ai bị bắt vì scam cả ạ. Cầu mong mọi chuyện cứ bình yên như vậy."
    lines = [f"{when} em đã bắt **{len(caught)}** vụ scam ạ:"]
    for ts, row in caught[-10:][::-1]:
        lines.append(f"- {ts.strftime('%H:%M' if days == 0 else '%d/%m %H:%M')} · **{row.get('user', '?')}** · "
                     f"#{row.get('channel', '?')} · {_catch_reason(row)}")
    if len(caught) > 10:
        lines.append(f"…và {len(caught) - 10} vụ cũ hơn nữa, Sensei xem đủ bằng `/scamlog` nhé.")
    return "\n".join(lines)


def _purge_request(action) -> dict | None:
    """The deletion Gemini says Sensei asked for, checked, or None."""
    if not isinstance(action, dict) or action.get("type") != "purge":
        return None
    try:
        count = int(action.get("count"))
    except (TypeError, ValueError):
        return None
    if not 1 <= count <= 1000:
        return None
    return {"count": count,
            "author": str(action.get("author") or "").strip().lstrip("@") or None,
            "bots": bool(action.get("bots")),
            "contains": str(action.get("contains") or "").strip() or None}


def _by_author(author: str | None):
    """Match a message's author by <@id>, or by username / display name / global name."""
    if author is None:
        return lambda m: True
    mention = re.fullmatch(r"<@!?(\d+)>", author)
    if mention:
        uid = int(mention.group(1))
        return lambda m: m.author.id == uid
    name = author.lower()
    return lambda m: name in {(m.author.name or "").lower(), (m.author.display_name or "").lower(),
                              (getattr(m.author, "global_name", None) or "").lower()}


class PurgeConfirm(discord.ui.View):
    """[Xóa] / [Hủy] under Mari's answer: nothing is deleted until Sensei presses Xóa."""

    def __init__(self, bot, request: discord.Message, purge: dict):
        super().__init__(timeout=120)
        self.bot, self.request, self.purge = bot, request, purge
        self.message = None  # Mari's answer, to drop the buttons on timeout

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if await is_sensei(self.bot, interaction.user):
            return True
        await interaction.response.send_message("Xin thứ lỗi, chỉ Sensei mới xác nhận được việc này.",
                                                ephemeral=True)
        return False

    @discord.ui.button(label="Xóa", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button):
        self.stop()
        await interaction.response.edit_message(view=None)  # answer now; deleting may take a while
        p = self.purge
        needle, by_author = (p["contains"] or "").lower(), _by_author(p["author"])
        scope = purge_scope(p["author"], p["bots"], p["contains"])

        def match(m):
            return by_author(m) and (not p["bots"] or m.author.bot) and needle in m.content.lower()

        try:
            # Only messages before Sensei's request: never the request or this answer.
            n = await delete_latest(self.request.channel, p["count"], match, scan_limit=SCAN_LIMIT,
                                    before=self.request, label=f"chat {p}")
            note = (f"Xong rồi ạ, em đã xóa {n} tin nhắn{scope}." if n else
                    f"Em đã tìm trong {SCAN_LIMIT} tin gần nhất nhưng không thấy tin nhắn nào{scope} cả ạ.")
            # Tidy up in the background, after Sensei has read the note; on an error
            # below both messages stay so the reason can be read.
            await self.request.delete(delay=CLEANUP_AFTER)
            await interaction.message.delete(delay=CLEANUP_AFTER)
        except discord.Forbidden:
            note = "Em xin lỗi, em chưa được cấp quyền xóa tin nhắn ở kênh này."
        except discord.HTTPException as e:
            note = f"Em xin lỗi, đã có trục trặc khi xóa. `({e})`"
        await interaction.edit_original_response(content=f"{interaction.message.content}\n*{note}*"[:2000])

    @discord.ui.button(label="Hủy", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button):
        self.stop()
        await interaction.response.edit_message(
            content=f"{interaction.message.content}\n*Vâng, em không xóa nữa ạ.*"[:2000], view=None)

    async def on_timeout(self):
        if self.message:
            try:
                await self.message.edit(view=None)
            except discord.HTTPException:
                pass


class ChatCog(MariCog):
    def __init__(self, bot):
        super().__init__(bot)
        self._history: dict[int, deque] = {}  # channel id -> (role, text) turns, memory only
        self._last: dict[int, float] = {}     # channel id -> time of the last turn
        self._answers: deque = deque(maxlen=200)  # ids of Mari's chat replies (reply to continue)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if message.author.bot:
            return
        call = _CALL.match(message.content or "")
        ref = message.reference
        continuing = ref is not None and ref.message_id in self._answers
        if not call and not continuing:
            return

        sensei = await is_sensei(self.bot, message.author)
        text = (message.content[call.end():] if call else message.content).strip()
        agent = getattr(self.bot, "agent", None)
        can_chat = sensei and agent and agent.enabled
        images = []
        if can_chat:
            images = await message_images(message, MAX_IMAGES)
            if not images and call and ref:  # "Mari ơi, ..." as a reply to someone's picture
                target = await self._referenced(message)
                images = await message_images(target, MAX_IMAGES) if target else []
        if can_chat and (text or images):
            await self._chat(message, text or "Sensei gửi em hình này.", agent, images)
        elif call:
            await self._reply(message, to_reader(
                "Vâng, Mari đây ạ. Bạn cần Mari giúp gì không? Cứ gọi Mari bất cứ lúc nào nhé, "
                "Mari luôn sẵn lòng.", sensei))

    @staticmethod
    async def _referenced(message: discord.Message):
        """The message being replied to, or None if it is gone."""
        ref = message.reference
        if isinstance(ref.resolved, discord.Message):
            return ref.resolved
        try:
            return await message.channel.fetch_message(ref.message_id)
        except discord.HTTPException:
            return None

    async def _chat(self, message: discord.Message, text: str, agent, images=()):
        cid = message.channel.id
        if time.time() - self._last.get(cid, 0) > FORGET_AFTER:
            self._history[cid] = deque(maxlen=HISTORY_TURNS)
        history = self._history.setdefault(cid, deque(maxlen=HISTORY_TURNS))

        async with message.channel.typing():
            answer = await agent.chat(list(history), text[:4000], images)
        if not answer:
            await self._reply(message, "Em xin lỗi Sensei, lúc này em chưa trả lời được. "
                                       "Sensei thử lại sau một chút nhé.")
            return
        reply, action = answer
        if (action or {}).get("type") == "scamlog":
            try:
                days = min(max(int(action.get("days") or 0), 0), 23)  # the log keeps 23 days
                reply = (catches_report(message.guild.name, days) if message.guild else
                         "Sensei hỏi em trong server nhé, em chỉ xem được nhật ký của từng server thôi ạ.")
            except (ValueError, OSError) as e:
                reply = f"Em xin lỗi, em chưa đọc được nhật ký bắt scam. `({e})`"
        purge = _purge_request(action)
        # Pictures are not kept: later turns only know that one was shown.
        seen = f" [kèm {len(images)} ảnh]" if images else ""
        history.extend([("user", text[:4000] + seen), ("model", reply)])
        self._last[cid] = time.time()
        parts = split_text(reply, 2000)[:3]
        for i, part in enumerate(parts):
            view = PurgeConfirm(self.bot, message, purge) if purge and i == len(parts) - 1 else None
            sent = await self._reply(message, part, view)
            if sent:
                self._answers.append(sent.id)
                if view:
                    view.message = sent

    @staticmethod
    async def _reply(message: discord.Message, text: str, view=None):
        try:
            # No pings: Mari's words are never allowed to mention @everyone or anyone else.
            return await message.reply(text, mention_author=False, view=view,
                                       allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException:
            return None
