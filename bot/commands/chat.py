"""Talking to Mari. Anyone can call "Mari ơi" to see she is there; her owner
can also chat with her (Gemini): "Mari ơi, <anything>", or reply to her answer.
Pictures attached to Sensei's message, or in the message Sensei replies to with
"Mari ơi ...", are shown to her too. Sensei can also ask her to delete messages
("Mari, xóa giúp Sensei 10 tin của X"); nothing is deleted until Sensei presses
the confirm button under her answer."""

import re
import time
from collections import deque

import discord
from discord.ext import commands

from bot.voice import is_sensei, to_reader
from .common import MariCog
from .moderation import SCAN_LIMIT, delete_latest, purge_scope
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
