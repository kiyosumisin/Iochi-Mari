"""Talking to Mari. Anyone can call "Mari ơi" to see she is there; her owner
can also chat with her (Gemini): "Mari ơi, <anything>", or reply to her answer."""

import re
import time
from collections import deque

import discord
from discord.ext import commands

from bot.voice import is_sensei, to_reader
from .common import MariCog
from .translate import split_text

# "Mari ơi", "mari oi", "Mari ơiii!" ... at the start of a message.
_CALL = re.compile(r"\s*mari\s+[oơ]i+\b[\s,.!?…:]*", re.IGNORECASE)
HISTORY_TURNS = 12   # messages (Sensei's and Mari's) remembered per channel
FORGET_AFTER = 1800  # seconds of silence before Mari starts a fresh conversation


class ChatCog(MariCog):
    def __init__(self, bot):
        super().__init__(bot)
        self._history: dict[int, deque] = {}  # channel id -> (role, text) turns, memory only
        self._last: dict[int, float] = {}     # channel id -> time of the last turn
        self._answers: set[int] = set()       # ids of Mari's chat replies (reply to continue)

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
        if sensei and text and agent and agent.enabled:
            await self._chat(message, text, agent)
        elif call:
            await self._reply(message, to_reader(
                "Vâng, Mari đây ạ. Bạn cần Mari giúp gì không? Cứ gọi Mari bất cứ lúc nào nhé, "
                "Mari luôn sẵn lòng.", sensei))

    async def _chat(self, message: discord.Message, text: str, agent):
        cid = message.channel.id
        if time.time() - self._last.get(cid, 0) > FORGET_AFTER:
            self._history[cid] = deque(maxlen=HISTORY_TURNS)
        history = self._history.setdefault(cid, deque(maxlen=HISTORY_TURNS))

        async with message.channel.typing():
            answer = await agent.chat(list(history), text[:4000])
        if not answer:
            await self._reply(message, "Em xin lỗi Sensei, lúc này em chưa trả lời được. "
                                       "Sensei thử lại sau một chút nhé.")
            return
        history.extend([("user", text[:4000]), ("model", answer)])
        self._last[cid] = time.time()
        for part in split_text(answer, 2000)[:3]:
            sent = await self._reply(message, part)
            if sent:
                self._answers.add(sent.id)
        if len(self._answers) > 500:
            self._answers = set(sorted(self._answers)[-200:])

    @staticmethod
    async def _reply(message: discord.Message, text: str):
        try:
            # No pings: Mari's words are never allowed to mention @everyone or anyone else.
            return await message.reply(text, mention_author=False,
                                       allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException:
            return None
