"""Talking to Mari. Anyone can call "Mari ơi" to see she is there; her owner
can also chat with her (Gemini): "Mari ơi, <anything>", or reply to her answer.
Pictures attached to Sensei's message, or in the message Sensei replies to with
"Mari ơi ...", are shown to her too. Sensei can also ask her, in plain words,
for what the slash commands do (see actions.py); no one else can."""

import time
from collections import deque

import discord
from discord.ext import commands

from bot.voice import CALL, is_sensei, to_reader
from .actions import Confirm, answer, plan
from .common import MariCog
from .translate import message_images, split_text

HISTORY_TURNS = 12   # messages (Sensei's and Mari's) remembered per channel
FORGET_AFTER = 1800  # seconds of silence before Mari starts a fresh conversation
MAX_IMAGES = 3      # pictures per message (the Gemini relay caps a request at 4.5 MB)


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
        call = CALL.match(message.content or "")
        ref = message.reference
        continuing = ref is not None and ref.message_id in self._answers
        if not call and not continuing:
            return

        sensei = await is_sensei(self.bot, message.author)
        text = (message.content[call.end():] if call else message.content).strip()
        agent = getattr(self.bot, "agent", None)
        can_chat = sensei and agent and agent.enabled
        images, about = [], ""
        if can_chat:
            images = await message_images(message, MAX_IMAGES)
            if call and ref and not continuing:  # "Mari, ..." as a reply to someone's message
                target = await self._referenced(message)
                if target:
                    # Who and what Sensei is pointing at ("bạn này", "ban người này", this picture).
                    about = (f"[Sensei đang trả lời tin nhắn của {target.author.display_name} "
                             f"(<@{target.author.id}>): \"{(target.content or '')[:500]}\"]\n")
                    images = images or await message_images(target, MAX_IMAGES)
        if can_chat and (text or images):
            await self._chat(message, about + (text or "Sensei gửi em hình này."), agent, images)
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
            reply_action = await agent.chat(list(history), text[:4000], images)
            if not reply_action:
                await self._reply(message, "Em xin lỗi Sensei, lúc này em chưa trả lời được. "
                                           "Sensei thử lại sau một chút nhé.")
                return
            reply, action = reply_action
            what = do = cleanup = None
            if action:
                looked_up = await answer(self.bot, message, action)
                if looked_up is not None:
                    reply = looked_up
                else:
                    what, do, cleanup = await plan(self.bot, message, action,
                                                   forget=lambda: self._history.pop(cid, None))
                    if what:  # show exactly what will happen, or why it can't
                        reply = f"{reply}\n{what}" if do else what
        # Pictures are not kept: later turns only know that one was shown.
        seen = f" [kèm {len(images)} ảnh]" if images else ""
        history.extend([("user", text[:4000] + seen), ("model", reply)])
        self._last[cid] = time.time()
        parts = split_text(reply, 2000)[:3]
        for i, part in enumerate(parts):
            view = Confirm(self.bot, message, what, do, cleanup) if do and i == len(parts) - 1 else None
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
