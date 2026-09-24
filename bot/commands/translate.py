"""Flag-reaction translation: react to a message with a country flag and Mari
translates it into that country's language (via the Gemini agent)."""

import asyncio
import logging

import discord
from discord.ext import commands

from core.image_scanner import ocr_image_bytes
from .common import MariCog

logger = logging.getLogger(__name__)

_REGIONAL_A = 0x1F1E6  # regional indicator symbol letter A
_REGIONAL_Z = 0x1F1FF


def flag_to_country(emoji: str):
    """'🇯🇵' -> 'JP'; None for anything that is not a two-letter country flag."""
    if len(emoji) == 2 and all(_REGIONAL_A <= ord(ch) <= _REGIONAL_Z for ch in emoji):
        return "".join(chr(ord(ch) - _REGIONAL_A + ord("A")) for ch in emoji)
    return None


async def image_text(message) -> str:
    """OCR text of the message's first image attachment, or ''."""
    for a in message.attachments:
        if (a.content_type or "").startswith("image/") and a.size <= 8_000_000:
            try:
                return (await asyncio.to_thread(ocr_image_bytes, await a.read())).strip()
            except Exception as exc:
                logger.warning("OCR for translation failed: %s", exc)
                return ""
    return ""


class TranslateCog(MariCog):
    def __init__(self, bot):
        super().__init__(bot)
        self._done: set[tuple[int, str]] = set()  # (message_id, country) already translated

    @commands.Cog.listener()
    async def on_raw_reaction_add(self, payload: discord.RawReactionActionEvent):
        # ponytail: shares the Gemini quota with scam analysis; add a per-guild
        # toggle or a separate quota if busy servers start starving it.
        if payload.guild_id is None or not payload.emoji.is_unicode_emoji():
            return
        code = flag_to_country(payload.emoji.name)
        agent = getattr(self.bot, "agent", None)
        if not code or not agent or not agent.enabled:
            return
        if payload.member is None or payload.member.bot:
            return

        key = (payload.message_id, code)
        if key in self._done:
            return
        if len(self._done) > 5000:
            self._done.clear()
        self._done.add(key)

        channel = self.bot.get_channel(payload.channel_id)
        if channel is None:
            return
        try:
            message = await channel.fetch_message(payload.message_id)
        except discord.HTTPException:
            return
        text = message.content.strip()
        from_image = not text
        if from_image:
            text = await image_text(message)
        if not text:
            return

        result = await agent.translate(text[:1500], code)
        if not result:
            self._done.discard(key)  # let a later reaction retry
            return

        embed = discord.Embed(
            description=str(result["translation"])[:4000],
            color=discord.Color.blurple(),
        )
        embed.set_author(
            name=message.author.display_name, icon_url=message.author.display_avatar.url
        )
        source = " (text read from the image)" if from_image else ""
        embed.set_footer(
            text=f"Translated into {result.get('language', code)}{source} for {payload.member.display_name}"
        )
        try:
            # Embed text never pings, so mentions inside the message stay harmless.
            await message.reply(embed=embed, mention_author=False)
        except discord.HTTPException as exc:
            logger.warning("Translation reply failed in #%s: %s", channel, exc)
