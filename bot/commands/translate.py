"""Flag-reaction translation: react to a message with a country flag and Mari
translates it into that country's language (via the Gemini agent)."""

import logging

import discord
from discord.ext import commands

from .common import MariCog

logger = logging.getLogger(__name__)

_REGIONAL_A = 0x1F1E6  # regional indicator symbol letter A
_REGIONAL_Z = 0x1F1FF


def flag_to_country(emoji: str):
    """'🇯🇵' -> 'JP'; None for anything that is not a two-letter country flag."""
    if len(emoji) == 2 and all(_REGIONAL_A <= ord(ch) <= _REGIONAL_Z for ch in emoji):
        return "".join(chr(ord(ch) - _REGIONAL_A + ord("A")) for ch in emoji)
    return None


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
        embed.set_footer(
            text=f"Translated into {result.get('language', code)} for {payload.member.display_name}"
        )
        try:
            # Embed text never pings, so mentions inside the message stay harmless.
            await message.reply(embed=embed, mention_author=False)
        except discord.HTTPException as exc:
            logger.warning("Translation reply failed in #%s: %s", channel, exc)
