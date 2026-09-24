"""Flag-reaction translation: react to a message with a country flag and Mari
translates it into that country's language (via the Gemini agent)."""

import asyncio
import io
import logging

import discord
from discord.ext import commands
from PIL import Image

from .common import MariCog

logger = logging.getLogger(__name__)

_REGIONAL_A = 0x1F1E6  # regional indicator symbol letter A
_REGIONAL_Z = 0x1F1FF


def flag_to_country(emoji: str):
    """'🇯🇵' -> 'JP'; None for anything that is not a two-letter country flag."""
    if len(emoji) == 2 and all(_REGIONAL_A <= ord(ch) <= _REGIONAL_Z for ch in emoji):
        return "".join(chr(ord(ch) - _REGIONAL_A + ord("A")) for ch in emoji)
    return None


def split_text(text: str, limit: int = 4000) -> list[str]:
    """Chunks of at most `limit` chars, cut at a paragraph, line, sentence or word
    break (in that order of preference) so no word is split."""
    chunks = []
    while len(text) > limit:
        for sep in ("\n\n", "\n", ". ", " "):
            cut = text.rfind(sep, limit // 2, limit)
            if cut != -1:
                cut += len(sep)
                break
        else:
            cut = limit  # one huge unbroken token: hard cut
        chunks.append(text[:cut].rstrip())
        text = text[cut:].lstrip()
    chunks.append(text)
    return chunks


def shrink_image(data: bytes) -> bytes:
    """Re-encode as a JPEG of at most 1600px so it fits through the Gemini relay
    (Vercel caps request bodies at 4.5 MB); Gemini reads text fine at this size."""
    with Image.open(io.BytesIO(data)) as im:
        im = im.convert("RGB")
        im.thumbnail((1600, 1600))
        buf = io.BytesIO()
        im.save(buf, "JPEG", quality=85)
        return buf.getvalue()


async def first_image(message):
    """The message's first image attachment as shrunk JPEG bytes, or None.
    Gemini reads the picture itself: far cleaner than OCR on phone photos of screens."""
    for a in message.attachments:
        if (a.content_type or "").startswith("image/") and a.size <= 20_000_000:
            try:
                return await asyncio.to_thread(shrink_image, await a.read())
            except Exception as exc:
                logger.warning("Could not read image for translation: %s", exc)
                return None
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
        image = None if text else await first_image(message)
        if not text and image is None:
            return

        result = await agent.translate(text[:4000], code, image=image)
        if not result:
            self._done.discard(key)  # let a later reaction retry
            return

        parts = split_text(str(result["translation"]))[:5]  # cap spam from huge texts
        source = " (text read from the image)" if image is not None else ""
        footer = (
            f"Translated into {result.get('language', code)}{source} "
            f"for {payload.member.display_name}"
        )
        try:
            # Embed text never pings, so mentions inside the message stay harmless.
            for i, part in enumerate(parts, 1):
                embed = discord.Embed(description=part, color=discord.Color.blurple())
                embed.set_footer(text=footer + (f" — part {i}/{len(parts)}" if len(parts) > 1 else ""))
                if i == 1:
                    embed.set_author(
                        name=message.author.display_name,
                        icon_url=message.author.display_avatar.url,
                    )
                    await message.reply(embed=embed, mention_author=False)
                else:
                    await channel.send(embed=embed)
        except discord.HTTPException as exc:
            logger.warning("Translation reply failed in #%s: %s", channel, exc)
