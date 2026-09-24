"""General, public-facing commands: /check, /help, !ping."""

import asyncio
import time
from collections import defaultdict

import discord
from discord import app_commands
from discord.ext import commands

from core.image_scanner import ocr_image_bytes
from .common import MariCog, is_owner, OWNER_ONLY_DENIAL

# ---------------------------------------------------------------------------
# Rate limiter: max 5 uses of /check per user per 60 seconds
# ---------------------------------------------------------------------------
_check_rate: dict[int, list[float]] = defaultdict(list)
_RATE_LIMIT = 5
_RATE_WINDOW = 60  # seconds


def _is_rate_limited(user_id: int) -> bool:
    now = time.time()
    timestamps = [t for t in _check_rate[user_id] if now - t < _RATE_WINDOW]
    _check_rate[user_id] = timestamps
    if len(timestamps) >= _RATE_LIMIT:
        return True
    _check_rate[user_id].append(now)
    return False


def _is_valid_url(url: str) -> bool:
    url = url.strip()
    return url.startswith(("http://", "https://")) and "." in url


def _verdict_embed(url: str, verdict: str) -> discord.Embed:
    if verdict in ("malware", "phishing", "scam"):
        color = discord.Color.red()
        label = f"Harmful ({verdict})"
        footer = "I have quietly taken this link away to keep everyone safe. Please take care of yourself."
    elif verdict in ("adult", "gambling"):
        color = discord.Color.orange()
        label = f"Flagged ({verdict})"
        footer = "This one may not belong here. Let us be considerate of one another, if you would."
    else:
        color = discord.Color.green()
        label = "Safe"
        footer = "This link appears safe. Even so, please stay careful — your wellbeing is what matters to me."

    embed = discord.Embed(title="Mari's Link Check", color=color)
    embed.add_field(name="URL", value=f"`{url}`", inline=False)
    embed.add_field(name="Verdict", value=label, inline=True)
    embed.set_footer(text=footer)
    return embed


class BasicCommands(MariCog):
    @commands.command()
    async def ping(self, ctx: commands.Context):
        await ctx.send(
            "Yes, I am here. Please do not hesitate to call upon me — helping you is never any trouble at all."
        )

    check_group = app_commands.Group(
        name="check",
        description="Inspect a link or an image",
    )

    @check_group.command(name="link", description="Check whether a URL is safe or harmful")
    @app_commands.describe(url="The URL you would like me to inspect")
    async def check_link(self, interaction: discord.Interaction, url: str):
        if _is_rate_limited(interaction.user.id):
            await interaction.response.send_message(
                f"Forgive me — you are asking a little quickly, and I cannot quite keep pace. "
                f"Please allow me {_RATE_WINDOW} seconds to gather myself, then do try again.",
                ephemeral=True,
            )
            return

        if not _is_valid_url(url):
            await interaction.response.send_message(
                "I am sorry, but that does not look like a valid link to me. "
                "Might you make sure it begins with `http://` or `https://`?",
                ephemeral=True,
            )
            return

        guild_threshold = (
            self.bot.guild_settings.get_threshold(interaction.guild.id)
            if interaction.guild
            else None
        )

        await interaction.response.defer(ephemeral=True, thinking=True)

        try:
            verdict = await self.bot.evaluator.evaluate(url, threshold=guild_threshold)
            embed = _verdict_embed(url, verdict)
            await interaction.followup.send(embed=embed, ephemeral=True)
        except Exception as e:
            await interaction.followup.send(
                f"I am afraid something went amiss while I was looking over that link. "
                f"Please forgive me. `({e})`",
                ephemeral=True,
            )

    @check_group.command(name="img", description="Read the text inside an image (owner only)")
    @app_commands.describe(image="The image you would like me to read")
    async def check_img(self, interaction: discord.Interaction, image: discord.Attachment):
        if not await is_owner(interaction):
            await interaction.response.send_message(OWNER_ONLY_DENIAL, ephemeral=True)
            return

        ctype = image.content_type or ""
        is_image = ctype.startswith("image/") or image.filename.lower().endswith(
            (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp")
        )
        if not is_image:
            await interaction.response.send_message(
                "I am sorry, that does not appear to be an image I can read.",
                ephemeral=True,
            )
            return

        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            data = await image.read()
            text = await asyncio.to_thread(ocr_image_bytes, data)
        except Exception as e:
            await interaction.followup.send(
                f"Forgive me — I could not read that image. `({e})`", ephemeral=True
            )
            return

        text = (text or "").strip()
        if not text:
            await interaction.followup.send(
                "I looked closely, but found no readable text within that image.",
                ephemeral=True,
            )
            return

        snippet = text if len(text) <= 3800 else text[:3800] + "\n…(truncated)"
        # Avoid breaking the code fence if the text itself contains backticks.
        snippet = snippet.replace("```", "``​`")
        embed = discord.Embed(
            title="What I could read",
            description=f"```\n{snippet}\n```",
            color=discord.Color.blurple(),
        )
        embed.set_footer(text=image.filename)
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="help", description="View all available commands")
    async def help(self, interaction: discord.Interaction):
        embed = discord.Embed(
            title="How may I help you?",
            description=(
                "I am Mari, of the Sisterhood. I will do all I can to keep everyone here safe "
                "and to lend a hand however you may need. Here is everything I can do for you:"
            ),
            color=discord.Color.blurple(),
        )
        embed.add_field(
            name="General",
            value=(
                "`/check link <url>` — I will quietly inspect a link for you (only you will see the result)\n"
                "`!ping` — Check if I am present"
            ),
            inline=False,
        )
        embed.add_field(
            name="Moderation (Administrator)",
            value=(
                "`/purge <count> [filter]` — Delete up to 1000 messages (filters: user, match, links, images, bots, …)\n"
                "`/ban <user> [reason]` — Remove a member\n"
                "`/unban <user_id>` — Lift a ban by user ID\n"
                "`/history <user>` — Review a member's past violations\n"
                "`/why <user>` — Ask why a user was flagged (Gemini agent)"
            ),
            inline=False,
        )
        embed.add_field(
            name="Configuration (Administrator)",
            value=(
                "`/honeypot set #channel` / `off` / `status` — Manage the bait channel\n"
                "`/logchannel set #channel` / `off` / `status` — Where I send moderation logs\n"
                "`/datamine set #channel` / `off` / `status` — Post new Discord datamine notes\n"
                "`/adultchannel add` / `remove` / `list` / `clear` — Channels allowed adult content\n"
                "`/whitelist add` / `remove` / `list` — Trusted domains (skip scanning)\n"
                "`/threshold <0.0-1.0>` — Adjust detection sensitivity"
            ),
            inline=False,
        )
        embed.add_field(
            name="Reports (Administrator)",
            value=(
                "`/stats` — This server's protection summary\n"
                "`/scamlog` — The log of scams caught (evidence)"
            ),
            inline=False,
        )
        if await is_owner(interaction):
            embed.add_field(
                name="Owner only",
                value=(
                    "`/check img <image>` — Read the text inside an image\n"
                    "`/text <message> [channel]` — Speak a message through me"
                ),
                inline=False,
            )
        embed.set_footer(text="If there is anything else you need, please do not hesitate to ask. It would be my pleasure to help.")
        await interaction.response.send_message(embed=embed, ephemeral=True)
