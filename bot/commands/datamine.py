"""Discord datamine feed: relays new analysis comments from the public
Discord-Datamining GitHub repo into a configured channel, verbatim.

The comment body is never parsed, so changes to how the datamine is written
need no code changes here — we only rely on stable GitHub API fields.
"""

import logging
from datetime import datetime
from pathlib import Path

import aiohttp
import discord
from discord import app_commands
from discord.ext import tasks

from core.guild_settings import atomic_write
from .common import AdminCog, say

logger = logging.getLogger(__name__)

EVENTS_URL = "https://api.github.com/repos/Discord-Datamining/Discord-Datamining/events?per_page=100"
STATE_FILE = Path(__file__).resolve().parents[2] / "log" / "datamine_last_id.txt"


def new_comments(events: list, last_id: int) -> list[dict]:
    """Commit comments newer than last_id, oldest first."""
    comments = [
        e["payload"]["comment"] for e in events if e.get("type") == "CommitCommentEvent"
    ]
    return sorted((c for c in comments if c["id"] > last_id), key=lambda c: c["id"])


def comment_embed(c: dict) -> discord.Embed:
    body = c["body"]
    if len(body) > 4000:
        body = body[:4000] + "\n…"
        if body.count("```") % 2:  # don't leave a code block open after cutting
            body += "\n```"
    embed = discord.Embed(
        title="Datamine Discord",
        url=c["html_url"],
        description=body,
        color=discord.Color.blurple(),
        timestamp=datetime.fromisoformat(c["created_at"]),
    )
    embed.set_footer(text=f"Bản build {c['commit_id'][:7]} — xem đầy đủ ở liên kết phía trên")
    return embed


class DatamineCommands(AdminCog):
    async def cog_load(self):
        self.poll.start()

    async def cog_unload(self):
        self.poll.cancel()

    datamine_group = app_commands.Group(
        name="datamine",
        description="Đăng tin datamine mới của Discord vào một kênh",
        default_permissions=discord.Permissions(administrator=True),
        guild_only=True,
    )

    @datamine_group.command(name="set", description="Chọn kênh đăng tin datamine")
    @app_commands.describe(channel="Kênh để đăng tin datamine")
    async def datamine_set(self, interaction: discord.Interaction, channel: discord.TextChannel):
        self.bot.guild_settings.set_datamine_channel(interaction.guild.id, channel.id)
        await say(
            interaction,
            f"Mari hiểu rồi ạ. Mỗi khi bản build mới của Discord hé lộ điều gì, "
            f"Mari sẽ mang tin về {channel.mention}.",
        )

    @datamine_group.command(name="off", description="Ngừng đăng tin datamine")
    async def datamine_off(self, interaction: discord.Interaction):
        self.bot.guild_settings.set_datamine_channel(interaction.guild.id, 0)
        await say(interaction, "Vâng ạ. Từ giờ Mari sẽ không đăng tin datamine nữa.")

    @datamine_group.command(name="status", description="Xem tin datamine đang được đăng ở đâu")
    async def datamine_status(self, interaction: discord.Interaction):
        cid = self.bot.guild_settings.get_datamine_channel(interaction.guild.id)
        msg = (
            f"Mari đang đăng tin datamine vào <#{cid}>."
            if cid
            else "Hiện Mari chưa đăng tin datamine ở server này."
        )
        await say(interaction, msg)

    # -- Background poll -----------------------------------------------------
    @tasks.loop(minutes=10)
    async def poll(self):
        # ponytail: one page of 100 events; if the bot is down long enough for
        # >100 repo events to pass, older comments are skipped, not backfilled.
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    EVENTS_URL,
                    headers={"Accept": "application/vnd.github+json"},
                    timeout=aiohttp.ClientTimeout(total=20),
                ) as r:
                    if r.status != 200:
                        logger.warning("Datamine poll: GitHub returned %s", r.status)
                        return
                    events = await r.json()

            first_run = not STATE_FILE.exists()
            last_id = 0 if first_run else int(STATE_FILE.read_text().strip() or 0)
            fresh = new_comments(events, last_id)
            if not fresh:
                return

            # On the very first run just remember where we are — no backlog flood.
            if not first_run:
                channels = [
                    ch
                    for g in self.bot.guilds
                    if (ch := g.get_channel(self.bot.guild_settings.get_datamine_channel(g.id)))
                ]
                for c in fresh:
                    embed = comment_embed(c)
                    for ch in channels:
                        try:
                            await ch.send(embed=embed)
                        except discord.HTTPException as exc:
                            logger.warning("Datamine post failed in #%s: %s", ch, exc)

            atomic_write(STATE_FILE, str(fresh[-1]["id"]))
        except Exception:
            # Never let one bad poll kill the loop.
            logger.exception("Datamine poll failed")

    @poll.before_loop
    async def _wait_ready(self):
        await self.bot.wait_until_ready()
