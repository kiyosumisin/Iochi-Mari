"""Reporting commands: /stats, /scamlog, /why."""

import csv
from pathlib import Path

import discord
from discord import app_commands

from .common import AdminCog, say


class ReportCommands(AdminCog):
    # -- Stats ---------------------------------------------------------------
    @app_commands.command(name="stats", description="View this server's protection summary")
    @app_commands.guild_only()
    @app_commands.default_permissions(administrator=True)
    async def stats(self, interaction: discord.Interaction):
        s = self.bot.guild_settings.get_stats(interaction.guild.id)
        embed = discord.Embed(
            title=f"Protection Summary — {interaction.guild.name}",
            description="Here is a humble account of all I have done to keep this place safe.",
            color=discord.Color.blurple(),
        )
        embed.add_field(name="Links Inspected", value=str(s.get("urls_scanned", 0)), inline=True)
        embed.add_field(name="Links Blocked", value=str(s.get("links_blocked", 0)), inline=True)
        embed.add_field(name="Auto Bans", value=str(s.get("auto_bans", 0)), inline=True)
        embed.add_field(name="Warnings Issued", value=str(s.get("warnings", 0)), inline=True)
        t = s.get("threshold")
        embed.add_field(
            name="Detection Sensitivity",
            value=f"`{t:.2f}`" if t is not None else "Model default",
            inline=True,
        )
        embed.add_field(name="Trusted Domains", value=str(s.get("whitelist_count", 0)), inline=True)
        ok, wrong = s.get("mod_confirmed", 0), s.get("mod_overturned", 0)
        embed.add_field(
            name="Moderator Reviews",
            value=(f"{ok} confirmed / {wrong} overturned ({ok / (ok + wrong):.0%} right)"
                   if ok + wrong else "None yet"),
            inline=False,
        )
        embed.set_footer(text="I will keep watching over everyone here, with all my heart.")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # -- Scam catch log ------------------------------------------------------
    @app_commands.command(name="scamlog", description="Show successful scam catches (evidence log)")
    @app_commands.default_permissions(administrator=True)
    async def scamlog(self, interaction: discord.Interaction):
        # This file lives at bot/commands/reports.py, so the project root is
        # three levels up.
        path = Path(__file__).resolve().parents[2] / "log" / "scam_catches.csv"
        if not path.exists() or path.stat().st_size == 0:
            await say(interaction, "I have caught no scams just yet — may it stay that way.")
            return
        try:
            with path.open("r", newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        except Exception as e:
            await say(interaction, f"I am sorry, I could not read the record. `({e})`")
            return

        total = len(rows)
        recent = rows[-10:][::-1]
        embed = discord.Embed(
            title="Scam Catches",
            description=f"I have caught and seen out **{total}** scam{'s' if total != 1 else ''} so far.",
            color=discord.Color.green(),
        )
        for r in recent:
            detail = (r.get("detail") or "")[:120]
            embed.add_field(
                name=f"{r.get('timestamp_utc', '?')} UTC — {r.get('category', '?')}",
                value=f"User: `{r.get('user', '?')}`\n`{detail}`",
                inline=False,
            )
        embed.set_footer(text=f"Showing the last {len(recent)} of {total} — the full record is attached.")
        await interaction.response.send_message(embed=embed, file=discord.File(str(path)))

    # -- Why (Gemini agent) --------------------------------------------------
    @app_commands.command(name="why", description="Ask Mari why a user was flagged or actioned")
    @app_commands.guild_only()
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(user="The member to ask about")
    async def why(self, interaction: discord.Interaction, user: discord.Member):
        agent = getattr(self.bot, "agent", None)
        if not agent or not getattr(agent, "enabled", False):
            await say(interaction, "I'm sorry, my analysis assistant is not configured right now.")
            return
        record = agent.latest_case_for(interaction.guild.id, user.id)
        if not record:
            await say(interaction, f"I have no recorded analysis for **{user}** to draw upon.")
            return
        await interaction.response.defer(thinking=True)
        answer = await agent.answer_why(record)
        if not answer:
            await interaction.followup.send(
                "I'm sorry, I could not put together an answer just now. Please try again in a moment."
            )
            return
        await interaction.followup.send(f"**Regarding {user}** — {answer}")
