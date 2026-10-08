"""Moderation commands: /purge, /ban, /unban, /history."""

import discord
from discord import app_commands

from .common import AdminCog, say


class ModerationCommands(AdminCog):
    # -- Purge ---------------------------------------------------------------
    @app_commands.command(name="purge", description="Delete recent messages, optionally only from a member or containing text")
    @app_commands.guild_only()
    @app_commands.default_permissions(administrator=True)
    @app_commands.checks.cooldown(1, 5.0)
    @app_commands.describe(
        count="How many recent messages to look through (1-1000)",
        user="Only delete this member's messages",
        contains="Only delete messages containing this text (not case-sensitive)",
    )
    async def purge(
        self,
        interaction: discord.Interaction,
        count: app_commands.Range[int, 1, 1000],
        user: discord.Member = None,
        contains: str = None,
    ):
        if not isinstance(interaction.channel, discord.TextChannel):
            await say(interaction, "I am sorry, I can only tidy messages within a text channel.")
            return

        needle = (contains or "").lower()

        def check(m):
            return (user is None or m.author.id == user.id) and needle in m.content.lower()

        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            deleted = await interaction.channel.purge(limit=count, check=check, bulk=True)
        except discord.Forbidden:
            await say(interaction, "Forgive me — I have not been given the permissions I would need to tidy messages here.")
            return
        except discord.HTTPException as e:
            await say(interaction, f"Something went amiss while I was tidying up. I am sorry. `({e})`")
            return
        which = (f" from {user.display_name}" if user else "") + (f' containing "{contains}"' if contains else "")
        noun = "message" if len(deleted) == 1 else "messages"
        await say(interaction, f"There, I have tidied things up — I removed {len(deleted)} {noun}{which}.")

    # -- Ban / Unban ---------------------------------------------------------
    @app_commands.command(name="ban", description="Remove a member from this server")
    @app_commands.guild_only()
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(user="The member to remove", reason="Reason for the removal")
    async def ban(
        self,
        interaction: discord.Interaction,
        user: discord.Member,
        reason: str = "No reason provided",
    ):
        if user.top_role >= interaction.guild.me.top_role:
            await say(
                interaction,
                "I am afraid I cannot act against this member. "
                "Their standing is above my own, and I must honour that.",
            )
            return
        try:
            await user.ban(reason=f"[Manual] {reason}")
            self.bot.guild_settings.record_violation(interaction.guild.id, user.id, reason=reason)
            await interaction.response.send_message(
                f"I have seen **{user}** out of the server.\nReason: `{reason}`\n"
                f"I take no joy in it, but I hope peace may be kept here."
            )
        except discord.Forbidden:
            await say(
                interaction,
                "Forgive me — I have not been given the permissions I would need for this.",
            )
        except Exception as e:
            await say(
                interaction,
                f"Something went amiss and I could not see it through. I am sorry. `({e})`",
            )

    @app_commands.command(name="unban", description="Lift a ban by Discord user ID")
    @app_commands.guild_only()
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(user_id="The Discord user ID to unban")
    async def unban(self, interaction: discord.Interaction, user_id: str):
        try:
            uid = int(user_id)
            user = await self.bot.fetch_user(uid)
            await interaction.guild.unban(user)
            await interaction.response.send_message(
                f"I have lifted the ban on **{user}**. May they make good use of this second chance."
            )
        except ValueError:
            await say(
                interaction,
                "I am sorry, but that does not look like a valid user ID. "
                "Might you check it and try once more?",
            )
        except discord.NotFound:
            await say(
                interaction,
                "I could find no banned soul with that ID. "
                "Perhaps the ban has already been lifted.",
            )
        except Exception as e:
            await say(
                interaction,
                f"I was unable to lift the ban. Please forgive the trouble. `({e})`",
            )

    # -- Violation history ---------------------------------------------------
    @app_commands.command(name="history", description="Review a member's past violations")
    @app_commands.guild_only()
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(user="The member to look up")
    async def history(self, interaction: discord.Interaction, user: discord.Member):
        records = self.bot.guild_settings.get_violations(interaction.guild.id, user.id)
        if not records:
            await say(
                interaction,
                f"I have noted no wrongdoing for **{user}**. "
                f"It seems they have conducted themselves well.",
            )
            return
        embed = discord.Embed(
            title=f"Violation History — {user}",
            description="Here is what I have gently noted of past incidents.",
            color=discord.Color.orange(),
        )
        for i, record in enumerate(records[-10:], 1):
            embed.add_field(
                name=f"Incident {i} — {record.get('timestamp', 'Unknown time')}",
                value=f"URL: `{record.get('url', 'N/A')}`\nReason: {record.get('reason', 'N/A')}",
                inline=False,
            )
        await interaction.response.send_message(embed=embed, ephemeral=True)
