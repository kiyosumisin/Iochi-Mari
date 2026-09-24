"""Moderation commands: /purge, /ban, /unban, /history."""

import discord
from discord import app_commands

from .common import AdminCog, say


class ModerationCommands(AdminCog):
    # -- Purge ---------------------------------------------------------------
    @app_commands.command(
        name="purge",
        description="Delete up to 1000 messages, optionally filtered",
    )
    @app_commands.guild_only()
    @app_commands.default_permissions(administrator=True)
    @app_commands.checks.cooldown(1, 5.0)
    @app_commands.describe(
        count="How many messages to scan and delete (1-1000)",
        filter="Which messages to delete (default: any)",
        user="Member whose messages to delete — for the 'user' filter",
        text="Text to look for — for match / not / startswith / endswith",
    )
    @app_commands.choices(
        filter=[
            app_commands.Choice(name="any — any message", value="any"),
            app_commands.Choice(name="user — sent by a member", value="user"),
            app_commands.Choice(name="match — contains text", value="match"),
            app_commands.Choice(name="not — does not contain text", value="not"),
            app_commands.Choice(name="startswith — starts with text", value="startswith"),
            app_commands.Choice(name="endswith — ends with text", value="endswith"),
            app_commands.Choice(name="links — contains a link", value="links"),
            app_commands.Choice(name="invites — contains an invite", value="invites"),
            app_commands.Choice(name="images — has an image/attachment", value="images"),
            app_commands.Choice(name="embeds — has an embed", value="embeds"),
            app_commands.Choice(name="mentions — has a mention", value="mentions"),
            app_commands.Choice(name="bots — sent by bots", value="bots"),
            app_commands.Choice(name="humans — sent by humans", value="humans"),
        ]
    )
    async def purge(
        self,
        interaction: discord.Interaction,
        count: app_commands.Range[int, 1, 1000],
        filter: app_commands.Choice[str] = None,
        user: discord.Member = None,
        text: str = None,
    ):
        mode = filter.value if filter else "any"

        if not isinstance(interaction.channel, discord.TextChannel):
            await say(interaction, "I am sorry, I can only tidy messages within a text channel.")
            return
        if mode == "user" and user is None:
            await say(
                interaction,
                "For that filter I need to know whose messages — please use the `user` option.",
            )
            return
        if mode in ("match", "not", "startswith", "endswith") and not text:
            await say(
                interaction,
                "For that filter I need some text to look for — please use the `text` option.",
            )
            return

        t = (text or "").lower()
        checks = {
            "any": None,
            "user": lambda m: user is not None and m.author.id == user.id,
            "match": lambda m: t in m.content.lower(),
            "not": lambda m: t not in m.content.lower(),
            "startswith": lambda m: m.content.lower().startswith(t),
            "endswith": lambda m: m.content.lower().endswith(t),
            "links": lambda m: "http://" in m.content or "https://" in m.content,
            "invites": lambda m: any(
                s in m.content.lower()
                for s in ("discord.gg/", "discord.com/invite", "discordapp.com/invite")
            ),
            "images": lambda m: any(
                (a.content_type or "").startswith("image/")
                or a.filename.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"))
                for a in m.attachments
            ),
            "embeds": lambda m: bool(m.embeds),
            "mentions": lambda m: bool(m.mentions) or bool(m.role_mentions),
            "bots": lambda m: m.author.bot,
            "humans": lambda m: not m.author.bot,
        }
        labels = {
            "any": "any messages",
            "user": f"from {user.display_name}" if user else "from a member",
            "match": f'containing "{text}"',
            "not": f'not containing "{text}"',
            "startswith": f'starting with "{text}"',
            "endswith": f'ending with "{text}"',
            "links": "containing links",
            "invites": "containing invites",
            "images": "with images",
            "embeds": "with embeds",
            "mentions": "with mentions",
            "bots": "from bots",
            "humans": "from humans",
        }
        check = checks.get(mode)
        label = labels.get(mode, "messages")

        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            kwargs = {"limit": count, "bulk": True}
            if check is not None:
                kwargs["check"] = check
            deleted = await interaction.channel.purge(**kwargs)
            total = len(deleted)
            noun = "message" if total == 1 else "messages"
            await say(
                interaction,
                f"There, I have tidied things up — I removed {total} {noun} ({label}).",
            )
        except discord.Forbidden:
            await say(
                interaction,
                "Forgive me — I have not been given the permissions I would need to tidy messages here.",
            )
        except discord.HTTPException as e:
            await say(
                interaction,
                f"Something went amiss while I was tidying up. I am sorry. `({e})`",
            )

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
