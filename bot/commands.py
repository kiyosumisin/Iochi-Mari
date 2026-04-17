import time
from collections import defaultdict

import discord
from discord import app_commands
from discord.ext import commands


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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _is_valid_url(url: str) -> bool:
    url = url.strip()
    return url.startswith(("http://", "https://")) and "." in url


def _verdict_embed(url: str, verdict: str) -> discord.Embed:
    if verdict in ("malware", "phishing", "scam"):
        color = discord.Color.red()
        label = f"Harmful ({verdict})"
        footer = "I have removed this link for your safety. Please be careful."
    elif verdict in ("adult", "gambling"):
        color = discord.Color.orange()
        label = f"Flagged ({verdict})"
        footer = "This link contains content that may not be appropriate here."
    else:
        color = discord.Color.green()
        label = "Safe"
        footer = "This link appears to be safe. Stay vigilant nonetheless."

    embed = discord.Embed(title="Link Inspection Result", color=color)
    embed.add_field(name="URL", value=f"`{url}`", inline=False)
    embed.add_field(name="Verdict", value=label, inline=True)
    embed.set_footer(text=footer)
    return embed


# ---------------------------------------------------------------------------
# BasicCommands Cog
# ---------------------------------------------------------------------------
class BasicCommands(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @commands.command()
    async def ping(self, ctx: commands.Context):
        await ctx.send(
            "Yes, I am here. Please do not hesitate to reach out if you need anything."
        )

    @app_commands.command(name="check", description="Check whether a URL is safe or harmful")
    @app_commands.describe(url="The URL you would like me to inspect")
    async def check(self, interaction: discord.Interaction, url: str):
        if _is_rate_limited(interaction.user.id):
            await interaction.response.send_message(
                f"I apologize, but you have been sending requests a little too quickly. "
                f"Please allow me {_RATE_WINDOW} seconds to catch my breath before trying again.",
                ephemeral=True,
            )
            return

        if not _is_valid_url(url):
            await interaction.response.send_message(
                "I'm sorry, but that does not appear to be a valid URL. "
                "Could you make sure it begins with `http://` or `https://`?",
                ephemeral=True,
            )
            return

        await interaction.response.defer(ephemeral=True, thinking=True)

        try:
            verdict = await self.bot.evaluator.evaluate(url)
            embed = _verdict_embed(url, verdict)
            await interaction.followup.send(embed=embed, ephemeral=True)
        except Exception as e:
            await interaction.followup.send(
                f"I'm afraid something went wrong while inspecting that link. "
                f"I apologize for the inconvenience. `({e})`",
                ephemeral=True,
            )

    @app_commands.command(name="help", description="View all available commands")
    async def help(self, interaction: discord.Interaction):
        embed = discord.Embed(
            title="How may I assist you?",
            description=(
                "My name is Mari. I am here to help keep this server safe "
                "and to assist you however I can. Below are the things I am able to do."
            ),
            color=discord.Color.blurple(),
        )
        embed.add_field(
            name="General",
            value=(
                "`/check <url>` — I will quietly inspect a link for you (only you will see the result)\n"
                "`!ping` — Check if I am present"
            ),
            inline=False,
        )
        embed.add_field(
            name="Server Management (requires Manage Server permission)",
            value=(
                "`/adultchannel add #channel` — Designate a channel for adult content\n"
                "`/adultchannel remove #channel` — Remove a channel from that list\n"
                "`/adultchannel list` — View all designated channels\n"
                "`/adultchannel clear` — Clear the entire list\n"
                "`/whitelist add <domain>` — Mark a domain as trusted\n"
                "`/whitelist remove <domain>` — Remove a domain from the trusted list\n"
                "`/whitelist list` — View all trusted domains\n"
                "`/purge` — Delete recent messages (up to 100)\n"
                "`/purge user` — Delete messages from a specific member\n"
                "`/purge match` — Delete messages containing specific text\n"
                "`/purge links` — Delete messages containing links\n"
                "`/purge images` — Delete messages with attachments\n"
                "`/purge bots` — Delete messages sent by bots\n"
                "`/purge humans` — Delete messages sent by humans\n"
                "`/ban <user> [reason]` — Remove a member from this server\n"
                "`/unban <user_id>` — Lift a ban by user ID\n"
                "`/history <user>` — Review a member's past violations\n"
                "`/threshold <0.0-1.0>` — Adjust the detection sensitivity\n"
                "`/stats` — View this server's protection summary"
            ),
            inline=False,
        )
        embed.set_footer(text="Please feel free to ask if you need anything else.")
        await interaction.response.send_message(embed=embed, ephemeral=True)


# ---------------------------------------------------------------------------
# AdminCommands Cog
# ---------------------------------------------------------------------------
class AdminCommands(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    # -- Purge group --------------------------------------------------------
    purge_group = app_commands.Group(
        name="purge",
        description="Delete messages in this channel with various filters",
    )

    async def _do_purge(
        self,
        interaction: discord.Interaction,
        count: int,
        check=None,
        label: str = "messages",
    ):
        """Shared purge executor used by all subcommands."""
        if not interaction.guild:
            await interaction.response.send_message(
                "I apologize, but this command can only be used within a server.",
                ephemeral=True,
            )
            return
        if not isinstance(interaction.channel, discord.TextChannel):
            await interaction.response.send_message(
                "I'm sorry, but I can only delete messages in a text channel.",
                ephemeral=True,
            )
            return

        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            deleted = await interaction.channel.purge(
                limit=count, check=check, bulk=True
            )
            total = len(deleted)
            noun = "message was" if total == 1 else "messages were"
            await interaction.followup.send(
                f"I have tidied things up. {total} {noun} removed ({label}).",
                ephemeral=True,
            )
        except discord.Forbidden:
            await interaction.followup.send(
                "I apologize, but I do not have the necessary permissions to delete messages here.",
                ephemeral=True,
            )
        except discord.HTTPException as e:
            await interaction.followup.send(
                f"Something went wrong while clearing the messages. I'm sorry. `({e})`",
                ephemeral=True,
            )

    @purge_group.command(name="all", description="Delete recent messages in this channel")
    @app_commands.checks.has_permissions(manage_messages=True)
    @app_commands.describe(count="Number of messages to delete (1-100)")
    async def purge_all(
        self,
        interaction: discord.Interaction,
        count: app_commands.Range[int, 1, 100],
    ):
        await self._do_purge(interaction, count, label="all")

    @purge_group.command(name="user", description="Delete messages from a specific member")
    @app_commands.checks.has_permissions(manage_messages=True)
    @app_commands.describe(
        user="The member whose messages to delete",
        count="Number of messages to scan (1-100)",
    )
    async def purge_user(
        self,
        interaction: discord.Interaction,
        user: discord.Member,
        count: app_commands.Range[int, 1, 100] = 100,
    ):
        await self._do_purge(
            interaction, count,
            check=lambda m: m.author.id == user.id,
            label=f"from {user.display_name}",
        )

    @purge_group.command(name="match", description="Delete messages containing specific text")
    @app_commands.checks.has_permissions(manage_messages=True)
    @app_commands.describe(
        text="Text to search for in messages",
        count="Number of messages to scan (1-100)",
    )
    async def purge_match(
        self,
        interaction: discord.Interaction,
        text: str,
        count: app_commands.Range[int, 1, 100] = 100,
    ):
        await self._do_purge(
            interaction, count,
            check=lambda m: text.lower() in m.content.lower(),
            label=f'matching "{text}"',
        )

    @purge_group.command(name="links", description="Delete messages containing links")
    @app_commands.checks.has_permissions(manage_messages=True)
    @app_commands.describe(count="Number of messages to scan (1-100)")
    async def purge_links(
        self,
        interaction: discord.Interaction,
        count: app_commands.Range[int, 1, 100] = 100,
    ):
        await self._do_purge(
            interaction, count,
            check=lambda m: "http://" in m.content or "https://" in m.content,
            label="containing links",
        )

    @purge_group.command(name="images", description="Delete messages with image attachments")
    @app_commands.checks.has_permissions(manage_messages=True)
    @app_commands.describe(count="Number of messages to scan (1-100)")
    async def purge_images(
        self,
        interaction: discord.Interaction,
        count: app_commands.Range[int, 1, 100] = 100,
    ):
        await self._do_purge(
            interaction, count,
            check=lambda m: bool(m.attachments) or bool(m.embeds),
            label="with images/attachments",
        )

    @purge_group.command(name="bots", description="Delete messages sent by bots")
    @app_commands.checks.has_permissions(manage_messages=True)
    @app_commands.describe(count="Number of messages to scan (1-100)")
    async def purge_bots(
        self,
        interaction: discord.Interaction,
        count: app_commands.Range[int, 1, 100] = 100,
    ):
        await self._do_purge(
            interaction, count,
            check=lambda m: m.author.bot,
            label="from bots",
        )

    @purge_group.command(name="humans", description="Delete messages sent by human members")
    @app_commands.checks.has_permissions(manage_messages=True)
    @app_commands.describe(count="Number of messages to scan (1-100)")
    async def purge_humans(
        self,
        interaction: discord.Interaction,
        count: app_commands.Range[int, 1, 100] = 100,
    ):
        await self._do_purge(
            interaction, count,
            check=lambda m: not m.author.bot,
            label="from humans",
        )

    @purge_group.command(name="mentions", description="Delete messages containing mentions")
    @app_commands.checks.has_permissions(manage_messages=True)
    @app_commands.describe(count="Number of messages to scan (1-100)")
    async def purge_mentions(
        self,
        interaction: discord.Interaction,
        count: app_commands.Range[int, 1, 100] = 100,
    ):
        await self._do_purge(
            interaction, count,
            check=lambda m: bool(m.mentions) or bool(m.role_mentions),
            label="containing mentions",
        )

    @purge_group.command(name="embeds", description="Delete messages containing embeds")
    @app_commands.checks.has_permissions(manage_messages=True)
    @app_commands.describe(count="Number of messages to scan (1-100)")
    async def purge_embeds(
        self,
        interaction: discord.Interaction,
        count: app_commands.Range[int, 1, 100] = 100,
    ):
        await self._do_purge(
            interaction, count,
            check=lambda m: bool(m.embeds),
            label="containing embeds",
        )

    # -- Adult channel group -------------------------------------------------
    adult_group = app_commands.Group(
        name="adultchannel",
        description="Manage channels designated for adult content",
    )

    @adult_group.command(name="add", description="Designate a channel for adult content")
    @app_commands.checks.has_permissions(manage_guild=True)
    @app_commands.describe(channel="The channel to designate")
    async def adult_add(self, interaction: discord.Interaction, channel: discord.TextChannel):
        if not interaction.guild:
            await interaction.response.send_message(
                "I apologize, but this command can only be used within a server.", ephemeral=True
            )
            return
        self.bot.guild_settings.add_adult_channel(interaction.guild.id, channel.id)
        await interaction.response.send_message(
            f"Understood. {channel.mention} has been added to the designated list. "
            f"I will allow adult content there from now on.",
            ephemeral=True,
        )

    @adult_group.command(name="remove", description="Remove a channel from the designated list")
    @app_commands.checks.has_permissions(manage_guild=True)
    @app_commands.describe(channel="The channel to remove")
    async def adult_remove(self, interaction: discord.Interaction, channel: discord.TextChannel):
        if not interaction.guild:
            await interaction.response.send_message(
                "I apologize, but this command can only be used within a server.", ephemeral=True
            )
            return
        self.bot.guild_settings.remove_adult_channel(interaction.guild.id, channel.id)
        await interaction.response.send_message(
            f"Noted. {channel.mention} has been removed from the designated list.",
            ephemeral=True,
        )

    @adult_group.command(name="list", description="View all designated adult channels")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def adult_list(self, interaction: discord.Interaction):
        if not interaction.guild:
            await interaction.response.send_message(
                "I apologize, but this command can only be used within a server.", ephemeral=True
            )
            return
        channel_ids = self.bot.guild_settings.get_adult_channels(interaction.guild.id)
        if not channel_ids:
            await interaction.response.send_message(
                "It seems no channels have been designated yet.", ephemeral=True
            )
            return
        mentions = [f"<#{cid}>" for cid in sorted(channel_ids)]
        await interaction.response.send_message(
            "The following channels have been designated for adult content:\n" + ", ".join(mentions),
            ephemeral=True,
        )

    @adult_group.command(name="clear", description="Clear all designated adult channels")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def adult_clear(self, interaction: discord.Interaction):
        if not interaction.guild:
            await interaction.response.send_message(
                "I apologize, but this command can only be used within a server.", ephemeral=True
            )
            return
        self.bot.guild_settings.clear_adult_channels(interaction.guild.id)
        await interaction.response.send_message(
            "The designated channel list has been cleared. I will treat all channels equally from now on.",
            ephemeral=True,
        )

    # -- Whitelist group -----------------------------------------------------
    whitelist_group = app_commands.Group(
        name="whitelist",
        description="Manage trusted domains that skip URL scanning",
    )

    @whitelist_group.command(name="add", description="Add a trusted domain to the whitelist")
    @app_commands.checks.has_permissions(manage_guild=True)
    @app_commands.describe(domain="Domain to trust (e.g. google.com)")
    async def whitelist_add(self, interaction: discord.Interaction, domain: str):
        if not interaction.guild:
            await interaction.response.send_message(
                "I apologize, but this command can only be used within a server.", ephemeral=True
            )
            return
        domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
        self.bot.guild_settings.add_whitelist(interaction.guild.id, domain)
        await interaction.response.send_message(
            f"I have added `{domain}` to the trusted list. I will not flag links from this domain.",
            ephemeral=True,
        )

    @whitelist_group.command(name="remove", description="Remove a domain from the trusted list")
    @app_commands.checks.has_permissions(manage_guild=True)
    @app_commands.describe(domain="Domain to remove")
    async def whitelist_remove(self, interaction: discord.Interaction, domain: str):
        if not interaction.guild:
            await interaction.response.send_message(
                "I apologize, but this command can only be used within a server.", ephemeral=True
            )
            return
        domain = domain.strip().lower()
        self.bot.guild_settings.remove_whitelist(interaction.guild.id, domain)
        await interaction.response.send_message(
            f"`{domain}` has been removed from the trusted list. I will resume monitoring it.",
            ephemeral=True,
        )

    @whitelist_group.command(name="list", description="View all trusted domains")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def whitelist_list(self, interaction: discord.Interaction):
        if not interaction.guild:
            await interaction.response.send_message(
                "I apologize, but this command can only be used within a server.", ephemeral=True
            )
            return
        domains = self.bot.guild_settings.get_whitelist(interaction.guild.id)
        if not domains:
            await interaction.response.send_message(
                "The trusted list is currently empty.", ephemeral=True
            )
            return
        await interaction.response.send_message(
            "The following domains are currently trusted:\n" + "\n".join(f"- `{d}`" for d in sorted(domains)),
            ephemeral=True,
        )

    # -- Ban / Unban ---------------------------------------------------------
    @app_commands.command(name="ban", description="Remove a member from this server")
    @app_commands.checks.has_permissions(ban_members=True)
    @app_commands.describe(user="The member to remove", reason="Reason for the removal")
    async def ban(
        self,
        interaction: discord.Interaction,
        user: discord.Member,
        reason: str = "No reason provided",
    ):
        if not interaction.guild:
            await interaction.response.send_message(
                "I apologize, but this command can only be used within a server.", ephemeral=True
            )
            return
        if user.top_role >= interaction.guild.me.top_role:
            await interaction.response.send_message(
                "I'm afraid I am unable to take action against this member. "
                "Their role stands above mine, and I must respect that boundary.",
                ephemeral=True,
            )
            return
        try:
            await user.ban(reason=f"[Manual] {reason}")
            self.bot.guild_settings.record_violation(interaction.guild.id, user.id, reason=reason)
            await interaction.response.send_message(
                f"**{user}** has been removed from the server.\nReason: `{reason}`\n"
                f"I hope this helps maintain peace here."
            )
        except discord.Forbidden:
            await interaction.response.send_message(
                "I apologize, but I do not have the necessary permissions to carry out this action.",
                ephemeral=True,
            )
        except Exception as e:
            await interaction.response.send_message(
                f"Something went wrong and I was unable to complete the action. I'm sorry. `({e})`",
                ephemeral=True,
            )

    @app_commands.command(name="unban", description="Lift a ban by Discord user ID")
    @app_commands.checks.has_permissions(ban_members=True)
    @app_commands.describe(user_id="The Discord user ID to unban")
    async def unban(self, interaction: discord.Interaction, user_id: str):
        if not interaction.guild:
            await interaction.response.send_message(
                "I apologize, but this command can only be used within a server.", ephemeral=True
            )
            return
        try:
            uid = int(user_id)
            user = await self.bot.fetch_user(uid)
            await interaction.guild.unban(user)
            await interaction.response.send_message(
                f"The ban on **{user}** has been lifted. I hope they use this second chance well."
            )
        except ValueError:
            await interaction.response.send_message(
                "I'm sorry, but that does not appear to be a valid user ID. "
                "Could you double-check and try again?",
                ephemeral=True,
            )
        except discord.NotFound:
            await interaction.response.send_message(
                "I could not find a banned member with that ID. "
                "They may have already been unbanned.",
                ephemeral=True,
            )
        except Exception as e:
            await interaction.response.send_message(
                f"I was unable to lift the ban. I apologize for the trouble. `({e})`",
                ephemeral=True,
            )

    # -- Violation history ---------------------------------------------------
    @app_commands.command(name="history", description="Review a member's past violations")
    @app_commands.checks.has_permissions(manage_guild=True)
    @app_commands.describe(user="The member to look up")
    async def history(self, interaction: discord.Interaction, user: discord.Member):
        if not interaction.guild:
            await interaction.response.send_message(
                "I apologize, but this command can only be used within a server.", ephemeral=True
            )
            return
        records = self.bot.guild_settings.get_violations(interaction.guild.id, user.id)
        if not records:
            await interaction.response.send_message(
                f"I have found no recorded violations for **{user}**. "
                f"It seems they have been conducting themselves well.",
                ephemeral=True,
            )
            return
        embed = discord.Embed(
            title=f"Violation History — {user}",
            description="Below is a record of past incidents I have noted.",
            color=discord.Color.orange(),
        )
        for i, record in enumerate(records[-10:], 1):
            embed.add_field(
                name=f"Incident {i} — {record.get('timestamp', 'Unknown time')}",
                value=f"URL: `{record.get('url', 'N/A')}`\nReason: {record.get('reason', 'N/A')}",
                inline=False,
            )
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # -- Threshold -----------------------------------------------------------
    @app_commands.command(name="threshold", description="Adjust the detection sensitivity (0.0-1.0)")
    @app_commands.checks.has_permissions(manage_guild=True)
    @app_commands.describe(value="A value between 0.0 and 1.0 (default: 0.5)")
    async def threshold(self, interaction: discord.Interaction, value: float):
        if not interaction.guild:
            await interaction.response.send_message(
                "I apologize, but this command can only be used within a server.", ephemeral=True
            )
            return
        if not (0.0 <= value <= 1.0):
            await interaction.response.send_message(
                "I'm sorry, but the value must be between `0.0` and `1.0`. "
                "Could you try again with a valid number?",
                ephemeral=True,
            )
            return
        self.bot.guild_settings.set_threshold(interaction.guild.id, value)
        await interaction.response.send_message(
            f"Understood. I have adjusted my detection sensitivity to `{value:.2f}`. "
            f"I will now flag links with a risk probability of {value:.0%} or higher.",
            ephemeral=True,
        )

    # -- Stats ---------------------------------------------------------------
    @app_commands.command(name="stats", description="View this server's protection summary")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def stats(self, interaction: discord.Interaction):
        if not interaction.guild:
            await interaction.response.send_message(
                "I apologize, but this command can only be used within a server.", ephemeral=True
            )
            return
        s = self.bot.guild_settings.get_stats(interaction.guild.id)
        embed = discord.Embed(
            title=f"Protection Summary — {interaction.guild.name}",
            description="Here is a summary of everything I have been doing to keep this server safe.",
            color=discord.Color.blurple(),
        )
        embed.add_field(name="Links Inspected", value=str(s.get("urls_scanned", 0)), inline=True)
        embed.add_field(name="Links Blocked", value=str(s.get("links_blocked", 0)), inline=True)
        embed.add_field(name="Auto Bans", value=str(s.get("auto_bans", 0)), inline=True)
        embed.add_field(name="Warnings Issued", value=str(s.get("warnings", 0)), inline=True)
        embed.add_field(name="Detection Sensitivity", value=f"`{s.get('threshold', 0.5):.2f}`", inline=True)
        embed.add_field(name="Trusted Domains", value=str(s.get("whitelist_count", 0)), inline=True)
        embed.set_footer(text="I will continue doing my best to protect everyone here.")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # -- Global error handler ------------------------------------------------
    async def cog_app_command_error(
        self, interaction: discord.Interaction, error: app_commands.AppCommandError
    ):
        if isinstance(error, app_commands.MissingPermissions):
            await interaction.response.send_message(
                "I'm sorry, but it seems you do not have the necessary permissions for this. "
                "Please speak with a server administrator if you believe this is a mistake.",
                ephemeral=True,
            )
        else:
            await interaction.response.send_message(
                f"Something unexpected happened and I was unable to complete your request. "
                f"I sincerely apologize. `({error})`",
                ephemeral=True,
            )