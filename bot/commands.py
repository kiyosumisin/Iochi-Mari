import csv
import time
from collections import defaultdict
from pathlib import Path

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


# ---------------------------------------------------------------------------
# BasicCommands Cog
# ---------------------------------------------------------------------------
class BasicCommands(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @commands.command()
    async def ping(self, ctx: commands.Context):
        await ctx.send(
            "Yes, I am here. Please do not hesitate to call upon me — helping you is never any trouble at all."
        )

    @app_commands.command(name="check", description="Check whether a URL is safe or harmful")
    @app_commands.describe(url="The URL you would like me to inspect")
    async def check(self, interaction: discord.Interaction, url: str):
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
                "`/check <url>` — I will quietly inspect a link for you (only you will see the result)\n"
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
        embed.set_footer(text="If there is anything else you need, please do not hesitate to ask. It would be my pleasure to help.")
        await interaction.response.send_message(embed=embed, ephemeral=True)


# ---------------------------------------------------------------------------
# AdminCommands Cog
# ---------------------------------------------------------------------------
class AdminCommands(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    # -- Purge ---------------------------------------------------------------
    @app_commands.command(
        name="purge",
        description="Delete up to 1000 messages, optionally filtered",
    )
    @app_commands.default_permissions(administrator=True)
    @app_commands.checks.has_permissions(administrator=True)
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

        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        if not isinstance(interaction.channel, discord.TextChannel):
            await interaction.response.send_message(
                "I am sorry, I can only tidy messages within a text channel.", ephemeral=True
            )
            return
        if mode == "user" and user is None:
            await interaction.response.send_message(
                "For that filter I need to know whose messages — please use the `user` option.",
                ephemeral=True,
            )
            return
        if mode in ("match", "not", "startswith", "endswith") and not text:
            await interaction.response.send_message(
                "For that filter I need some text to look for — please use the `text` option.",
                ephemeral=True,
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
            await interaction.followup.send(
                f"There, I have tidied things up — I removed {total} {noun} ({label}).",
                ephemeral=True,
            )
        except discord.Forbidden:
            await interaction.followup.send(
                "Forgive me — I have not been given the permissions I would need to tidy messages here.",
                ephemeral=True,
            )
        except discord.HTTPException as e:
            await interaction.followup.send(
                f"Something went amiss while I was tidying up. I am sorry. `({e})`",
                ephemeral=True,
            )

    # -- Adult channel group -------------------------------------------------
    adult_group = app_commands.Group(
        name="adultchannel",
        description="Manage channels designated for adult content",
        default_permissions=discord.Permissions(administrator=True),
    )

    @adult_group.command(name="add", description="Designate a channel for adult content")
    @app_commands.checks.has_permissions(administrator=True)
    @app_commands.describe(channel="The channel to designate")
    async def adult_add(self, interaction: discord.Interaction, channel: discord.TextChannel):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        self.bot.guild_settings.add_adult_channel(interaction.guild.id, channel.id)
        await interaction.response.send_message(
            f"Understood. I have set {channel.mention} aside for such content, "
            f"and will permit it there from now on.",
            ephemeral=True,
        )

    @adult_group.command(name="remove", description="Remove a channel from the designated list")
    @app_commands.checks.has_permissions(administrator=True)
    @app_commands.describe(channel="The channel to remove")
    async def adult_remove(self, interaction: discord.Interaction, channel: discord.TextChannel):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        self.bot.guild_settings.remove_adult_channel(interaction.guild.id, channel.id)
        await interaction.response.send_message(
            f"Noted. I have removed {channel.mention} from that list.",
            ephemeral=True,
        )

    @adult_group.command(name="list", description="View all designated adult channels")
    @app_commands.checks.has_permissions(administrator=True)
    async def adult_list(self, interaction: discord.Interaction):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        channel_ids = self.bot.guild_settings.get_adult_channels(interaction.guild.id)
        if not channel_ids:
            await interaction.response.send_message(
                "It seems no channels have been set aside yet.", ephemeral=True
            )
            return
        mentions = [f"<#{cid}>" for cid in sorted(channel_ids)]
        await interaction.response.send_message(
            "These are the channels I have set aside for such content:\n" + ", ".join(mentions),
            ephemeral=True,
        )

    @adult_group.command(name="clear", description="Clear all designated adult channels")
    @app_commands.checks.has_permissions(administrator=True)
    async def adult_clear(self, interaction: discord.Interaction):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        self.bot.guild_settings.clear_adult_channels(interaction.guild.id)
        await interaction.response.send_message(
            "I have cleared that list, and will watch over every channel alike from now on.",
            ephemeral=True,
        )

    # -- Whitelist group -----------------------------------------------------
    whitelist_group = app_commands.Group(
        name="whitelist",
        description="Manage trusted domains that skip URL scanning",
        default_permissions=discord.Permissions(administrator=True),
    )

    @whitelist_group.command(name="add", description="Add a trusted domain to the whitelist")
    @app_commands.checks.has_permissions(administrator=True)
    @app_commands.describe(domain="Domain to trust (e.g. google.com)")
    async def whitelist_add(self, interaction: discord.Interaction, domain: str):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
        self.bot.guild_settings.add_whitelist(interaction.guild.id, domain)
        await interaction.response.send_message(
            f"I have placed my trust in `{domain}`, and will let its links pass without worry.",
            ephemeral=True,
        )

    @whitelist_group.command(name="remove", description="Remove a domain from the trusted list")
    @app_commands.checks.has_permissions(administrator=True)
    @app_commands.describe(domain="Domain to remove")
    async def whitelist_remove(self, interaction: discord.Interaction, domain: str):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        domain = domain.strip().lower()
        self.bot.guild_settings.remove_whitelist(interaction.guild.id, domain)
        await interaction.response.send_message(
            f"I have removed `{domain}` from those I trust, and will keep a gentle watch on it once more.",
            ephemeral=True,
        )

    @whitelist_group.command(name="list", description="View all trusted domains")
    @app_commands.checks.has_permissions(administrator=True)
    async def whitelist_list(self, interaction: discord.Interaction):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        domains = self.bot.guild_settings.get_whitelist(interaction.guild.id)
        if not domains:
            await interaction.response.send_message(
                "There are no trusted domains just yet.", ephemeral=True
            )
            return
        await interaction.response.send_message(
            "These are the domains I currently trust:\n" + "\n".join(f"- `{d}`" for d in sorted(domains)),
            ephemeral=True,
        )

    # -- Honeypot ------------------------------------------------------------
    honeypot_group = app_commands.Group(
        name="honeypot",
        description="Manage the scam-bot honeypot (bait) channel",
        default_permissions=discord.Permissions(administrator=True),
    )

    @honeypot_group.command(name="set", description="Set the honeypot (bait) channel")
    @app_commands.checks.has_permissions(administrator=True)
    @app_commands.describe(channel="The channel to use as the bait/honeypot")
    async def honeypot_set(self, interaction: discord.Interaction, channel: discord.TextChannel):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        self.bot.guild_settings.set_honeypot_channel(interaction.guild.id, channel.id)
        await interaction.response.send_message(
            f"Understood. I will keep my watch upon {channel.mention} as the trap from now on — "
            f"anyone who brings scam links or images there will be seen out at once, and I will "
            f"leave every other channel in peace.",
            ephemeral=True,
        )

    @honeypot_group.command(name="off", description="Disable the honeypot and resume normal moderation")
    @app_commands.checks.has_permissions(administrator=True)
    async def honeypot_off(self, interaction: discord.Interaction):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        self.bot.guild_settings.set_honeypot_channel(interaction.guild.id, 0)
        await interaction.response.send_message(
            "The trap has been set aside. Do be aware: I will now watch over **all** channels "
            "again, so I may err a little more easily — please forgive me if I do.",
            ephemeral=True,
        )

    @honeypot_group.command(name="status", description="Show the current honeypot channel")
    @app_commands.checks.has_permissions(administrator=True)
    async def honeypot_status(self, interaction: discord.Interaction):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        gid = self.bot.guild_settings.get_honeypot_channel(interaction.guild.id)
        if gid is None:
            gid = getattr(self.bot.config, "HONEYPOT_CHANNEL_ID", 0)
        if gid:
            await interaction.response.send_message(
                f"My watch is set upon <#{gid}>. I am tending to that channel alone for now.",
                ephemeral=True,
            )
        else:
            await interaction.response.send_message(
                "No trap is set just now — I am watching over every channel as usual.",
                ephemeral=True,
            )

    # -- Log channel ---------------------------------------------------------
    logchannel_group = app_commands.Group(
        name="logchannel",
        description="Choose where Mari sends her moderation logs",
        default_permissions=discord.Permissions(administrator=True),
    )

    @logchannel_group.command(name="set", description="Set the channel for moderation logs")
    @app_commands.checks.has_permissions(administrator=True)
    @app_commands.describe(channel="The channel to send moderation logs to")
    async def logchannel_set(self, interaction: discord.Interaction, channel: discord.TextChannel):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        self.bot.guild_settings.set_log_channel(interaction.guild.id, channel.id)
        await interaction.response.send_message(
            f"Understood. From now on I will quietly bring all my notices to {channel.mention}.",
            ephemeral=True,
        )

    @logchannel_group.command(name="off", description="Stop using a dedicated log channel")
    @app_commands.checks.has_permissions(administrator=True)
    async def logchannel_off(self, interaction: discord.Interaction):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        self.bot.guild_settings.set_log_channel(interaction.guild.id, 0)
        await interaction.response.send_message(
            "Understood. I will keep no separate log channel now — my notices will appear "
            "wherever each matter arises instead.",
            ephemeral=True,
        )

    @logchannel_group.command(name="status", description="Show the current log channel")
    @app_commands.checks.has_permissions(administrator=True)
    async def logchannel_status(self, interaction: discord.Interaction):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        cid = self.bot.guild_settings.get_log_channel(interaction.guild.id)
        if cid is None:
            cid = getattr(self.bot.config, "LOG_CHANNEL_ID", 0)
        if cid:
            await interaction.response.send_message(
                f"I am bringing my notices to <#{cid}> at present.", ephemeral=True
            )
        else:
            await interaction.response.send_message(
                "I keep no separate log channel just now; my notices appear wherever each matter arises.",
                ephemeral=True,
            )

    # -- Ban / Unban ---------------------------------------------------------
    @app_commands.command(name="ban", description="Remove a member from this server")
    @app_commands.default_permissions(administrator=True)
    @app_commands.checks.has_permissions(administrator=True)
    @app_commands.describe(user="The member to remove", reason="Reason for the removal")
    async def ban(
        self,
        interaction: discord.Interaction,
        user: discord.Member,
        reason: str = "No reason provided",
    ):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        if user.top_role >= interaction.guild.me.top_role:
            await interaction.response.send_message(
                "I am afraid I cannot act against this member. "
                "Their standing is above my own, and I must honour that.",
                ephemeral=True,
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
            await interaction.response.send_message(
                "Forgive me — I have not been given the permissions I would need for this.",
                ephemeral=True,
            )
        except Exception as e:
            await interaction.response.send_message(
                f"Something went amiss and I could not see it through. I am sorry. `({e})`",
                ephemeral=True,
            )

    @app_commands.command(name="unban", description="Lift a ban by Discord user ID")
    @app_commands.default_permissions(administrator=True)
    @app_commands.checks.has_permissions(administrator=True)
    @app_commands.describe(user_id="The Discord user ID to unban")
    async def unban(self, interaction: discord.Interaction, user_id: str):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        try:
            uid = int(user_id)
            user = await self.bot.fetch_user(uid)
            await interaction.guild.unban(user)
            await interaction.response.send_message(
                f"I have lifted the ban on **{user}**. May they make good use of this second chance."
            )
        except ValueError:
            await interaction.response.send_message(
                "I am sorry, but that does not look like a valid user ID. "
                "Might you check it and try once more?",
                ephemeral=True,
            )
        except discord.NotFound:
            await interaction.response.send_message(
                "I could find no banned soul with that ID. "
                "Perhaps the ban has already been lifted.",
                ephemeral=True,
            )
        except Exception as e:
            await interaction.response.send_message(
                f"I was unable to lift the ban. Please forgive the trouble. `({e})`",
                ephemeral=True,
            )

    # -- Violation history ---------------------------------------------------
    @app_commands.command(name="history", description="Review a member's past violations")
    @app_commands.default_permissions(administrator=True)
    @app_commands.checks.has_permissions(administrator=True)
    @app_commands.describe(user="The member to look up")
    async def history(self, interaction: discord.Interaction, user: discord.Member):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        records = self.bot.guild_settings.get_violations(interaction.guild.id, user.id)
        if not records:
            await interaction.response.send_message(
                f"I have noted no wrongdoing for **{user}**. "
                f"It seems they have conducted themselves well.",
                ephemeral=True,
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

    # -- Threshold -----------------------------------------------------------
    @app_commands.command(name="threshold", description="Adjust the detection sensitivity (0.0-1.0)")
    @app_commands.default_permissions(administrator=True)
    @app_commands.checks.has_permissions(administrator=True)
    @app_commands.describe(value="A value between 0.0 and 1.0 (default: 0.5)")
    async def threshold(self, interaction: discord.Interaction, value: float):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        if not (0.0 <= value <= 1.0):
            await interaction.response.send_message(
                "I am sorry, but the value must rest between `0.0` and `1.0`. "
                "Might you try again with a number in that range?",
                ephemeral=True,
            )
            return
        self.bot.guild_settings.set_threshold(interaction.guild.id, value)
        await interaction.response.send_message(
            f"Understood. I have set my watchfulness to `{value:.2f}` — I will now flag links "
            f"I judge {value:.0%} or more likely to bring harm.",
            ephemeral=True,
        )

    # -- Stats ---------------------------------------------------------------
    @app_commands.command(name="stats", description="View this server's protection summary")
    @app_commands.default_permissions(administrator=True)
    @app_commands.checks.has_permissions(administrator=True)
    async def stats(self, interaction: discord.Interaction):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
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
        embed.add_field(name="Detection Sensitivity", value=f"`{s.get('threshold', 0.5):.2f}`", inline=True)
        embed.add_field(name="Trusted Domains", value=str(s.get("whitelist_count", 0)), inline=True)
        embed.set_footer(text="I will keep watching over everyone here, with all my heart.")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # -- Scam catch log ------------------------------------------------------
    @app_commands.command(name="scamlog", description="Show successful scam catches (evidence log)")
    @app_commands.default_permissions(administrator=True)
    @app_commands.checks.has_permissions(administrator=True)
    async def scamlog(self, interaction: discord.Interaction):
        path = Path(__file__).resolve().parent.parent / "log" / "scam_catches.csv"
        if not path.exists() or path.stat().st_size == 0:
            await interaction.response.send_message(
                "I have caught no scams just yet — may it stay that way.", ephemeral=True
            )
            return
        try:
            with path.open("r", newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        except Exception as e:
            await interaction.response.send_message(
                f"I am sorry, I could not read the record. `({e})`", ephemeral=True
            )
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
    @app_commands.default_permissions(administrator=True)
    @app_commands.checks.has_permissions(administrator=True)
    @app_commands.describe(user="The member to ask about")
    async def why(self, interaction: discord.Interaction, user: discord.Member):
        if not interaction.guild:
            await interaction.response.send_message(
                "Forgive me — this is something I can only do within a server.", ephemeral=True
            )
            return
        agent = getattr(self.bot, "agent", None)
        if not agent or not getattr(agent, "enabled", False):
            await interaction.response.send_message(
                "I'm sorry, my analysis assistant is not configured right now.", ephemeral=True
            )
            return
        record = agent.latest_case_for(interaction.guild.id, user.id)
        if not record:
            await interaction.response.send_message(
                f"I have no recorded analysis for **{user}** to draw upon.", ephemeral=True
            )
            return
        await interaction.response.defer(thinking=True)
        answer = await agent.answer_why(record)
        if not answer:
            await interaction.followup.send(
                "I'm sorry, I could not put together an answer just now. Please try again in a moment."
            )
            return
        await interaction.followup.send(f"**Regarding {user}** — {answer}")

    # -- Global error handler ------------------------------------------------
    async def cog_app_command_error(
        self, interaction: discord.Interaction, error: app_commands.AppCommandError
    ):
        if isinstance(error, app_commands.CommandOnCooldown):
            msg = (
                f"Please allow me a brief moment to catch my breath — "
                f"do try again in {error.retry_after:.0f}s."
            )
        elif isinstance(error, app_commands.MissingPermissions):
            msg = (
                "I am sorry, but it seems you do not have the standing for this. "
                "Please speak with an administrator if you believe this is a mistake."
            )
        else:
            msg = (
                f"Something unexpected happened, and I could not see your request through. "
                f"I am truly sorry. `({error})`"
            )

        try:
            if interaction.response.is_done():
                await interaction.followup.send(msg, ephemeral=True)
            else:
                await interaction.response.send_message(msg, ephemeral=True)
        except Exception:
            pass
