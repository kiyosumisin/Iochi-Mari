"""Per-server configuration commands: adult channels, whitelist, honeypot,
log channel and detection threshold."""

import discord
from discord import app_commands

from .common import AdminCog, say


class ConfigCommands(AdminCog):
    # -- Adult channel group -------------------------------------------------
    adult_group = app_commands.Group(
        name="adultchannel",
        description="Manage channels designated for adult content",
        default_permissions=discord.Permissions(administrator=True),
        guild_only=True,
    )

    @adult_group.command(name="add", description="Designate a channel for adult content")
    @app_commands.describe(channel="The channel to designate")
    async def adult_add(self, interaction: discord.Interaction, channel: discord.TextChannel):
        self.bot.guild_settings.add_adult_channel(interaction.guild.id, channel.id)
        await say(
            interaction,
            f"Understood. I have set {channel.mention} aside for such content, "
            f"and will permit it there from now on.",
        )

    @adult_group.command(name="remove", description="Remove a channel from the designated list")
    @app_commands.describe(channel="The channel to remove")
    async def adult_remove(self, interaction: discord.Interaction, channel: discord.TextChannel):
        self.bot.guild_settings.remove_adult_channel(interaction.guild.id, channel.id)
        await say(interaction, f"Noted. I have removed {channel.mention} from that list.")

    @adult_group.command(name="list", description="View all designated adult channels")
    async def adult_list(self, interaction: discord.Interaction):
        channel_ids = self.bot.guild_settings.get_adult_channels(interaction.guild.id)
        if not channel_ids:
            await say(interaction, "It seems no channels have been set aside yet.")
            return
        mentions = [f"<#{cid}>" for cid in sorted(channel_ids)]
        await say(
            interaction,
            "These are the channels I have set aside for such content:\n" + ", ".join(mentions),
        )

    @adult_group.command(name="clear", description="Clear all designated adult channels")
    async def adult_clear(self, interaction: discord.Interaction):
        self.bot.guild_settings.clear_adult_channels(interaction.guild.id)
        await say(
            interaction,
            "I have cleared that list, and will watch over every channel alike from now on.",
        )

    # -- Whitelist group -----------------------------------------------------
    whitelist_group = app_commands.Group(
        name="whitelist",
        description="Manage trusted domains that skip URL scanning",
        default_permissions=discord.Permissions(administrator=True),
        guild_only=True,
    )

    @whitelist_group.command(name="add", description="Add a trusted domain to the whitelist")
    @app_commands.describe(domain="Domain to trust (e.g. google.com)")
    async def whitelist_add(self, interaction: discord.Interaction, domain: str):
        domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
        self.bot.guild_settings.add_whitelist(interaction.guild.id, domain)
        await say(
            interaction,
            f"I have placed my trust in `{domain}`, and will let its links pass without worry.",
        )

    @whitelist_group.command(name="remove", description="Remove a domain from the trusted list")
    @app_commands.describe(domain="Domain to remove")
    async def whitelist_remove(self, interaction: discord.Interaction, domain: str):
        domain = domain.strip().lower()
        self.bot.guild_settings.remove_whitelist(interaction.guild.id, domain)
        await say(
            interaction,
            f"I have removed `{domain}` from those I trust, and will keep a gentle watch on it once more.",
        )

    @whitelist_group.command(name="list", description="View all trusted domains")
    async def whitelist_list(self, interaction: discord.Interaction):
        domains = self.bot.guild_settings.get_whitelist(interaction.guild.id)
        if not domains:
            await say(interaction, "There are no trusted domains just yet.")
            return
        await say(
            interaction,
            "These are the domains I currently trust:\n" + "\n".join(f"- `{d}`" for d in sorted(domains)),
        )

    # -- Honeypot ------------------------------------------------------------
    honeypot_group = app_commands.Group(
        name="honeypot",
        description="Manage the scam-bot honeypot (bait) channel",
        default_permissions=discord.Permissions(administrator=True),
        guild_only=True,
    )

    @honeypot_group.command(name="set", description="Set the honeypot (bait) channel")
    @app_commands.describe(channel="The channel to use as the bait/honeypot")
    async def honeypot_set(self, interaction: discord.Interaction, channel: discord.TextChannel):
        self.bot.guild_settings.set_honeypot_channel(interaction.guild.id, channel.id)
        await say(
            interaction,
            f"Understood. I will keep my watch upon {channel.mention} as the trap from now on — "
            f"anyone who brings scam links or images there will be seen out at once, and I will "
            f"leave every other channel in peace.",
        )

    @honeypot_group.command(name="off", description="Disable the honeypot and resume normal moderation")
    async def honeypot_off(self, interaction: discord.Interaction):
        self.bot.guild_settings.set_honeypot_channel(interaction.guild.id, 0)
        await say(
            interaction,
            "The trap has been set aside. Do be aware: I will now watch over **all** channels "
            "again, so I may err a little more easily — please forgive me if I do.",
        )

    @honeypot_group.command(name="status", description="Show the current honeypot channel")
    async def honeypot_status(self, interaction: discord.Interaction):
        gid = self.bot.guild_settings.get_honeypot_channel(interaction.guild.id)
        if gid is None:
            gid = getattr(self.bot.config, "HONEYPOT_CHANNEL_ID", 0)
        if gid:
            await say(
                interaction,
                f"My watch is set upon <#{gid}>. I am tending to that channel alone for now.",
            )
        else:
            await say(
                interaction,
                "No trap is set just now — I am watching over every channel as usual.",
            )

    # -- Log channel ---------------------------------------------------------
    logchannel_group = app_commands.Group(
        name="logchannel",
        description="Choose where Mari sends her moderation logs",
        default_permissions=discord.Permissions(administrator=True),
        guild_only=True,
    )

    @logchannel_group.command(name="set", description="Set the channel for moderation logs")
    @app_commands.describe(channel="The channel to send moderation logs to")
    async def logchannel_set(self, interaction: discord.Interaction, channel: discord.TextChannel):
        self.bot.guild_settings.set_log_channel(interaction.guild.id, channel.id)
        await say(
            interaction,
            f"Understood. From now on I will quietly bring all my notices to {channel.mention}.",
        )

    @logchannel_group.command(name="off", description="Stop using a dedicated log channel")
    async def logchannel_off(self, interaction: discord.Interaction):
        self.bot.guild_settings.set_log_channel(interaction.guild.id, 0)
        await say(
            interaction,
            "Understood. I will keep no separate log channel now — my notices will appear "
            "wherever each matter arises instead.",
        )

    @logchannel_group.command(name="status", description="Show the current log channel")
    async def logchannel_status(self, interaction: discord.Interaction):
        cid = self.bot.guild_settings.get_log_channel(interaction.guild.id)
        if cid is None:
            cid = getattr(self.bot.config, "LOG_CHANNEL_ID", 0)
        if cid:
            await say(interaction, f"I am bringing my notices to <#{cid}> at present.")
        else:
            await say(
                interaction,
                "I keep no separate log channel just now; my notices appear wherever each matter arises.",
            )

    # -- Threshold -----------------------------------------------------------
    @app_commands.command(name="threshold", description="Adjust the detection sensitivity (0.0-1.0)")
    @app_commands.guild_only()
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(value="A value between 0.0 and 1.0 (default: 0.5)")
    async def threshold(self, interaction: discord.Interaction, value: float):
        if not (0.0 <= value <= 1.0):
            await say(
                interaction,
                "I am sorry, but the value must rest between `0.0` and `1.0`. "
                "Might you try again with a number in that range?",
            )
            return
        self.bot.guild_settings.set_threshold(interaction.guild.id, value)
        await say(
            interaction,
            f"Understood. I have set my watchfulness to `{value:.2f}` — I will now flag links "
            f"I judge {value:.0%} or more likely to bring harm.",
        )
