"""Owner-only commands: !resync (command cleanup) and /text (speak/sticker)."""

import discord
from discord import app_commands
from discord.ext import commands

from .common import MariCog, is_owner, OWNER_ONLY_DENIAL


class OwnerCommands(MariCog):
    @commands.command()
    @commands.is_owner()
    async def resync(self, ctx: commands.Context):
        """Clean up duplicate/stale slash commands in this server (owner only)."""
        try:
            g = ctx.guild
            if g is not None:
                # Remove this server's command copies (left over from earlier
                # !sync) so they stop duplicating the global ones.
                ctx.bot.tree.clear_commands(guild=g)
                await ctx.bot.tree.sync(guild=g)
            # Re-sync the global set as the single source of truth.
            synced = await ctx.bot.tree.sync()
            names = ", ".join(sorted(c.name for c in synced)) or "(none)"
            await ctx.send(
                f"Tidied up — cleared this server's copies and re-synced "
                f"{len(synced)} global commands:\n`{names}`\n"
                f"Press Ctrl+R to refresh. Global changes can take up to ~1h to settle."
            )
        except Exception as e:
            await ctx.send(f"Forgive me, I could not tidy the commands. `({e})`")

    # -- Speak through Mari (owner only) -------------------------------------
    @app_commands.command(
        name="text",
        description="Send a message or a server sticker through Mari (owner only)",
    )
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(
        message="What you would like me to say (optional if sending a sticker)",
        sticker="A sticker from this server to send (start typing its name)",
        channel="Where to send it (default: this channel)",
    )
    async def text(
        self,
        interaction: discord.Interaction,
        message: str = None,
        sticker: str = None,
        channel: discord.TextChannel = None,
    ):
        if not await is_owner(interaction):
            await interaction.response.send_message(OWNER_ONLY_DENIAL, ephemeral=True)
            return

        target = channel or interaction.channel
        if not isinstance(target, (discord.TextChannel, discord.Thread)):
            await interaction.response.send_message(
                "I am sorry, I can only speak within a text channel.", ephemeral=True
            )
            return

        stickers = []
        if sticker:
            guild = interaction.guild
            found = None
            if guild:
                for s in guild.stickers:
                    if s.name.lower() == sticker.lower() or str(s.id) == sticker:
                        found = s
                        break
            if not found:
                await interaction.response.send_message(
                    "I am sorry, I could not find a sticker by that name here. "
                    "I am only able to send this server's own stickers.",
                    ephemeral=True,
                )
                return
            stickers = [found]

        if not message and not stickers:
            await interaction.response.send_message(
                "Please give me something to share — a message, a sticker, or both.",
                ephemeral=True,
            )
            return

        await interaction.response.defer(ephemeral=True)
        try:
            kwargs = {}
            if message:
                kwargs["content"] = message
            if stickers:
                kwargs["stickers"] = stickers
            await target.send(**kwargs)
            # No confirmation message — just quietly acknowledge and clear it.
            await interaction.delete_original_response()
        except discord.Forbidden:
            await interaction.followup.send(
                "Forgive me — I have not been given leave to speak in that channel.",
                ephemeral=True,
            )
        except discord.HTTPException as e:
            await interaction.followup.send(
                f"Something went amiss and I could not speak. I am sorry. `({e})`",
                ephemeral=True,
            )

    @text.autocomplete("sticker")
    async def _text_sticker_autocomplete(
        self, interaction: discord.Interaction, current: str
    ):
        guild = interaction.guild
        if not guild:
            return []
        current_l = current.lower()
        return [
            app_commands.Choice(name=s.name, value=s.name)
            for s in guild.stickers
            if current_l in s.name.lower()
        ][:25]
