"""Owner-only commands: /text (speak a message or sticker through Mari)."""

import discord
from discord import app_commands

from .common import MariCog, is_owner, OWNER_ONLY_DENIAL, say


class OwnerCommands(MariCog):
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
            await say(interaction, OWNER_ONLY_DENIAL)
            return

        target = channel or interaction.channel
        if not isinstance(target, (discord.TextChannel, discord.Thread)):
            await say(interaction, "I am sorry, I can only speak within a text channel.")
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
                await say(
                    interaction,
                    "I am sorry, I could not find a sticker by that name here. "
                    "I am only able to send this server's own stickers.",
                )
                return
            stickers = [found]

        if not message and not stickers:
            await say(
                interaction,
                "Please give me something to share — a message, a sticker, or both.",
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
            await say(
                interaction,
                "Forgive me — I have not been given leave to speak in that channel.",
            )
        except discord.HTTPException as e:
            await say(
                interaction,
                f"Something went amiss and I could not speak. I am sorry. `({e})`",
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
