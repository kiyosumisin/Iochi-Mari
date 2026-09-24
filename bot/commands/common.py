"""Shared helpers and a base cog for Mari's command modules."""

import discord
from discord import app_commands
from discord.ext import commands

# Message shown when a non-owner tries to use an owner-only command.
OWNER_ONLY_DENIAL = "Forgive me — this is something only my keeper may ask of me."


async def is_owner(interaction: discord.Interaction) -> bool:
    """True only for the configured OWNER_ID or the bot's application owner."""
    owner_id = getattr(getattr(interaction.client, "config", None), "OWNER_ID", 0)
    if owner_id and interaction.user.id == owner_id:
        return True
    try:
        return await interaction.client.is_owner(interaction.user)
    except Exception:
        return False


class MariCog(commands.Cog):
    """
    Base class for all of Mari's cogs.

    Holds the shared bot reference and a single, gentle error handler so every
    command module reports failures in Mari's voice without repeating the code.
    """

    def __init__(self, bot: commands.Bot):
        self.bot = bot

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
