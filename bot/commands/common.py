"""Shared helpers and a base cog for Mari's command modules."""

import discord
from discord import app_commands
from discord.ext import commands

from bot.voice import is_sensei, to_reader

# Message shown when a non-owner tries to use an owner-only command.
OWNER_ONLY_DENIAL = "Mari xin lỗi, việc này chỉ có Sensei mới nhờ Mari làm được thôi ạ."


async def is_owner(interaction: discord.Interaction) -> bool:
    return await is_sensei(interaction.client, interaction.user)


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
                f"Xin cho Mari nghỉ một chút để lấy lại hơi nhé. "
                f"Bạn thử lại sau {error.retry_after:.0f} giây giúp Mari nha."
            )
        elif isinstance(error, app_commands.MissingPermissions):
            msg = (
                "Mari xin lỗi, có vẻ bạn chưa có quyền làm việc này. "
                "Nếu bạn nghĩ đây là nhầm lẫn, xin hãy nói chuyện với quản trị viên nhé."
            )
        else:
            msg = (
                f"Đã có chuyện ngoài ý muốn xảy ra, nên Mari chưa làm xong việc bạn nhờ. "
                f"Mari thật lòng xin lỗi. `({error})`"
            )

        try:
            await say(interaction, msg)
        except Exception:
            pass


class AdminCog(MariCog):
    """Every app command in this cog requires Administrator at runtime, on top
    of default_permissions (which server admins can loosen per command)."""

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.permissions.administrator:
            return True
        raise app_commands.MissingPermissions(["administrator"])


async def say(interaction: discord.Interaction, msg: str):
    """Reply privately to the user who ran the command (works before or after defer)."""
    msg = to_reader(msg, await is_owner(interaction))
    if interaction.response.is_done():
        await interaction.followup.send(msg, ephemeral=True)
    else:
        await interaction.response.send_message(msg, ephemeral=True)
