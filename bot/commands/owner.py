"""Owner-only commands: /text (speak a message or sticker through Mari)."""

import discord
from discord import app_commands

from .common import MariCog, is_owner, OWNER_ONLY_DENIAL, say


class OwnerCommands(MariCog):
    # -- Speak through Mari (owner only) -------------------------------------
    @app_commands.command(
        name="text",
        description="Nhờ Mari gửi tin nhắn hoặc sticker của server (chỉ dành cho Sensei)",
    )
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(
        message="Điều bạn muốn Mari nói (có thể bỏ trống nếu gửi sticker)",
        sticker="Sticker của server này (gõ vài chữ trong tên để tìm)",
        channel="Gửi vào kênh nào (mặc định: kênh này)",
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
            await say(interaction, "Mari xin lỗi, Mari chỉ nói được trong kênh chữ thôi.")
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
                    "Mari xin lỗi, Mari không tìm thấy sticker nào có tên đó ở đây. "
                    "Mari chỉ gửi được sticker của chính server này thôi.",
                )
                return
            stickers = [found]

        if not message and not stickers:
            await say(
                interaction,
                "Sensei cho Mari biết cần gửi gì nhé: một tin nhắn, một sticker, hoặc cả hai.",
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
                "Xin thứ lỗi, Mari chưa được phép nói trong kênh đó.",
            )
        except discord.HTTPException as e:
            await say(
                interaction,
                f"Đã có trục trặc nên Mari chưa gửi được. Mari xin lỗi. `({e})`",
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
