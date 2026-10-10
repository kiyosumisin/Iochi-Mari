"""Moderation commands: /purge, /ban, /unban, /history."""

import discord
from discord import app_commands

from .common import AdminCog, say

SCAN_LIMIT = 1000  # how far back /purge looks for messages matching its filters


class ModerationCommands(AdminCog):
    # -- Purge ---------------------------------------------------------------
    @app_commands.command(name="purge", description="Xóa các tin gần đây; có thể chỉ xóa tin của một người, của bot, hoặc có chứa một đoạn chữ")
    @app_commands.guild_only()
    @app_commands.default_permissions(administrator=True)
    @app_commands.checks.cooldown(1, 5.0)
    @app_commands.describe(
        count="Số tin cần xóa (1-1000); nếu có lọc thì là những tin khớp gần nhất",
        user="Chỉ xóa tin của thành viên này",
        contains="Chỉ xóa tin có chứa đoạn chữ này (không phân biệt hoa thường)",
        bots="Chỉ xóa tin do bot gửi",
    )
    async def purge(
        self,
        interaction: discord.Interaction,
        count: app_commands.Range[int, 1, 1000],
        user: discord.Member = None,
        contains: str = None,
        bots: bool = False,
    ):
        if not isinstance(interaction.channel, discord.TextChannel):
            await say(interaction, "Mari xin lỗi, Mari chỉ dọn tin nhắn được trong kênh chữ thôi.")
            return

        needle = (contains or "").lower()
        filtered = bool(user or bots or needle)
        found = 0

        def check(m):
            # Delete the latest `count` matching messages, looking back up to
            # SCAN_LIMIT messages when a filter skips some of them.
            nonlocal found
            if found >= count or not ((user is None or m.author.id == user.id)
                                      and (not bots or m.author.bot) and needle in m.content.lower()):
                return False
            found += 1
            return True

        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            deleted = await interaction.channel.purge(limit=SCAN_LIMIT if filtered else count,
                                                      check=check, bulk=True)
        except discord.Forbidden:
            await say(interaction, "Xin thứ lỗi, Mari chưa được cấp quyền để dọn tin nhắn ở đây.")
            return
        except discord.HTTPException as e:
            await say(interaction, f"Đã có trục trặc trong lúc Mari dọn dẹp. Mari xin lỗi. `({e})`")
            return
        which = ((f" của {user.display_name}" if user else "") + (" của bot" if bots else "")
                 + (f' có chứa "{contains}"' if contains else ""))
        await say(interaction, f"Xong rồi ạ, Mari đã dọn {len(deleted)} tin nhắn{which}.")

    # -- Ban / Unban ---------------------------------------------------------
    @app_commands.command(name="ban", description="Mời một thành viên rời khỏi server")
    @app_commands.guild_only()
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(user="Thành viên cần mời ra", reason="Lý do")
    async def ban(
        self,
        interaction: discord.Interaction,
        user: discord.Member,
        reason: str = "Không ghi lý do",
    ):
        if user.top_role >= interaction.guild.me.top_role:
            await say(
                interaction,
                "Mari e là không thể làm vậy với thành viên này. "
                "Vai trò của họ cao hơn Mari, và Mari phải tôn trọng điều đó.",
            )
            return
        try:
            await user.ban(reason=f"[Manual] {reason}")
            self.bot.guild_settings.record_violation(interaction.guild.id, user.id, reason=reason)
            await interaction.response.send_message(
                f"Mari đã mời **{user}** rời khỏi server.\nLý do: `{reason}`\n"
                f"Mari không vui gì khi làm vậy, chỉ mong nơi này được giữ bình yên."
            )
        except discord.Forbidden:
            await say(
                interaction,
                "Xin thứ lỗi, Mari chưa được cấp quyền để làm việc này.",
            )
        except Exception as e:
            await say(
                interaction,
                f"Đã có trục trặc nên Mari chưa làm được. Mari xin lỗi. `({e})`",
            )

    @app_commands.command(name="unban", description="Gỡ ban theo ID người dùng Discord")
    @app_commands.guild_only()
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(user_id="ID Discord của người cần gỡ ban")
    async def unban(self, interaction: discord.Interaction, user_id: str):
        try:
            uid = int(user_id)
            user = await self.bot.fetch_user(uid)
            await interaction.guild.unban(user)
            await interaction.response.send_message(
                f"Mari đã gỡ ban cho **{user}**. Cầu mong họ trân trọng cơ hội thứ hai này."
            )
        except ValueError:
            await say(
                interaction,
                "Mari xin lỗi, đây có vẻ không phải là một ID hợp lệ. "
                "Bạn kiểm tra lại rồi thử thêm lần nữa giúp Mari nhé?",
            )
        except discord.NotFound:
            await say(
                interaction,
                "Mari không tìm thấy ai bị ban với ID này. "
                "Có lẽ họ đã được gỡ ban từ trước rồi.",
            )
        except Exception as e:
            await say(
                interaction,
                f"Mari chưa gỡ ban được. Xin bạn thứ lỗi vì phiền phức này. `({e})`",
            )

    # -- Violation history ---------------------------------------------------
    @app_commands.command(name="history", description="Xem các lần vi phạm trước đây của một thành viên")
    @app_commands.guild_only()
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(user="Thành viên cần xem")
    async def history(self, interaction: discord.Interaction, user: discord.Member):
        records = self.bot.guild_settings.get_violations(interaction.guild.id, user.id)
        if not records:
            await say(
                interaction,
                f"Mari chưa ghi nhận vi phạm nào của **{user}**. "
                f"Có vẻ họ vẫn luôn cư xử tốt."
            )
            return
        embed = discord.Embed(
            title=f"Lịch sử vi phạm — {user}",
            description="Đây là những gì Mari đã ghi lại về các lần trước.",
            color=discord.Color.orange(),
        )
        for i, record in enumerate(records[-10:], 1):
            embed.add_field(
                name=f"Lần {i} — {record.get('timestamp', 'không rõ thời gian')}",
                value=f"Liên kết: `{record.get('url') or 'không có'}`\nLý do: {record.get('reason') or 'không có'}",
                inline=False,
            )
        await interaction.response.send_message(embed=embed, ephemeral=True)
