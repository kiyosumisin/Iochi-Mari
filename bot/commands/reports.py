"""Reporting commands: /stats, /scamlog, /why."""

import csv
from pathlib import Path

import discord
from discord import app_commands

from .common import AdminCog, say


class ReportCommands(AdminCog):
    # -- Stats ---------------------------------------------------------------
    @app_commands.command(name="stats", description="Xem tóm tắt việc bảo vệ server này")
    @app_commands.guild_only()
    @app_commands.default_permissions(administrator=True)
    async def stats(self, interaction: discord.Interaction):
        s = self.bot.guild_settings.get_stats(interaction.guild.id)
        embed = discord.Embed(
            title=f"Tóm tắt bảo vệ — {interaction.guild.name}",
            description="Đây là đôi điều Mari đã làm để giữ bình yên cho nơi này.",
            color=discord.Color.blurple(),
        )
        embed.add_field(name="Liên kết đã kiểm tra", value=str(s.get("urls_scanned", 0)), inline=True)
        embed.add_field(name="Liên kết đã chặn", value=str(s.get("links_blocked", 0)), inline=True)
        embed.add_field(name="Ban tự động", value=str(s.get("auto_bans", 0)), inline=True)
        embed.add_field(name="Lần nhắc nhở", value=str(s.get("warnings", 0)), inline=True)
        t = s.get("threshold")
        embed.add_field(
            name="Độ nhạy phát hiện",
            value=f"`{t:.2f}`" if t is not None else "Mặc định của model",
            inline=True,
        )
        embed.add_field(name="Tên miền tin cậy", value=str(s.get("whitelist_count", 0)), inline=True)
        ok, wrong = s.get("mod_confirmed", 0), s.get("mod_overturned", 0)
        embed.add_field(
            name="Mod duyệt lại",
            value=(f"{ok} lần đúng / {wrong} lần sai (đúng {ok / (ok + wrong):.0%})"
                   if ok + wrong else "Chưa có"),
            inline=False,
        )
        embed.set_footer(text="Mari sẽ tiếp tục dõi theo mọi người ở đây bằng cả tấm lòng.")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # -- Scam catch log ------------------------------------------------------
    @app_commands.command(name="scamlog", description="Xem các vụ scam đã bắt (nhật ký bằng chứng)")
    @app_commands.default_permissions(administrator=True)
    async def scamlog(self, interaction: discord.Interaction):
        # This file lives at bot/commands/reports.py, so the project root is
        # three levels up.
        path = Path(__file__).resolve().parents[2] / "log" / "scam_catches.csv"
        if not path.exists() or path.stat().st_size == 0:
            await say(interaction, "Mari chưa bắt được vụ scam nào cả. Cầu mong mọi chuyện cứ yên bình như vậy.")
            return
        try:
            with path.open("r", newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        except Exception as e:
            await say(interaction, f"Mari xin lỗi, Mari không đọc được nhật ký. `({e})`")
            return

        total = len(rows)
        recent = rows[-10:][::-1]
        embed = discord.Embed(
            title="Các vụ scam đã bắt",
            description=f"Đến giờ Mari đã bắt và mời ra **{total}** vụ scam.",
            color=discord.Color.green(),
        )
        for r in recent:
            detail = (r.get("detail") or "")[:120]
            embed.add_field(
                name=f"{r.get('timestamp_utc', '?')} UTC — {r.get('category', '?')}",
                value=f"Người dùng: `{r.get('user', '?')}`\n`{detail}`",
                inline=False,
            )
        embed.set_footer(text=f"Đang hiện {len(recent)} vụ gần nhất trên tổng {total}, nhật ký đầy đủ ở file đính kèm.")
        await interaction.response.send_message(embed=embed, file=discord.File(str(path)))

    # -- Why (Gemini agent) --------------------------------------------------
    @app_commands.command(name="why", description="Hỏi Mari vì sao một người bị đánh dấu hoặc bị xử lý")
    @app_commands.guild_only()
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(user="Thành viên cần hỏi")
    async def why(self, interaction: discord.Interaction, user: discord.Member):
        agent = getattr(self.bot, "agent", None)
        if not agent or not getattr(agent, "enabled", False):
            await say(interaction, "Mari xin lỗi, trợ lý phân tích của Mari hiện chưa được thiết lập.")
            return
        record = agent.latest_case_for(interaction.guild.id, user.id)
        if not record:
            await say(interaction, f"Mari chưa có ghi chép phân tích nào về **{user}** cả.")
            return
        await interaction.response.defer(thinking=True)
        answer = await agent.answer_why(record)
        if not answer:
            await interaction.followup.send(
                "Mari xin lỗi, lúc này Mari chưa trả lời được. Bạn thử lại sau một chút nhé."
            )
            return
        await interaction.followup.send(f"**Về {user}** — {answer}")
