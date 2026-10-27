"""Reporting commands: /stats, /scamlog, /why."""

import csv
import io

import discord
from discord import app_commands

from core.retention import CATCH_LOG
from .common import AdminCog, say


def load_catches() -> list[dict]:
    """Rows of the scam catch log (log/scam_catches.csv), oldest first."""
    if not CATCH_LOG.exists():
        return []
    with CATCH_LOG.open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def catches_of(guild) -> list[dict]:
    """This server's rows of the catch log. Rows written before the server_id
    column existed carry only the name, so those are matched by name."""
    return [r for r in load_catches()
            if (r.get("server_id") == str(guild.id) if r.get("server_id") else r.get("server") == guild.name)]


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
    @app_commands.guild_only()
    @app_commands.default_permissions(administrator=True)
    async def scamlog(self, interaction: discord.Interaction):
        """Only this server's catches, shown only to the admin who asked: the log
        names people and their IDs."""
        try:
            rows = catches_of(interaction.guild)
        except Exception as e:
            await say(interaction, f"Mari xin lỗi, Mari không đọc được nhật ký. `({e})`")
            return
        if not rows:
            await say(interaction, "Mari chưa bắt được vụ scam nào cả. Cầu mong mọi chuyện cứ yên bình như vậy.")
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
        out = io.StringIO()
        w = csv.DictWriter(out, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
        await interaction.response.send_message(
            embed=embed, ephemeral=True,
            file=discord.File(io.BytesIO(out.getvalue().encode("utf-8")), filename="scam_catches.csv"))

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
        await interaction.response.defer(thinking=True, ephemeral=True)
        answer = await agent.answer_why(record)
        if not answer:
            await interaction.followup.send(
                "Mari xin lỗi, lúc này Mari chưa trả lời được. Bạn thử lại sau một chút nhé."
            )
            return
        await interaction.followup.send(f"**Về {user}** — {answer}")
