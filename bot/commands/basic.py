"""General, public-facing commands: /check, /help, and answering "Mari ơi"."""

import asyncio
import re

import discord
from discord import app_commands
from discord.ext import commands

from core.image_scanner import ocr_image_bytes
from bot.voice import VERDICT_VI, is_sensei, to_reader
from .common import MariCog, is_owner, OWNER_ONLY_DENIAL, say


# "Mari ơi", "mari oi", "Mari ơiii!" ... at the start of a message.
_CALL = re.compile(r"\s*mari\s+[oơ]i+\b", re.IGNORECASE)


def _is_valid_url(url: str) -> bool:
    url = url.strip()
    return url.startswith(("http://", "https://")) and "." in url


def _verdict_embed(url: str, verdict: str, sensei: bool = False) -> discord.Embed:
    if verdict in ("malware", "phishing", "scam"):
        color = discord.Color.red()
        label = f"Nguy hiểm ({VERDICT_VI.get(verdict, verdict)})"
        footer = "Xin đừng mở liên kết này nhé. Cầu mong bạn luôn được bình an."
    elif verdict == "gambling":
        color = discord.Color.orange()
        label = f"Cần lưu ý ({VERDICT_VI.get(verdict, verdict)})"
        footer = "Liên kết này có lẽ không hợp với nơi đây. Mong mọi người cùng nghĩ cho nhau nhé."
    else:
        color = discord.Color.green()
        label = "An toàn"
        footer = "Liên kết này có vẻ an toàn. Dù vậy vẫn cẩn thận nhé, vì điều Mari mong nhất là bạn được bình an."

    embed = discord.Embed(title="Mari xem giúp liên kết", color=color)
    embed.add_field(name="Liên kết", value=f"`{url}`", inline=False)
    embed.add_field(name="Kết quả", value=label, inline=True)
    embed.set_footer(text=to_reader(footer, sensei))
    return embed


class BasicCommands(MariCog):
    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if message.author.bot or not _CALL.match(message.content or ""):
            return
        try:
            await message.reply(to_reader(
                "Vâng, Mari đây ạ. Bạn cần Mari giúp gì không? Cứ gọi Mari bất cứ lúc nào nhé, "
                "Mari luôn sẵn lòng.",
                await is_sensei(self.bot, message.author),
            ), mention_author=False)
        except discord.HTTPException:
            pass

    check_group = app_commands.Group(
        name="check",
        description="Kiểm tra một liên kết hoặc một hình ảnh",
    )

    @check_group.command(name="link", description="Kiểm tra xem một liên kết an toàn hay nguy hiểm")
    @app_commands.checks.cooldown(5, 60.0)  # 5 checks per user per minute
    @app_commands.describe(url="Liên kết bạn muốn Mari xem giúp")
    async def check_link(self, interaction: discord.Interaction, url: str):
        if not _is_valid_url(url):
            await say(
                interaction,
                "Mari xin lỗi, đây có vẻ không phải là một liên kết hợp lệ. "
                "Bạn xem lại giúp Mari là nó có bắt đầu bằng `http://` hoặc `https://` không nhé?",
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
            embed = _verdict_embed(url, verdict, await is_owner(interaction))
            await interaction.followup.send(embed=embed, ephemeral=True)
        except Exception as e:
            await say(
                interaction,
                f"Mari e là đã có trục trặc khi xem liên kết này. "
                f"Xin bạn thứ lỗi cho Mari. `({e})`",
            )

    @check_group.command(name="img", description="Đọc chữ trong một hình ảnh (chỉ dành cho Sensei)")
    @app_commands.describe(image="Hình ảnh bạn muốn Mari đọc giúp")
    async def check_img(self, interaction: discord.Interaction, image: discord.Attachment):
        if not await is_owner(interaction):
            await say(interaction, OWNER_ONLY_DENIAL)
            return

        ctype = image.content_type or ""
        is_image = ctype.startswith("image/") or image.filename.lower().endswith(
            (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp")
        )
        if not is_image:
            await say(interaction, "Mari xin lỗi, đây có vẻ không phải là hình ảnh Mari đọc được.")
            return

        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            data = await image.read()
            text = await asyncio.to_thread(ocr_image_bytes, data)
        except Exception as e:
            await say(interaction, f"Xin thứ lỗi, Mari không đọc được hình ảnh này. `({e})`")
            return

        text = (text or "").strip()
        if not text:
            await say(
                interaction,
                "Mari đã nhìn thật kỹ, nhưng không thấy chữ nào đọc được trong hình này cả.",
            )
            return

        snippet = text if len(text) <= 3800 else text[:3800] + "\n…(đã rút gọn)"
        # Avoid breaking the code fence if the text itself contains backticks.
        snippet = snippet.replace("```", "``​`")
        embed = discord.Embed(
            title="Những gì Mari đọc được",
            description=f"```\n{snippet}\n```",
            color=discord.Color.blurple(),
        )
        embed.set_footer(text=image.filename)
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="help", description="Xem tất cả những việc Mari có thể làm")
    async def help(self, interaction: discord.Interaction):
        sensei = await is_owner(interaction)
        embed = discord.Embed(
            title="Mari có thể giúp gì cho bạn?",
            description=(
                "Mari là thành viên Sisterhood của Trinity. Mari sẽ cố hết sức để giữ bình yên "
                "cho mọi người ở đây, và giúp bạn mỗi khi cần. Đây là những việc Mari có thể làm:"
            ),
            color=discord.Color.blurple(),
        )
        embed.add_field(
            name="Chung",
            value=(
                "`/check link <url>` — Mari xem giúp một liên kết (chỉ mình bạn thấy kết quả)\n"
                "Thả cờ một quốc gia vào tin nhắn — Mari dịch tin đó sang ngôn ngữ của nước ấy\n"
                "`Mari ơi` — Gọi xem Mari có ở đây không"
            ),
            inline=False,
        )
        embed.add_field(
            name="Kiểm duyệt (Quản trị viên)",
            value=(
                "`/purge <count> [user] [bots] [contains]` — Xóa các tin gần đây; có thể chỉ xóa tin của một người, của bot, hoặc tin có chứa một đoạn chữ\n"
                "`/ban <user> [reason]` — Mời một thành viên rời server\n"
                "`/unban <user_id>` — Gỡ ban theo ID người dùng\n"
                "`/history <user>` — Xem các lần vi phạm trước đây của một thành viên\n"
                "`/why <user>` — Hỏi vì sao một người bị đánh dấu (Gemini)"
            ),
            inline=False,
        )
        embed.add_field(
            name="Cấu hình (Quản trị viên)",
            value=(
                "`/honeypot set #channel` / `off` / `status` — Quản lý kênh bẫy (honeypot)\n"
                "`/logchannel set #channel` / `off` / `status` — Kênh Mari gửi thông báo kiểm duyệt\n"
                "`/datamine set #channel` / `off` / `status` — Đăng tin datamine mới của Discord\n"
                "`/whitelist add` / `remove` / `list` — Tên miền tin cậy (không cần kiểm tra)\n"
                "`/threshold <0.0-1.0>` — Chỉnh độ nhạy phát hiện"
            ),
            inline=False,
        )
        embed.add_field(
            name="Báo cáo (Quản trị viên)",
            value=(
                "`/stats` — Tóm tắt việc bảo vệ server này\n"
                "`/scamlog` — Nhật ký các vụ scam đã bắt (bằng chứng)"
            ),
            inline=False,
        )
        if sensei:
            embed.add_field(
                name="Chỉ dành cho Sensei",
                value=(
                    "`/check img <image>` — Đọc chữ trong một hình ảnh\n"
                    "`/text <message> [sticker] [channel]` — Nhờ Mari gửi tin nhắn hoặc sticker"
                ),
                inline=False,
            )
        embed.set_footer(text="Nếu còn cần gì nữa, xin đừng ngại nói với Mari nhé. Được giúp bạn là niềm vui của Mari.")
        embed.title = to_reader(embed.title, sensei)
        embed.description = to_reader(embed.description, sensei)
        for i, f in enumerate(embed.fields):
            embed.set_field_at(i, name=f.name, value=to_reader(f.value, sensei), inline=f.inline)
        embed.set_footer(text=to_reader(embed.footer.text, sensei))
        await interaction.response.send_message(embed=embed, ephemeral=True)
