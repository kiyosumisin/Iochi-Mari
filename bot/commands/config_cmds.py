"""Per-server configuration commands: whitelist, honeypot, log channel,
datamine feed and detection threshold."""

import discord
from discord import app_commands

from .common import AdminCog, say


class ConfigCommands(AdminCog):
    # -- Whitelist group -----------------------------------------------------
    whitelist_group = app_commands.Group(
        name="whitelist",
        description="Quản lý các tên miền tin cậy (Mari sẽ không kiểm tra)",
        default_permissions=discord.Permissions(administrator=True),
        guild_only=True,
    )

    @whitelist_group.command(name="add", description="Thêm một tên miền tin cậy")
    @app_commands.describe(domain="Tên miền cần tin cậy (ví dụ google.com)")
    async def whitelist_add(self, interaction: discord.Interaction, domain: str):
        domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
        self.bot.guild_settings.add_whitelist(interaction.guild.id, domain)
        await say(
            interaction,
            f"Mari đã đặt niềm tin vào `{domain}`, từ giờ các liên kết của nó sẽ được đi qua mà không cần lo nữa.",
        )

    @whitelist_group.command(name="remove", description="Bỏ một tên miền khỏi danh sách tin cậy")
    @app_commands.describe(domain="Tên miền cần bỏ")
    async def whitelist_remove(self, interaction: discord.Interaction, domain: str):
        domain = domain.strip().lower()
        self.bot.guild_settings.remove_whitelist(interaction.guild.id, domain)
        await say(
            interaction,
            f"Mari đã bỏ `{domain}` khỏi danh sách tin cậy, và sẽ lại nhẹ nhàng để mắt tới nó như trước.",
        )

    @whitelist_group.command(name="list", description="Xem tất cả tên miền tin cậy")
    async def whitelist_list(self, interaction: discord.Interaction):
        domains = self.bot.guild_settings.get_whitelist(interaction.guild.id)
        if not domains:
            await say(interaction, "Hiện chưa có tên miền tin cậy nào cả.")
            return
        await say(
            interaction,
            "Đây là những tên miền Mari đang tin cậy:\n" + "\n".join(f"- `{d}`" for d in sorted(domains)),
        )

    # -- Honeypot ------------------------------------------------------------
    honeypot_group = app_commands.Group(
        name="honeypot",
        description="Quản lý kênh bẫy (honeypot) để bắt bot scam",
        default_permissions=discord.Permissions(administrator=True),
        guild_only=True,
    )

    @honeypot_group.command(name="set", description="Chọn kênh làm bẫy (honeypot)")
    @app_commands.describe(channel="Kênh dùng làm bẫy")
    async def honeypot_set(self, interaction: discord.Interaction, channel: discord.TextChannel):
        self.bot.guild_settings.set_honeypot_channel(interaction.guild.id, channel.id)
        await say(
            interaction,
            f"Mari hiểu rồi ạ. Từ giờ Mari sẽ canh {channel.mention} làm bẫy: ai mang link hay "
            f"ảnh scam vào đó sẽ bị mời ra ngay. Ở các kênh khác, Mari chỉ xử lý những scam "
            f"đã biết chắc, còn lại Mari để mọi người được yên.",
        )

    @honeypot_group.command(name="off", description="Tắt bẫy và quay lại kiểm duyệt mọi kênh như thường")
    async def honeypot_off(self, interaction: discord.Interaction):
        self.bot.guild_settings.set_honeypot_channel(interaction.guild.id, 0)
        await say(
            interaction,
            "Mari đã cất bẫy đi rồi. Xin lưu ý: từ giờ Mari sẽ canh lại **tất cả** các kênh, "
            "nên có thể dễ nhầm hơn một chút. Nếu Mari có lỡ nhầm, mong mọi người thứ lỗi nhé.",
        )

    @honeypot_group.command(name="status", description="Xem kênh bẫy hiện tại")
    async def honeypot_status(self, interaction: discord.Interaction):
        gid = self.bot.guild_settings.get_honeypot_channel(interaction.guild.id)
        if gid is None:
            gid = getattr(self.bot.config, "HONEYPOT_CHANNEL_ID", 0)
        if gid:
            await say(
                interaction,
                f"Mari đang canh bẫy ở <#{gid}>. Ở các kênh khác, Mari chỉ xử lý những scam đã biết chắc thôi.",
            )
        else:
            await say(
                interaction,
                "Hiện chưa đặt bẫy nào, Mari đang canh tất cả các kênh như thường lệ.",
            )

    # -- Log channel ---------------------------------------------------------
    logchannel_group = app_commands.Group(
        name="logchannel",
        description="Chọn kênh Mari gửi thông báo kiểm duyệt",
        default_permissions=discord.Permissions(administrator=True),
        guild_only=True,
    )

    @logchannel_group.command(name="set", description="Chọn kênh nhận thông báo kiểm duyệt")
    @app_commands.describe(channel="Kênh nhận thông báo kiểm duyệt")
    async def logchannel_set(self, interaction: discord.Interaction, channel: discord.TextChannel):
        self.bot.guild_settings.set_log_channel(interaction.guild.id, channel.id)
        await say(
            interaction,
            f"Mari hiểu rồi ạ. Từ giờ Mari sẽ lặng lẽ gửi mọi thông báo vào {channel.mention}.",
        )

    @logchannel_group.command(name="off", description="Thôi dùng kênh thông báo riêng")
    async def logchannel_off(self, interaction: discord.Interaction):
        self.bot.guild_settings.set_log_channel(interaction.guild.id, 0)
        await say(
            interaction,
            "Mari hiểu rồi ạ. Từ giờ Mari không dùng kênh thông báo riêng nữa, "
            "chuyện xảy ra ở đâu Mari sẽ báo ngay tại đó.",
        )

    @logchannel_group.command(name="status", description="Xem kênh thông báo hiện tại")
    async def logchannel_status(self, interaction: discord.Interaction):
        cid = self.bot.guild_settings.get_log_channel(interaction.guild.id)
        if cid is None:
            cid = getattr(self.bot.config, "LOG_CHANNEL_ID", 0)
        if cid:
            await say(interaction, f"Hiện Mari đang gửi thông báo vào <#{cid}>.")
        else:
            await say(
                interaction,
                "Hiện Mari không dùng kênh thông báo riêng, chuyện xảy ra ở đâu Mari báo ngay tại đó.",
            )

    # -- Threshold -----------------------------------------------------------
    @app_commands.command(name="threshold", description="Chỉnh độ nhạy phát hiện (0.0-1.0)")
    @app_commands.guild_only()
    @app_commands.default_permissions(administrator=True)
    @app_commands.describe(value="Một số từ 0.0 đến 1.0 (mặc định: ngưỡng model đã tự tinh chỉnh)")
    async def threshold(self, interaction: discord.Interaction, value: float):
        if not (0.0 <= value <= 1.0):
            await say(
                interaction,
                "Mari xin lỗi, giá trị phải nằm trong khoảng `0.0` đến `1.0`. "
                "Bạn thử lại với một số trong khoảng đó giúp Mari nhé?",
            )
            return
        self.bot.guild_settings.set_threshold(interaction.guild.id, value)
        await say(
            interaction,
            f"Mari hiểu rồi ạ. Mari đã chỉnh độ nhạy thành `{value:.2f}`: từ giờ Mari sẽ đánh dấu "
            f"những liên kết mà Mari thấy có từ {value:.0%} khả năng gây hại trở lên.",
        )
