"""Buttons under Mari's moderation notices, so an administrator can confirm or
overturn a decision in one click. They keep working after a restart: the
button's custom_id carries only an action and a case id, and the case itself
lives in core.feedback.FeedbackStore."""

import logging

import discord

logger = logging.getLogger(__name__)

# action -> (label, style, does it mark the case as a scam?, note added to the notice)
_ACTIONS = {
    "ok":      ("Đúng rồi", discord.ButtonStyle.secondary, True,
                "{who} đã xác nhận Mari làm đúng. Cảm ơn bạn nhiều."),
    "wrong":   ("Sai - gỡ ban", discord.ButtonStyle.danger, False,
                "{who} cho biết Mari đã nhầm, và thành viên này đã được gỡ ban. Cảm ơn bạn đã sửa giúp Mari."),
    "ban":     ("Ban", discord.ButtonStyle.danger, True,
                "{who} đã xác nhận đây là scam, và thành viên này đã bị ban."),
    "dismiss": ("Bỏ qua", discord.ButtonStyle.secondary, False,
                "{who} đã xem và thấy không có gì đáng lo."),
}


class FeedbackButton(
    discord.ui.DynamicItem[discord.ui.Button],
    template=r"mari:fb:(?P<action>ok|wrong|ban|dismiss):(?P<case>[0-9a-f]{8})",
):
    def __init__(self, action: str, case_id: str):
        label, style, _, _ = _ACTIONS[action]
        super().__init__(discord.ui.Button(label=label, style=style, custom_id=f"mari:fb:{action}:{case_id}"))
        self.action, self.case_id = action, case_id

    @classmethod
    async def from_custom_id(cls, interaction, item, match):
        return cls(match["action"], match["case"])

    async def callback(self, interaction: discord.Interaction):
        async def say(text):
            await interaction.response.send_message(text, ephemeral=True)

        user = interaction.user
        if not getattr(getattr(user, "guild_permissions", None), "administrator", False):
            return await say("Xin thứ lỗi, chỉ quản trị viên mới duyệt lại quyết định của Mari được thôi.")

        bot = interaction.client
        case = bot.feedback.cases.get(self.case_id)
        if case is None:
            return await say("Mari xin lỗi, Mari không còn lưu ca này nữa.")
        if case["resolved"]:
            return await say(f"Ca này đã được {case['resolved']['by']} duyệt rồi ạ.")

        guild = interaction.guild
        target = discord.Object(id=case["user_id"])
        try:
            if self.action == "wrong":
                await guild.unban(target, reason=f"{user} đã sửa lại quyết định")
            elif self.action == "ban":
                await guild.ban(target, reason=f"{user} xác nhận scam (ca {self.case_id})",
                                delete_message_days=1)
                bot.guild_settings.record_violation(
                    guild.id, case["user_id"], url=case.get("url") or "", reason="Mod xác nhận scam")
        except discord.NotFound:
            pass  # already unbanned, or the account is gone
        except discord.Forbidden:
            return await say("Xin thứ lỗi, Mari chưa được cấp quyền để làm việc này.")

        _, _, malicious, note = _ACTIONS[self.action]
        bot.feedback.resolve(self.case_id, malicious, str(user))
        if case["kind"] == "actioned":
            bot.guild_settings.increment_stat(guild.id, "mod_confirmed" if malicious else "mod_overturned")
        logger.info("Feedback | case=%s | %s by %s", self.case_id, self.action, user)

        note = note.format(who=user.display_name)
        await interaction.response.edit_message(
            content=f"{interaction.message.content}\n*{note}*"[:2000], view=None,
        )


def feedback_view(case_id: str, review: bool = False) -> discord.ui.View:
    """Correct / Wrong-unban under an action Mari took; Ban / Dismiss under a
    case she only flagged for review."""
    view = discord.ui.View(timeout=None)
    for action in (("ban", "dismiss") if review else ("ok", "wrong")):
        view.add_item(FeedbackButton(action, case_id))
    return view
