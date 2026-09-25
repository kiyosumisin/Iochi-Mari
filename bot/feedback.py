"""Buttons under Mari's moderation notices, so an administrator can confirm or
overturn a decision in one click. They keep working after a restart: the
button's custom_id carries only an action and a case id, and the case itself
lives in core.feedback.FeedbackStore."""

import logging

import discord

logger = logging.getLogger(__name__)

# action -> (label, style, does it mark the case as a scam?)
_ACTIONS = {
    "ok":      ("Correct", discord.ButtonStyle.secondary, True),
    "wrong":   ("Wrong - unban", discord.ButtonStyle.danger, False),
    "ban":     ("Ban", discord.ButtonStyle.danger, True),
    "dismiss": ("Dismiss", discord.ButtonStyle.secondary, False),
}
_NOTES = {
    "ok":      "Confirmed as correct by {who}. Thank you.",
    "wrong":   "Marked as my mistake by {who}; the member has been unbanned. Thank you for correcting me.",
    "ban":     "Confirmed as a scam by {who}; the member has been banned.",
    "dismiss": "Dismissed as harmless by {who}.",
}


class FeedbackButton(
    discord.ui.DynamicItem[discord.ui.Button],
    template=r"mari:fb:(?P<action>ok|wrong|ban|dismiss):(?P<case>[0-9a-f]{8})",
):
    def __init__(self, action: str, case_id: str):
        label, style, _ = _ACTIONS[action]
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
            return await say("Forgive me — only an administrator may review my decisions.")

        bot = interaction.client
        case = bot.feedback.cases.get(self.case_id)
        if case is None:
            return await say("I am sorry, I no longer have this case on record.")
        if case["resolved"]:
            return await say(f"This case was already reviewed by {case['resolved']['by']}.")

        guild = interaction.guild
        target = discord.Object(id=case["user_id"])
        try:
            if self.action == "wrong":
                await guild.unban(target, reason=f"Decision overturned by {user}")
            elif self.action == "ban":
                await guild.ban(target, reason=f"Confirmed scam by {user} (case {self.case_id})",
                                delete_message_days=1)
                bot.guild_settings.record_violation(
                    guild.id, case["user_id"], url=case.get("url") or "", reason="Confirmed scam (review)")
        except discord.NotFound:
            pass  # already unbanned, or the account is gone
        except discord.Forbidden:
            return await say("Forgive me — I have not been given the permissions I would need for this.")

        malicious = _ACTIONS[self.action][2]
        bot.feedback.resolve(self.case_id, malicious, str(user))
        if case["kind"] == "actioned":
            bot.guild_settings.increment_stat(guild.id, "mod_confirmed" if malicious else "mod_overturned")
        logger.info("Feedback | case=%s | %s by %s", self.case_id, self.action, user)

        note = _NOTES[self.action].format(who=user.display_name)
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
