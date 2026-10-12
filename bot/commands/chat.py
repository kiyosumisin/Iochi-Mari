"""Talking to Mari. Anyone can call "Mari ơi" to see she is there; her owner
can also chat with her (Gemini): "Mari ơi, <anything>", or reply to her answer.
Pictures attached to Sensei's message, or in the message Sensei replies to with
"Mari ơi ...", are shown to her too. Sensei can also ask her to delete messages
("Mari, xóa giúp Sensei 10 tin của X") or to ban, unban or time someone out;
nothing happens until Sensei presses the confirm button under her answer, and
no one else can use any of this."""

import asyncio
import logging
import re
import time
from collections import deque
from datetime import datetime, timedelta, timezone

import discord
from discord.ext import commands

from bot.voice import VERDICT_VI, is_sensei, to_reader
from .common import MariCog
from .moderation import SCAN_LIMIT, delete_latest, purge_scope
from .reports import load_catches
from .translate import message_images, split_text

logger = logging.getLogger(__name__)

# Calling Mari at the start of a message: "Mari ơi", "Mari à", "Mari ạ", "Mari này",
# "Mari nè", "Mari ới", "Mari, ...", "Mari!" or just "Mari", optionally after
# "này" / "ê" / "hey" / "chào". "Mari bắt scam giỏi ghê" only talks about her.
_CALL = re.compile(
    r"\s*(?:(?:này|nè|ê|hey|hi|chào)\s+)?mari"
    r"(?:\s+(?:[oơ]i+|ới|[aàạ]|này|nay|nè|ne)\b|(?=\s*(?:[,.!?…:]|$)))[\s,.!?…:]*",
    re.IGNORECASE,
)
HISTORY_TURNS = 12   # messages (Sensei's and Mari's) remembered per channel
FORGET_AFTER = 1800  # seconds of silence before Mari starts a fresh conversation
MAX_IMAGES = 3      # pictures per message (the Gemini relay caps a request at 4.5 MB)
VN_TIME = timezone(timedelta(hours=7))  # Sensei's "hôm nay" (Vietnam has no DST)
CLEANUP_AFTER = 8   # seconds before Sensei's request and Mari's "done" answer are deleted


def _catch_reason(row: dict) -> str:
    kind, _, verdict = (row.get("category") or "").partition(":")
    detail = (row.get("detail") or "")[:80]
    if kind in ("url", "link"):
        return f"liên kết {VERDICT_VI.get(verdict, 'scam')} `{detail}`"
    if kind == "image":
        return "ảnh scam đã biết" if verdict == "known" else "ảnh scam"
    if kind == "spread":
        return f"rải tin hàng loạt (`{detail}`)"
    return f"`{row.get('category')}`"


def catches_report(guild_name: str, days: int) -> str:
    """Who Mari caught in this server today (days=0) or in the last `days` days,
    read from the real catch log, never from the model's imagination."""
    now = datetime.now(VN_TIME)
    since = now.replace(hour=0, minute=0, second=0, microsecond=0) if days == 0 else now - timedelta(days=days)
    caught = []
    for row in load_catches():
        try:
            ts = datetime.strptime(row["timestamp_utc"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        if row.get("server") == guild_name and ts >= since:
            caught.append((ts.astimezone(VN_TIME), row))
    when = "Hôm nay" if days == 0 else f"Trong {days} ngày qua"
    if not caught:
        return f"{when} chưa có ai bị bắt vì scam cả ạ. Cầu mong mọi chuyện cứ bình yên như vậy."
    lines = [f"{when} em đã bắt **{len(caught)}** vụ scam ạ:"]
    for ts, row in caught[-10:][::-1]:
        lines.append(f"- {ts.strftime('%H:%M' if days == 0 else '%d/%m %H:%M')} · **{row.get('user', '?')}** · "
                     f"#{row.get('channel', '?')} · {_catch_reason(row)}")
    if len(caught) > 10:
        lines.append(f"…và {len(caught) - 10} vụ cũ hơn nữa, Sensei xem đủ bằng `/scamlog` nhé.")
    return "\n".join(lines)


def _purge_request(action) -> dict | None:
    """The deletion Gemini says Sensei asked for, checked, or None."""
    if not isinstance(action, dict) or action.get("type") != "purge":
        return None
    try:
        count = int(action.get("count"))
    except (TypeError, ValueError):
        return None
    if not 1 <= count <= 1000:
        return None
    return {"count": count,
            "author": str(action.get("author") or "").strip().lstrip("@") or None,
            "bots": bool(action.get("bots")),
            "contains": str(action.get("contains") or "").strip() or None}


def _by_author(author: str | None):
    """Match a message's author by <@id>, or by username / display name / global name."""
    if author is None:
        return lambda m: True
    mention = re.fullmatch(r"<@!?(\d+)>", author)
    if mention:
        uid = int(mention.group(1))
        return lambda m: m.author.id == uid
    name = author.lower()
    return lambda m: name in {(m.author.name or "").lower(), (m.author.display_name or "").lower(),
                              (getattr(m.author, "global_name", None) or "").lower()}


_ID = re.compile(r"<@!?(\d+)>|(\d{15,20})")


async def _find_member(guild: discord.Guild, who: str):
    """(member, None), or (None, why not), for a username, display name, <@mention> or ID."""
    if m := _ID.fullmatch(who):
        uid = int(m.group(1) or m.group(2))
        try:
            return await guild.fetch_member(uid), None
        except discord.NotFound:
            return None, f"Em không tìm thấy thành viên nào có ID `{uid}` trong server ạ."
    try:
        found = await guild.query_members(query=who, limit=10)  # no Members intent needed
    except asyncio.TimeoutError:
        return None, "Em xin lỗi, Discord trả lời chậm quá, Sensei thử lại giúp em nhé."
    name = who.lower()
    pool = [x for x in found if name in {x.name.lower(), x.display_name.lower(),
                                         (x.global_name or "").lower()}] or found
    if len(pool) == 1:
        return pool[0], None
    if not pool:
        return None, f"Em không tìm thấy ai tên **{who}** trong server ạ."
    names = ", ".join(f"{x.display_name} (`{x.name}`)" for x in pool[:5])
    return None, f"Có nhiều người khớp với **{who}**: {names}. Sensei nhắc đúng người (@) giúp em nhé."


async def _find_banned(guild: discord.Guild, who: str):
    """(user, None), or (None, why not), among this server's bans."""
    m = _ID.fullmatch(who)
    uid, name = (int(m.group(1) or m.group(2)) if m else None), who.lower()
    async for entry in guild.bans(limit=1000):
        u = entry.user
        if u.id == uid or name in {u.name.lower(), (u.global_name or "").lower()}:
            return u, None
    return None, f"Em không thấy ai tên **{who}** trong danh sách bị ban ạ."


async def _plan(bot, request: discord.Message, action: dict):
    """Get a requested action ready for Sensei to confirm: (what Mari will do,
    async do() -> note, tidy up afterwards?), or (why she can't, None, False).
    Only Sensei ever reaches this, and nothing runs before the button."""
    kind = action.get("type")
    if kind == "purge":
        p = _purge_request(action)
        if not p:
            return "Sensei cho em biết cần xóa bao nhiêu tin giúp em nhé.", None, False
        needle, by_author = (p["contains"] or "").lower(), _by_author(p["author"])
        scope = purge_scope(p["author"], p["bots"], p["contains"])

        def match(m):
            return by_author(m) and (not p["bots"] or m.author.bot) and needle in m.content.lower()

        async def purge():
            # Only messages before Sensei's request: never the request or this answer.
            n = await delete_latest(request.channel, p["count"], match, scan_limit=SCAN_LIMIT,
                                    before=request, label=f"chat {p}")
            return (f"Xong rồi ạ, em đã xóa {n} tin nhắn{scope}." if n else
                    f"Em đã tìm trong {SCAN_LIMIT} tin gần nhất nhưng không thấy tin nhắn nào{scope} cả ạ.")
        return f"> Xóa {p['count']} tin nhắn{scope} trong kênh này", purge, True

    if kind not in ("ban", "unban", "timeout"):
        return None, None, False
    guild = request.guild
    who = str(action.get("user") or "").strip().lstrip("@")
    if not guild or not who:
        return "Sensei cho em biết là ai giúp em nhé.", None, False

    if kind == "unban":
        user, why = await _find_banned(guild, who)
        if not user:
            return why, None, False

        async def unban():
            await guild.unban(user, reason="Sensei nhờ Mari gỡ ban")
            return f"Em đã gỡ ban cho **{user.name}** rồi ạ."
        return f"> Gỡ ban **{user.name}** (ID `{user.id}`)", unban, False

    member, why = await _find_member(guild, who)
    if not member:
        return why, None, False
    if member.id == bot.user.id or await is_sensei(bot, member):
        return "Việc này em không làm được đâu ạ.", None, False
    if member.top_role >= guild.me.top_role:
        return f"Vai trò của **{member.display_name}** cao hơn em, nên em không làm được ạ.", None, False
    target = f"**{member.display_name}** (`{member.name}`, ID `{member.id}`)"

    if kind == "ban":
        reason = str(action.get("reason") or "").strip() or "Sensei nhờ Mari ban"

        async def ban():
            await member.ban(reason=f"[Sensei qua Mari] {reason}")
            bot.guild_settings.record_violation(guild.id, member.id, reason=reason)
            return f"Em đã mời **{member.display_name}** rời server rồi ạ."
        return f"> Ban {target}, lý do: {reason}", ban, False

    try:
        minutes = int(action.get("minutes"))
    except (TypeError, ValueError):
        return "Sensei muốn timeout trong bao lâu ạ?", None, False
    if not 0 <= minutes <= 40320:
        return "Discord chỉ cho timeout tối đa 28 ngày thôi ạ.", None, False

    async def timeout():
        await member.timeout(timedelta(minutes=minutes) if minutes else None, reason="Sensei nhờ Mari")
        return (f"Em đã cho **{member.display_name}** tạm nghỉ {minutes} phút rồi ạ." if minutes
                else f"Em đã gỡ timeout cho **{member.display_name}** rồi ạ.")
    return (f"> Timeout {target} trong {minutes} phút" if minutes else f"> Gỡ timeout cho {target}"), timeout, False


class Confirm(discord.ui.View):
    """[Đồng ý] / [Hủy] under Mari's answer: nothing happens until Sensei agrees,
    and only Sensei can press them."""

    def __init__(self, bot, request: discord.Message, what: str, do, cleanup: bool):
        super().__init__(timeout=120)
        self.bot, self.request, self.what, self.do, self.cleanup = bot, request, what, do, cleanup
        self.message = None  # Mari's answer, to drop the buttons on timeout

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if await is_sensei(self.bot, interaction.user):
            return True
        await interaction.response.send_message("Xin thứ lỗi, chỉ Sensei mới xác nhận được việc này.",
                                                ephemeral=True)
        return False

    @discord.ui.button(label="Đồng ý", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button):
        self.stop()
        await interaction.response.edit_message(view=None)  # answer now; the work may take a while
        try:
            note = await self.do()
            logger.info("Chat action by Sensei | %s | %s", self.what, note)
            if self.cleanup:  # deleting messages: tidy up after Sensei has read the note
                await self.request.delete(delay=CLEANUP_AFTER)
                await interaction.message.delete(delay=CLEANUP_AFTER)
        except discord.Forbidden:
            note = "Em xin lỗi, em chưa được cấp quyền để làm việc này."
        except discord.HTTPException as e:
            note = f"Em xin lỗi, đã có trục trặc. `({e})`"
        await interaction.edit_original_response(content=f"{interaction.message.content}\n*{note}*"[:2000])

    @discord.ui.button(label="Hủy", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button):
        self.stop()
        await interaction.response.edit_message(
            content=f"{interaction.message.content}\n*Vâng, em không làm nữa ạ.*"[:2000], view=None)

    async def on_timeout(self):
        if self.message:
            try:
                await self.message.edit(view=None)
            except discord.HTTPException:
                pass


class ChatCog(MariCog):
    def __init__(self, bot):
        super().__init__(bot)
        self._history: dict[int, deque] = {}  # channel id -> (role, text) turns, memory only
        self._last: dict[int, float] = {}     # channel id -> time of the last turn
        self._answers: deque = deque(maxlen=200)  # ids of Mari's chat replies (reply to continue)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if message.author.bot:
            return
        call = _CALL.match(message.content or "")
        ref = message.reference
        continuing = ref is not None and ref.message_id in self._answers
        if not call and not continuing:
            return

        sensei = await is_sensei(self.bot, message.author)
        text = (message.content[call.end():] if call else message.content).strip()
        agent = getattr(self.bot, "agent", None)
        can_chat = sensei and agent and agent.enabled
        images = []
        if can_chat:
            images = await message_images(message, MAX_IMAGES)
            if not images and call and ref:  # "Mari ơi, ..." as a reply to someone's picture
                target = await self._referenced(message)
                images = await message_images(target, MAX_IMAGES) if target else []
        if can_chat and (text or images):
            await self._chat(message, text or "Sensei gửi em hình này.", agent, images)
        elif call:
            await self._reply(message, to_reader(
                "Vâng, Mari đây ạ. Bạn cần Mari giúp gì không? Cứ gọi Mari bất cứ lúc nào nhé, "
                "Mari luôn sẵn lòng.", sensei))

    @staticmethod
    async def _referenced(message: discord.Message):
        """The message being replied to, or None if it is gone."""
        ref = message.reference
        if isinstance(ref.resolved, discord.Message):
            return ref.resolved
        try:
            return await message.channel.fetch_message(ref.message_id)
        except discord.HTTPException:
            return None

    async def _chat(self, message: discord.Message, text: str, agent, images=()):
        cid = message.channel.id
        if time.time() - self._last.get(cid, 0) > FORGET_AFTER:
            self._history[cid] = deque(maxlen=HISTORY_TURNS)
        history = self._history.setdefault(cid, deque(maxlen=HISTORY_TURNS))

        async with message.channel.typing():
            answer = await agent.chat(list(history), text[:4000], images)
        if not answer:
            await self._reply(message, "Em xin lỗi Sensei, lúc này em chưa trả lời được. "
                                       "Sensei thử lại sau một chút nhé.")
            return
        reply, action = answer
        if (action or {}).get("type") == "scamlog":
            try:
                days = min(max(int(action.get("days") or 0), 0), 23)  # the log keeps 23 days
                reply = (catches_report(message.guild.name, days) if message.guild else
                         "Sensei hỏi em trong server nhé, em chỉ xem được nhật ký của từng server thôi ạ.")
            except (ValueError, OSError) as e:
                reply = f"Em xin lỗi, em chưa đọc được nhật ký bắt scam. `({e})`"
        what = do = None
        if action and action.get("type") != "scamlog":
            what, do, cleanup = await _plan(self.bot, message, action)
            if what:  # show exactly what will happen, or why it can't
                reply = f"{reply}\n{what}" if do else what
        # Pictures are not kept: later turns only know that one was shown.
        seen = f" [kèm {len(images)} ảnh]" if images else ""
        history.extend([("user", text[:4000] + seen), ("model", reply)])
        self._last[cid] = time.time()
        parts = split_text(reply, 2000)[:3]
        for i, part in enumerate(parts):
            view = Confirm(self.bot, message, what, do, cleanup) if do and i == len(parts) - 1 else None
            sent = await self._reply(message, part, view)
            if sent:
                self._answers.append(sent.id)
                if view:
                    view.message = sent

    @staticmethod
    async def _reply(message: discord.Message, text: str, view=None):
        try:
            # No pings: Mari's words are never allowed to mention @everyone or anyone else.
            return await message.reply(text, mention_author=False, view=view,
                                       allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException:
            return None
