"""What Sensei can ask Mari to do in plain words (the slash commands, by chat).

Only Sensei ever reaches this: Mari's chat with Gemini is Sensei-only. Looking
things up (answer) is read from real data and changes nothing. Doing things
(plan) is shown to Sensei first and only runs when Sensei presses Đồng ý on the
Confirm buttons, which no one else can press.
"""

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone

import discord

from bot.voice import CALL, VERDICT_VI, is_sensei
from .moderation import SCAN_LIMIT, delete_latest, purge_scope
from .reports import catches_of

logger = logging.getLogger(__name__)

VN_TIME = timezone(timedelta(hours=7))  # Sensei's "hôm nay" (Vietnam has no DST)
CLEANUP_AFTER = 8  # seconds before Sensei's request and Mari's "done" answer are deleted
_ID = re.compile(r"<@!?(\d+)>|(\d{15,20})")
_CHANNEL_ID = re.compile(r"<#(\d+)>|(\d{15,20})")


# -- looking things up -------------------------------------------------------

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


def catches_report(guild, days: int) -> str:
    """Who Mari caught in this server today (days=0) or in the last `days` days,
    read from the real catch log, never from the model's imagination."""
    now = datetime.now(VN_TIME)
    since = now.replace(hour=0, minute=0, second=0, microsecond=0) if days == 0 else now - timedelta(days=days)
    caught = []
    for row in catches_of(guild):
        try:
            ts = datetime.strptime(row["timestamp_utc"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        if ts >= since:
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


def _channel(cid) -> str:
    return f"<#{cid}>" if cid else "đang tắt"


async def answer(bot, request: discord.Message, action: dict) -> str | None:
    """Mari's answer to a look-up request, from real data, or None if the action
    is not a look-up. Changes nothing."""
    kind, guild = action.get("type"), request.guild
    if kind not in ("scamlog", "stats", "settings", "check_link", "history", "why"):
        return None
    if not guild:
        return "Sensei hỏi em trong server nhé, em chỉ xem được thông tin của từng server thôi ạ."
    gs, gid = bot.guild_settings, guild.id

    if kind == "scamlog":
        try:
            days = min(max(int(action.get("days") or 0), 0), 23)  # the log keeps 23 days
            return catches_report(guild, days)
        except (ValueError, OSError) as e:
            return f"Em xin lỗi, em chưa đọc được nhật ký bắt scam. `({e})`"

    if kind == "stats":
        s = gs.get_stats(gid)
        reviewed = s["mod_confirmed"] + s["mod_overturned"]
        return "\n".join([
            f"Tóm tắt bảo vệ **{guild.name}** ạ:",
            f"- Liên kết đã kiểm tra: **{s['urls_scanned']}**, đã chặn: **{s['links_blocked']}**",
            f"- Ban tự động: **{s['auto_bans']}**, lần nhắc nhở: **{s['warnings']}**",
            f"- Mod duyệt lại: " + (f"{s['mod_confirmed']} lần đúng, {s['mod_overturned']} lần sai"
                                    if reviewed else "chưa có"),
        ])

    if kind == "settings":
        hp = gs.get_honeypot_channel(gid)
        log = gs.get_log_channel(gid)
        t = gs.get_threshold(gid)
        trusted = sorted(gs.get_whitelist(gid))
        return "\n".join([
            "Cài đặt của em ở server này ạ:",
            f"- Kênh bẫy: {_channel(hp if hp is not None else bot.config.HONEYPOT_CHANNEL_ID)}",
            f"- Kênh thông báo: {_channel(log if log is not None else bot.config.LOG_CHANNEL_ID)}",
            f"- Kênh datamine: {_channel(gs.get_datamine_channel(gid))}",
            f"- Độ nhạy: {f'`{t:.2f}`' if t is not None else 'mặc định của model'}",
            "- Tên miền tin cậy: " + (", ".join(f"`{d}`" for d in trusted) if trusted else "chưa có"),
        ])

    if kind == "check_link":
        url = str(action.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            return "Sensei gửi em đường link đầy đủ (bắt đầu bằng `http://` hoặc `https://`) nhé."
        verdict = await bot.evaluator.evaluate(url, threshold=gs.get_threshold(gid))
        if verdict in ("phishing", "malware", "scam"):
            return f"Liên kết `{url}` **nguy hiểm** ({VERDICT_VI.get(verdict, verdict)}) ạ. Sensei đừng mở nhé."
        if verdict == "gambling":
            return f"Liên kết `{url}` có dấu hiệu **cờ bạc** ạ."
        return f"Em kiểm tra rồi, `{url}` có vẻ an toàn ạ. Dù vậy Sensei vẫn cẩn thận nhé."

    user, why_not = await _find_user(guild, str(action.get("user") or "").strip().lstrip("@"))
    if not user:
        return why_not
    if kind == "history":
        records = gs.get_violations(gid, user.id)
        if not records:
            return f"Em chưa ghi nhận vi phạm nào của **{user.name}** ạ."
        lines = [f"Các lần vi phạm của **{user.name}** ạ:"]
        for r in records[-10:][::-1]:
            url = f" · `{r['url']}`" if r.get("url") else ""
            lines.append(f"- {r.get('timestamp', '?')} · {r.get('reason') or 'không ghi lý do'}{url}")
        return "\n".join(lines)
    record = bot.agent.latest_case_for(gid, user.id)
    if not record:
        return f"Em chưa có ghi chép phân tích nào về **{user.name}** ạ."
    return await bot.agent.answer_why(record) or "Em xin lỗi, lúc này em chưa trả lời được ạ."


# -- finding people and channels ---------------------------------------------

async def _find_member(guild: discord.Guild, who: str):
    """(member, None), or (None, why not), for a username, display name, <@mention> or ID."""
    if not who:
        return None, "Sensei cho em biết là ai giúp em nhé."
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


async def _find_user(guild: discord.Guild, who: str):
    """A member, or failing that a banned user (history and /why cover both)."""
    member, why_not = await _find_member(guild, who)
    if member or not who:
        return member, why_not
    user, _ = await _find_banned(guild, who)
    return (user, None) if user else (None, why_not)


def _find_channel(guild: discord.Guild, ref: str, here):
    """(text channel, None), or (None, why not), for <#id>, an ID, a name or "this"."""
    ref = ref.strip()
    if ref.lower() in ("this", "here", "kênh này", "đây"):
        return (here, None) if isinstance(here, discord.TextChannel) else (None, "Kênh này không đặt được ạ.")
    if m := _CHANNEL_ID.fullmatch(ref):
        ch = guild.get_channel(int(m.group(1) or m.group(2)))
        return (ch, None) if isinstance(ch, discord.TextChannel) else (None, "Em không tìm thấy kênh đó ạ.")
    name = ref.lower().lstrip("#")
    chans = guild.text_channels
    pool = [c for c in chans if c.name.lower() == name] or [c for c in chans if name in c.name.lower()]
    if len(pool) == 1:
        return pool[0], None
    if not pool:
        return None, f"Em không tìm thấy kênh nào tên **{ref}** ạ."
    return None, ("Có nhiều kênh khớp: " + ", ".join(c.mention for c in pool[:5])
                  + ". Sensei chọn giúp em kênh nào ạ (gõ # để nhắc kênh).")


# -- doing things (always confirmed by Sensei first) -------------------------

def _purge_request(action) -> dict | None:
    """The deletion Gemini says Sensei asked for, checked, or None."""
    try:
        count = int(action.get("count"))
    except (TypeError, ValueError):
        return None
    if not 1 <= count <= 1000:
        return None
    return {"count": count,
            "author": str(action.get("author") or "").strip().lstrip("@") or None,
            "bots": bool(action.get("bots")),
            "contains": str(action.get("contains") or "").strip() or None,
            "chat": bool(action.get("chat"))}


def _by_author(author: str | None):
    """Match a message's author by <@id> or ID, or by username / display name / global name."""
    if author is None:
        return lambda m: True
    if m := _ID.fullmatch(author):
        uid = int(m.group(1) or m.group(2))
        return lambda msg: msg.author.id == uid
    name = author.lower()
    return lambda m: name in {(m.author.name or "").lower(), (m.author.display_name or "").lower(),
                              (getattr(m.author, "global_name", None) or "").lower()}


def _our_chat(bot, sensei_id: int):
    """Match the messages of Sensei's conversation with Mari: Sensei calling Mari
    or replying to her, and Mari's replies to Sensei. Nobody else's."""
    def match(m):
        ref = m.reference.resolved if m.reference else None
        to = getattr(getattr(ref, "author", None), "id", None)
        if m.author.id == bot.user.id:
            return to == sensei_id
        if m.author.id == sensei_id:
            return bool(CALL.match(m.content or "")) or to == bot.user.id
        return False
    return match


_SETTERS = {"honeypot": ("set_honeypot_channel", "kênh bẫy"),
            "log": ("set_log_channel", "kênh thông báo"),
            "datamine": ("set_datamine_channel", "kênh datamine")}


async def plan(bot, request: discord.Message, action: dict, forget=None):
    """Get a requested action ready for Sensei to confirm: (what Mari will do,
    async do() -> note, tidy up afterwards?), or (why she can't, None, False).
    Nothing runs before the button."""
    kind, guild = action.get("type"), request.guild
    if kind == "purge":
        p = _purge_request(action)
        if not p:
            return "Sensei cho em biết cần xóa bao nhiêu tin giúp em nhé.", None, False
        needle, by_author = (p["contains"] or "").lower(), _by_author(p["author"])
        scope = purge_scope(p["author"], p["bots"], p["contains"])
        if p["chat"]:
            scope, match = " giữa Sensei và em", _our_chat(bot, request.author.id)
        else:
            def match(m):
                return by_author(m) and (not p["bots"] or m.author.bot) and needle in m.content.lower()

        async def purge():
            # Only messages before Sensei's request: never the request or this answer.
            n = await delete_latest(request.channel, p["count"], match, scan_limit=SCAN_LIMIT,
                                    before=request, label=f"chat {p}")
            if p["chat"] and forget:
                forget()  # "xóa lịch sử": Mari forgets the conversation too
            return (f"Xong rồi ạ, em đã xóa {n} tin nhắn{scope}." if n else
                    f"Em đã tìm trong {SCAN_LIMIT} tin gần nhất nhưng không thấy tin nhắn nào{scope} cả ạ.")
        what = (f"> Xóa cuộc trò chuyện giữa Sensei và em (tối đa {p['count']} tin gần nhất), tin của người khác giữ nguyên"
                if p["chat"] else f"> Xóa {p['count']} tin nhắn{scope} trong kênh này")
        return what, purge, True

    if kind not in ("ban", "unban", "timeout", "warn", "set_channel", "whitelist", "threshold", "say"):
        return None, None, False
    if not guild:
        return "Việc này em chỉ làm được trong server thôi ạ.", None, False
    gs = bot.guild_settings

    if kind == "set_channel":
        if action.get("what") not in _SETTERS:
            return "Sensei muốn đặt kênh nào ạ: kênh bẫy, kênh thông báo hay kênh datamine?", None, False
        setter, label = _SETTERS[action["what"]]
        ch = None
        if action.get("channel"):
            ch, why_not = _find_channel(guild, str(action["channel"]), request.channel)
            if not ch:
                return why_not, None, False

        async def set_channel():
            getattr(gs, setter)(guild.id, ch.id if ch else 0)
            return f"Em đã đặt {label} là {ch.mention} rồi ạ." if ch else f"Em đã tắt {label} rồi ạ."
        return (f"> Đặt {label}: {ch.mention}" if ch else f"> Tắt {label}"), set_channel, False

    if kind == "whitelist":
        op = action.get("op")
        domain = (str(action.get("domain") or "").strip().lower()
                  .removeprefix("http://").removeprefix("https://").split("/")[0])
        if op not in ("add", "remove") or "." not in domain:
            return "Sensei muốn thêm hay bỏ tên miền nào khỏi danh sách tin cậy ạ?", None, False

        async def whitelist():
            (gs.add_whitelist if op == "add" else gs.remove_whitelist)(guild.id, domain)
            return (f"Em đã tin cậy `{domain}` rồi ạ." if op == "add"
                    else f"Em đã bỏ `{domain}` khỏi danh sách tin cậy rồi ạ.")
        return (f"> {'Thêm' if op == 'add' else 'Bỏ'} `{domain}` "
                f"{'vào' if op == 'add' else 'khỏi'} danh sách tên miền tin cậy"), whitelist, False

    if kind == "threshold":
        value = action.get("value")
        if value is not None:
            try:
                value = float(value)
            except (TypeError, ValueError):
                value = -1
            if not 0.0 <= value <= 1.0:
                return "Độ nhạy phải nằm trong khoảng 0.0 đến 1.0 ạ.", None, False

        async def threshold():
            gs.set_threshold(guild.id, value)
            return (f"Em đã chỉnh độ nhạy thành `{value:.2f}` rồi ạ." if value is not None
                    else "Em đã đưa độ nhạy về mặc định của model rồi ạ.")
        return (f"> Đặt độ nhạy: `{value:.2f}`" if value is not None
                else "> Đưa độ nhạy về mặc định của model"), threshold, False

    if kind == "say":
        text = str(action.get("text") or "").strip()[:2000]
        if not text:
            return "Sensei muốn em nói gì ạ?", None, False
        ch, why_not = _find_channel(guild, str(action.get("channel") or "this"), request.channel)
        if not ch:
            return why_not, None, False

        async def say():
            await ch.send(text, allowed_mentions=discord.AllowedMentions.none())
            return f"Em đã gửi vào {ch.mention} rồi ạ."
        quoted = "\n".join("> " + line for line in text[:500].splitlines())
        return f"> Gửi vào {ch.mention}:\n{quoted}", say, True

    if kind == "unban":
        user, why_not = await _find_banned(guild, str(action.get("user") or "").strip().lstrip("@"))
        if not user:
            return why_not, None, False

        async def unban():
            await guild.unban(user, reason="Sensei nhờ Mari gỡ ban")
            bot.handler.forgive(guild.id, user.id)
            return f"Em đã gỡ ban cho **{user.name}** rồi ạ."
        return f"> Gỡ ban **{user.name}** (ID `{user.id}`)", unban, False

    member, why_not = await _find_member(guild, str(action.get("user") or "").strip().lstrip("@"))
    if not member:
        return why_not, None, False
    if member.id == bot.user.id or await is_sensei(bot, member):
        return "Việc này em không làm được đâu ạ.", None, False
    if member.top_role >= guild.me.top_role:
        return f"Vai trò của **{member.display_name}** cao hơn em, nên em không làm được ạ.", None, False
    target = f"**{member.display_name}** (`{member.name}`, ID `{member.id}`)"

    if kind == "ban":
        reason = str(action.get("reason") or "").strip() or "Sensei nhờ Mari ban"

        async def ban():
            await member.ban(reason=f"[Sensei qua Mari] {reason}")
            gs.record_violation(guild.id, member.id, reason=reason)
            return f"Em đã mời **{member.display_name}** rời server rồi ạ."
        return f"> Ban {target}, lý do: {reason}", ban, False

    if kind == "warn":
        reason = str(action.get("reason") or "").strip() or "Sensei nhờ Mari nhắc nhở"

        async def warn():
            gs.record_violation(guild.id, member.id, reason=f"Cảnh cáo: {reason}")
            n = len(gs.get_violations(guild.id, member.id))
            await request.channel.send(
                f"{member.mention}, Mari xin phép nhắc bạn: {reason}. Mong bạn để ý giúp Mari nhé.",
                allowed_mentions=discord.AllowedMentions(users=[member]))
            return f"Em đã nhắc nhở **{member.display_name}** rồi ạ (lần ghi nhận thứ {n} trong lịch sử)."
        return f"> Cảnh cáo {target} trong kênh này, lý do: {reason}", warn, False

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
            if self.cleanup:  # tidy up after Sensei has read the note
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
