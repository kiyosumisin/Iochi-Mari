import csv
import json
import time
import asyncio
from collections import deque
from pathlib import Path
from datetime import datetime, timezone
import discord
import logging
from core.url_utils import URLUtils
from core.guild_settings import atomic_write
from core.retention import CATCH_LOG
from core.image_scanner import ocr_image_bytes, scan_ocr_text, shrink_image, dhash
from bot.feedback import feedback_view
from bot.voice import KIND_VI, VERDICT_VI

logger = logging.getLogger(__name__)

# Scam bots blast the same post across many channels at once; a member who
# posts in the honeypot by mistake doesn't. Posting media/links in the honeypot
# plus SPAM_CHANNELS-1 other channels within SPAM_WINDOW_S seconds is a ban.
SPAM_WINDOW_S = 120
SPAM_CHANNELS = 3
# Outside the honeypot Mari never bans on a guess: she asks Sensei, pinging at
# most once per this many seconds.
PING_EVERY = 600
# Posts from someone Mari banned less than this many seconds ago (the tail of a
# spam burst arriving late) are just deleted, without asking anyone.
AFTER_BAN = 600
# Links per message that get the costly checks (model, Safe Browsing, VirusTotal,
# page fetch); a message with 50 links must not drain quotas or stall the bot.
MAX_LINKS = 5
# Gemini must be at least this sure an honeypot image is a scam to ban on it.
SCAM_IMAGE_CONFIDENCE = 0.8
# Bigger attachments are not images worth checking (scam lures are screenshots),
# and downloading/OCRing them would only stall the bot.
MAX_IMAGE_BYTES = 10 * 1024 * 1024


def _fingerprint(data: bytes):
    """Image fingerprint (see core.image_scanner.dhash), or None if unreadable."""
    try:
        return dhash(data)
    except Exception:
        return None


class MessageHandler:
    def __init__(self, evaluator, config, guild_settings=None, agent=None, feedback=None):
        self.evaluator = evaluator
        self.config = config
        self.guild_settings = guild_settings
        self.agent = agent
        self.feedback = feedback  # core.feedback.FeedbackStore: review buttons + image fingerprints
        self.warn_file = Path(__file__).resolve().parent.parent / "data" / "warnings.json"
        self.warns = self._load_warns()
        self.honeypot_warn_limit = config.HONEYPOT_WARN_LIMIT
        # Keyed by (guild id, user id): what someone does in one server says
        # nothing about the others.
        self._media_posts: dict[tuple, deque] = {}  # -> (time, channel id) of media/link posts
        self._banned_recently: dict[tuple, float] = {}  # -> ban time, one ban per burst
        self._last_ping = 0.0  # last time Mari pinged Sensei about a suspicious post
        self._asks: dict[tuple, list] = {}  # -> (time, Mari's in-channel question) about them
        self._downloads: dict[int, bytes] = {}  # attachment id -> bytes, for the last few images

    @staticmethod
    def _key(message) -> tuple:
        return getattr(message.guild, "id", 0), message.author.id

    async def _read(self, att) -> bytes:
        """An attachment's bytes, downloaded once although several checks look at it."""
        data = self._downloads.get(att.id)
        if data is None:
            data = self._downloads[att.id] = await att.read()
            while len(self._downloads) > 8:
                self._downloads.pop(next(iter(self._downloads)))
        return data

    def _note_media_post(self, message) -> set[int]:
        """Record a media/link post and return the channels this author posted
        media/links in during the last SPAM_WINDOW_S seconds."""
        now = time.time()
        posts = self._media_posts.setdefault(self._key(message), deque(maxlen=20))
        if message.attachments or URLUtils.extract_urls(message.content or ""):
            posts.append((now, message.channel.id))
        while posts and now - posts[0][0] > SPAM_WINDOW_S:
            posts.popleft()
        if len(self._media_posts) > 5000:  # forget idle users
            self._media_posts = {u: d for u, d in self._media_posts.items() if d and now - d[-1][0] <= SPAM_WINDOW_S}
        return {ch for _, ch in posts}

    @staticmethod
    def _is_admin(author) -> bool:
        perms = getattr(author, "guild_permissions", None)
        return perms is not None and perms.administrator

    def _case_view(self, message, *, review: bool = False, verdict: str = "",
                   url: str | None = None, image_hash: int | None = None):
        """Open a feedback case for this decision and return the buttons for its
        notice (Correct / Wrong-unban, or Ban / Dismiss for a review)."""
        if not (self.feedback and message.guild):
            return None
        case_id = self.feedback.new_case(
            "review" if review else "actioned", message.guild.id, message.author.id,
            verdict=verdict, url=url, image_hash=image_hash,
        )
        return feedback_view(case_id, review=review)

    def _load_warns(self):
        try:
            if not self.warn_file.exists():
                return {}
            with self.warn_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            logger.warning("Failed to load warnings.json: %s", exc)
            return {}

    def _save_warns(self):
        try:
            atomic_write(self.warn_file, json.dumps(self.warns, ensure_ascii=False, indent=2))
        except Exception as exc:
            logger.warning("Failed to save warnings.json: %s", exc)

    # Warn counters by key: str(user_id) for gambling links, "hp:<id>" for honeypot
    # posts, "ks:<id>" for known scams posted outside the honeypot.
    def _bump_warn(self, key: str) -> int:
        count = int(self.warns.get(key, 0)) + 1
        self.warns[key] = count
        self._save_warns()
        return count

    def _reset_warn(self, key: str):
        if self.warns.pop(key, None) is not None:
            self._save_warns()

    def _stat(self, guild, key: str, amount: int = 1):
        """Increment a per-guild protection stat (no-op outside a guild)."""
        if guild and self.guild_settings:
            self.guild_settings.increment_stat(guild.id, key, amount)

    def _record(self, guild, user_id: int, reason: str, url: str = ""):
        """Log a violation to the per-guild audit history (no-op outside a guild)."""
        if guild and self.guild_settings:
            self.guild_settings.record_violation(guild.id, user_id, url=url, reason=reason)

    def _log_catch(self, guild, author, category: str, detail: str, channel):
        """Append a successful scam catch to log/scam_catches.csv (evidence trail)."""
        try:
            path = CATCH_LOG
            path.parent.mkdir(parents=True, exist_ok=True)
            new = not path.exists() or path.stat().st_size == 0
            with path.open("a", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                if new:
                    w.writerow([
                        "timestamp_utc", "server", "channel",
                        "user", "user_id", "category", "detail", "action", "server_id",
                    ])
                w.writerow([
                    datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                    getattr(guild, "name", "") or "",
                    getattr(channel, "name", "") or "",
                    str(author),
                    getattr(author, "id", ""),
                    category,
                    (detail or "")[:300].replace("\n", " ").replace("\r", " "),
                    "banned",
                    getattr(guild, "id", ""),
                ])
        except Exception as exc:
            logger.warning("Could not write scam catch log: %s", exc)

    # ------------------------------------------------------------------
    # Log channel
    # ------------------------------------------------------------------
    def _get_log_channel(self, guild: discord.Guild):
        """Resolve the log channel: per-guild setting wins, else env LOG_CHANNEL_ID."""
        cid = None
        if guild and self.guild_settings:
            cid = self.guild_settings.get_log_channel(guild.id)
        if cid is None:
            cid = int(getattr(self.config, "LOG_CHANNEL_ID", 0) or 0)
        if cid:
            return guild.get_channel(int(cid))
        return None

    async def _notify(self, guild, fallback_channel, text, view=None):
        """
        Send a moderation notice (optionally with review buttons) to the
        configured log channel. Falls back to the channel where the action
        happened only if no log channel is available, so notices are never lost.
        """
        target = self._get_log_channel(guild) if guild else None
        if target is None:
            target = fallback_channel
        try:
            return await target.send(text, view=view)
        except Exception as exc:
            logger.warning("Could not send moderation notice: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Honeypot channel
    # ------------------------------------------------------------------
    @staticmethod
    def _is_image_attachment(attachment) -> bool:
        if attachment.size > MAX_IMAGE_BYTES:
            return False
        if attachment.content_type:
            return attachment.content_type.startswith("image/")
        return attachment.filename.lower().endswith(
            (".png", ".jpg", ".jpeg", ".webp", ".bmp")
        )

    def _honeypot_channel_id(self, guild) -> int:
        """Resolve the active honeypot channel: per-guild setting wins, else env."""
        if guild and self.guild_settings:
            gid = self.guild_settings.get_honeypot_channel(guild.id)
            if gid is not None:
                return gid
        return int(getattr(self.config, "HONEYPOT_CHANNEL_ID", 0) or 0)

    async def _honeypot_detect_scam(self, message):
        """Return (is_scam, category, detail, evidence) for a honeypot post, where
        evidence is {"url": ...} or {"image_hash": ...} for the review buttons."""
        guild = message.guild
        guild_threshold = (
            self.guild_settings.get_threshold(guild.id)
            if guild and self.guild_settings
            else None
        )
        for url in self._links(message):
            verdict = await self.evaluator.evaluate(url, threshold=guild_threshold)
            if verdict not in ("safe", "none"):
                return True, f"link:{verdict}", url, {"url": url}

        agent = self.agent if getattr(self.agent, "enabled", False) else None
        ocr_enabled = self.config.OCR_ENABLED
        for att in message.attachments:
            if not self._is_image_attachment(att):
                continue
            try:
                raw = await self._read(att)
                image_hash = await asyncio.to_thread(_fingerprint, raw)
                # Gemini looks at the picture itself — far better than OCR on
                # screenshots of fake Nitro/Steam pages. Honeypot posts are rare,
                # so this costs almost no quota.
                if agent:
                    res = await agent.classify_scam_image(await asyncio.to_thread(shrink_image, raw))
                    if res is not None:
                        logger.info("Honeypot Gemini image check | %s | %s", att.filename, res)
                        if res["scam"] and float(res.get("confidence") or 0) >= SCAM_IMAGE_CONFIDENCE:
                            # Remember it, so the rest of the spam wave is caught on
                            # sight in every channel (a moderator can still undo it).
                            if self.feedback and image_hash is not None:
                                self.feedback.add_scam_hash(image_hash)
                            return (True, "image:gemini", f"{att.filename}: {res.get('reason', '')}",
                                    {"image_hash": image_hash})
                        continue  # judged not (clearly) a scam -> the warning path
                if not ocr_enabled:
                    continue
                # Fallback when Gemini is unavailable: OCR + whole-word phrases.
                text = await asyncio.to_thread(ocr_image_bytes, raw)
                if text and text.strip():
                    verdict = scan_ocr_text(text)
                    if verdict == "scam":  # a single phrase ("suspected") only warns
                        return True, "image:scam", att.filename, {"image_hash": image_hash}
            except Exception as exc:
                logger.warning(
                    "Honeypot image check failed | attachment=%s | error=%s",
                    att.filename, exc,
                )
        return False, "", "", {}

    async def _honeypot_ban(self, message, reason: str, already_deleted: bool = False, catch=None,
                            evidence: dict | None = None, headline: str | None = None):
        """Delete, ban and purge the author's last day of messages, then post a
        notice with review buttons. `evidence` ({"url"} / {"image_hash"}) is what
        a moderator's answer teaches Mari; `headline` replaces the honeypot wording."""
        guild = message.guild
        author = message.author
        # A spam burst can reach here from several messages at once: act once
        # per burst (time-based, so a later /unban + re-offence is still handled).
        now, key = time.time(), self._key(message)
        if now - self._banned_recently.get(key, 0) < AFTER_BAN:
            return
        if len(self._banned_recently) > 1000:
            self._banned_recently = {k: t for k, t in self._banned_recently.items() if now - t < AFTER_BAN}
        self._banned_recently[key] = now
        if not already_deleted:
            try:
                await message.delete()
            except (discord.NotFound, discord.Forbidden):
                logger.warning("Honeypot: could not delete message from %s", author)

        self._stat(guild, "links_blocked")
        banned = False
        if guild:
            try:
                await guild.ban(author, reason=reason, delete_message_days=1)
                banned = True
                # Questions to Sensei about this burst's earlier posts are moot now.
                for _, ask in self._asks.pop(key, []):
                    try:
                        await ask.delete()
                    except discord.HTTPException:
                        pass
                self._stat(guild, "auto_bans")
                self._record(guild, author.id, reason=reason)
                self._reset_warn(f"hp:{author.id}")
                if catch:
                    self._log_catch(guild, author, catch[0], catch[1], message.channel)
                logger.info("Honeypot banned %s (ID: %s) | %s", author, author.id, reason)
            except discord.Forbidden:
                logger.error("Honeypot: no permission to ban %s", author)
            except Exception as exc:
                logger.error("Honeypot ban failed for %s: %s", author, exc)

        action = "Đã xóa tin nhắn và ban người gửi." if banned else "Đã xóa tin nhắn."
        headline = headline or (
            f"**Có kẻ đã sa vào bẫy.** Mari bắt gặp **{author}** ở nơi mà người ngay thẳng sẽ không bước vào."
        )
        await self._notify(
            guild, message.channel,
            f"{headline}\n"
            f"Lý do: `{reason}`\n{action}\nMọi người cứ yên tâm nhé, Mari vẫn đang canh giữ nơi này.",
            view=self._case_view(message, verdict=reason, **(evidence or {})) if banned else None,
        )

    async def _handle_honeypot(self, message, spread=frozenset()):
        """
        Real members are told not to post in the honeypot channel.
          - A clear scam link/image, or the same media/link burst across
            several channels            -> instant ban (assumed scam bot).
          - Any other post              -> delete + escalating warning; ban
                                           once the warning limit is exceeded.
        Admins are never punished here.
        """
        author = message.author

        if self._is_admin(author):
            logger.info("Honeypot post from admin %s — ignored.", author)
            return

        is_scam, category, detail, evidence = await self._honeypot_detect_scam(message)
        if not is_scam and len(spread) >= SPAM_CHANNELS:
            is_scam, category, detail = True, "spread", f"{len(spread)} kênh trong {SPAM_WINDOW_S} giây"
        if is_scam:
            await self._honeypot_ban(
                message,
                reason=f"Honeypot {category}",
                catch=(category, detail),
                evidence=evidence,
            )
            return

        # Accidental / benign post: remove it and warn the user.
        try:
            await message.delete()
        except (discord.NotFound, discord.Forbidden):
            pass

        count = self._bump_warn(f"hp:{author.id}")
        self._stat(message.guild, "warnings")
        if count > self.honeypot_warn_limit:
            await self._honeypot_ban(
                message,
                reason=f"Honeypot: vẫn đăng sau {self.honeypot_warn_limit} lần nhắc",
                already_deleted=True,
            )
        else:
            # Warn the violator where they can actually see it: a mention in the
            # channel that auto-deletes after 15s. A true "only you can see this"
            # message (ephemeral) isn't possible here — that needs a slash-command
            # interaction, and this fires from a normal message the bot reacts to.
            try:
                await message.channel.send(
                    f"{author.mention}, xin bạn đừng đăng ở đây nhé. Kênh này được dành riêng để bắt "
                    f"những bot có ý xấu. Đây là lần nhắc {count}/{self.honeypot_warn_limit}. "
                    f"Mari sẽ buồn lắm nếu phải mời bạn ra, nên bạn cẩn thận giúp Mari nha.",
                    delete_after=15,
                )
            except discord.Forbidden:
                logger.warning("Honeypot: cannot post warning in %s", message.channel)

    async def handle(self, message):
        """Entry point for every message, the same rule in every server: known
        scams anywhere; bans in the honeypot (if the server has one) and for a
        spam burst that hit it; everywhere else only hide and ask Sensei."""
        if message.author.bot:
            return

        guild = message.guild
        if guild and time.time() - self._banned_recently.get(self._key(message), 0) < AFTER_BAN:
            try:  # the rest of a burst from someone just banned: no need to ask Sensei
                await message.delete()
            except (discord.NotFound, discord.Forbidden):
                pass
            return
        honeypot_id = self._honeypot_channel_id(guild)
        spread = self._note_media_post(message)

        # Copies of confirmed scams are caught in any channel: a list or
        # fingerprint match is a fact, not a guess.
        if await self._check_known_scams(message, honeypot_id, spread):
            return

        if honeypot_id and message.channel.id == honeypot_id:
            await self._handle_honeypot(message, spread)
        elif (honeypot_id in spread and len(spread) >= SPAM_CHANNELS
              and not self._is_admin(message.author)):
            # The honeypot post came first (and was only warned); the same
            # burst is now landing in other channels too -> scam bot.
            await self._honeypot_ban(
                message,
                reason=f"Honeypot: cùng một bài rải ra {len(spread)} kênh",
                catch=("spread", f"{len(spread)} kênh trong {SPAM_WINDOW_S} giây"),
            )
        else:
            await self._watch(message)

    async def _find_known_scam(self, message):
        """(evidence, kind) for the first confirmed scam in the message, else
        (None, ""): a link on the scam lists, or an image whose fingerprint
        matches a confirmed scam image."""
        trusted = self.guild_settings.get_whitelist(message.guild.id) if self.guild_settings else set()
        for url in URLUtils.extract_urls(message.content or ""):
            domain = URLUtils.get_domain(url)
            if not URLUtils.domain_in(domain, trusted) and self.evaluator.is_known_scam(domain):
                return {"url": url}, "link"
        if self.feedback and self.feedback.scam_hashes:
            for att in message.attachments:
                if not self._is_image_attachment(att):
                    continue
                try:
                    image_hash = await asyncio.to_thread(_fingerprint, await self._read(att))
                except Exception:
                    continue
                if image_hash is not None and self.feedback.is_known_scam(image_hash):
                    return {"image_hash": image_hash}, "image"
        return None, ""

    async def _check_known_scams(self, message, honeypot_id: int, spread: set) -> bool:
        """A confirmed scam in the honeypot, or in a burst across SPAM_CHANNELS
        channels, is a scam bot: ban. Anywhere else it may be a member warning
        others about it: delete, warn, and let moderators decide (ban after the
        warning limit). Returns True if the message was acted on."""
        if not message.guild or self._is_admin(message.author):
            return False
        evidence, kind = await self._find_known_scam(message)
        if not evidence:
            return False

        guild, author, channel = message.guild, message.author, message.channel
        where = f"#{getattr(channel, 'name', '?')}"
        detail = evidence.get("url") or ", ".join(a.filename for a in message.attachments)
        headline = f"**Mari nhận ra một {KIND_VI[kind]} scam đã biết** từ **{author}** ở {where}."
        if channel.id == honeypot_id or len(spread) >= SPAM_CHANNELS:
            await self._honeypot_ban(message, reason=f"Scam đã biết ({KIND_VI[kind]})",
                                     catch=(f"{kind}:known", detail),
                                     evidence=evidence, headline=headline)
            return True

        limit = self.honeypot_warn_limit
        count = self._bump_warn(f"ks:{author.id}")
        self._stat(guild, "warnings")
        if count > limit:
            await self._honeypot_ban(message, reason=f"Vẫn đăng scam đã biết sau {limit} lần nhắc",
                                     catch=(f"{kind}:known", detail),
                                     evidence=evidence, headline=headline)
            return True

        # "Bỏ qua" here means "this member meant well", not "this scam is safe",
        # so the case carries no evidence to learn from.
        await self._ask_sensei(
            message, kind=kind, verdict=f"known scam {kind}", strong=True,
            reason=f"{KIND_VI[kind]} scam đã biết", url=evidence.get("url"), learn=False,
            aside=(f"\nBạn {author.mention} ơi, nếu bạn chỉ muốn cảnh báo mọi người thì cảm ơn bạn "
                   f"nhiều nhé, lần sau bạn kể bằng lời thôi là được ạ (lần nhắc {count}/{limit})."),
        )
        return True

    def _links(self, message) -> list[str]:
        """The message's links, without repeats, known scams first (the list check is
        free, so a scam hidden behind five harmless links is still reached), at most
        MAX_LINKS of them."""
        urls = list(dict.fromkeys(URLUtils.extract_urls(message.content or "")))
        urls.sort(key=lambda u: not self.evaluator.is_known_scam(URLUtils.get_domain(u)))
        return urls[:MAX_LINKS]

    def forgive(self, guild_id: int, user_id: int):
        """Called on an unban: their next posts are judged normally again."""
        self._banned_recently.pop((guild_id, user_id), None)

    async def _ask_sensei(self, message, *, kind: str, verdict: str, reason: str, strong: bool,
                          url: str | None = None, image_hash: int | None = None, learn: bool = True,
                          aside: str = "", note: str = ""):
        """Outside the honeypot Mari never bans on her own. A strong suspicion:
        hide the post and ask Sensei right in that channel, with Ban / Bỏ qua (the
        ping at most every PING_EVERY seconds). A weak one: leave the post and only
        note it in the log channel, without a ping. With learn=False a "Bỏ qua"
        teaches Mari nothing (the item itself is a known scam). `note` is
        Gemini's view of the case, if any."""
        guild, channel, author = message.guild, message.channel, message.author
        view = (self._case_view(message, review=True, verdict=verdict, url=url, image_hash=image_hash)
                if learn else self._case_view(message, review=True, verdict=verdict))
        link = (f"\nLiên kết: `{url}`" if url else "") + (f"\n{note}" if note else "")
        if not strong:
            await self._notify(
                guild, channel,
                f"**Mari hơi nghi một {KIND_VI[kind]}** của **{author}** ở "
                f"#{getattr(channel, 'name', '?')} ({reason}).{link}\n"
                f"Mari để yên tin nhắn, mod xem giúp khi rảnh nhé.",
                view=view,
            )
            return
        try:
            await message.delete()
        except (discord.NotFound, discord.Forbidden):
            logger.warning("Could not hide suspicious %s from %s", kind, author)
        self._stat(guild, "links_blocked")
        owner = int(getattr(self.config, "OWNER_ID", 0) or 0)
        ping = bool(owner) and time.time() - self._last_ping >= PING_EVERY
        if ping:
            self._last_ping = time.time()
        text = (f"{f'<@{owner}> ' if owner else ''}Sensei ơi, em vừa tạm giấu một {KIND_VI[kind]} rất đáng ngờ "
                f"của **{author}** ({reason}).{link}\n"
                f"Sensei xem giúp em: bấm **Ban** nếu là scam, **Bỏ qua** nếu không sao ạ.{aside}")
        mentioned = [discord.Object(owner)] if ping else []
        if aside:
            mentioned.append(author)
        try:
            sent = await channel.send(text, view=view, allowed_mentions=discord.AllowedMentions(
                users=mentioned, everyone=False, roles=False))
            now, key = time.time(), self._key(message)
            if len(self._asks) > 1000:  # forget people who were never banned
                self._asks = {k: v for k, v in self._asks.items() if now - v[-1][0] < AFTER_BAN}
            asks = [a for a in self._asks.get(key, []) if now - a[0] < AFTER_BAN]
            self._asks[key] = asks + [(now, sent)]
        except discord.HTTPException:
            await self._notify(guild, channel, text, view=view)  # no right to speak here: log it instead

    async def _watch(self, message):
        """Every channel but the honeypot: check links and image text, and ask
        Sensei about anything suspicious (see _ask_sensei). Never bans."""
        guild = message.guild
        if not guild or self._is_admin(message.author):
            return
        gs = self.guild_settings
        trusted = gs.get_whitelist(guild.id) if gs else set()
        threshold = gs.get_threshold(guild.id) if gs else None
        for url in self._links(message):
            if URLUtils.domain_in(URLUtils.get_domain(url), trusted):
                continue
            detail = await self.evaluator.evaluate_detailed(url, threshold=threshold)
            verdict = detail["verdict"]
            self._stat(message.guild, "urls_scanned")
            if verdict in ("safe", "none"):
                continue
            p = detail.get("probability")
            external = any(s in ("scanner:malware", "scanner:phishing") for s in detail.get("sources") or [])
            reason = ("Google/VirusTotal báo trang này nguy hiểm" if external else
                      f"Mari đoán là {VERDICT_VI.get(verdict, verdict)}"
                      + (f", chắc khoảng {p:.0%}" if p is not None else ""))
            await self._ask_sensei(message, kind="link", verdict=verdict, url=url, reason=reason,
                                   strong=external or (p is not None and p >= self.config.AI_OVERRIDE_THRESHOLD),
                                   note="" if external else await self._gemini_note(message, url, verdict, p))
            return
        if not self.config.OCR_ENABLED:
            return
        for att in message.attachments:
            if not self._is_image_attachment(att):
                continue
            try:
                data = await self._read(att)
                text = await asyncio.to_thread(ocr_image_bytes, data)
            except Exception as exc:
                logger.warning("Watch OCR failed | %s | %s", att.filename, exc)
                continue
            # One scam-like phrase is everyday text ("claim rewards" on a game banner):
            # ignored. Two or more need Gemini to look at the picture and agree.
            if (scan_ocr_text(text) if text and text.strip() else None) != "scam":
                continue
            res = None
            if self.agent and getattr(self.agent, "enabled", False):
                res = await self.agent.classify_scam_image(await asyncio.to_thread(shrink_image, data))
            if res and res["scam"] and float(res.get("confidence") or 0) >= SCAM_IMAGE_CONFIDENCE:
                await self._ask_sensei(
                    message, kind="image", verdict="image:gemini", strong=True,
                    image_hash=await asyncio.to_thread(_fingerprint, data),
                    reason=f"chữ trong ảnh giống scam, và Gemini cũng thấy vậy: {res.get('reason', '')}".strip(": "),
                )
                return

    async def _gemini_note(self, message, url: str, verdict: str, p) -> str:
        """Gemini's two-sentence view of a link only the model flagged, for
        Sensei's question (it is also what /why answers from later), or ""."""
        if not (self.agent and getattr(self.agent, "enabled", False)):
            return ""
        out = await self.agent.explain_case({
            "guild_id": message.guild.id, "user_id": message.author.id, "user": str(message.author),
            "channel": getattr(message.channel, "name", None),
            "message_text": (message.content or "")[:500],
            "url": url, "domain": URLUtils.get_domain(url), "verdict": verdict, "probability": p,
        })
        return f"Gemini nhận xét: {out.strip()}" if out else ""
