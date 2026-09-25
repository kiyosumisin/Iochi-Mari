import csv
import json
import time
import asyncio
from collections import deque
from pathlib import Path
from datetime import timedelta, datetime, timezone
import discord
import logging
from core.url_utils import URLUtils
from core.guild_settings import atomic_write
from core.image_scanner import ocr_image_bytes, append_ocr_log, scan_ocr_text, shrink_image, dhash
from ai.agent import domain_age_days
from bot.feedback import feedback_view

logger = logging.getLogger(__name__)

# Scam bots blast the same post across many channels at once; a member who
# posts in the honeypot by mistake doesn't. Posting media/links in the honeypot
# plus SPAM_CHANNELS-1 other channels within SPAM_WINDOW_S seconds is a ban.
SPAM_WINDOW_S = 120
SPAM_CHANNELS = 3
# Gemini must be at least this sure an honeypot image is a scam to ban on it.
SCAM_IMAGE_CONFIDENCE = 0.8


def _fingerprint(data: bytes):
    """Image fingerprint (see core.image_scanner.dhash), or None if unreadable."""
    try:
        return dhash(data)
    except Exception:
        return None


def _log_page_content(url: str, verdict: str) -> None:
    try:
        from ai.page_analyzer import analyze_page
        import requests
        import textwrap
        from bs4 import BeautifulSoup

        _HEADERS = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            )
        }

        resp = requests.get(url, timeout=8, headers=_HEADERS, allow_redirects=True)
        soup = BeautifulSoup(resp.text, "lxml")

        title = ""
        if soup.title and soup.title.string:
            title = soup.title.string.strip()

        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        content = textwrap.shorten(
            soup.get_text(" ", strip=True), width=300, placeholder="..."
        )

        features = analyze_page(url)

        signals = []
        if features.get("has_login_form"):
            signals.append("login_form")
        if features.get("external_form_action"):
            signals.append("ext_form_action")
        if features.get("domain_changed"):
            signals.append("domain_changed")
        if features.get("hidden_iframe_count", 0) > 0:
            signals.append(f"hidden_iframes={features['hidden_iframe_count']}")
        if features.get("meta_refresh"):
            signals.append("meta_refresh")
        if features.get("favicon_external"):
            signals.append("ext_favicon")
        if features.get("copyright_mismatch"):
            signals.append("copyright_mismatch")
        signals_str = ",".join(signals) if signals else "none"

        logger.info(
            "page_content | url=%s | status=%s | verdict=%s | "
            "redirects=%s | domain_changed=%s | has_login=%s | "
            "ext_link_ratio=%s | signals=%s | title=%s | content=%s",
            url,
            resp.status_code,
            verdict,
            features.get("redirect_count", 0),
            features.get("domain_changed", 0),
            features.get("has_login_form", 0),
            features.get("external_link_ratio", 0.0),
            signals_str,
            title or "(no title)",
            content or "(no content)",
        )

    except Exception as exc:
        logger.warning("page_content fetch failed | url=%s | error=%s", url, exc)


class MessageHandler:
    def __init__(self, evaluator, config, guild_settings=None, agent=None, feedback=None):
        self.evaluator = evaluator
        self.config = config
        self.guild_settings = guild_settings
        self.agent = agent
        self.feedback = feedback  # core.feedback.FeedbackStore: review buttons + image fingerprints
        self.warn_file = Path(__file__).resolve().parent.parent / "data" / "warnings.json"
        self.warns = self._load_warns()
        self.timeout_durations = config.TIMEOUT_DURATIONS
        self.honeypot_warn_limit = config.HONEYPOT_WARN_LIMIT
        self._media_posts: dict[int, deque] = {}  # user id -> (time, channel id) of media/link posts
        self._banned_recently: dict[int, float] = {}  # user id -> ban time, one ban per burst

    def _note_media_post(self, message) -> set[int]:
        """Record a media/link post and return the channels this author posted
        media/links in during the last SPAM_WINDOW_S seconds."""
        now = time.time()
        posts = self._media_posts.setdefault(message.author.id, deque(maxlen=20))
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

    def _add_warn(self, user_id: int):
        key = str(user_id)
        count = int(self.warns.get(key, 0)) + 1
        self.warns[key] = count
        self._save_warns()
        return count

    def _parse_duration(self, value: str) -> timedelta:
        value = value.strip().lower()
        if value.endswith("d"):
            return timedelta(days=int(value[:-1]))
        if value.endswith("h"):
            return timedelta(hours=int(value[:-1]))
        if value.endswith("m"):
            return timedelta(minutes=int(value[:-1]))
        if value.endswith("s"):
            return timedelta(seconds=int(value[:-1]))
        return timedelta(minutes=10)

    def _reset_warns(self, user_id: int):
        key = str(user_id)
        if key in self.warns:
            self.warns.pop(key, None)
            self._save_warns()

    def _add_honeypot_warn(self, user_id: int) -> int:
        """Separate warn counter for accidental posts in the honeypot channel."""
        key = f"hp:{user_id}"
        count = int(self.warns.get(key, 0)) + 1
        self.warns[key] = count
        self._save_warns()
        return count

    def _reset_honeypot_warn(self, user_id: int):
        key = f"hp:{user_id}"
        if key in self.warns:
            self.warns.pop(key, None)
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
            log_dir = Path(__file__).resolve().parent.parent / "log"
            log_dir.mkdir(parents=True, exist_ok=True)
            path = log_dir / "scam_catches.csv"
            new = not path.exists() or path.stat().st_size == 0
            with path.open("a", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                if new:
                    w.writerow([
                        "timestamp_utc", "server", "channel",
                        "user", "user_id", "category", "detail", "action",
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
                ])
        except Exception as exc:
            logger.warning("Could not write scam catch log: %s", exc)

    # ------------------------------------------------------------------
    # Borderline agent layer (Gemini)
    # ------------------------------------------------------------------
    def _is_borderline(self, detail: dict, verdict: str) -> bool:
        if not (self.agent and getattr(self.agent, "enabled", False)):
            return False
        if verdict not in ("phishing", "scam"):
            return False
        prob = detail.get("probability")
        if prob is None:
            return False
        sources = detail.get("sources", [])
        hard = ("blacklist" in sources) or any(str(s).startswith("scanner:") for s in sources)
        if hard:
            return False
        low = float(getattr(self.config, "AI_BORDERLINE_LOW", 0.0))
        high = float(getattr(self.config, "AI_BORDERLINE_HIGH", 0.9))
        return low <= prob < high

    async def _recent_messages(self, message, author, limit: int = 5):
        out = []
        try:
            async for m in message.channel.history(limit=50):
                if m.id == message.id:
                    continue
                if m.author.id == author.id:
                    out.append((m.content or "")[:200])
                    if len(out) >= limit:
                        break
        except Exception as exc:
            logger.warning("Could not fetch recent messages: %s", exc)
        return out

    async def _handle_borderline(self, message, url, verdict, detail, guild) -> bool:
        """
        Hand a borderline case to the Gemini agent: investigate -> (optional data
        fetch) -> explain -> post to the mod log. Returns True if the case was
        flagged (no auto-action); returns False if the agent is unavailable or
        fails, so the caller falls back to the original LightGBM action.
        """
        if not (self.agent and getattr(self.agent, "enabled", False)):
            return False

        author = message.author
        domain = URLUtils.get_domain(url)

        try:
            from ai.feature_extractor import extract_features
            raw = extract_features(url)
        except Exception:
            raw = {}

        age_days = None
        created = getattr(author, "created_at", None)
        if created is not None:
            try:
                age_days = (datetime.now(timezone.utc) - created).days
            except Exception:
                age_days = None

        prior = 0
        if guild and self.guild_settings:
            prior = len(self.guild_settings.get_violations(guild.id, author.id))

        case = {
            "guild_id": getattr(guild, "id", None),
            "user_id": getattr(author, "id", None),
            "user": str(author),
            "channel": getattr(message.channel, "name", None),
            "message_text": (message.content or "")[:500],
            "url": url,
            "domain": domain,
            "verdict": verdict,
            "probability": detail.get("probability"),
            "shap_top_features": detail.get("top_features"),
            "url_features": {
                k: raw.get(k)
                for k in (
                    "url_length", "domain_length", "subdomain_depth", "entropy",
                    "num_digits", "num_special", "is_ip_address", "tld_suspicious",
                )
                if k in raw
            },
            "account_age_days": age_days,
            "prior_violations": prior,
        }

        # 1) Investigate: let the agent decide what extra data to gather.
        inv = await self.agent.investigate_case(case)
        if inv:
            if inv.get("fetch_recent_messages"):
                case["recent_messages"] = await self._recent_messages(message, author)
            if inv.get("check_domain_age"):
                loop = asyncio.get_event_loop()
                case["domain_age_days"] = await loop.run_in_executor(
                    None, domain_age_days, domain
                )
            case["investigation"] = inv

        # 2) Explain: produce the mod-log assessment.
        explanation = await self.agent.explain_case(case)
        if not explanation:
            return False  # agent failed -> fall back to the original action

        prob = detail.get("probability")
        susp = (inv or {}).get("suspicion", "unknown")
        await self._notify(
            guild, message.channel,
            f"**Borderline case flagged for review** — {author} in "
            f"#{getattr(message.channel, 'name', '?')}\n"
            f"Link: `{url}` | AI verdict: `{verdict}` "
            f"(p={prob:.2f}) | suspicion: `{susp}`\n"
            f"{explanation}\n"
            f"Action: flagged for manual review (no automatic action taken).",
            view=self._case_view(message, review=True, verdict=verdict, url=url),
        )
        logger.info(
            "Borderline flagged | user=%s | url=%s | p=%.3f | suspicion=%s",
            getattr(author, "id", "?"),
            url,
            prob if prob is not None else -1,
            susp,
        )
        return True

    # ------------------------------------------------------------------
    # Helpers for scam image action
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
            return await target.send(text, view=view) if view else await target.send(text)
        except Exception as exc:
            logger.warning("Could not send moderation notice: %s", exc)
            return None

    async def _handle_scam_image(
        self,
        message: discord.Message,
        verdict: str,
        filename: str,
        ocr_text: str,
        image_hash: int | None = None,
    ) -> None:
        """
        Khi OCR phát hiện scam image:
          1. Xoá message
          2. Ban user
          3. Gửi alert ngắn vào channel
          4. Log chi tiết vào log channel
        """
        author  = message.author
        channel = message.channel
        guild   = message.guild

        # Bảo vệ: không ban admin
        if guild and author.guild_permissions.administrator:
            logger.warning("Scam image from admin %s — skipping ban.", author)
            return

        # 1. Xoá message
        try:
            await message.delete()
            logger.info(
                "Deleted scam image message | user=%s | file=%s | verdict=%s",
                author.id, filename, verdict,
            )
        except discord.NotFound:
            logger.warning("Message already deleted | file=%s", filename)
        except discord.Forbidden:
            logger.warning("No permission to delete message | file=%s", filename)

        # 2. Ban user
        banned = False
        try:
            await guild.ban(
                author,
                reason=f"Scam image detected ({verdict}) | file={filename}",
                delete_message_days=1,
            )
            banned = True
            self._stat(guild, "auto_bans")
            self._record(guild, author.id, reason=f"Scam image ({verdict}) | file={filename}")
            self._log_catch(guild, author, f"image:{verdict}", f"{filename} | {ocr_text[:120]}", channel)
            logger.info("Banned user %s (ID: %s) for scam image.", author, author.id)
        except discord.Forbidden:
            logger.error("No permission to ban %s.", author)
        except Exception as exc:
            logger.error("Ban failed for %s: %s", author, exc)

        # 3. Alert ngắn gọn — gửi vào kênh log riêng (fallback kênh hiện tại nếu chưa cấu hình)
        try:
            action = "Message removed. User banned." if banned else "Message removed."
            alert = (
                f"**I have found a scam image** from **{author}** — Verdict: `{verdict}`\n"
                f"Image: `{filename}`\n"
                f"{action}\nPlease watch over yourselves, everyone."
            )
            await self._notify(guild, channel, alert,
                               view=self._case_view(message, verdict=verdict, image_hash=image_hash))
        except Exception as exc:
            logger.warning("Could not send scam alert: %s", exc)

        # 4. Log chi tiết vào log channel
        if guild:
            log_channel = self._get_log_channel(guild)
            if log_channel:
                try:
                    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    preview = ocr_text[:200].replace("\n", " ") if ocr_text else "(empty)"
                    log_msg = (
                        f"```\n"
                        f"[SCAM IMAGE LOG] {ts}\n"
                        f"Server  : {guild.name}\n"
                        f"Channel : #{channel.name}\n"
                        f"User    : {author} (ID: {author.id})\n"
                        f"File    : {filename}\n"
                        f"Verdict : {verdict}\n"
                        f"OCR     : {preview}\n"
                        f"Banned  : {banned}\n"
                        f"```"
                    )
                    await log_channel.send(log_msg)
                except Exception as exc:
                    logger.warning("Could not send to log channel: %s", exc)

    # ------------------------------------------------------------------
    # Honeypot channel
    # ------------------------------------------------------------------
    @staticmethod
    def _is_image_attachment(attachment) -> bool:
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
        for url in URLUtils.extract_urls(message.content or ""):
            verdict = await self.evaluator.evaluate(url, threshold=guild_threshold)
            if verdict not in ("safe", "none"):
                return True, f"link:{verdict}", url, {"url": url}

        agent = self.agent if getattr(self.agent, "enabled", False) else None
        ocr_enabled = self.config.OCR_ENABLED
        for att in message.attachments:
            if not self._is_image_attachment(att):
                continue
            try:
                raw = await att.read()
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
                    append_ocr_log(
                        text,
                        source=f"honeypot:{message.id}:{att.filename}",
                        verdict=verdict,
                    )
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
        now = time.time()
        if now - self._banned_recently.get(author.id, 0) < 60:
            return
        if len(self._banned_recently) > 1000:
            self._banned_recently = {u: t for u, t in self._banned_recently.items() if now - t < 60}
        self._banned_recently[author.id] = now
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
                self._stat(guild, "auto_bans")
                self._record(guild, author.id, reason=reason)
                self._reset_honeypot_warn(author.id)
                if catch:
                    self._log_catch(guild, author, catch[0], catch[1], message.channel)
                logger.info("Honeypot banned %s (ID: %s) | %s", author, author.id, reason)
            except discord.Forbidden:
                logger.error("Honeypot: no permission to ban %s", author)
            except Exception as exc:
                logger.error("Honeypot ban failed for %s: %s", author, exc)

        action = "Message removed. User banned." if banned else "Message removed."
        headline = headline or (
            f"**Someone slipped into the trap.** I found **{author}** where no honest member should wander."
        )
        await self._notify(
            guild, message.channel,
            f"{headline}\n"
            f"Reason: `{reason}`\n{action}\nPlease rest easy, everyone — I am keeping watch over this place.",
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
            is_scam, category, detail = True, "spread", f"{len(spread)} channels in {SPAM_WINDOW_S}s"
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

        count = self._add_honeypot_warn(author.id)
        if count > self.honeypot_warn_limit:
            await self._honeypot_ban(
                message,
                reason=f"Honeypot: kept posting after {self.honeypot_warn_limit} warnings",
                already_deleted=True,
            )
        else:
            # Warn the violator where they can actually see it: a mention in the
            # channel that auto-deletes after 15s. A true "only you can see this"
            # message (ephemeral) isn't possible here — that needs a slash-command
            # interaction, and this fires from a normal message the bot reacts to.
            try:
                await message.channel.send(
                    f"{author.mention}, please — you mustn't post here; this place is set aside to "
                    f"catch ill-meaning bots. This is warning {count}/{self.honeypot_warn_limit}. "
                    f"I would be so sad to have to see you out, so do take care.",
                    delete_after=15,
                )
            except discord.Forbidden:
                logger.warning("Honeypot: cannot post warning in %s", message.channel)

    async def handle(self, message):
        """Entry point for every message: honeypot mode, else links, then images."""
        if message.author.bot:
            return

        # A re-post of an image already confirmed as a scam is caught in any
        # channel — even in honeypot mode, since it is a copy, not a guess.
        if await self._check_known_scam_images(message):
            return

        guild = message.guild
        honeypot_id = self._honeypot_channel_id(guild)
        if honeypot_id:
            await self._route_honeypot_mode(message, honeypot_id)
            return

        threshold = (
            self.guild_settings.get_threshold(guild.id) if guild and self.guild_settings else None
        )
        for url in URLUtils.extract_urls(message.content):
            if await self._check_url(message, url, guild, threshold):
                return  # message already removed; don't act on it twice

        if self.config.OCR_ENABLED:
            for attachment in message.attachments:
                if self._is_image_attachment(attachment):
                    await self._check_image(message, attachment)

    async def _check_known_scam_images(self, message) -> bool:
        """Ban on sight for an image whose fingerprint matches a confirmed scam
        image (Gemini-certain honeypot catch or a moderator's "Correct"). Images
        a moderator marked as safe never match. Returns True if acted on."""
        if not (self.feedback and self.feedback.scam_hashes and message.guild):
            return False
        if self._is_admin(message.author):
            return False
        for att in message.attachments:
            if not self._is_image_attachment(att):
                continue
            try:
                image_hash = await asyncio.to_thread(_fingerprint, await att.read())
            except Exception:
                continue
            if image_hash is not None and self.feedback.is_known_scam(image_hash):
                await self._honeypot_ban(
                    message,
                    reason="Known scam image",
                    catch=("image:known", att.filename),
                    evidence={"image_hash": image_hash},
                    headline=(f"**I recognised a known scam image** from **{message.author}** "
                              f"in #{getattr(message.channel, 'name', '?')}."),
                )
                return True
        return False

    async def _route_honeypot_mode(self, message, honeypot_id: int):
        """Honeypot mode: the bot ONLY moderates the honeypot channel, so an
        over-eager verdict can never cause a wrongful ban elsewhere — except for
        a spam burst that also hit the honeypot."""
        spread = self._note_media_post(message)
        if message.channel.id == honeypot_id:
            await self._handle_honeypot(message, spread)
        elif (honeypot_id in spread and len(spread) >= SPAM_CHANNELS
              and not self._is_admin(message.author)):
            # The honeypot post came first (and was only warned); the same
            # burst is now landing in other channels too -> scam bot.
            await self._honeypot_ban(
                message,
                reason=f"Honeypot: same post spread across {len(spread)} channels",
                catch=("spread", f"{len(spread)} channels in {SPAM_WINDOW_S}s"),
            )

    async def _check_url(self, message, url: str, guild, threshold) -> bool:
        """Evaluate one link and act on it. Returns True if the message was removed."""
        domain = URLUtils.get_domain(url)
        # Per-server trusted domains (/whitelist add) are never scanned or actioned.
        if guild and self.guild_settings and URLUtils.domain_in(
            domain, self.guild_settings.get_whitelist(guild.id)
        ):
            return False
        detail = await self.evaluator.evaluate_detailed(url, threshold=threshold)
        verdict = detail["verdict"]
        self._stat(guild, "urls_scanned")
        logger.info(
            "URL checked | user=%s | url=%s | domain=%s | verdict=%s",
            getattr(message.author, "id", "unknown"), url, domain, verdict,
        )
        if verdict in ("safe", "none"):
            return False

        # Fire-and-forget in a thread: the page-content log does blocking HTTP
        # fetches, so never let it stall the event loop or the action.
        asyncio.create_task(asyncio.to_thread(_log_page_content, url, verdict))

        # Borderline agent layer: an uncertain AI-only verdict goes to the Gemini
        # agent for review instead of an automatic ban. Falls back to the normal
        # action if the agent is unavailable or fails.
        if self._is_borderline(detail, verdict) and await self._handle_borderline(
            message, url, verdict, detail, guild
        ):
            return False

        try:
            if verdict in ("malware", "phishing", "scam"):
                await self._ban_for_link(message, url, verdict, guild)
                return True
            if verdict == "gambling":
                await self._timeout_for_gambling(message, url, verdict, guild)
                return True
        except discord.NotFound:
            logger.warning("Message not found for deletion | url=%s", url)
        except discord.Forbidden:
            await self._notify(
                guild, message.channel,
                "Mari does not have sufficient permissions to take action.",
            )
        return False

    async def _ban_for_link(self, message, url: str, verdict: str, guild):
        await message.delete()
        self._stat(guild, "links_blocked")
        await message.author.ban(reason=verdict)
        self._stat(guild, "auto_bans")
        self._record(guild, message.author.id, reason=verdict, url=url)
        self._log_catch(guild, message.author, f"url:{verdict}", url, message.channel)
        self._reset_warns(message.author.id)
        await self._notify(
            guild, message.channel,
            f"I am sorry — I had to see {message.author.mention} out for {verdict}. "
            f"I take no joy in it; I only wish to keep everyone here safe.\nLink: `{url}`",
            view=self._case_view(message, verdict=verdict, url=url),
        )

    async def _timeout_for_gambling(self, message, url: str, verdict: str, guild):
        """Delete + escalating timeout (TIMEOUT_DURATIONS); ban at the 5th warning."""
        await message.delete()
        self._stat(guild, "links_blocked")
        warn_count = self._add_warn(message.author.id)
        duration = self.timeout_durations[min(warn_count - 1, len(self.timeout_durations) - 1)].strip()
        reason = f"{verdict} content | warn {warn_count}/5"
        until = datetime.now(timezone.utc) + self._parse_duration(duration)
        await message.author.timeout(until, reason=reason)
        self._stat(guild, "warnings")
        self._record(guild, message.author.id, reason=reason, url=url)
        await self._notify(
            guild, message.channel,
            f"{message.author.mention}, I must ask you to step back for a little while "
            f"({duration}) — {reason}. Please be mindful; I would far rather guide you than scold you.",
        )
        if warn_count >= 5:
            await message.author.ban(reason=f"Reached {warn_count} warnings")
            self._reset_warns(message.author.id)
            self._stat(guild, "auto_bans")
            self._record(guild, message.author.id, reason=f"Banned after {warn_count} warnings", url=url)
            await self._notify(
                guild, message.channel,
                f"I am truly sorry. After {warn_count} warnings I had no choice but to see "
                f"{message.author.mention} out. I gave every chance I could.",
            )

    async def _check_image(self, message, attachment):
        """OCR an image; ban only on a clear match (2+ scam phrases) — one phrase
        such as "login" on an ordinary screenshot is no reason to ban."""
        try:
            data = await attachment.read()
            text = await asyncio.to_thread(ocr_image_bytes, data)
            if not (text and text.strip()):
                return
            verdict = scan_ocr_text(text)
            append_ocr_log(text, source=f"discord:{message.id}:{attachment.filename}", verdict=verdict)
            logger.info(
                "OCR extracted text | message=%s | attachment=%s | verdict=%s",
                message.id, attachment.filename, verdict,
            )
            if verdict == "scam":
                await self._handle_scam_image(
                    message=message, verdict=verdict, filename=attachment.filename, ocr_text=text,
                    image_hash=await asyncio.to_thread(_fingerprint, data),
                )
        except Exception as exc:
            logger.warning(
                "OCR failed | message=%s | attachment=%s | error=%s",
                message.id, attachment.filename, exc,
            )
