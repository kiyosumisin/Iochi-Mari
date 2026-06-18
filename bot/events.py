import os
import csv
import json
from pathlib import Path
from datetime import timedelta, datetime, timezone
import discord
import logging
from core.url_utils import URLUtils
from core.image_scanner import ocr_image_bytes, append_ocr_log, scan_ocr_text

logger = logging.getLogger(__name__)


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
    def __init__(self, evaluator, config, guild_settings=None):
        self.evaluator = evaluator
        self.config = config
        self.guild_settings = guild_settings
        self.warn_file = Path(__file__).resolve().parent.parent / "data" / "warnings.json"
        self.warns = self._load_warns()
        self.timeout_durations = os.getenv(
            "TIMEOUT_DURATIONS",
            "10m,1h,6h,1d,3d"
        ).split(",")
        self.honeypot_warn_limit = int(os.getenv("HONEYPOT_WARN_LIMIT", "3"))

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
            self.warn_file.parent.mkdir(parents=True, exist_ok=True)
            with self.warn_file.open("w", encoding="utf-8") as f:
                json.dump(self.warns, f, ensure_ascii=False, indent=2)
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

    async def _notify(self, guild, fallback_channel, text):
        """
        Send a moderation notice to the configured log channel.
        Falls back to the channel where the action happened only if no log
        channel is available, so notices are never silently lost.
        """
        target = self._get_log_channel(guild) if guild else None
        if target is None:
            target = fallback_channel
        try:
            return await target.send(text)
        except Exception as exc:
            logger.warning("Could not send moderation notice: %s", exc)
            return None

    async def _handle_scam_image(
        self,
        message: discord.Message,
        verdict: str,
        filename: str,
        ocr_text: str,
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
            await self._notify(guild, channel, alert)
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
        """Return (True, category, detail) if the message carries a scam link/image."""
        guild = message.guild
        guild_threshold = (
            self.guild_settings.get_threshold(guild.id)
            if guild and self.guild_settings
            else None
        )
        for url in URLUtils.extract_urls(message.content or ""):
            verdict = await self.evaluator.evaluate(url, threshold=guild_threshold)
            if verdict not in ("safe", "none"):
                return True, f"link:{verdict}", url

        ocr_enabled = os.getenv("OCR_ENABLED", "true").lower() in ("1", "true", "yes")
        if ocr_enabled:
            for att in message.attachments:
                if not self._is_image_attachment(att):
                    continue
                try:
                    text = ocr_image_bytes(await att.read())
                    if text and text.strip():
                        verdict = scan_ocr_text(text)
                        append_ocr_log(
                            text,
                            source=f"honeypot:{message.id}:{att.filename}",
                            verdict=verdict,
                        )
                        if verdict in ("scam", "suspected"):
                            return True, f"image:{verdict}", att.filename
                except Exception as exc:
                    logger.warning(
                        "Honeypot OCR failed | attachment=%s | error=%s",
                        att.filename, exc,
                    )
        return False, "", ""

    async def _honeypot_ban(self, message, reason: str, already_deleted: bool = False, catch=None):
        guild = message.guild
        author = message.author
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
        await self._notify(
            guild, message.channel,
            f"**Someone slipped into the trap.** I found **{author}** where no honest member should wander.\n"
            f"Reason: `{reason}`\n{action}\nPlease rest easy, everyone — I am keeping watch over this place.",
        )

    async def _handle_honeypot(self, message):
        """
        Real members are told not to post in the honeypot channel.
          - A scam link/image -> instant ban (assumed scam bot).
          - Any other post     -> delete + escalating warning; ban once the
                                   warning limit is exceeded.
        Admins are never punished here.
        """
        author = message.author

        perms = getattr(author, "guild_permissions", None)
        if perms is not None and perms.administrator:
            logger.info("Honeypot post from admin %s — ignored.", author)
            return

        is_scam, category, detail = await self._honeypot_detect_scam(message)
        if is_scam:
            await self._honeypot_ban(
                message,
                reason=f"Honeypot {category}",
                catch=(category, detail),
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
        if message.author.bot:
            return

        guild = message.guild

        # Honeypot mode: if a honeypot channel is configured, the bot ONLY
        # moderates that channel and ignores every other channel, so an
        # over-eager verdict can never cause a wrongful ban elsewhere.
        honeypot_id = self._honeypot_channel_id(guild)
        if honeypot_id:
            if message.channel.id == honeypot_id:
                await self._handle_honeypot(message)
            return

        guild_threshold = (
            self.guild_settings.get_threshold(guild.id)
            if guild and self.guild_settings
            else None
        )

        urls = URLUtils.extract_urls(message.content)
        for url in urls:
            verdict = await self.evaluator.evaluate(url, threshold=guild_threshold)
            domain = URLUtils.get_domain(url)

            self._stat(guild, "urls_scanned")

            if verdict == "adult" and guild:
                allowed_channels = set(self.config.ADULT_CHANNEL_IDS)
                if self.guild_settings:
                    allowed_channels = self.guild_settings.get_adult_channels(guild.id)
                if message.channel.id in allowed_channels:
                    continue

            logger.info(
                "URL checked | user=%s | url=%s | domain=%s | verdict=%s",
                getattr(message.author, "id", "unknown"),
                url,
                domain,
                verdict,
            )

            if verdict not in ("safe", "none"):
                _log_page_content(url, verdict)

            try:
                if verdict in ("malware", "phishing", "scam"):
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
                        f"I take no joy in it; I only wish to keep everyone here safe.",
                    )

                elif verdict in ("adult", "gambling"):
                    await message.delete()
                    self._stat(guild, "links_blocked")
                    warn_count = self._add_warn(message.author.id)
                    duration = self.timeout_durations[
                        min(warn_count - 1, len(self.timeout_durations) - 1)
                    ].strip()
                    duration_td = self._parse_duration(duration)
                    reason = f"{verdict} content | warn {warn_count}/5"
                    until = datetime.now(timezone.utc) + duration_td
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
                        self._record(
                            guild, message.author.id,
                            reason=f"Banned after {warn_count} warnings", url=url,
                        )
                        await self._notify(
                            guild, message.channel,
                            f"I am truly sorry. After {warn_count} warnings I had no choice but to see "
                            f"{message.author.mention} out. I gave every chance I could.",
                        )

            except discord.NotFound:
                logger.warning("Message not found for deletion | url=%s", url)
            except discord.Forbidden:
                await self._notify(
                    guild, message.channel,
                    "Mari does not have sufficient permissions to take action.",
                )

        # ===== OCR for image attachments =====
        ocr_enabled = os.getenv("OCR_ENABLED", "true").lower() in ("1", "true", "yes")
        if not ocr_enabled:
            return

        for attachment in message.attachments:
            if not self._is_image_attachment(attachment):
                continue

            try:
                data = await attachment.read()
                text = ocr_image_bytes(data)
                if text and text.strip():
                    verdict = scan_ocr_text(text)
                    append_ocr_log(
                        text,
                        source=f"discord:{message.id}:{attachment.filename}",
                        verdict=verdict,
                    )
                    logger.info(
                        "OCR extracted text | message=%s | attachment=%s | verdict=%s",
                        message.id,
                        attachment.filename,
                        verdict,
                    )

                    # ── Scam image: xoá + ban + log ──────────────────────
                    if verdict in ("scam", "suspected"):
                        await self._handle_scam_image(
                            message=message,
                            verdict=verdict,
                            filename=attachment.filename,
                            ocr_text=text,
                        )

            except Exception as exc:
                logger.warning(
                    "OCR failed | message=%s | attachment=%s | error=%s",
                    message.id,
                    attachment.filename,
                    exc,
                )