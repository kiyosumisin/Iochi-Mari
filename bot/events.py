import os
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

    # ------------------------------------------------------------------
    # Helpers for scam image action
    # ------------------------------------------------------------------
    def _get_log_channel(self, guild: discord.Guild):
        """Trả về log channel nếu config có LOG_CHANNEL_ID."""
        log_channel_id = getattr(self.config, "LOG_CHANNEL_ID", 0)
        if log_channel_id:
            return guild.get_channel(int(log_channel_id))
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
            logger.info("Banned user %s (ID: %s) for scam image.", author, author.id)
        except discord.Forbidden:
            logger.error("No permission to ban %s.", author)
        except Exception as exc:
            logger.error("Ban failed for %s: %s", author, exc)

        # 3. Alert ngắn gọn vào channel
        try:
            action = "Message removed. User banned." if banned else "Message removed."
            alert = (
                f"**Scam image detected** from **{author}** — Verdict: `{verdict}`\n"
                f"Image: `{filename}`\n"
                f"{action}"
            )
            await channel.send(alert)
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

    async def handle(self, message):
        if message.author.bot:
            return

        urls = URLUtils.extract_urls(message.content)
        for url in urls:
            verdict = await self.evaluator.evaluate(url)
            domain = URLUtils.get_domain(url)

            if verdict == "adult" and message.guild:
                allowed_channels = set(self.config.ADULT_CHANNEL_IDS)
                if self.guild_settings:
                    allowed_channels = self.guild_settings.get_adult_channels(message.guild.id)
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
                    await message.author.ban(reason=verdict)
                    self._reset_warns(message.author.id)
                    await message.channel.send(
                        f"{message.author.mention} has been banned for {verdict}"
                    )

                elif verdict in ("adult", "gambling"):
                    await message.delete()
                    warn_count = self._add_warn(message.author.id)
                    duration = self.timeout_durations[
                        min(warn_count - 1, len(self.timeout_durations) - 1)
                    ].strip()
                    duration_td = self._parse_duration(duration)
                    reason = f"{verdict} content | warn {warn_count}/5"
                    until = datetime.now(timezone.utc) + duration_td
                    await message.author.timeout(until, reason=reason)
                    warn_msg = await message.channel.send(
                        f"{message.author.mention} timeout {duration} ({reason})"
                    )
                    try:
                        await warn_msg.delete(delay=30)
                    except discord.NotFound:
                        logger.warning("Warn message not found for deletion")
                    if warn_count >= 5:
                        await message.author.ban(reason=f"Reached {warn_count} warnings")
                        self._reset_warns(message.author.id)
                        ban_msg = await message.channel.send(
                            f"{message.author.mention} has been banned after {warn_count} warnings"
                        )
                        try:
                            await ban_msg.delete(delay=30)
                        except discord.NotFound:
                            logger.warning("Ban message not found for deletion")

            except discord.NotFound:
                logger.warning("Message not found for deletion | url=%s", url)
            except discord.Forbidden:
                await message.channel.send(
                    "Mari does not have sufficient permissions to take action."
                )

        # ===== OCR for image attachments =====
        ocr_enabled = os.getenv("OCR_ENABLED", "true").lower() in ("1", "true", "yes")
        if not ocr_enabled:
            return

        for attachment in message.attachments:
            is_image = False
            if attachment.content_type:
                is_image = attachment.content_type.startswith("image/")
            else:
                is_image = attachment.filename.lower().endswith(
                    (".png", ".jpg", ".jpeg", ".webp", ".bmp")
                )

            if not is_image:
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