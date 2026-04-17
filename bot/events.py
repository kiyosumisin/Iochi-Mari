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
    """
    Fetch the page and log its content in the same pipe-separated style as mari.log:

    INFO | ai.page_analyzer | url=... | status=200 | verdict=malware |
          redirects=0 | domain_changed=0 | has_login=1 | signals=login_form,ext_form |
          title=... | content=...
    """
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

        # Extract title
        title = ""
        if soup.title and soup.title.string:
            title = soup.title.string.strip()

        # Extract visible text
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        content = textwrap.shorten(
            soup.get_text(" ", strip=True), width=300, placeholder="..."
        )

        # Get features from page_analyzer
        features = analyze_page(url)

        # Build signals list
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

            # Log page content for any non-safe verdict
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

                    if verdict in ("scam", "suspected"):
                        try:
                            await message.delete()
                            admin_role_id = getattr(self.config, "ADMIN_ROLE_ID", 0)
                            admin_mention = (
                                f"<@&{admin_role_id}>" if admin_role_id else "@admin"
                            )
                            await message.channel.send(
                                f"{admin_mention} removed a suspected scam image from "
                                f"{message.author.mention}. Verdict: {verdict}."
                            )
                        except discord.NotFound:
                            logger.warning(
                                "Message not found for deletion | attachment=%s",
                                attachment.filename,
                            )
                        except discord.Forbidden:
                            await message.channel.send(
                                "Mari does not have sufficient permissions to take action."
                            )
            except Exception as exc:
                logger.warning(
                    "OCR failed | message=%s | attachment=%s | error=%s",
                    message.id,
                    attachment.filename,
                    exc,
                )