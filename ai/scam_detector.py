"""
scam_detector.py
----------------
Tổng hợp: URL ML model + Social context + OCR image analysis → verdict + auto-action.

Tích hợp vào bot:
    from ai.scam_detector import scan_message, execute_scam_action

    @bot.event
    async def on_message(message):
        result = await scan_message(message)
        if result.is_suspicious:
            await execute_scam_action(message, result, log_channel_id=LOG_CHANNEL_ID)
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from ai.social_context import analyze_social_context, SocialRisk
from ai.image_analyzer  import analyze_image_url, ImageRisk

logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.I)

COMBINED_HIGH_THRESHOLD   = 5.0
COMBINED_MEDIUM_THRESHOLD = 2.5

# Chỉ auto-ban khi HIGH và có ảnh scam
AUTO_BAN_THRESHOLD = COMBINED_HIGH_THRESHOLD


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class URLScanResult:
    url: str
    probability: float
    is_malicious: bool


@dataclass
class ScanResult:
    message_text: str
    urls_found:       list[str]          = field(default_factory=list)
    images_analyzed:  int                = 0
    url_results:      list[URLScanResult]= field(default_factory=list)
    social_risk:      Optional[SocialRisk] = None
    image_risks:      list[ImageRisk]    = field(default_factory=list)
    combined_score:   float              = 0.0
    risk_level:       str                = "LOW"
    has_scam_image:   bool               = False   # True nếu ít nhất 1 ảnh bị flag

    @property
    def is_suspicious(self) -> bool:
        return self.risk_level in ("HIGH", "MEDIUM")

    def discord_alert(self, username: str = "") -> str:
        """Compact English alert posted to the channel where scam was detected."""
        who   = f" from **{username}**" if username else ""
        lines = [f"**Scam detected**{who} — Risk: `{self.risk_level}` | Score: {self.combined_score:.0f}"]

        # Malicious URLs
        bad_urls = [r for r in self.url_results if r.is_malicious]
        if bad_urls:
            lines.append("Malicious URL: " + ", ".join(f"`{r.url}`" for r in bad_urls[:3]))

        # Top text patterns (deduped)
        if self.social_risk and self.social_risk.pattern_hits:
            patterns = list(dict.fromkeys(
                h.pattern_desc for h in self.social_risk.pattern_hits
            ))[:2]
            lines.append("Text: " + " | ".join(patterns))

        # Top image patterns (deduped across all images)
        if self.has_scam_image:
            img_hits = list(dict.fromkeys(
                h.pattern_desc
                for r in self.image_risks
                for h in r.hits
                if r.is_suspicious
            ))[:3]
            if img_hits:
                lines.append("Image: " + " | ".join(img_hits))

        lines.append("Message removed. User banned.")
        return "\n".join(lines)

    def discord_log(self, username: str, user_id: int, guild_name: str, channel_name: str) -> str:
        """Format log chi tiết gửi vào log channel."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines = [
            "```",
            f"[SCAM LOG] {ts}",
            f"Server  : {guild_name}",
            f"Channel : #{channel_name}",
            f"User    : {username} (ID: {user_id})",
            f"Risk    : {self.risk_level}  Score: {self.combined_score:.1f}",
            f"Images  : {self.images_analyzed}  Scam image: {self.has_scam_image}",
        ]
        if self.urls_found:
            lines.append(f"URLs    : {', '.join(self.urls_found[:3])}")
        if self.message_text.strip():
            preview = self.message_text[:150].replace('\n', ' ')
            lines.append(f"Message : {preview}")
        if self.social_risk and self.social_risk.pattern_hits:
            descs = [h.pattern_desc for h in self.social_risk.pattern_hits[:3]]
            lines.append(f"Patterns: {' | '.join(descs)}")
        if self.has_scam_image:
            img_hits = list(dict.fromkeys(
                h.pattern_desc for r in self.image_risks for h in r.hits if r.is_suspicious
            ))[:4]
            lines.append(f"ImgHits : {' | '.join(img_hits)}")
        lines.append("```")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# URL scan
# ---------------------------------------------------------------------------
def _scan_urls(urls: list[str]) -> list[URLScanResult]:
    results = []
    try:
        from ai.predict import predict_url
    except ImportError:
        return results
    for url in urls[:5]:
        try:
            r = predict_url(url, top_n=0)
            results.append(URLScanResult(url=url, probability=r.probability, is_malicious=r.is_malicious))
        except Exception as exc:
            logger.warning("URL scan failed for %s: %s", url, exc)
    return results


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------
async def scan_message(message, scan_images: bool = True) -> ScanResult:
    """Phân tích Discord message: URL + text + ảnh đính kèm."""
    text = message.content or ""
    urls = list(dict.fromkeys(URL_PATTERN.findall(text)))

    # URL ML scan
    loop = asyncio.get_event_loop()
    url_results = await loop.run_in_executor(None, _scan_urls, urls)

    # OCR ảnh
    image_risks: list[ImageRisk] = []
    image_texts: list[str] = []

    if scan_images and message.attachments:
        tasks = []
        for att in message.attachments[:4]:
            ct = getattr(att, "content_type", "") or ""
            if ct.startswith("image/") or att.filename.lower().endswith(
                (".png", ".jpg", ".jpeg", ".webp", ".gif")
            ):
                tasks.append(analyze_image_url(att.url))
        if tasks:
            image_risks = await asyncio.gather(*tasks, return_exceptions=False)
            image_texts = [r.extracted_text for r in image_risks if r.extracted_text]

    # Social context
    social_risk = analyze_social_context(text=text, image_texts=image_texts)

    # Combined score
    url_score    = sum(r.probability for r in url_results if r.is_malicious) * 3.0
    social_score = social_risk.total_score
    image_score  = sum(r.total_score for r in image_risks)
    combined     = url_score + social_score + image_score

    if combined >= COMBINED_HIGH_THRESHOLD:
        level = "HIGH"
    elif combined >= COMBINED_MEDIUM_THRESHOLD:
        level = "MEDIUM"
    else:
        level = "LOW"

    has_scam_image = any(r.is_suspicious for r in image_risks)

    logger.info(
        "Scan result: level=%s score=%.1f url=%.1f social=%.1f image=%.1f scam_img=%s",
        level, combined, url_score, social_score, image_score, has_scam_image,
    )

    return ScanResult(
        message_text=text[:300],
        urls_found=urls,
        images_analyzed=len(image_risks),
        url_results=url_results,
        social_risk=social_risk,
        image_risks=image_risks,
        combined_score=round(combined, 1),
        risk_level=level,
        has_scam_image=has_scam_image,
    )


# ---------------------------------------------------------------------------
# Action: xóa message + ban user + log
# ---------------------------------------------------------------------------
async def execute_scam_action(
    message,
    result: ScanResult,
    log_channel_id: Optional[int] = None,
    ban_reason: str = "Scam/Phishing content detected by Mari Meow",
    only_ban_on_image: bool = True,
) -> None:
    """
    Thực thi action khi phát hiện scam:
      1. Xóa message gốc
      2. Ban user (nếu đủ điều kiện)
      3. Gửi cảnh báo ngắn vào channel hiện tại
      4. Log chi tiết vào log channel riêng

    Args:
        message         : discord.Message
        result          : ScanResult từ scan_message()
        log_channel_id  : ID của channel dùng để log (None = không log)
        ban_reason      : Lý do ban hiển thị trong Discord audit log
        only_ban_on_image: Chỉ ban khi có ảnh scam (True = an toàn hơn)
    """
    guild   = message.guild
    author  = message.author
    channel = message.channel

    # Bảo vệ: không ban admin / bot khác
    if author.bot:
        return
    if guild and author.guild_permissions.administrator:
        logger.warning("Scam detected from admin %s — skipping ban.", author)
        return

    username     = str(author)
    user_id      = author.id
    guild_name   = guild.name if guild else "DM"
    channel_name = channel.name if hasattr(channel, "name") else "unknown"

    # 1. Xóa message
    try:
        await message.delete()
        logger.info("Deleted scam message from %s in #%s", username, channel_name)
    except Exception as exc:
        logger.warning("Could not delete message: %s", exc)

    # 2. Ban user
    should_ban = result.risk_level == "HIGH" and (
        not only_ban_on_image or result.has_scam_image
    )

    banned = False
    if should_ban and guild:
        try:
            await guild.ban(
                author,
                reason=f"{ban_reason} | score={result.combined_score:.0f}",
                delete_message_days=1,   # xóa thêm message 1 ngày trước
            )
            banned = True
            logger.info("Banned user %s (ID: %s) for scam content.", username, user_id)
        except Exception as exc:
            logger.error("Could not ban %s: %s", username, exc)

    # 3. Gửi cảnh báo ngắn vào channel
    try:
        alert = result.discord_alert(username=username)
        if not banned:
            # Chưa ban thì bỏ dòng cuối
            alert = alert.replace("\n*Message đã bị xóa. User đã bị ban.*", "")
        await channel.send(alert)
    except Exception as exc:
        logger.warning("Could not send alert: %s", exc)

    # 4. Log chi tiết vào log channel
    if log_channel_id and guild:
        try:
            log_channel = guild.get_channel(log_channel_id)
            if log_channel:
                log_msg = result.discord_log(username, user_id, guild_name, channel_name)
                if banned:
                    log_msg += f"\n✅ **User đã bị ban** | Reason: {ban_reason}"
                else:
                    log_msg += "\n⚠️ **Không ban** (không đủ điều kiện hoặc thiếu quyền)"
                await log_channel.send(log_msg)
        except Exception as exc:
            logger.warning("Could not send to log channel: %s", exc)