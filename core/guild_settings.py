import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


class GuildSettings:
    def __init__(self):
        self.path = Path(__file__).resolve().parent.parent / "data" / "guild_settings.json"
        self.data = self._load()

    def _load(self):
        try:
            if not self.path.exists():
                return {}
            with self.path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            logger.warning("Failed to load guild_settings.json: %s", exc)
            return {}

    def _save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
        except Exception as exc:
            logger.warning("Failed to save guild_settings.json: %s", exc)

    def _guild(self, guild_id: int) -> dict:
        """Return the settings dict for a guild, creating it if missing."""
        key = str(guild_id)
        if key not in self.data:
            self.data[key] = {}
        return self.data[key]

    # ── Adult channels ──────────────────────────────────────────────────────

    def get_adult_channels(self, guild_id: int) -> set[int]:
        channels = self._guild(guild_id).get("adult_channel_ids", [])
        return {int(x) for x in channels if str(x).isdigit()}

    def set_adult_channels(self, guild_id: int, channel_ids: list[int]):
        self._guild(guild_id)["adult_channel_ids"] = channel_ids
        self._save()

    def add_adult_channel(self, guild_id: int, channel_id: int):
        channels = self.get_adult_channels(guild_id)
        channels.add(channel_id)
        self.set_adult_channels(guild_id, sorted(channels))

    def remove_adult_channel(self, guild_id: int, channel_id: int):
        channels = self.get_adult_channels(guild_id)
        if channel_id in channels:
            channels.remove(channel_id)
            self.set_adult_channels(guild_id, sorted(channels))

    def clear_adult_channels(self, guild_id: int):
        self.set_adult_channels(guild_id, [])

    # ── Whitelist ───────────────────────────────────────────────────────────

    def get_whitelist(self, guild_id: int) -> set[str]:
        return set(self._guild(guild_id).get("whitelist", []))

    def add_whitelist(self, guild_id: int, domain: str):
        wl = self.get_whitelist(guild_id)
        wl.add(domain.lower())
        self._guild(guild_id)["whitelist"] = sorted(wl)
        self._save()

    def remove_whitelist(self, guild_id: int, domain: str):
        wl = self.get_whitelist(guild_id)
        wl.discard(domain.lower())
        self._guild(guild_id)["whitelist"] = sorted(wl)
        self._save()

    # ── Honeypot channel ──────────────────────────────────────────────────────

    def get_honeypot_channel(self, guild_id: int):
        """Channel id of the honeypot, 0 if explicitly off, or None if unset."""
        val = self._guild(guild_id).get("honeypot_channel_id")
        return int(val) if val is not None else None

    def set_honeypot_channel(self, guild_id: int, channel_id: int):
        self._guild(guild_id)["honeypot_channel_id"] = int(channel_id)
        self._save()

    # ── Log channel ───────────────────────────────────────────────────────────

    def get_log_channel(self, guild_id: int):
        """Channel id for moderation logs, 0 if explicitly off, or None if unset."""
        val = self._guild(guild_id).get("log_channel_id")
        return int(val) if val is not None else None

    def set_log_channel(self, guild_id: int, channel_id: int):
        self._guild(guild_id)["log_channel_id"] = int(channel_id)
        self._save()

    # ── Violations / history ────────────────────────────────────────────────

    def record_violation(self, guild_id: int, user_id: int, url: str = "", reason: str = ""):
        guild = self._guild(guild_id)
        violations = guild.setdefault("violations", {})
        user_records = violations.setdefault(str(user_id), [])
        user_records.append({
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "url": url,
            "reason": reason,
        })
        self._save()

    def get_violations(self, guild_id: int, user_id: int) -> list[dict]:
        return (
            self._guild(guild_id)
            .get("violations", {})
            .get(str(user_id), [])
        )

    def clear_violations(self, guild_id: int, user_id: int):
        violations = self._guild(guild_id).get("violations", {})
        if str(user_id) in violations:
            del violations[str(user_id)]
            self._save()

    # ── Threshold ───────────────────────────────────────────────────────────

    def get_threshold(self, guild_id: int) -> float:
        return float(self._guild(guild_id).get("threshold", 0.5))

    def set_threshold(self, guild_id: int, value: float):
        self._guild(guild_id)["threshold"] = value
        self._save()

    # ── Stats ───────────────────────────────────────────────────────────────

    def increment_stat(self, guild_id: int, key: str, amount: int = 1):
        stats = self._guild(guild_id).setdefault("stats", {})
        stats[key] = stats.get(key, 0) + amount
        self._save()

    def get_stats(self, guild_id: int) -> dict:
        guild = self._guild(guild_id)
        stats = guild.get("stats", {})
        return {
            "urls_scanned":   stats.get("urls_scanned", 0),
            "links_blocked":  stats.get("links_blocked", 0),
            "auto_bans":      stats.get("auto_bans", 0),
            "warnings":       stats.get("warnings", 0),
            "threshold":      guild.get("threshold", 0.5),
            "whitelist_count": len(guild.get("whitelist", [])),
        }