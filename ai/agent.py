"""
agent.py
--------
Gemini-powered analysis layer for borderline moderation cases.

It is only invoked when the LightGBM classifier is uncertain (probability inside
the configured borderline band) and no hard signal (blacklist / external scanner)
fired. It never runs on every message — the LightGBM threshold check stays the
fast path.

Capabilities
------------
explain_case(case)      -> str   : a short English explanation for the mod log
investigate_case(case)  -> dict  : decide (as JSON) what extra data to gather
answer_why(record)      -> str   : answer a moderator's /why question from logs

Fails safe: on any error / timeout / rate-limit, every method returns None and
the caller falls back to the original LightGBM decision.

Conventions: all output is English, no emoji (matches the rest of the bot).
"""

from __future__ import annotations

import os
import json
import time
import asyncio
import logging
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

try:
    from google import genai
    from google.genai import types
except Exception:  # pragma: no cover - library optional
    genai = None
    types = None

logger = logging.getLogger(__name__)

_AGENT_LOG = Path(__file__).resolve().parent.parent / "log" / "agent_calls.jsonl"


# ---------------------------------------------------------------------------
# System instructions — fixed rules, kept separate from the per-case prompt.
# ---------------------------------------------------------------------------
EXPLAIN_SYSTEM = (
    "You are the analysis assistant for Mari, a Discord anti-scam moderation bot. "
    "You are given a borderline message the bot was unsure about. Write a concise "
    "assessment of 2-3 sentences for the moderator log: what looks suspicious or "
    "benign and why the case is borderline. English only. No emoji. State the "
    "assessment plainly; do not address anyone and do not invent facts."
)

INVESTIGATE_SYSTEM = (
    "You are the triage assistant for Mari, a Discord anti-scam moderation bot. "
    "Given a borderline case, decide whether gathering more data would help the "
    "decision. Respond ONLY with a JSON object using exactly these keys: "
    '"need_more_data" (boolean), "fetch_recent_messages" (boolean), '
    '"check_domain_age" (boolean), "suspicion" (one of "low","medium","high"), '
    '"reason" (a short English string). Be conservative: only request data that is '
    "clearly useful. No emoji."
)

WHY_SYSTEM = (
    "You are the analysis assistant for Mari, a Discord anti-scam moderation bot. "
    "A moderator is asking why the bot treated a user the way it did. Using only the "
    "recorded case data provided, answer in 2-4 sentences. English only. No emoji. Be "
    "factual and neutral. If the data is insufficient, say so plainly."
)


def domain_age_days(domain: str):
    """Rough domain age in days via WHOIS, or None. Blocking — run in an executor."""
    try:
        import whois  # python-whois, optional
        info = whois.whois(domain)
        created = info.creation_date
        if isinstance(created, list):
            created = created[0] if created else None
        if created is None:
            return None
        if getattr(created, "tzinfo", None) is None:
            created = created.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - created).days
    except Exception as exc:
        logger.debug("WHOIS lookup failed for %s: %s", domain, exc)
        return None


class MariAgent:
    def __init__(self, config):
        self.config = config
        self.model_name = getattr(config, "GEMINI_MODEL", "gemini-2.5-flash")
        self.api_key = getattr(config, "GEMINI_API_KEY", None)
        agent_on = getattr(config, "AGENT_ENABLED", True)

        self.enabled = bool(self.api_key) and genai is not None and agent_on
        self._client = None

        # Rate limiting (free tier ~15 RPM / 1500 RPD) + timeout.
        self._lock = asyncio.Lock()
        self._minute: deque[float] = deque()
        self._day: deque[float] = deque()
        self._rpm = int(os.getenv("GEMINI_RPM", "15"))
        self._rpd = int(os.getenv("GEMINI_RPD", "1500"))
        self._timeout = float(os.getenv("GEMINI_TIMEOUT", "8"))

        if self.enabled:
            try:
                self._client = genai.Client(api_key=self.api_key)
                logger.info("MariAgent enabled (model=%s)", self.model_name)
            except Exception as exc:
                logger.warning("MariAgent init failed, disabling: %s", exc)
                self.enabled = False
        else:
            logger.info("MariAgent disabled (no GEMINI_API_KEY / library / AGENT_ENABLED).")

    # -- rate-limit gate: reserve one slot or refuse -------------------------
    async def _reserve_slot(self) -> bool:
        async with self._lock:
            now = time.time()
            while self._minute and now - self._minute[0] > 60:
                self._minute.popleft()
            while self._day and now - self._day[0] > 86400:
                self._day.popleft()
            if len(self._minute) >= self._rpm or len(self._day) >= self._rpd:
                return False
            self._minute.append(now)
            self._day.append(now)
            return True

    # -- core call: system instruction + prompt -> text, with retry/timeout --
    async def _generate(self, system_instruction: str, prompt: str, *, json_out: bool = False):
        if not self.enabled:
            return None
        if not await self._reserve_slot():
            logger.warning("Gemini rate limit reached — skipping call (fallback).")
            return None

        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=0.2,
            response_mime_type="application/json" if json_out else None,
        )
        delay = 1.0
        for attempt in range(3):
            try:
                resp = await asyncio.wait_for(
                    self._client.aio.models.generate_content(
                        model=self.model_name,
                        contents=prompt,
                        config=config,
                    ),
                    timeout=self._timeout,
                )
                text = (resp.text or "").strip()
                if text:
                    return text
                logger.warning("Gemini returned empty text (attempt %d).", attempt + 1)
            except asyncio.TimeoutError:
                logger.warning("Gemini timeout (attempt %d).", attempt + 1)
            except Exception as exc:
                logger.warning("Gemini error (attempt %d): %s", attempt + 1, exc)
            await asyncio.sleep(delay)
            delay *= 2
        return None

    # -- public: explain a borderline case -----------------------------------
    async def explain_case(self, case: dict):
        prompt = self._case_prompt(case, "Explain why this case is borderline.")
        out = await self._generate(EXPLAIN_SYSTEM, prompt)
        self._log_call("explain", case, out)
        return out

    # -- public: decide what extra data to gather (structured JSON) ----------
    async def investigate_case(self, case: dict):
        prompt = self._case_prompt(case, "Decide what extra data, if any, to gather.")
        out = await self._generate(INVESTIGATE_SYSTEM, prompt, json_out=True)
        self._log_call("investigate", case, out)
        if not out:
            return None
        try:
            data = json.loads(out)
            return data if isinstance(data, dict) else None
        except Exception as exc:
            logger.warning("Gemini investigate JSON parse failed: %s", exc)
            return None

    # -- public: answer a moderator's /why question --------------------------
    async def answer_why(self, record: dict):
        prompt = (
            "A moderator asks: why was this user flagged or actioned?\n\n"
            "Recorded case data (JSON):\n"
            + json.dumps(record, ensure_ascii=False, indent=2, default=str)
        )
        out = await self._generate(WHY_SYSTEM, prompt)
        self._log_call("answer_why", record, out)
        return out

    @staticmethod
    def _case_prompt(case: dict, task: str) -> str:
        return (
            f"Task: {task}\n\n"
            "Case data (JSON):\n"
            + json.dumps(case, ensure_ascii=False, indent=2, default=str)
        )

    # -- append every call (input + output) for later /why -------------------
    def _log_call(self, kind: str, payload, output):
        try:
            _AGENT_LOG.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "kind": kind,
                "guild_id": (payload or {}).get("guild_id"),
                "user_id": (payload or {}).get("user_id"),
                "input": payload,
                "output": output,
            }
            with _AGENT_LOG.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except Exception as exc:
            logger.warning("Could not write agent call log: %s", exc)

    # -- read the latest recorded case for a user (for /why) -----------------
    def latest_case_for(self, guild_id, user_id):
        if not _AGENT_LOG.exists():
            return None
        latest = None
        try:
            with _AGENT_LOG.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    if str(rec.get("user_id")) != str(user_id):
                        continue
                    if guild_id is not None and rec.get("guild_id") is not None:
                        if str(rec.get("guild_id")) != str(guild_id):
                            continue
                    latest = rec
        except Exception as exc:
            logger.warning("Could not read agent call log: %s", exc)
        return latest
