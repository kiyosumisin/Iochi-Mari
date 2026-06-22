# Mari — Discord Anti-Scam Bot

Mari is a Discord moderation bot that automatically detects and acts on malicious,
phishing, scam, adult and gambling content — using heuristics, an AI URL classifier,
external threat intelligence, web-page analysis and image OCR.

It is themed after **Iochi Mari** from *Blue Archive* (a gentle Sister of Trinity's
Sisterhood), so all of the bot's messages speak in her calm, caring voice.

---

## Features

- **URL scanning** — every link in a message is evaluated through several layers:
  heuristics, an AI (LightGBM) classifier, web-page content analysis, and external
  scanners (Google Safe Browsing, VirusTotal).
- **Image OCR** — extracts text from attached images (Tesseract) and flags scam content.
- **Honeypot channel** — a bait channel where real members are told not to post; any
  scam link/image there is banned instantly, while the bot leaves every other channel
  alone (near-zero false positives).
- **Auto-moderation** — deletes offending messages and bans/timeouts the author.
- **Gemini agent layer** *(optional)* — for borderline cases the classifier is unsure
  about, a Gemini agent investigates and writes a short explanation to the mod log
  instead of auto-banning; `/why` lets mods ask about a user afterwards.
- **Per-guild configuration via slash commands** — channels, whitelist and sensitivity
  are all set in Discord; no need to edit files per server.
- **Evidence log** — every successful catch is recorded to `log/scam_catches.csv` and
  viewable with `/scamlog`.
- **Permission-aware** — admin commands are hidden from normal members.

---

## How it works

For each link, `core/url_evaluator.py` runs (in order): cache check → short-URL
resolution → whitelist/blacklist → heuristic scan → AI classifier → (in parallel)
content scan + Google Safe Browsing + VirusTotal. The strongest verdict wins:
`malware`/`phishing` > `adult`/`gambling`/`scam` > `safe`.

Actions taken:

| Verdict | Action |
|---|---|
| malware / phishing / scam | delete message + ban |
| adult / gambling | delete + escalating timeout (warn 1–5, then ban) |
| scam image (OCR) | delete + ban |

When a **honeypot channel** is set, the bot moderates **only** that channel: a scam
link/image → instant ban; an accidental benign post → delete + warning, with a ban
after the warning limit is exceeded. Admins are never punished there.

**Borderline cases (optional Gemini agent).** When the AI probability falls in the
uncertain band (`AI_BORDERLINE_LOW`–`AI_BORDERLINE_HIGH`, default 0.4–0.7) and no hard
signal (blacklist / external scanner) fired, the bot does **not** auto-ban. Instead the
Gemini agent decides whether to gather more data (recent messages, WHOIS domain age),
writes a 2-3 sentence assessment, and flags the case to the mod log for a human to
decide. If Gemini is unavailable, times out, or is rate-limited, it falls back to the
original LightGBM action. This runs only in normal mode (not the honeypot) and only for
borderline cases — every other message uses the fast path unchanged.

All moderation notices go to the configured **log channel** (`/logchannel`), keeping
public channels clean.

---

## Project structure

```
.
├── bot/                 # Discord layer: bot class, slash commands, message handler
│   ├── mari_bot.py
│   ├── commands.py
│   └── events.py
├── core/                # Scanning engine: config, evaluator, scanners, guild settings
├── ai/                  # ML pipeline: feature extractor, train, predict, model.pkl
├── data/                # whitelist / blacklist / guild_settings / warnings (JSON)
├── log/                 # Log files + scam_catches.csv
├── run.py               # Bot entry point
├── app.py               # Optional FastAPI service (URL prediction + feedback/retrain)
├── requirements.txt
└── README.md
```

---

## Prerequisites

- **Python 3.10+** (developed on 3.12)
- **Tesseract-OCR** installed on the host (for image scanning):
  - Windows: <https://github.com/UB-Mannheim/tesseract/wiki> (auto-detected at the
    default path, or set `TESSERACT_CMD`)
  - macOS: `brew install tesseract`
  - Linux: `sudo apt-get install tesseract-ocr`
  - For Vietnamese OCR also install the `vie` language data and set `OCR_LANG=vie+eng`.
- A **Discord bot application** (token + privileged intents — see below)
- *(Optional)* a **Gemini API key** to enable the borderline-case agent layer
  (`google-genai` and `python-whois` ship in `requirements.txt`)

---

## Installation

```bash
# 1. (recommended) virtual environment
python -m venv venv
venv\Scripts\activate            # Windows
source venv/bin/activate          # macOS/Linux

# 2. dependencies
pip install -r requirements.txt

# 3. create .env (see Configuration), then run
python run.py
```

---

## Discord setup

1. **Privileged Gateway Intents** — in the Developer Portal → *Bot*, enable
   **Message Content Intent** and **Server Members Intent** (the bot will not start
   without them).
2. **Invite** the bot with both scopes `bot` and `applications.commands`. Grant only
   the permissions it needs (do **not** grant Administrator to the bot):
   View Channels, Send Messages, Embed Links, Attach Files, Read Message History,
   Manage Messages, Ban Members, Moderate Members.
3. **Role position** — drag the bot's role above the members it should be able to
   ban/timeout.

---

## Configuration

Only `DISCORD_TOKEN` is required. Everything else has safe defaults, and channels are
best configured with the slash commands below (stored per server).

### `.env`

```
DISCORD_TOKEN=your_discord_bot_token
GOOGLE_API_KEY=your_key        # optional — enables Google Safe Browsing
VIRUSTOTAL_API_KEY=your_key    # optional — enables VirusTotal
GEMINI_API_KEY=your_key        # optional — enables the borderline-case agent + /why
```

### Optional tuning (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `GUILD_ID` | `0` | `0` = global slash-command sync (all servers, ~1h to appear). Set a server ID for instant single-guild sync (dev). |
| `OCR_ENABLED` | `true` | Turn image OCR on/off |
| `OCR_LANG` | `eng` | Tesseract language(s), e.g. `vie+eng` |
| `TESSERACT_CMD` | auto | Path to the `tesseract` binary |
| `AI_THRESHOLD` | model | Decision threshold for the AI classifier |
| `AI_SCAM_THRESHOLD` | `0.3` | Lower bound to tag a borderline URL as `scam` |
| `AI_OVERRIDE_THRESHOLD` | `0.9` | AI may override an adult/gambling verdict above this probability |
| `AI_ENABLE_SHAP` | `false` | Build SHAP explanations (heavy; only needed for `app.py`) |
| `AI_MODEL_PATH` | `ai/model.pkl` | Custom model path |
| `TIMEOUT_DURATIONS` | `10m,1h,6h,1d,3d` | Escalating timeout ladder for adult/gambling |
| `HONEYPOT_WARN_LIMIT` | `3` | Honeypot warnings before a ban |
| `AGENT_ENABLED` | `true` | Master switch for the Gemini agent (also needs `GEMINI_API_KEY`) |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Gemini model name |
| `AI_BORDERLINE_LOW` / `AI_BORDERLINE_HIGH` | `0.4` / `0.7` | Probability band treated as borderline |
| `GEMINI_RPM` / `GEMINI_RPD` | `15` / `1500` | Gemini rate limits (free tier) |
| `GEMINI_TIMEOUT` | `8` | Per-call timeout (seconds) before fallback |

`LOG_CHANNEL_ID`, `HONEYPOT_CHANNEL_ID` and `ADULT_CHANNEL_IDS` also exist as env
fallbacks, but prefer the per-server slash commands — they work correctly across
multiple servers.

### Data files

- `data/whitelist.json` — trusted domains (skipped)
- `data/blacklist.json` — always-blocked domains
- `data/guild_settings.json` — per-guild config, violations, stats
- `data/warnings.json` — warning counters

---

## Commands

### Everyone

| Command | Description |
|---|---|
| `/check <url>` | Inspect a link (result is private to you) |
| `/help` | List available commands |
| `!ping` | Check the bot is alive |

### Admin only (require **Administrator**; hidden from other members)

| Command | Description |
|---|---|
| `/purge <amount> [filter] [user] [text]` | Delete up to 1000 messages, optionally filtered (`any`, `user`, `match`, `not`, `startswith`, `endswith`, `links`, `invites`, `images`, `embeds`, `mentions`, `bots`, `humans`) |
| `/ban <user> [reason]` / `/unban <user_id>` | Remove / restore a member |
| `/history <user>` | Review a member's recorded violations |
| `/threshold <0.0-1.0>` | Adjust detection sensitivity (per server) |
| `/stats` | Server protection summary |
| `/scamlog` | Show successful scam catches + attach the evidence CSV |
| `/honeypot set #channel \| off \| status` | Manage the bait channel |
| `/logchannel set #channel \| off \| status` | Choose where moderation logs are sent |
| `/adultchannel add \| remove \| list \| clear` | Channels where adult content is allowed |
| `/whitelist add \| remove \| list` | Trusted domains that skip scanning |
| `/why <user>` | Ask the Gemini agent why a user was flagged/actioned (from the case log) |

Admin commands are hidden from the slash menu via Discord `default_permissions`
(Administrator) and re-checked at runtime. Server owners can still delegate individual
commands to specific roles in **Server Settings → Integrations**.

---

## AI model

The trained model ships at `ai/model.pkl`. To retrain from `ai/data/urls.csv`:

```bash
python -m ai.train            # URL features only (fast)
python -m ai.train --with-page   # also fetch live page features (slower)
```

The bot itself only uses the probability/verdict, so SHAP explainability is **off by
default**. Enable it (e.g. for `app.py`) with `AI_ENABLE_SHAP=true`.

---

## Gemini agent layer (borderline cases)

`ai/agent.py` adds an optional Gemini-powered layer used **only** for borderline URL
cases (probability inside the borderline band, no hard signal). It:

- **investigates** — decides as structured JSON whether to fetch recent messages or a
  WHOIS domain-age lookup;
- **explains** — writes a short English assessment to the mod log (no auto-ban); and
- answers **`/why <user>`** — a moderator can ask why a user was flagged, and the agent
  replies in the channel from the recorded case log.

Every call is logged to `log/agent_calls.jsonl` (git-ignored). The layer is
rate-limited and fails safe: any error / timeout / rate-limit falls back to the original
LightGBM decision. It stays disabled unless `GEMINI_API_KEY` is set and
`google-genai` is installed. System instructions (fixed rules) are kept separate
from the per-case prompt.

---

## Optional API service (`app.py`)

A standalone FastAPI service exposing `POST /predict`, `POST /feedback`,
`POST /feedback/retrain` and `GET /health`:

```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --workers 1
```

Set `AI_ENABLE_SHAP=true` if you want SHAP explanations in the `/predict` response.

---

## Hosting

The bot needs to run continuously. Run it on a small always-on host (a cheap VPS, a
free student cloud credit, or a spare machine) with a process manager
(systemd / Docker `--restart unless-stopped`). Remember to install Tesseract on the
host and set environment variables there. `.env` is git-ignored and must be recreated
on the server.

---

## Troubleshooting

- **Bot offline** — check the token in `.env`, that both privileged intents are
  enabled, and `log/mari.log` for a startup traceback.
- **Slash commands missing** — the bot must be invited with the `applications.commands`
  scope; with `GUILD_ID=0` (global) they take up to ~1h to appear.
- **Can't ban a member** — the bot's role must sit above that member's highest role,
  and it needs the Ban Members permission.
- **OCR reads nothing** — verify Tesseract is installed (and the `vie` data for
  Vietnamese), or set `OCR_ENABLED=false`.
- **Notices appear in the public channel** — set a log channel with `/logchannel set`.
- **Borderline cases not flagged** — set `GEMINI_API_KEY`, install `google-genai`,
  and look for "MariAgent enabled" in `log/mari.log`.

---

## License

MIT
