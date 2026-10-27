# Mari — Discord Anti-Scam Bot

Mari is a Discord moderation bot that automatically detects and acts on malicious,
phishing, scam and gambling content — using heuristics, an AI URL classifier,
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
  scam link/image there is banned instantly.
- **Never a ban on a guess** — in every other channel a suspicious post is hidden and
  Sensei is asked, right there, to **Ban** or **Bỏ qua**.
- **Gemini agent layer** *(optional)* — a short note on links only the classifier
  flagged, a second look at scam-like images, and `/why` for mods afterwards.
- **Per-guild configuration via slash commands** — channels, whitelist and sensitivity
  are all set in Discord; no need to edit files per server.
- **Moderator feedback** — every ban notice carries *Correct* / *Wrong - unban* buttons,
  and every question to Sensei *Ban* / *Bỏ qua*. One click fixes the mistake, and the
  answer is kept for retraining (links) or remembered as an image fingerprint.
- **Known scam images** — once an image is confirmed as a scam (by a moderator, or
  by Gemini with high confidence in the honeypot), re-posts of it are caught in
  **every** channel, even resized or recompressed. Images a moderator marked as
  safe are never punished again.
- **Evidence log** — every successful catch is recorded to `log/scam_catches.csv` and
  viewable with `/scamlog`.
- **Permission-aware** — admin commands are hidden from normal members.

---

## How it works

For each link, `core/url_evaluator.py` runs (in order): cache check → short-URL
resolution → whitelist/blacklist → heuristic scan → AI classifier → (in parallel)
content scan + Google Safe Browsing + VirusTotal. The strongest verdict wins:
`malware`/`phishing` > `gambling`/`scam` > `safe`.

Actions taken (the same rule in every server):

| Where | Action |
|---|---|
| honeypot channel (if set) | scam link/image → instant ban; an accidental post → delete + warning, ban after the warning limit |
| a known scam (scam lists, blacklist, fingerprinted image) anywhere | delete + warning, Sensei asked; ban in the honeypot or for a burst across 3+ channels |
| any other channel | never a ban on a guess: a strong suspicion (Safe Browsing/VirusTotal, or the model at `AI_OVERRIDE_THRESHOLD`+) is hidden and Sensei is asked in that channel with **Ban / Bỏ qua**; a weak one only goes to the log channel |

Images outside the honeypot need two scam phrases in the OCR text **and** Gemini
agreeing before they are hidden. For a link only the model flagged, Gemini adds a
short note to Sensei's question (also what `/why` answers from). Admins are never
punished.

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
- *(Optional)* a **Gemini API key** to enable the agent layer
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
GEMINI_API_KEY=your_key        # optional — enables the Gemini agent + /why
```

### Optional tuning (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `GUILD_ID` | `0` | `0` = global slash-command sync (all servers, ~1h to appear). Set a server ID for instant single-guild sync (dev). |
| `OCR_ENABLED` | `true` | Turn image OCR on/off |
| `OCR_LANG` | `eng` | Tesseract language(s), e.g. `vie+eng` |
| `TESSERACT_CMD` | auto | Path to the `tesseract` binary |
| `AI_THRESHOLD` | model | Decision threshold for the AI classifier |
| `AI_OVERRIDE_THRESHOLD` | `0.9` | At or above this, an AI-only verdict hides the post and asks Sensei (below it, only a log note) |
| `AI_ENABLE_SHAP` | `false` | Build SHAP explanations (heavy; the bot does not use them) |
| `AI_MODEL_PATH` | `ai/model.pkl` | Custom model path |
| `HONEYPOT_WARN_LIMIT` | `3` | Honeypot warnings before a ban |
| `AGENT_ENABLED` | `true` | Master switch for the Gemini agent (also needs `GEMINI_API_KEY`) |
| `GEMINI_MODEL` | `gemini-3.5-flash-lite` | Gemini model name (flash-lite: far higher free quota than flash) |
| `GEMINI_FALLBACK_MODEL` | `gemini-3.1-flash-lite` | Tried when the main model is overloaded, out of quota or slower than `GEMINI_TIMEOUT` (empty = off) |
| `GEMINI_BASE_URL` / `GEMINI_RELAY_TOKEN` | — | Route Gemini calls through the `relay/` Vercel function (needed on hosts Google geo-blocks, e.g. Hong Kong) |
| `GEMINI_RPM` / `GEMINI_RPD` | `15` / `500` | Gemini rate limits (free tier of gemini-3.5-flash-lite; check ai.dev/rate-limit) |
| `GEMINI_TIMEOUT` | `15` | Seconds to wait for a model before trying the fallback model |

`LOG_CHANNEL_ID` and `HONEYPOT_CHANNEL_ID` also exist as env
fallbacks, but prefer the per-server slash commands — they work correctly across
multiple servers.

### Data files

- `data/whitelist.json` — trusted domains (skipped)
- `data/blacklist.json` — always-blocked domains
- `data/guild_settings.json` — per-guild config, violations, stats
- `data/warnings.json` — warning counters
- `data/feedback_cases.json` — open/answered review cases behind the notice buttons
- `data/image_hashes.json` — fingerprints of confirmed scam / confirmed safe images
- `ai/feedback.csv` — links labelled by moderators, for retraining

---

## Commands

### Everyone

| Command | Description |
|---|---|
| `/check <url>` | Inspect a link (result is private to you) |
| `/help` | List available commands |
| `Mari ơi` / `Mari à` / `Mari,` / `Mari` (at the start of a message) | Mari answers, so you know she is there; the owner can chat with her this way |

### Admin only (require **Administrator**; hidden from other members)

| Command | Description |
|---|---|
| `/purge <count> [user] [bots] [contains]` | Delete recent messages (up to 1000), optionally only a member's, only bots', and/or those containing some text |
| `/ban <user> [reason]` / `/unban <user_id>` | Remove / restore a member |
| `/history <user>` | Review a member's recorded violations |
| `/threshold <0.0-1.0>` | Adjust detection sensitivity (per server) |
| `/stats` | Server protection summary |
| `/scamlog` | Show successful scam catches + attach the evidence CSV |
| `/honeypot set #channel \| off \| status` | Manage the bait channel |
| `/logchannel set #channel \| off \| status` | Choose where moderation logs are sent |
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

To learn from your moderators' answers, copy the bot's feedback file and retrain
with it (a moderator's label overrides the dataset's label for the same URL):

```bash
scp mari:~/Iochi-Mari/ai/feedback.csv ai/
python -m ai.train --augment --feedback
```

The bot itself only uses the probability/verdict, so SHAP explainability is **off by
default**. Enable it with `AI_ENABLE_SHAP=true`.

---

## Gemini agent layer

`ai/agent.py` is an optional Gemini layer: notes on links only the model flagged,
`/why <user>`, scam-image checks, flag translations and Sensei's chat (see the module
docstring). Every case call is logged to `log/agent_calls.jsonl` (git-ignored). It is
rate-limited and fails safe: on any error, timeout or rate limit Mari carries on
without it. It stays disabled unless `GEMINI_API_KEY` is set.

---

## Hosting

The bot needs to run continuously. Run it on a small always-on host (a cheap VPS, a
free student cloud credit, or a spare machine) with a process manager
(systemd / Docker `--restart unless-stopped`). Remember to install Tesseract on the
host and set environment variables there. `.env` is git-ignored and must be recreated
on the server.

### Backups & monitoring

`deploy/backup.sh` (cron, daily) encrypts `data/`, `.env`, the catch log and
`ai/feedback.csv` with the passphrase in `~/.mari-backup-pass`, keeps 7 days in
`~/backups`, and force-pushes them to a private repo when `.env` has
`BACKUP_REPO=git@github.com:<you>/<repo>.git` (deploy key with write access at
`~/.ssh/mari_backup`). Keep a copy of the passphrase off the server. Restore with
`gpg --decrypt mari-YYYY-MM-DD.tar.gz.gpg | tar xzf -`.

```cron
15 3 * * * /home/azureuser/Iochi-Mari/deploy/backup.sh >> /home/azureuser/backups/backup.log 2>&1 # mari-backup
```

With `HEALTHCHECK_URL` (and `BACKUP_HEALTHCHECK_URL`) set to
[healthchecks.io](https://healthchecks.io) ping URLs, Mari pings every 5 minutes while
connected to Discord and the backup pings after each success; you get an email when
either stops.

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
- **No Gemini notes** — set `GEMINI_API_KEY`, install `google-genai`,
  and look for "MariAgent enabled" in `log/mari.log`.

---

## License

MIT
