# Mari Discord Bot

Mari is a powerful Discord moderation bot that automatically detects and handles malicious, phishing, scam, adult, and gambling URLs using a combination of heuristics, external threat intelligence, AI-based classification, and image analysis.

## Features

- **URL Analysis**: Automated extraction and evaluation of URLs in messages.
- **Heuristic Scanning**: Fast, pattern-based detection for phishing and scam indicators.
- **External Scanners**: Integrates with Google Safe Browsing, VirusTotal, and URLScan for threat intelligence.
- **AI Classification**: Machine learning model for advanced URL threat detection.
- **Image Analysis**: OCR-based text extraction from images to detect scam content.
- **Content Scanning**: Deep analysis of web page content for malicious patterns.
- **Guild Management**: Per-server (guild) settings and configuration.
- **Whitelist/Blacklist**: Custom management of trusted and blocked URLs.
- **User Warnings**: Tracks and manages user violations.
- **Structured Logging**: Comprehensive logging for moderation and debugging.

## Project Structure

```
.
├── ai/                  # AI/ML components (feature extraction, model, training, utils)
├── bot/                 # Discord bot implementation (main class, commands, events)
├── core/                # Core logic (config, scanners, evaluators, utilities)
├── data/                # Persistent data (whitelist, blacklist, guild settings, warnings)
├── log/                 # Log files
├── run.py               # Bot entry point
├── requirements.txt      # Python dependencies
└── README.md
```

## Prerequisites

- Python 3.8+
- Discord bot token
- (Optional) API keys for:
  - Google Safe Browsing
  - VirusTotal
  - URLScan
- (Optional) Tesseract OCR for image analysis

## Installation

1. Clone or download this repository.
2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # macOS/Linux
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Create a `.env` file in the root directory:
   ```
   DISCORD_TOKEN=your_discord_bot_token
   GOOGLE_API_KEY=your_google_api_key
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   URLSCAN_API_KEY=your_urlscan_api_key
   ADMIN_ROLE_ID=your_admin_role_id
   GUILD_ID=your_guild_id
   ADULT_CHANNEL_IDS=channel_id_1,channel_id_2
   ```

## Usage

### Run the Bot

```bash
python run.py
```

The bot will start and listen for messages in your Discord server.

### Train the AI Model

```bash
python ai/train.py
```
This will create or update the model at `ai/model.pkl` using training data in `ai/data/urls.csv`.

### Run Tests

```bash
python -m pytest test/
```
Or run individual test files as needed.

## Image Analysis (OCR)

To enable image scam detection, install Tesseract OCR:

- **Windows**: Download from https://github.com/UB-Mannheim/tesseract/wiki and install. Update `.env` with the Tesseract path if needed.
- **macOS**: `brew install tesseract`
- **Linux**: `sudo apt-get install tesseract-ocr`

To disable OCR if Tesseract is not available, set in `.env`:
```
OCR_ENABLED=false
```

## Configuration

### Environment Variables

- `DISCORD_TOKEN` (required): Your Discord bot token
- `GOOGLE_API_KEY`, `VIRUSTOTAL_API_KEY`, `URLSCAN_API_KEY` (optional): API keys for external scanners
- `ADMIN_ROLE_ID`, `GUILD_ID`, `ADULT_CHANNEL_IDS` (optional): Admin and server settings
- `OCR_ENABLED` (optional, default: true): Enable/disable image OCR
- `AI_THRESHOLD`, `AI_SCAM_THRESHOLD` (optional): Model thresholds
- `AI_MODEL_PATH` (optional): Custom model path

### Data Files

- `data/blacklist.json`: Blocked URLs
- `data/whitelist.json`: Trusted URLs
- `data/guild_settings.json`: Per-guild settings
- `data/warnings.json`: User warnings

## Architecture

- **URL Evaluator**: Orchestrates the full URL evaluation pipeline.
- **Heuristic Scanner**: Fast, pattern-based detection.
- **External Scanners**: Integrates with Google Safe Browsing, VirusTotal, URLScan.
- **Content Scanner**: Analyzes web page content for threats.
- **Image Scanner**: OCR-based image text analysis.
- **AI Model**: Machine learning for threat classification.
- **Discord Bot**: Handles events, commands, and moderation.

## Logging

Logs are stored in the `log/` directory. Check logs for analysis results, errors, and moderation actions.

## Troubleshooting

- **Bot not responding**: Check `DISCORD_TOKEN`, permissions, and logs.
- **URLs not detected**: Ensure message content intent is enabled, check whitelist, review heuristics.
- **AI model issues**: Retrain with more data, adjust thresholds.
- **OCR not working**: Verify Tesseract installation, set `OCR_ENABLED=false` if needed.

## Guild Settings

Manage adult channels with slash commands (requires Manage Server permission):

- `/adultchannel add #channel`
- `/adultchannel remove #channel`
- `/adultchannel list`
- `/adultchannel clear`

Settings are stored in `data/guild_settings.json`.

## Whitelist / Blacklist

Add trusted domains to `data/whitelist.json` and blocked domains to `data/blacklist.json`.

Example:
```
[
  "facebook.com",
  "youtube.com"
]
```

## License

MIT

### Prerequisites

- Python 3.8+
- Discord bot token
- (Optional) API keys for external scanners:
  - Google Safe Browsing API key
  - VirusTotal API key
  - URLScan API key
- (Optional) Tesseract OCR for image scanning

### Installation

1. Clone or download the project

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   # On Windows
   venv\Scripts\activate
   # On macOS/Linux
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Create a `.env` file in the root directory:
   ```
   DISCORD_TOKEN=your_discord_bot_token
   GOOGLE_API_KEY=your_google_api_key
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   URLSCAN_API_KEY=your_urlscan_api_key
   ADMIN_ROLE_ID=your_admin_role_id
   GUILD_ID=your_guild_id
   ADULT_CHANNEL_IDS=channel_id_1,channel_id_2
   ```

## Usage

### Run the Bot

```bash
python run.py
```

The bot will start and begin listening for messages in your Discord server.

### Train AI Model

To train or retrain the AI model:

## Usage

### Run the Bot

```bash
python run.py
```

The bot will start and begin listening for messages in your Discord server.

### Train AI Model

To train or retrain the AI model:

```bash
python ai/train.py
```

This will create/update the model at `ai/model.pkl` using the training data in `ai/data/urls.csv`.

### Run Tests

```bash
python -m pytest test/
```

Or run individual test files:
```bash
python test/test_evaluator.py
python test/test_heuristic.py
python test/test_utils.py
```

## Image Analysis (OCR)

The bot can analyze images for scam/phishing text using Tesseract OCR. Optional feature.

### Windows Installation

1. Download Tesseract installer from: https://github.com/UB-Mannheim/tesseract/wiki

2. Install Tesseract (default or custom path)

3. Update `.env` with Tesseract path if needed (or it will use the default installation path)

### macOS Installation

```bash
brew install tesseract
```

### Linux Installation

```bash
sudo apt-get install tesseract-ocr
```

### Optional Configuration

Disable OCR if Tesseract is not installed:

```
OCR_ENABLED=false
```

## Configuration

### Environment Variables

- `DISCORD_TOKEN` (required): Your Discord bot token
- `GOOGLE_API_KEY` (optional): Google Safe Browsing API key
- `VIRUSTOTAL_API_KEY` (optional): VirusTotal API key
- `URLSCAN_API_KEY` (optional): URLScan API key
- `ADMIN_ROLE_ID` (optional): Discord role ID for admin commands
- `GUILD_ID` (optional): Discord server ID for bot
- `ADULT_CHANNEL_IDS` (optional): Comma-separated channel IDs where adult content is allowed
- `OCR_ENABLED` (optional, default: true): Enable/disable image OCR scanning
- `AI_THRESHOLD` (optional, default: 0.5): Confidence threshold for AI model to flag a URL as malicious
- `AI_SCAM_THRESHOLD` (optional, default: 0.3): Lower threshold for scam classification
- `AI_MODEL_PATH` (optional): Custom path to the trained model file

### Data Files

- `data/blacklist.json`: Manually blacklisted URLs
- `data/whitelist.json`: Whitelisted URLs (trusted domains)
- `data/guild_settings.json`: Per-guild configuration and preferences
- `data/warnings.json`: Track user warning history

## Architecture

### Core Components

**URL Evaluator** (`core/url_evaluator.py`)
- Orchestrates the complete URL evaluation pipeline
- Combines results from multiple scanners
- Returns a final verdict on URL safety

**Heuristic Scanner** (`core/heuristic_scanner.py`)
- Quick pattern-based detection
- Identifies common phishing/scam indicators in URLs and content
- Low false positive rate

**External Scanners** (`core/external_scanners.py`)
- Google Safe Browsing API integration
- VirusTotal API integration
- URLScan integration
- Provides community-based threat intelligence

**Content Scanner** (`core/content_scanner.py`)
- Analyzes page content for malicious patterns
- Detects phishing/scam signals in HTML/text
- Works in conjunction with external scanners

**Image Scanner** (`core/image_scanner.py`)
- Extracts text from images using OCR
- Analyzes extracted text for threats
- Supports various image formats

**AI Model** (`ai/predict.py`)
- Machine learning model for threat classification
- Trained on labeled URL datasets
- Provides probability scores for different threat categories

### Bot Components

**Discord Bot** (`bot/mari_bot.py`)
- Main bot client and lifecycle management
- Event loop orchestration

**Commands** (`bot/commands.py`)
- Implementation of Discord slash commands
- Admin and user-facing commands

**Events** (`bot/events.py`)
- Message event handlers
- Automatic URL scanning in messages
- User warning tracking

## Logging

Bot logs are stored in the `log/` directory. Check logs for:
- URL analysis results
- API errors and retries
- Bot lifecycle events
- Moderation actions taken

## Troubleshooting

### Bot doesn't respond
- Verify `DISCORD_TOKEN` is correct in `.env`
- Ensure bot has proper Discord permissions (read messages, send messages, manage messages)
- Check `log/` directory for error messages

### URLs not being detected
- Verify message content intent is enabled in Discord Developer Portal
- Check that the URL is not already in whitelist
- Review heuristics in `core/heuristic_scanner.py`

### AI model accuracy issues
- Retrain the model: `python ai/train.py`
- Ensure `ai/data/urls.csv` has sufficient training data
- Adjust thresholds in `.env` if needed

### Image OCR not working
- Verify Tesseract is installed and in PATH
- Try setting `OCR_ENABLED=false` if Tesseract unavailable
- Check Tesseract installation on your system

## Contributing

Feel free to submit issues and enhancement requests!
- `AI_MALICIOUS_LABEL` (default 0): which label is malicious in your dataset

## Whitelist / Blacklist

Add trusted domains to `data/whitelist.json` and blocked domains to `data/blacklist.json`.

Example:

```
[
  "facebook.com",
  "youtube.com"
]
```

## Notes

- `log/mari.log` stores all bot logs.
- The bot needs permissions to delete messages and ban users.

## Guild Settings (per server)

Slash commands (Manage Server permission required):

- `/adultchannel add #channel`
- `/adultchannel remove #channel`
- `/adultchannel list`
- `/adultchannel clear`

These settings are stored in `data/guild_settings.json`.

## License

MIT
