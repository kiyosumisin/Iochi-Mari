# Mari — Privacy Policy

*Last updated: 8 October 2026*

Mari is a Discord bot that protects servers from scams: it checks links and
images posted in messages and removes scams. This page explains what data Mari
reads, what it keeps, who it shares it with, and how to have it removed.

## What Mari reads

- **Message text and attachments** in channels Mari can see, in order to find
  scam links and scam images. Ordinary messages are checked in memory and are
  **not stored**.
- **Reactions with a country flag**, to translate the message they were added to.
- **Slash commands** you use with Mari.

## What Mari stores

Only when Mari takes action, or a server administrator configures it:

| Data | When | Why |
|---|---|---|
| User ID, username, the offending link or image description, time, channel and server name | A message is removed or a user is warned, timed out or banned | Evidence log for moderators (`/scamlog`, `/why`) |
| The message text (first 500 characters) and the author's few previous messages | A link is unclear and is sent to moderators for review | So moderators can decide, and `/why` can explain the decision |
| A fingerprint of an image (a 64-bit number, not the image itself) | Moderators or the honeypot confirm an image is a scam, or mark it safe | To recognise the same scam image if it is posted again |
| A link and the moderator's verdict | A moderator presses a review button | To improve Mari's link classifier |
| Server settings (log channel, honeypot channel, trusted domains, counters) | An administrator sets them | To run the bot in that server |

Mari does not store ordinary messages, translated messages, images, voice, or
direct messages, and it does not build profiles of users.

## Who data is shared with

Mari sends data to these services only to do its job:

- **Google Gemini API**: the text and image of a message you ask Mari to
  translate (by reacting with a flag), images posted in a honeypot channel, and
  the details of an unclear link case. Requests pass through a relay that
  forwards them and keeps nothing. Mari uses Gemini's free tier, under which
  Google may use the content to improve its products.
- **Google Safe Browsing and VirusTotal**: links found in messages, to check
  them against known threats.
- **Websites of suspicious links**: Mari may open a link to inspect its page.

Data is never sold, and is not shared with anyone else.

## Retention

Stored records are kept until the server's administrators or the bot owner
delete them. Server backups are kept for 7 days. If Mari is removed from a
server, that server's data can be deleted on request.

## Your choices

- Server administrators can remove Mari at any time.
- To ask what Mari holds about you, or to have it deleted, open an issue at
  <https://github.com/kiyosumisin/Iochi-Mari/issues> or contact the bot owner
  on Discord. Please do not post personal data in a public issue: just ask to
  be contacted.

## Changes

Changes to this policy are published in this file; its history is visible on
GitHub.
