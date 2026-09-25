import re
from urllib.parse import unquote, urlparse

from core.url_utils import URLUtils

# Keywords are matched as whole tokens (the URL split on non-alphanumerics), not
# as substrings: substring matching made "bet" hit "beta", "poker" hit
# "pokerogue" and "rat" hit "generate" — punishing ~2% of ordinary links.
_TOKEN = re.compile(r"[a-z0-9]+")

# Discord/Steam giveaway lures ("free nitro", "steam gift", ...). On a site that
# is not Discord's or Steam's own, these are a strong scam tell — but they only
# mark the link as suspicious ("lure") so it gets a closer look; never a ban.
_LURE = re.compile(
    r"(free|claim|get)[\W_]*nitro"
    r"|nitro[\W_]*(gift|free|claim|generator|drop|boost)"
    r"|steam[\W_]*(gift|nitro)"
    # "discord" plus common look-alikes: dlscord, d1scord, discorcl, d1sc0rd, ...
    r"|d[i1l]s?c[o0]r(?:d|cl|c)[\W_]*(gift|nitro)"
)
_LURE_OFFICIAL = {
    "discord.com", "discord.gg", "discord.gift", "discordapp.com", "discordapp.net",
    "discord.media", "discord.new", "steampowered.com", "steamcommunity.com",
}


class HeuristicScanner:
    GAMBLING = {"casino", "bet", "gamble", "jackpot", "poker", "ball88", "188bet", "12bet", "sbobet", "maxbet"}
    # "rat" and "exploit" dropped: they matched everyday words and banned people.
    MALWARE_KEYWORDS = {"malware", "stealer", "keylogger", "trojan", "botnet"}
    # ".js" dropped: ordinary web script links are not malware downloads.
    MALWARE_EXTENSIONS = (".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".jar")
    SUSPICIOUS_TLDS = (".art", ".xyz", ".top", ".work", ".trade", ".click", ".download", ".review")
    AFFILIATE_PATTERNS = ["utm_source=", "utm_campaign=", "aff_id=", "affiliate_id=", "promo_code="]

    @classmethod
    def scan(cls, url: str):
        decoded = unquote(url).lower()
        domain = URLUtils.get_domain(url).lower()
        tokens = set(_TOKEN.findall(decoded))

        # Malware first (highest priority)
        if tokens & cls.MALWARE_KEYWORDS or urlparse(decoded).path.endswith(cls.MALWARE_EXTENSIONS):
            return "malware"

        # Suspicious TLD combined with affiliate/tracking bait
        if domain.endswith(cls.SUSPICIOUS_TLDS) and any(p in decoded for p in cls.AFFILIATE_PATTERNS):
            return "scam"

        if tokens & cls.GAMBLING:
            return "gambling"

        # Discord giveaway lure on a non-official site: escalate, don't punish.
        if _LURE.search(decoded) and not URLUtils.domain_in(domain, _LURE_OFFICIAL):
            return "lure"

        return None
