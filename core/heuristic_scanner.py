from urllib.parse import unquote
from core.url_utils import URLUtils

class HeuristicScanner:
    SCAM = ["nitro", "free", "gift", "claim", "bonus", "discordgift"]
    ADULT = ["porn", "sex", "xxx", "hentai", "xnxx", "xvideos"]
    GAMBLING = ["casino", "bet", "gamble", "jackpot", "poker", "ball88", "188bet", "12bet", "sbobet", "maxbet"]
    MALWARE_KEYWORDS = ["malware", "stealer", "keylogger", "rat", "trojan", "botnet", "exploit"]
    MALWARE_EXTENSIONS = (".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar")
    SUSPICIOUS_TLDS = [".art", ".xyz", ".top", ".work", ".trade", ".click", ".download", ".review"]
    AFFILIATE_PATTERNS = ["utm_source=", "utm_campaign=", "aff_id=", "affiliate_id=", "promo_code="]

    @classmethod
    def scan(cls, url: str):
        decoded = unquote(url).lower()
        domain = URLUtils.get_domain(url).lower()
        text = f"{domain} {decoded}"

        # Check malware first (highest priority)
        if any(k in text for k in cls.MALWARE_KEYWORDS) or decoded.endswith(cls.MALWARE_EXTENSIONS):
            return "malware"

        # Check suspicious TLDs with affiliate/suspicious patterns
        if any(tld in domain for tld in cls.SUSPICIOUS_TLDS):
            if any(pattern in decoded for pattern in cls.AFFILIATE_PATTERNS):
                return "scam"

        # Check adult content
        for kw in cls.ADULT:
            if kw in text:
                return "adult"
        
        # Check gambling sites
        for kw in cls.GAMBLING:
            if kw in text:
                return "gambling"
        
        # Check scam keywords
        for kw in cls.SCAM:
            if kw in text:
                return "scam"

        return None
