"""Regression checks for URL verdicts that lead to bans. Run: python tests/test_url_safety.py"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.heuristic_scanner import HeuristicScanner as H  # noqa: E402
from core.scam_list import ScamDomainList, parse_domains  # noqa: E402
from core.url_utils import URLUtils  # noqa: E402


def test_everyday_links_are_not_punished():
    # All of these were banned or timed out by the old substring matching.
    for url in [
        "https://www.kaggle.com/code/dansbecker/basic-data-exploration",    # "rat"
        "https://dreamina.capcut.com/ai-tool/generate",                     # "rat"
        "https://archive-beta.ics.uci.edu/dataset/967",                     # "bet"
        "https://pokerogue.net/",                                           # "poker"
        "https://hsr.hoyoverse.com/gift?code=AA39GPEL9NHB",                 # "gift"
        "https://www.microsoft.com/en/microsoft-365/free-office-online",    # "free"
        "https://cdn.example.com/static/app.min.js",                        # ".js"
        "https://news.topgear.com/?utm_source=x",                           # ".top" substring
    ]:
        assert H.scan(url) is None, url


def test_real_signals_still_caught():
    assert H.scan("https://play-casino.example/slots") == "gambling"
    assert H.scan("https://files.example.com/setup.exe") == "malware"
    assert H.scan("https://cheap.xyz/deal?utm_source=spam") == "scam"


def test_discord_lures_escalate_but_official_links_do_not():
    assert H.scan("https://my-site.com/free-nitro-claim-now") == "lure"
    assert H.scan("https://dlscord-gift.com/claim") == "lure"      # look-alike domain
    assert H.scan("https://d1sc0rd-nitro.ru/") == "lure"
    assert H.scan("https://discorcl.gift/abc") == "lure"
    assert H.scan("https://discord.gift/AbCdEf123") is None
    assert H.scan("https://steamcommunity.com/gift/123") is None


def test_userinfo_trick_resolves_to_real_host():
    assert URLUtils.get_domain("https://discord.com@evil.com/login") == "evil.com"
    assert URLUtils.get_domain("https://www.example.com:8080/x") == "example.com"
    assert URLUtils.domain_in("a.b.evil.com", {"evil.com"})
    assert not URLUtils.domain_in("notevil.com", {"evil.com"})


def test_scam_list_parsing_and_protection():
    assert parse_domains('["a.com", "B.com"]') == {"a.com", "b.com"}
    assert parse_domains('{"domains": ["c.com"]}') == {"c.com"}
    assert parse_domains("# comment\nd.com\nhttps://www.e.com/path\n") == {"d.com", "e.com"}

    s = ScamDomainList.__new__(ScamDomainList)
    s.protected = {"discord.com", "google.com", "trusted.org"}
    s.domains = {"evil.com", "discord.com", "evil.vercel.app", "vercel.app", "com", "sites.google.com"}
    assert s.contains("evil.com") and s.contains("login.evil.com")
    assert s.contains("evil.vercel.app")                  # a site on a platform can be listed
    for safe in ["discord.com", "cdn.discord.com", "vercel.app", "other.vercel.app",
                 "sites.google.com", "trusted.org", "example.com"]:
        assert not s.contains(safe), safe
    # poisoned entries are dropped at refresh time
    assert all(s.is_protected(d) for d in ["discord.com", "vercel.app", "com", "sites.google.com"])
    assert not s.is_protected("evil.vercel.app")


def test_ocr_keywords_are_whole_words():
    from core.image_scanner import scan_ocr_text
    assert scan_ocr_text("let's play together tonight, something new") is None  # not "eth"
    assert scan_ocr_text("Please login to continue") == "suspected"              # warn, never ban
    assert scan_ocr_text("FREE NITRO giveaway - claim now!") == "scam"


if __name__ == "__main__":
    tests = [f for name, f in dict(globals()).items() if name.startswith("test_")]
    for t in tests:
        t()
        print("ok  ", t.__name__)
    print(f"{len(tests)} passed")
