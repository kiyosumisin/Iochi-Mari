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


def test_popular_sites_trusted_but_not_pages_anyone_can_publish():
    from core.popular import PopularDomains
    pop = PopularDomains()
    pop.domains = {"hdslb.com", "klipy.com", "fxtwitter.com", "pages.dev", "google.com", "docs.google.com"}
    for host in ("i0.hdslb.com", "klipy.com", "gif.fxtwitter.com"):
        assert pop.contains(host), host
    for host in ("evil-nitro.pages.dev", "docs.google.com", "ghosts-wallets.xyz", "hdslb.com.evil.ru"):
        assert not pop.contains(host), host


def test_mari_never_opens_private_addresses():
    import asyncio
    import types as T
    from core.url_utils import BlockedURL, _is_public, get_public

    async def check():
        for url in ("http://127.0.0.1/", "http://localhost:8000/admin", "http://10.0.0.5/",
                    "http://192.168.1.1/", "http://169.254.169.254/metadata", "http://[::1]/",
                    "file:///etc/passwd", "ftp://8.8.8.8/", "http://0.0.0.0/"):
            assert not await _is_public(url), url
        assert await _is_public("http://8.8.8.8/")

        # A public link that redirects into the private network is stopped at the hop.
        class Resp:
            status, headers, url = 302, {"Location": "http://169.254.169.254/latest"}, "http://8.8.8.8/x"
            def release(self): pass

        async def get(url, allow_redirects):
            return Resp()
        try:
            async with get_public(T.SimpleNamespace(get=get), "http://8.8.8.8/x"):
                raise AssertionError("followed a redirect into the private network")
        except BlockedURL:
            pass
    asyncio.run(check())


def test_hidden_characters_and_lookalikes_cannot_dodge_the_lists():
    d = URLUtils.get_domain
    assert d("https://disc​ord.gift./claim") == "discord.gift"     # zero-width space, trailing dot
    assert d("https://DISCORD.GIFT/x") == "discord.gift"
    assert d("https://dіscord.gift/").startswith("xn--")               # Cyrillic і: punycode, not discord.gift
    assert d("https://discord.com@evil.example/") == "evil.example"


def test_costly_checks_cover_at_most_five_links_known_scams_first():
    import types as T
    from bot.events import MessageHandler
    h = MessageHandler.__new__(MessageHandler)
    h.evaluator = T.SimpleNamespace(is_known_scam=lambda dom: dom == "d-giftnitro.com")
    msg = T.SimpleNamespace(content=" ".join(f"https://ok{i}.example/" for i in range(8))
                            + " https://ok0.example/ https://d-giftnitro.com/claim")
    links = h._links(msg)
    assert len(links) == 5 and links[0] == "https://d-giftnitro.com/claim"


if __name__ == "__main__":
    tests = [f for name, f in dict(globals()).items() if name.startswith("test_")]
    for t in tests:
        t()
        print("ok  ", t.__name__)
    print(f"{len(tests)} passed")
