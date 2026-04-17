from enum import Enum

class Verdict(Enum):
    SAFE = 0
    SCAM = 1
    GAMBLING = 2
    ADULT = 3
    PHISHING = 4
    MALWARE = 5
    BLACKLISTED = 6
