import math
from collections import Counter

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    entropy = 0.0
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)

    return entropy
