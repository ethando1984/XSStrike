"""Dependency-free fuzzy string matching.

Drop-in replacement for the single ``fuzzywuzzy`` function XSStrike relied on
(``fuzz.partial_ratio``). ``fuzzywuzzy`` is unmaintained and was itself only a
thin wrapper around the standard-library :mod:`difflib`, so this reimplements
the same algorithm on top of ``difflib`` and keeps the 0-100 scoring identical
enough that the efficiency thresholds elsewhere in the code stay meaningful.
"""

from difflib import SequenceMatcher


def _ratio(a, b):
    return SequenceMatcher(None, a, b).ratio()


def partial_ratio(s1, s2):
    """Best partial-match score (0-100) between two strings.

    The shorter string is slid across the longer one and the highest
    ``difflib`` similarity ratio found is returned, mirroring the behaviour of
    ``fuzzywuzzy.fuzz.partial_ratio``.
    """
    if not s1 or not s2:
        return 0

    if len(s1) <= len(s2):
        shorter, longer = s1, s2
    else:
        shorter, longer = s2, s1

    matcher = SequenceMatcher(None, shorter, longer)
    best = 0.0
    for short_start, long_start, _ in matcher.get_matching_blocks():
        start = max(long_start - short_start, 0)
        window = longer[start:start + len(shorter)]
        score = _ratio(shorter, window)
        if score > 0.995:
            return 100
        if score > best:
            best = score
    return int(round(100 * best))
