"""Shared string normalization for product names and CPE tokens."""

from __future__ import annotations

import re

_TOKEN = re.compile(r"[a-z0-9]+")


def tokens(value: str) -> list[str]:
    return _TOKEN.findall(value.lower())


def normalize(value: str) -> str:
    return " ".join(tokens(value))


def phrase_in(haystack: list[str], phrase: list[str]) -> bool:
    if not phrase:
        return False
    if phrase == haystack:
        return True
    width = len(phrase)
    if width > len(haystack):
        return False
    for index in range(len(haystack) - width + 1):
        if haystack[index : index + width] == phrase:
            return True
    return False
