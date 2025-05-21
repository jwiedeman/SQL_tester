import re
from difflib import SequenceMatcher


def normalize(text: str) -> str:
    """Normalize dynamic values in a response."""
    # Replace common timestamp patterns with placeholder
    text = re.sub(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}", "TIMESTAMP", text)
    # Replace long hex strings (tokens)
    text = re.sub(r"[0-9a-fA-F]{32,}", "HEXTOKEN", text)
    # Collapse sequences of digits
    text = re.sub(r"\d+", "0", text)
    return text


def is_significant_diff(a: str, b: str, threshold: float = 0.1) -> bool:
    """Return True if difference ratio exceeds the threshold."""
    a_norm = normalize(a)
    b_norm = normalize(b)
    ratio = SequenceMatcher(None, a_norm, b_norm).ratio()
    return (1 - ratio) > threshold
