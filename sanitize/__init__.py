"""Small standard-library-only HTML sanitizer exercise."""

from .html import (
    allowed_tag,
    escape_text,
    safe_url,
    sanitize,
    sanitize_attrs,
    sanitize_batch,
    tokenize,
    validate_policy,
)

__all__ = [
    "tokenize",
    "allowed_tag",
    "sanitize_attrs",
    "safe_url",
    "escape_text",
    "sanitize",
    "validate_policy",
    "sanitize_batch",
]
