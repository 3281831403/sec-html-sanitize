"""A small, dependency-free HTML sanitizer.

The module is offline and standard-library-only.  Untrusted rich-text input
is made inert while safe text and a small whitelist of formatting markup are
preserved.  The docstrings of the public helpers are the authoritative
contract.

Security rules that apply across the module:

* ``script`` and ``style`` are never emitted, even if a policy asks for them.
* Event-handler attributes (any name beginning with ``on``, case-insensitive)
  are never emitted.
* URLs are accepted only after entity decoding, whitespace/control stripping,
  case folding, and an exact scheme comparison.
* Text and attribute values are escaped before serialization.
* Comparison, matching, and serialization tolerance is zero.
"""

from __future__ import annotations

import html
import re
from urllib.parse import urlsplit

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

# HTML void elements are never serialized with an end tag.
_VOID_TAGS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)

# These containers are removed as a unit or unwrapped by ``sanitize``.
_HARD_DENY_TAGS = frozenset(
    {"script", "style", "iframe", "object", "embed", "svg", "math", "template"}
)
# The subset of the hard denylist whose *contents* are dropped as well.
_CONTENT_DENY_TAGS = frozenset({"script", "style"})

_DANGEROUS_ATTRS = frozenset({"style", "srcdoc"})
_URL_ATTRS = frozenset(
    {"href", "src", "action", "formaction", "poster", "cite", "background"}
)

# Raster-only media types permitted for ``data:`` URLs.
_DATA_IMAGE_MIMES = frozenset(
    {"image/png", "image/jpeg", "image/gif", "image/webp"}
)
_DEFAULT_PORTS = {"http": 80, "https": 443}

# Schemes a policy may never whitelist (``data`` cannot express the MIME
# restriction enforced by :func:`safe_url`).
_POLICY_BAD_SCHEMES = frozenset({"javascript", "vbscript", "file", "data"})
_POLICY_BAD_TAGS = frozenset(
    {"script", "style", "iframe", "object", "embed", "svg", "math", "template"}
)

# Characters browsers ignore when they occur inside/around a scheme.
_IGNORABLE_RE = re.compile(r"[\x00-\x20\x7f]+")
_SCHEME_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*):")

# ---------------------------------------------------------------------------
# Lexical layer
# ---------------------------------------------------------------------------

_TAG_START = (
    r"<(?P<startname>[A-Za-z][^\s/>]*)"
    r"(?P<attrs>(?:[^>\"']|\"[^\"]*\"|'[^']*')*?)"
    r"(?P<selfclose>/?)(?:>|$)"
)
_TAG_END = r"</\s*(?P<endname>[A-Za-z][^\s/>]*)[^>]*(?:>|$)"
_COMMENT = r"<!--.*?(?:-->|$)"
_DECL = r"<![^>]*(?:>|$)"
_BOGUS = r"<[!?][^>]*(?:>|$)"

_TOKEN_RE = re.compile(
    "(?P<comment>" + _COMMENT + ")"
    "|(?P<doctype>" + _DECL + ")"
    "|(?P<end>" + _TAG_END + ")"
    "|(?P<start>" + _TAG_START + ")"
    "|(?P<bogus>" + _BOGUS + ")",
    re.S,
)

_ATTR_RE = re.compile(
    r"""([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?""",
    re.S,
)


def _parse_attrs(body: str) -> dict:
    """Parse a raw start-tag attribute body into a lower-case name map."""
    attrs: dict = {}
    for match in _ATTR_RE.finditer(body):
        name = match.group(1).lower()
        if name in attrs:
            # First occurrence wins; later duplicates are ignored.
            continue
        if match.group(2) is not None:
            value = match.group(2)
        elif match.group(3) is not None:
            value = match.group(3)
        elif match.group(4) is not None:
            value = match.group(4)
        else:
            value = ""
        attrs[name] = value
    return attrs


def tokenize(html_text: str) -> list[dict]:
    """Split *html_text* into a lossless stream of lexical tokens.

    The tokenizer is lexical only: it does not build a tree, balance tags,
    execute anything, or infer browser repair behavior.  It returns a list of
    dictionaries, each with exactly the keys shown below.

    Text token::

        {"type": "text", "value": raw_text, "raw": raw_text}

    Tag token::

        {"type": "tag", "name": lower_name, "attrs": {lower_name: value},
         "closing": bool, "self_closing": bool, "raw": raw_source}

    ``attrs`` values are the unquoted source text (character references are
    left intact, not decoded); a valueless attribute maps to ``""``.
    Duplicate attribute names are compared case-insensitively and the first
    occurrence wins.  Attribute and tag names are lower-cased.

    Comment token::

        {"type": "comment", "value": inner_text, "raw": raw_source}

    DOCTYPE token::

        {"type": "doctype", "value": full_declaration, "raw": raw_source}

    Text outside markup is preserved exactly, including whitespace.  Joining
    every ``raw`` field in order must reproduce *html_text* byte-for-byte
    (tolerance 0).  An empty string returns ``[]``.  Malformed or truncated
    markup must still produce tokens that cover all input rather than being
    dropped or raising.
    """
    if not isinstance(html_text, str):
        raise TypeError("tokenize() expects a string")

    tokens: list[dict] = []
    if html_text == "":
        return tokens

    pos = 0
    length = len(html_text)
    while pos < length:
        match = _TOKEN_RE.search(html_text, pos)
        if match is None:
            tokens.append(
                {"type": "text", "value": html_text[pos:], "raw": html_text[pos:]}
            )
            break
        if match.start() > pos:
            chunk = html_text[pos : match.start()]
            tokens.append({"type": "text", "value": chunk, "raw": chunk})

        raw = match.group(0)
        if match.group("comment") is not None:
            inner = raw[4:]
            if inner.endswith("-->"):
                inner = inner[:-3]
            tokens.append({"type": "comment", "value": inner, "raw": raw})
        elif match.group("doctype") is not None:
            tokens.append({"type": "doctype", "value": raw, "raw": raw})
        elif match.group("end") is not None:
            tokens.append(
                {
                    "type": "tag",
                    "name": match.group("endname").lower(),
                    "attrs": {},
                    "closing": True,
                    "self_closing": False,
                    "raw": raw,
                }
            )
        elif match.group("start") is not None:
            tokens.append(
                {
                    "type": "tag",
                    "name": match.group("startname").lower(),
                    "attrs": _parse_attrs(match.group("attrs")),
                    "closing": False,
                    "self_closing": match.group("selfclose") == "/",
                    "raw": raw,
                }
            )
        else:  # pragma: no cover - bogus declaration / processing instruction
            tokens.append({"type": "doctype", "value": raw, "raw": raw})

        pos = match.end()

    return tokens


# ---------------------------------------------------------------------------
# Name and attribute filtering
# ---------------------------------------------------------------------------


def allowed_tag(name: str, allow) -> bool:
    """Return whether *name* is an exactly whitelisted tag.

    Matching is ASCII case-insensitive and exact; no prefix, substring, or
    fuzzy matching is performed.  Empty, non-string, and missing names are
    rejected.  Tolerance is zero; the result is a real ``bool``.
    """
    if not isinstance(name, str) or name == "":
        return False
    target = name.lower()
    try:
        entries = allow
        if entries is None:
            return False
        for entry in entries:
            if isinstance(entry, str) and entry.lower() == target:
                return True
    except TypeError:
        return False
    return False


def _allowed_attr_set(allow: dict, tag_name: str) -> set:
    """Return the lower-cased attribute names allowed for *tag_name*."""
    permitted: set = set()
    if not isinstance(allow, dict):
        return permitted
    for key, values in allow.items():
        if not isinstance(key, str) or key.lower() != tag_name:
            continue
        if isinstance(values, str):
            values = (values,)
        try:
            for value in values:
                if isinstance(value, str):
                    permitted.add(value.lower())
        except TypeError:
            continue
    return permitted


def _is_event_attr(name: str) -> bool:
    return name.lower().startswith("on")


def sanitize_attrs(tag: str, attrs: dict, allow: dict) -> dict:
    """Filter one tag's attributes and remove dangerous names.

    An attribute survives only when its lower-cased name is listed for this
    tag or for ``"*"``.  Regardless of the whitelist, every name beginning
    with ``on`` (case-insensitive), ``style``, and ``srcdoc`` is dropped.
    Return a new dictionary; never mutate *attrs* or *allow*.
    """
    tag_name = tag.lower() if isinstance(tag, str) else ""
    permitted = _allowed_attr_set(allow, tag_name)
    permitted |= _allowed_attr_set(allow, "*")

    result: dict = {}
    if not isinstance(attrs, dict):
        return result
    for raw_name, value in attrs.items():
        if not isinstance(raw_name, str):
            continue
        name = raw_name.lower()
        if name in result:
            # Preserve the first occurrence of a case-insensitively
            # duplicated name.
            continue
        if _is_event_attr(name) or name in _DANGEROUS_ATTRS:
            continue
        if name not in permitted:
            continue
        result[name] = value
    return result


# ---------------------------------------------------------------------------
# URL policy
# ---------------------------------------------------------------------------


def _decode_entities_stable(text: str) -> str:
    """Decode HTML character references repeatedly until stable."""
    for _ in range(32):
        decoded = html.unescape(text)
        if decoded == text:
            return text
        text = decoded
    return text


def _safe_data_url(url: str) -> bool:
    """Validate the MIME type of a ``data:`` URL."""
    rest = url[len("data:") :]
    meta, sep, _payload = rest.partition(",")
    if not sep:
        return False
    mime = meta.split(";", 1)[0].strip().lower()
    return mime in _DATA_IMAGE_MIMES


def safe_url(url: str, schemes) -> bool:
    """Return whether *url* may be emitted under a scheme whitelist.

    Character references are decoded until stable, ASCII whitespace and C0
    controls are removed, and the scheme is compared by exact,
    case-insensitive equality.  Scheme-less relative URLs are allowed;
    syntactically empty URLs are rejected.  ``data:`` is accepted only for
    raster image media types.  Ambiguity is rejection; tolerance is zero.
    """
    if not isinstance(url, str):
        return False

    try:
        if isinstance(schemes, str):
            scheme_set = {schemes.lower()}
        else:
            scheme_set = {s.lower() for s in schemes if isinstance(s, str)}
    except TypeError:
        return False

    decoded = _decode_entities_stable(url)
    cleaned = _IGNORABLE_RE.sub("", decoded)
    if not cleaned:
        return False

    match = _SCHEME_RE.match(cleaned)
    if match is None:
        # No scheme: a relative reference such as "/inbox", "#top", "?q=1".
        return True

    scheme = match.group(1).lower()
    if scheme not in scheme_set:
        return False

    if scheme == "data":
        return _safe_data_url(cleaned)

    if scheme in _DEFAULT_PORTS:
        try:
            parts = urlsplit(cleaned)
            port = parts.port
        except ValueError:
            return False
        if port is not None and port != _DEFAULT_PORTS[scheme]:
            return False

    return True


# ---------------------------------------------------------------------------
# Escaping and serialization
# ---------------------------------------------------------------------------


def escape_text(text: str) -> str:
    """Escape untrusted character data for an HTML text or attribute context.

    ``&``, ``<``, ``>``, ``"``, and ``'`` become ``&amp;``, ``&lt;``,
    ``&gt;``, ``&quot;``, and ``&#x27;``.  ``&`` is handled first so the
    result is never double interpreted.
    """
    if not isinstance(text, str):
        raise TypeError("escape_text() expects a string")
    return html.escape(text, quote=True)


def _policy_tag_names(policy: dict) -> tuple:
    tags = policy.get("allowed_tags", ())
    if isinstance(tags, str):
        tags = (tags,)
    try:
        return tuple(tag for tag in tags if isinstance(tag, str))
    except TypeError:
        return ()


def _policy_schemes(policy: dict) -> tuple:
    schemes = policy.get("url_schemes", ())
    if isinstance(schemes, str):
        return (schemes,)
    try:
        return tuple(s for s in schemes if isinstance(s, str))
    except TypeError:
        return ()


def _skip_element(tokens: list, start: int) -> int:
    """Return the index just past the element opening at *tokens[start]*."""
    name = tokens[start]["name"]
    depth = 1
    index = start + 1
    while index < len(tokens):
        token = tokens[index]
        if token["type"] == "tag" and token["name"] == name:
            if token["closing"]:
                depth -= 1
            elif not token["self_closing"]:
                depth += 1
        index += 1
        if depth == 0:
            return index
    return len(tokens)


def _serialize_attrs(
    tag_name: str, attrs: dict, allowed_attrs: dict, schemes: tuple
) -> str:
    """Filter, URL-check, and serialize attributes."""
    kept = sanitize_attrs(tag_name, attrs, allowed_attrs)
    parts = []
    for name, value in kept.items():
        if name in _URL_ATTRS and not safe_url(value, schemes):
            continue
        parts.append(' %s="%s"' % (name, escape_text(value)))
    return "".join(parts)


def sanitize(html_text: str, policy: dict) -> str:
    """Sanitize a complete HTML fragment according to *policy*.

    Only whitelisted tags/attributes survive.  All text and attribute values
    are escaped.  Comments and DOCTYPE declarations are dropped wholesale.
    ``script``/``style`` elements are removed with their contents; other
    hard-denied containers are never emitted; disallowed ordinary tags are
    unwrapped so their safe text survives.  URL-bearing attributes are kept
    only when :func:`safe_url` accepts them.  *policy* is never mutated and
    no cache is used.
    """
    if not isinstance(html_text, str):
        raise TypeError("sanitize() expects a string")
    if not isinstance(policy, dict):
        raise TypeError("policy must be a mapping")

    allowed_tags = _policy_tag_names(policy)
    allowed_attrs = policy.get("allowed_attrs", {})
    if not isinstance(allowed_attrs, dict):
        allowed_attrs = {}
    schemes = _policy_schemes(policy)

    tokens = tokenize(html_text)
    out: list[str] = []
    stack: list[dict] = []

    index = 0
    count = len(tokens)
    while index < count:
        token = tokens[index]
        kind = token["type"]

        if kind == "text":
            out.append(escape_text(token["value"]))
            index += 1
            continue
        if kind != "tag":
            # Comments and DOCTYPE declarations are removed completely.
            index += 1
            continue

        name = token["name"]

        if token["closing"]:
            match_at = None
            for depth in range(len(stack) - 1, -1, -1):
                if stack[depth]["name"] == name:
                    match_at = depth
                    break
            if match_at is None:
                # Stray closing tag; there is nothing to close.
                index += 1
                continue
            while len(stack) > match_at:
                entry = stack.pop()
                if entry["emitted"]:
                    out.append("</%s>" % entry["name"])
            index += 1
            continue

        if name in _CONTENT_DENY_TAGS:
            # Drop the element together with everything inside it.
            index = _skip_element(tokens, index)
            continue

        emit = allowed_tag(name, allowed_tags) and name not in _HARD_DENY_TAGS
        if emit:
            serialized = _serialize_attrs(
                name, token["attrs"], allowed_attrs, schemes
            )
            out.append("<%s%s>" % (name, serialized))
            if name in _VOID_TAGS:
                index += 1
                continue
            stack.append({"name": name, "emitted": True})
        elif name not in _VOID_TAGS:
            # Unwrapped transparent container: keep processing its content.
            stack.append({"name": name, "emitted": False})
        index += 1

    while stack:
        entry = stack.pop()
        if entry["emitted"]:
            out.append("</%s>" % entry["name"])

    return "".join(out)


# ---------------------------------------------------------------------------
# Policy validation and batch helper
# ---------------------------------------------------------------------------


def validate_policy(policy: dict) -> list[str]:
    """Return a list of human-readable policy problems; empty means safe.

    Malformed input is reported, not raised.  Every violation is reported and
    messages are stable and de-duplicated.
    """
    issues: list[str] = []
    seen: set = set()

    def add(message: str) -> None:
        if message not in seen:
            seen.add(message)
            issues.append(message)

    if not isinstance(policy, dict):
        return ["policy: expected a mapping"]

    # allowed_tags -----------------------------------------------------------
    if "allowed_tags" not in policy:
        add("allowed_tags: missing")
    else:
        tags = policy["allowed_tags"]
        if isinstance(tags, str):
            tags = (tags,)
        try:
            iterator = iter(tags)
        except TypeError:
            add("allowed_tags: expected an iterable of tag names")
        else:
            for tag in iterator:
                if not isinstance(tag, str):
                    add("allowed_tags: invalid tag name %r" % (tag,))
                    continue
                lowered = tag.lower()
                if lowered in _POLICY_BAD_TAGS:
                    add("allowed_tags: dangerous tag '%s'" % lowered)

    # allowed_attrs ----------------------------------------------------------
    if "allowed_attrs" not in policy:
        add("allowed_attrs: missing")
    else:
        attrs_map = policy["allowed_attrs"]
        if not isinstance(attrs_map, dict):
            add("allowed_attrs: expected a mapping of tag names to attribute lists")
        else:
            for tag_name, values in attrs_map.items():
                if isinstance(values, str):
                    values = (values,)
                try:
                    iterator = iter(values)
                except TypeError:
                    add(
                        "allowed_attrs[%r]: expected an iterable of attribute names"
                        % (tag_name,)
                    )
                    continue
                for attr in iterator:
                    if not isinstance(attr, str):
                        add(
                            "allowed_attrs[%r]: invalid attribute name %r"
                            % (tag_name, attr)
                        )
                        continue
                    lowered = attr.lower()
                    if lowered.startswith("on"):
                        add(
                            "allowed_attrs: dangerous event attribute '%s'"
                            % lowered
                        )
                    elif lowered in _DANGEROUS_ATTRS:
                        add(
                            "allowed_attrs: dangerous attribute '%s'" % lowered
                        )

    # url_schemes ------------------------------------------------------------
    if "url_schemes" not in policy:
        add("url_schemes: missing")
    else:
        schemes = policy["url_schemes"]
        if isinstance(schemes, str):
            schemes = (schemes,)
        try:
            iterator = iter(schemes)
        except TypeError:
            add("url_schemes: expected an iterable of scheme names")
        else:
            for scheme in iterator:
                if not isinstance(scheme, str):
                    add("url_schemes: invalid scheme %r" % (scheme,))
                    continue
                lowered = scheme.lower()
                if lowered in _POLICY_BAD_SCHEMES:
                    add("url_schemes: dangerous scheme '%s'" % lowered)

    return issues


def sanitize_batch(parts, policy: dict) -> dict:
    """Independently sanitize every fragment in *parts*.

    Returns ``{"parts": [sanitized_string, ...], "changed": bool}``.  Each
    fragment is handled in a fresh state, exactly as
    ``sanitize(parts[i], policy)``; *policy* is never mutated.
    """
    if isinstance(parts, str):
        raise TypeError("sanitize_batch() expects an iterable of strings, not a string")

    results: list[str] = []
    changed = False
    for part in parts:
        if not isinstance(part, str):
            raise TypeError("each part must be a string")
        cleaned = sanitize(part, policy)
        results.append(cleaned)
        if cleaned != part:
            changed = True
    return {"parts": results, "changed": changed}
