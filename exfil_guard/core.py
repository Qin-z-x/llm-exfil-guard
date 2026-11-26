"""Detect and defuse data-exfiltration channels in rendered LLM output.

The threat this module addresses: a chat UI renders model output as Markdown or
HTML. Remote resources embedded in that output (images, iframes, stylesheets,
CSS ``url()``, link prefetch, meta refresh) are fetched automatically by the
user's browser, so any secret an attacker can get into the URL is exfiltrated —
no click required. Hidden content (``display:none``, zero opacity, white text,
``aria-hidden``, HTML comments) is invisible to the human but still present in
the text an LLM agent reads.

``scan()`` reports findings; ``clean()`` removes or neutralizes the remote loads
while preserving the visible text. The implementation is a deliberately careful
heuristic: it parses the Markdown/HTML constructs that create automatic network
requests, protects fenced/inline code from modification, and documents its
limits in ``docs/THREAT_MODEL.md``.
"""

from __future__ import annotations

import base64
import math
import re
import urllib.parse
from bisect import bisect_right
from dataclasses import dataclass, field

VERSION = "0.1.0"

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """One deterministic detection.

    Offsets are Python ``str`` indices (code points). ``line``/``column`` are
    1-based. ``data`` is JSON-serializable and stable for a given input.
    """

    code: str
    kind: str
    severity: str
    start: int
    end: int
    line: int
    column: int
    message: str
    data: dict = field(default_factory=dict)

    @property
    def length(self) -> int:
        return self.end - self.start

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "kind": self.kind,
            "severity": self.severity,
            "start": self.start,
            "end": self.end,
            "length": self.length,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "data": self.data,
        }


def summarize(findings: list[Finding]) -> dict:
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[finding.severity] += 1
    return {"total": len(findings), "high": counts["high"], "medium": counts["medium"], "low": counts["low"]}


def severity_at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold]


def _line_col(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    column = offset - text.rfind("\n", 0, offset)
    return line, column


def _collapse(text: str, limit: int = 160) -> str:
    collapsed = re.sub(r"\s+", " ", text).strip()
    if len(collapsed) > limit:
        collapsed = collapsed[: limit - 1] + "\u2026"
    return collapsed


# ---------------------------------------------------------------------------
# Region tracking (fenced code, inline code, HTML comments, script/style)
# ---------------------------------------------------------------------------


def _in_regions(position: int, regions: list[tuple[int, int]]) -> bool:
    if not regions:
        return False
    starts = [start for start, _ in regions]
    index = bisect_right(starts, position) - 1
    if index < 0:
        return False
    return regions[index][0] <= position < regions[index][1]


def _code_regions(text: str) -> list[tuple[int, int]]:
    """Fenced code blocks and inline code spans: rendered literally, never loaded."""
    regions: list[tuple[int, int]] = []
    fence = re.compile(r"(?ms)^[ \t]{0,3}(`{3,}|~{3,})[^\n]*\n.*?^[ \t]{0,3}\1[ \t]*$")
    for match in fence.finditer(text):
        regions.append((match.start(), match.end()))
    gaps: list[tuple[int, int]] = []
    cursor = 0
    for start, end in regions:
        if cursor < start:
            gaps.append((cursor, start))
        cursor = end
    if cursor < len(text):
        gaps.append((cursor, len(text)))
    inline = re.compile(r"`[^`\n]+`")
    for start, end in gaps:
        for match in inline.finditer(text, start, end):
            regions.append((match.start(), match.end()))
    regions.sort()
    return regions


def _comment_regions(text: str) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in re.finditer(r"(?s)<!--.*?-->", text)]


# ---------------------------------------------------------------------------
# HTML vocabulary
# ---------------------------------------------------------------------------

HTML_TAGS = frozenset(
    """
    a abbr address area article aside audio b base bdi bdo blockquote body br
    button canvas caption cite code col colgroup data datalist dd del details
    dfn dialog div dl dt em embed fieldset figcaption figure footer form h1 h2
    h3 h4 h5 h6 head header hgroup hr html i iframe img input ins kbd label
    legend li link main map mark menu meta meter nav noscript object ol
    optgroup option output p param picture pre progress q rp rt ruby s samp
    script section select slot small source span strong style sub summary sup
    table tbody td template textarea tfoot th thead time title tr track u ul
    var video wbr svg path circle rect g image use defs line polyline polygon
    text tspan clippath mask lineargradient radialgradient stop foreignobject
    symbol marker pattern animate animatemotion
    """.split()
)

VOID_TAGS = frozenset(
    "area base br col embed hr img input link meta param source track wbr".split()
)

CONTAINER_TAGS_REMOVED_WHOLE = frozenset({"script", "style", "svg"})

# Tags that create an automatic request when rendered and are removed entirely
# (unwrappable container tags are handled by UNWRAP_TAGS instead).
AUTO_LOAD_TAGS = frozenset({"img", "link", "source", "track", "embed", "input"})

UNWRAP_TAGS = frozenset({"iframe", "frame", "object", "video", "audio", "form"})

TAG_URL_ATTRS = {
    "img": ("src", "data-src", "data-original", "srcset"),
    "iframe": ("src",),
    "frame": ("src",),
    "embed": ("src",),
    "object": ("data",),
    "video": ("src", "poster"),
    "audio": ("src",),
    "source": ("src", "srcset"),
    "track": ("src",),
    "input": ("src", "formaction"),
    "form": ("action",),
    "script": ("src",),
    "link": ("href",),
    "a": ("href",),
    "area": ("href",),
    "use": ("href", "xlink:href"),
    "image": ("href", "xlink:href"),
    "base": ("href",),
}

NON_RESOURCE_LINK_RELS = frozenset(
    {"canonical", "alternate", "author", "help", "license", "next", "prev", "search", "me", "bookmark"}
)

A11Y_SR_ONLY_CLASSES = frozenset(
    {"sr-only", "visually-hidden", "visuallyhidden", "screen-reader-only", "screen-reader-text", "a11y-hidden", "sronly"}
)

EVENT_HANDLER_RE = re.compile(r"^on[a-z]+$")

_HTML_TAG_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9:-]*)((?:[^>\"']|\"[^\"]*\"|'[^']*')*)>", re.S)
_HTML_CLOSE_TAG_RE = re.compile(r"</([a-zA-Z][a-zA-Z0-9:-]*)\s*>", re.S)
_HTML_ATTR_RE = re.compile(
    r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'>]+))", re.S
)
_BARE_URL_RE = re.compile(r"(?<![\w\"'=(<])(https?://[^\s<>\"'`]+)")
_AUTOLINK_RE = re.compile(r"<((?:https?|ftp)://[^>\s]+)>")
_CSS_URL_RE = re.compile(r"url\(\s*(?:\"([^\"]*)\"|'([^']*)'|([^)'\"]*?))\s*\)", re.I)
_INLINE_EVENT_ATTR_RE = re.compile(r"(?:^|\s)(on[a-zA-Z]+)\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)")


def _parse_attrs(attr_text: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for match in _HTML_ATTR_RE.finditer(attr_text):
        name = match.group(1).lower()
        value = match.group(2) if match.group(2) is not None else (
            match.group(3) if match.group(3) is not None else match.group(4)
        )
        attrs.setdefault(name, value or "")
    return attrs


def _has_boolean_attr(attr_text: str, name: str) -> bool:
    return re.search(r"(?:^|\s)" + re.escape(name) + r"(?:\s|=|$)", attr_text, re.I) is not None


def _css_urls(css: str) -> list[str]:
    urls: list[str] = []
    for match in _CSS_URL_RE.finditer(css):
        value = match.group(1) if match.group(1) is not None else (
            match.group(2) if match.group(2) is not None else match.group(3)
        )
        if value:
            urls.append(value.strip())
    return urls


# ---------------------------------------------------------------------------
# URL classification
# ---------------------------------------------------------------------------

WEBHOOK_DOMAINS = (
    "webhook.site",
    "requestbin.net",
    "requestbin.io",
    "requestbin.com",
    "pipedream.net",
    "hookbin.com",
    "burpcollaborator.net",
    "burpcollaborator.com",
    "oast.fun",
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "interact.sh",
    "interactsh.com",
    "canarytokens.com",
    "canarytokens.org",
    "beeceptor.com",
    "requestcatcher.com",
    "webhook.website",
    "ngrok.io",
    "ngrok.app",
    "ngrok-free.app",
    "serveo.net",
    "localtunnel.me",
)

WEBHOOK_PATH_RULES = (
    ("discord.com", ("/api/webhooks/",)),
    ("discordapp.com", ("/api/webhooks/",)),
    ("hooks.slack.com", ("/services/",)),
    ("api.telegram.org", ("/bot",)),
)

SUSPICIOUS_QUERY_KEYS = frozenset(
    {
        "d", "data", "q", "p", "payload", "c", "content", "t", "text", "token",
        "secret", "s", "x", "leak", "exfil", "msg", "message", "prompt",
        "conversation", "chat", "input", "output", "cookie", "auth", "key",
        "session", "creds", "credentials",
    }
)

_SENSITIVE_WORDS = (
    "secret", "password", "passwd", "token", "api key", "apikey", "cookie",
    "conversation", "session", "credential", "private", "ignore previous",
    "ignore the", "system prompt", "exfil", "send ",
)

INSTRUCTION_MARKERS = (
    "ignore previous",
    "ignore the",
    "disregard",
    "system prompt",
    "you are an",
    "you must",
    "do not tell",
    "exfiltrat",
    "send the",
    "send all",
    "send it",
    "conversation",
    "api key",
    "password",
    "secret",
    "token=",
    "http://",
    "https://",
)

_B64_RE = re.compile(r"^[A-Za-z0-9+/_=\-]{12,}$")
_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_COMMON_HASH_LENGTHS = frozenset({7, 8, 12, 32, 40, 64, 128})


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum(count / length * math.log2(count / length) for count in counts.values())


def _url_info(url: str) -> dict:
    raw = url.strip().strip("<>").strip()
    if raw.startswith("//"):
        raw = "https:" + raw
    info = {"raw": raw, "scheme": "", "host": "", "path": "", "query": "", "remote": False}
    if raw.startswith("data:"):
        info["scheme"] = "data"
        return info
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):", raw)
    if scheme_match:
        info["scheme"] = scheme_match.group(1).lower()
    try:
        parts = urllib.parse.urlsplit(raw if scheme_match else "http://" + raw)
    except ValueError:
        return info
    info["host"] = (parts.hostname or "").lower().rstrip(".")
    info["path"] = parts.path or ""
    info["query"] = parts.query or ""
    info["remote"] = bool(info["host"]) and info["scheme"] in ("http", "https")
    if not scheme_match and not raw.startswith("//"):
        info["remote"] = False  # relative path, no external request
    return info


def _normalize_domains(domains) -> tuple[str, ...]:
    if not domains:
        return ()
    if isinstance(domains, str):
        domains = [domains]
    normalized: list[str] = []
    for item in domains:
        value = str(item).strip().lower()
        if not value:
            continue
        if "://" in value:
            value = urllib.parse.urlsplit(value).hostname or ""
        value = value.strip().lstrip("*.").rstrip(".")
        if value and value not in normalized:
            normalized.append(value)
    return tuple(normalized)


def _host_allowed(host: str, domains: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    for domain in domains:
        if host == domain or host.endswith("." + domain):
            return True
    return False


def _match_webhook(host: str, path: str) -> str | None:
    host = host.lower().rstrip(".")
    for domain in WEBHOOK_DOMAINS:
        if host == domain or host.endswith("." + domain):
            return "known webhook/collaborator host %s" % domain
    for domain, prefixes in WEBHOOK_PATH_RULES:
        if host == domain or host.endswith("." + domain):
            for prefix in prefixes:
                if path.startswith(prefix):
                    return "known webhook endpoint %s%s..." % (domain, prefix)
    return None


def _decode_base64(value: str) -> str | None:
    value = value.replace("-", "+").replace("_", "/")
    value += "=" * (-len(value) % 4)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    printable = sum(1 for char in text if char.isprintable())
    if printable / len(text) < 0.9:
        return None
    if sum(1 for char in text if char.isalpha()) < 4:
        return None
    return text


def _exfil_value_reason(key: str, value: str) -> str | None:
    value = urllib.parse.unquote(value).strip()
    if len(value) < 12:
        return None
    key = key.lower()
    if _JWT_RE.match(value):
        return "JWT-like bearer token"
    decoded = None
    if _B64_RE.match(value) and len(value) >= 12:
        decoded = _decode_base64(value)
    if decoded:
        low = decoded.lower()
        if any(word in low for word in _SENSITIVE_WORDS):
            return "base64 payload decodes to sensitive-looking text %r" % _collapse(decoded, 60)
        if len(value) >= 16:
            return "base64-looking %d-character value" % len(value)
    if len(value) >= 20 and not _HEX_RE.match(value):
        classes = sum(
            (
                any(char.islower() for char in value),
                any(char.isupper() for char in value),
                any(char.isdigit() for char in value),
                any(not char.isalnum() for char in value),
            )
        )
        if classes >= 2 and _entropy(value) >= 3.4:
            return "long high-entropy value (%d chars, entropy %.2f bits/char)" % (len(value), _entropy(value))
    if key in SUSPICIOUS_QUERY_KEYS and len(value) >= 16 and _entropy(value) >= 3.0:
        return "long value in sensitive-looking parameter %r" % key
    return None


def _exfil_path_reason(segment: str) -> str | None:
    segment = urllib.parse.unquote(segment)
    if not (16 <= len(segment) <= 512):
        return None
    if _UUID_RE.match(segment):
        return None
    if _HEX_RE.match(segment) and len(segment) in _COMMON_HASH_LENGTHS:
        return None
    if _B64_RE.match(segment):
        decoded = _decode_base64(segment)
        if decoded:
            return "base64-looking path segment decodes to %r" % _collapse(decoded, 60)
    if len(segment) >= 24 and not _HEX_RE.match(segment) and _entropy(segment) >= 3.5:
        return "long high-entropy path segment (%d chars)" % len(segment)
    return None


def _exfil_reasons(info: dict) -> list[str]:
    reasons: list[str] = []
    webhook = _match_webhook(info["host"], info["path"])
    if webhook:
        reasons.append(webhook)
    for key, value in urllib.parse.parse_qsl(info["query"], keep_blank_values=True):
        reason = _exfil_value_reason(key, value)
        if reason:
            reasons.append("query %r: %s" % (key, reason))
    for segment in info["path"].split("/"):
        if not segment:
            continue
        reason = _exfil_path_reason(segment)
        if reason:
            reasons.append(reason)
    return reasons


def _looks_instructional(text: str) -> bool:
    low = text.lower()
    return any(marker in low for marker in INSTRUCTION_MARKERS)


# ---------------------------------------------------------------------------
# Hidden-content heuristics
# ---------------------------------------------------------------------------


def _split_css_declarations(css: str) -> list[str]:
    declarations: list[str] = []
    buffer: list[str] = []
    depth = 0
    quote: str | None = None
    for char in css:
        if quote is not None:
            buffer.append(char)
            if char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
            buffer.append(char)
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char == ";" and depth == 0:
            declarations.append("".join(buffer))
            buffer = []
            continue
        buffer.append(char)
    declarations.append("".join(buffer))
    return [declaration for declaration in declarations if declaration.strip()]


def _css_hiding_reasons(css: str) -> list[str]:
    reasons: list[str] = []
    declarations: dict[str, str] = {}
    for declaration in _split_css_declarations(css):
        if ":" not in declaration:
            continue
        prop, value = declaration.split(":", 1)
        prop = prop.strip().lower()
        value = value.strip().lower()
        declarations[prop] = value
        if prop == "display" and value.startswith("none"):
            reasons.append("display:none")
        elif prop == "visibility" and value in ("hidden", "collapse"):
            reasons.append("visibility:hidden")
        elif prop == "opacity":
            number = re.match(r"^([0-9.]+)", value)
            try:
                if number and float(number.group(1)) <= 0.05:
                    reasons.append("opacity<=0.05")
            except ValueError:
                pass
        elif prop == "font-size" and value in ("0", "0px", "0em", "0rem", "0%"):
            reasons.append("font-size:0")
        elif prop in ("width", "height") and value in ("0", "0px", "0em", "0rem"):
            reasons.append("zero-size")
        elif prop == "color" and value.replace(" ", "") in (
            "white",
            "#fff",
            "#ffffff",
            "rgb(255,255,255)",
            "rgba(255,255,255,1)",
        ):
            reasons.append("white-text")
        elif prop == "text-indent" and re.match(r"^-\d{3,}px$", value):
            reasons.append("negative text-indent")
        elif prop == "clip" and value.startswith("rect(0"):
            reasons.append("clip:rect(0...)")
        elif prop == "transform" and re.search(r"scale\(0(?:[.,]0*)?\)", value):
            reasons.append("transform:scale(0)")
    color = declarations.get("color")
    background = declarations.get("background-color") or declarations.get("background")
    if color and background and color.replace(" ", "") == background.replace(" ", ""):
        reasons.append("foreground equals background")
    return reasons


def _style_block_hiding(css: str) -> list[str]:
    reasons: list[str] = []
    for needle, label in (
        (r"display\s*:\s*none", "display:none"),
        (r"visibility\s*:\s*hidden", "visibility:hidden"),
        (r"opacity\s*:\s*0(?:[.][0-9]*)?\s*[;}]", "opacity:0"),
        (r"font-size\s*:\s*0(?:px|em|rem)?\s*[;}]", "font-size:0"),
        (r"color\s*:\s*(?:white|#fff(?:fff)?)\b", "white-text"),
        (r"text-indent\s*:\s*-\d{3,}px", "negative text-indent"),
        (r"clip\s*:\s*rect\(0", "clip:rect(0...)"),
    ):
        if re.search(needle, css, re.I):
            reasons.append(label)
    return reasons


def _element_inner_text(text: str, tag_name: str, tag_end: int) -> str:
    match = re.search(r"</" + re.escape(tag_name) + r"\s*>", text[tag_end:], re.I)
    if not match:
        return ""
    return text[tag_end : tag_end + match.start()]


# ---------------------------------------------------------------------------
# scan()
# ---------------------------------------------------------------------------


def scan(text: str, allow_domains=()) -> list[Finding]:
    """Return deterministic findings for exfiltration channels in ``text``.

    ``allow_domains`` is an iterable of trusted hostnames (subdomains included)
    whose remote loads are not reported.
    """
    domains = _normalize_domains(allow_domains)
    findings: list[Finding] = []
    code = _code_regions(text)
    comments = _comment_regions(text)
    inert: list[tuple[int, int]] = list(code) + list(comments)

    def add(code_name: str, kind: str, severity: str, start: int, end: int, message: str, data: dict | None = None):
        line, column = _line_col(text, start)
        findings.append(
            Finding(
                code=code_name,
                kind=kind,
                severity=severity,
                start=start,
                end=end,
                line=line,
                column=column,
                message=message,
                data=data or {},
            )
        )

    # --- HTML comments: invisible to the human, readable by agents ---------
    for start, end in comments:
        content = text[start + 4 : end - 3]
        if _looks_instructional(content):
            add(
                "EG-HIDDEN-COMMENT",
                "hidden-content",
                "high",
                start,
                end,
                "HTML comment carries instruction/exfiltration-like content invisible in the rendered page",
                {"excerpt": _collapse(content)},
            )
        elif content.strip():
            add(
                "EG-HIDDEN-COMMENT",
                "hidden-content",
                "medium",
                start,
                end,
                "HTML comment is invisible when rendered but still present in the text an agent reads",
                {"excerpt": _collapse(content, 80)},
            )

    # --- <script> and <style> blocks --------------------------------------
    tag_spans: list[tuple[int, int]] = []
    for match in _HTML_TAG_RE.finditer(text):
        if _in_regions(match.start(), inert):
            continue
        name = match.group(1).lower()
        if name not in HTML_TAGS:
            continue
        tag_spans.append((match.start(), match.end()))
        attrs = _parse_attrs(match.group(2))
        attr_text = match.group(2)

        # Inline event handlers execute code in the rendering context.
        for handler in _INLINE_EVENT_ATTR_RE.finditer(attr_text):
            add(
                "EG-ACTIVE-CONTENT",
                "active-content",
                "high",
                match.start(),
                match.end(),
                "inline event handler attribute %r executes in the rendering context" % handler.group(1),
                {"tag": name, "attribute": handler.group(1).lower()},
            )

        # Hidden via inline style.
        style = attrs.get("style", "")
        style_reasons = _css_hiding_reasons(style) if style else []
        class_attr = attrs.get("class", "").lower()
        sr_only = any(token in A11Y_SR_ONLY_CLASSES for token in re.split(r"\s+", class_attr) if token)
        aria_hidden = attrs.get("aria-hidden", "").strip().lower() == "true"
        hidden_attr = _has_boolean_attr(attr_text, "hidden") or _has_boolean_attr(attr_text, "inert")
        if style_reasons or aria_hidden or hidden_attr:
            inner = "" if name in VOID_TAGS else _element_inner_text(text, name, match.end())
            verdict = _looks_instructional(inner) or _looks_instructional(style)
            reasons = list(style_reasons)
            if aria_hidden:
                reasons.append("aria-hidden=true")
            if hidden_attr:
                reasons.append("hidden attribute")
            if sr_only and not verdict:
                add(
                    "EG-A11Y-HIDDEN",
                    "a11y",
                    "low",
                    match.start(),
                    match.end(),
                    "visually-hidden accessibility class (invisible to sighted users, still read by agents)",
                    {"tag": name, "reasons": reasons, "class": class_attr},
                )
            elif verdict:
                add(
                    "EG-HIDDEN-INJECTION",
                    "hidden-content",
                    "high",
                    match.start(),
                    match.end(),
                    "hidden element contains instruction/exfiltration-like content (agents may read it)",
                    {"tag": name, "reasons": reasons, "excerpt": _collapse(inner)},
                )
            else:
                add(
                    "EG-HIDDEN-STYLE",
                    "hidden-content",
                    "medium",
                    match.start(),
                    match.end(),
                    "element is hidden from the human but readable by agents: %s" % ", ".join(reasons),
                    {"tag": name, "reasons": reasons, "excerpt": _collapse(inner, 80)},
                )

        # Remote loads from a style attribute (background-image etc.).
        if style:
            for url in _css_urls(style):
                _analyze_url(add, url, "image", match.start(), match.end(), domains)

        # Tag-specific remote loads / active content.
        if name in CONTAINER_TAGS_REMOVED_WHOLE:
            if name == "script":
                add(
                    "EG-ACTIVE-CONTENT",
                    "active-content",
                    "high",
                    match.start(),
                    match.end(),
                    "<script> tag in model output executes code in the rendering context",
                    {"tag": name},
                )
            elif name == "style":
                block = _element_inner_text(text, name, match.end())
                reasons = _style_block_hiding(block)
                if reasons:
                    add(
                        "EG-HIDDEN-STYLE",
                        "hidden-content",
                        "medium",
                        match.start(),
                        match.end(),
                        "<style> block hides content from the human renderer: %s" % ", ".join(reasons),
                        {"tag": name, "reasons": reasons},
                    )
                for url in _css_urls(block):
                    _analyze_url(add, url, "image", match.start(), match.end(), domains)
            continue

        if name == "base":
            add(
                "EG-ACTIVE-CONTENT",
                "active-content",
                "high",
                match.start(),
                match.end(),
                "<base> tag can rebase every relative URL in the rendered document",
                {"tag": name, "href": _collapse(attrs.get("href", ""), 120)},
            )
            continue

        # <link>, <form> and <input formaction> are handled by dedicated blocks
        # below; avoid duplicate findings from the generic attribute loop.
        if name in ("link", "form"):
            pass
        else:
            for attribute in TAG_URL_ATTRS.get(name, ()):
                if name == "input" and attribute == "formaction":
                    continue
                value = attrs.get(attribute)
                if not value:
                    continue
                context = "link" if name in ("a", "area") else "image"
                if attribute == "srcset":
                    for candidate in value.split(","):
                        candidate = candidate.strip().split(" ")[0]
                        if candidate:
                            _analyze_url(add, candidate, context, match.start(), match.end(), domains)
                    continue
                if attribute in ("href", "xlink:href") and name in ("use", "image"):
                    context = "image"
                if attribute == "ping":
                    values = value.split()
                    for candidate in values:
                        _analyze_url(add, candidate, "image", match.start(), match.end(), domains)
                    continue
                _analyze_url(add, value, context, match.start(), match.end(), domains)

        ping = attrs.get("ping")
        if ping:
            add(
                "EG-PING-ATTR",
                "active-content",
                "high",
                match.start(),
                match.end(),
                "ping attribute sends extra requests to attacker-chosen URLs",
                {"urls": [value.strip() for value in ping.split() if value.strip()]},
            )

        if name == "form":
            action = attrs.get("action", "")
            if action:
                _analyze_url(add, action, "navigation", match.start(), match.end(), domains)

        if name == "input":
            formaction = attrs.get("formaction", "")
            src = attrs.get("src", "")
            if formaction:
                _analyze_url(add, formaction, "navigation", match.start(), match.end(), domains)
            if src:
                _analyze_url(add, src, "image", match.start(), match.end(), domains)

        # Meta refresh auto-navigates / auto-loads.
        if name == "meta":
            http_equiv = attrs.get("http-equiv", "").strip().lower()
            if http_equiv == "refresh":
                content = attrs.get("content", "")
                url_match = re.search(r"url\s*=\s*(.+)$", content, re.I)
                if url_match:
                    add(
                        "EG-REMOTE-ASSET",
                        "remote-load",
                        "medium",
                        match.start(),
                        match.end(),
                        "meta refresh automatically navigates the renderer to a remote URL",
                        {"url": _collapse(url_match.group(1).strip(), 200)},
                    )
                    _analyze_url(add, url_match.group(1).strip(), "navigation", match.start(), match.end(), domains)

        if name == "iframe" and attrs.get("srcdoc"):
            add(
                "EG-HIDDEN-CONTAINER",
                "hidden-content",
                "medium",
                match.start(),
                match.end(),
                "iframe srcdoc embeds inline HTML that renderers execute and agents read",
                {"excerpt": _collapse(attrs.get("srcdoc", ""), 120)},
            )

        if name in ("template", "noscript"):
            inner = _element_inner_text(text, name, match.end())
            if _looks_instructional(inner):
                add(
                    "EG-HIDDEN-INJECTION",
                    "hidden-content",
                    "high",
                    match.start(),
                    match.end(),
                    "<%s> content is not shown to the human but remains in the text/agent path" % name,
                    {"tag": name, "excerpt": _collapse(inner)},
                )
            elif inner.strip():
                add(
                    "EG-HIDDEN-CONTAINER",
                    "hidden-content",
                    "medium",
                    match.start(),
                    match.end(),
                    "<%s> content is hidden from the human renderer but readable by agents" % name,
                    {"tag": name, "excerpt": _collapse(inner, 80)},
                )

        if name == "link":
            rel = attrs.get("rel", "").strip().lower()
            href = attrs.get("href", "")
            if not href:
                continue
            rel_tokens = set(re.split(r"\s+", rel)) if rel else set()
            if rel_tokens and rel_tokens.issubset(NON_RESOURCE_LINK_RELS):
                _analyze_url(add, href, "link", match.start(), match.end(), domains)
            else:
                _analyze_url(add, href, "image", match.start(), match.end(), domains)

    # --- Markdown inline images and links ----------------------------------
    md_spans: list[tuple[int, int]] = []
    for target in _iter_markdown_targets(text):
        md_spans.append((target["start"], target["end"]))
        if _in_regions(target["start"], inert):
            continue
        context = "image" if target["image"] else "link"
        _analyze_url(add, target["url"], context, target["start"], target["end"], domains)

    # --- Markdown reference-style images/links and their definitions -------
    definitions = _reference_definitions(text)
    ref_spans: list[tuple[int, int]] = []
    for match in _MD_REF_USE_RE.finditer(text):
        if _in_regions(match.start(), inert):
            continue
        ref_spans.append((match.start(), match.end()))
        ref_key = _norm_ref(match.group(3) or match.group(2))
        definition = definitions.get(ref_key)
        if not definition:
            continue
        context = "image" if match.group(1) == "!" else "link"
        _analyze_url(add, definition["url"], context, match.start(), match.end(), domains)

    definition_spans = [
        (definition["start"], definition["end"])
        for definition in definitions.values()
        if not _in_regions(definition["start"], inert)
    ]

    # --- Autolinks and bare URLs ------------------------------------------
    autolink_spans: list[tuple[int, int]] = []
    for match in _AUTOLINK_RE.finditer(text):
        autolink_spans.append((match.start(), match.end()))
        if _in_regions(match.start(), inert):
            continue
        _analyze_url(add, match.group(1), "link", match.start(), match.end(), domains)

    skip_spans = tag_spans + md_spans + ref_spans + autolink_spans + definition_spans
    for match in _BARE_URL_RE.finditer(text):
        if _in_regions(match.start(), inert):
            continue
        if any(start <= match.start() < end for start, end in skip_spans):
            continue
        url = match.group(1).rstrip(".,;:!?)]}")
        info = _url_info(url)
        reasons = _exfil_reasons(info) if info["remote"] and not _host_allowed(info["host"], domains) else []
        if not reasons:
            continue
        webhook = _match_webhook(info["host"], info["path"]) is not None
        code_name = "EG-WEBHOOK" if webhook and len(reasons) == 1 else "EG-EXFIL-URL"
        add(
            code_name,
            "exfil-url",
            "high",
            match.start(),
            match.start() + len(url),
            "URL in rendered text carries encoded data to an untrusted endpoint",
            {"url": _collapse(url, 300), "host": info["host"], "reasons": reasons, "context": "text"},
        )

    # --- Deduplicate and order deterministically --------------------------
    unique: dict[tuple, Finding] = {}
    for finding in findings:
        unique.setdefault((finding.start, finding.end, finding.code), finding)
    return sorted(unique.values(), key=lambda finding: (finding.start, finding.end, finding.code))


def _analyze_url(add, url: str, context: str, start: int, end: int, domains: tuple[str, ...]) -> None:
    """Emit findings for one URL reference. Shared by scan() and clean()."""
    if not url or not url.strip():
        return
    raw = url.strip().strip("<>").strip()
    if not raw or raw.startswith("#"):
        return
    if raw.startswith("data:"):
        _analyze_data_uri(add, raw, context, start, end)
        return
    info = _url_info(raw)
    scheme = info["scheme"]
    if scheme in ("javascript", "vbscript"):
        add(
            "EG-ACTIVE-SCHEME",
            "active-content",
            "high",
            start,
            end,
            "%s: URL executes script in the rendering context" % scheme,
            {"url": _collapse(raw, 120), "scheme": scheme},
        )
        return
    if scheme == "file":
        add(
            "EG-ACTIVE-SCHEME",
            "active-content",
            "medium",
            start,
            end,
            "file: URL can read local resources in some renderers",
            {"url": _collapse(raw, 120), "scheme": scheme},
        )
        return
    if not info["remote"]:
        return  # relative/local reference: no external request
    if _host_allowed(info["host"], domains):
        return
    reasons = _exfil_reasons(info)
    webhook = _match_webhook(info["host"], info["path"])
    if reasons:
        code_name = "EG-WEBHOOK" if webhook and len(reasons) == 1 else "EG-EXFIL-URL"
        add(
            code_name,
            "exfil-url",
            "high",
            start,
            end,
            "remote URL carries data to an untrusted endpoint (%s)" % "; ".join(reasons[:3]),
            {"url": _collapse(raw, 300), "host": info["host"], "reasons": reasons, "context": context},
        )
    context_codes = {
        "image": ("EG-REMOTE-ASSET", "medium", "rendered output automatically loads a remote resource"),
        "link": ("EG-REMOTE-LINK", "low", "rendered output contains a link to a remote host (click required)"),
        "navigation": ("EG-REMOTE-ASSET", "medium", "rendered output automatically navigates to a remote URL"),
    }
    if context in context_codes:
        code_name, severity, message = context_codes[context]
        add(
            code_name,
            "remote-load",
            severity,
            start,
            end,
            message,
            {"url": _collapse(raw, 300), "host": info["host"], "context": context},
        )


def _analyze_data_uri(add, raw: str, context: str, start: int, end: int) -> None:
    header, _, payload = raw.partition(",")
    mime = header[5:].split(";")[0].strip().lower() if header.startswith("data:") else ""
    suspicious_mime = mime in (
        "text/html",
        "application/xhtml+xml",
        "image/svg+xml",
        "text/javascript",
        "application/javascript",
        "application/x-javascript",
    )
    decoded = None
    if ";base64" in header.lower():
        decoded = _decode_base64(payload.strip())
    if suspicious_mime or (decoded and ("<script" in decoded.lower() or "<html" in decoded.lower())):
        add(
            "EG-DATA-URI",
            "payload",
            "high",
            start,
            end,
            "data: URI embeds active content (%s)" % (mime or "unknown mime"),
            {"mime": mime, "context": context, "chars": len(raw)},
        )
        return
    add(
        "EG-DATA-URI",
        "payload",
        "medium",
        start,
        end,
        "inline data: URI payload (%s, %d chars) can carry hidden content" % (mime or "unknown mime", len(raw)),
        {"mime": mime, "context": context, "chars": len(raw)},
    )


# ---------------------------------------------------------------------------
# Markdown helpers
# ---------------------------------------------------------------------------

_MD_REF_USE_RE = re.compile(r"(!?)\[([^\]\n]*)\]\[\s*([^\]\n]*)\s*\]")
_MD_REF_DEF_RE = re.compile(
    r"(?m)^[ \t]{0,3}\[([^\]\n]+)\]:[ \t]*(<[^>\n]*>|[^\s]+)(?:[ \t]+(?:\"[^\"]*\"|'[^']*'|\([^)]*\)))?[ \t]*$"
)


def _norm_ref(ref: str) -> str:
    return re.sub(r"\s+", " ", ref.strip().lower())


def _reference_definitions(text: str) -> dict[str, dict]:
    definitions: dict[str, dict] = {}
    for match in _MD_REF_DEF_RE.finditer(text):
        url = match.group(2).strip()
        url = url[1:-1] if url.startswith("<") and url.endswith(">") else url
        definitions.setdefault(
            _norm_ref(match.group(1)),
            {"url": url, "start": match.start(), "end": match.end()},
        )
    return definitions


def _iter_markdown_targets(text: str):
    """Yield inline Markdown ``![alt](url)`` and ``[text](url)`` targets.

    Handles angle-bracket destinations, balanced parentheses in the destination
    and optional titles. Yields dicts with absolute offsets.
    """
    index = 0
    length = len(text)
    while index < length:
        close_bracket = text.find("](", index)
        if close_bracket < 0:
            return
        depth = 0
        start = None
        position = close_bracket - 1
        while position >= 0:
            char = text[position]
            if char == "]":
                depth += 1
            elif char == "[":
                if depth == 0:
                    start = position
                    break
                depth -= 1
            position -= 1
        if start is None:
            index = close_bracket + 2
            continue
        position = close_bracket + 2
        while position < length and text[position] in " \t":
            position += 1
        if position < length and text[position] == "<":
            closing = text.find(">", position + 1)
            if closing < 0:
                index = close_bracket + 2
                continue
            url = text[position + 1 : closing]
            url_start, url_end = position + 1, closing
            after = closing + 1
        else:
            url_start = position
            paren_depth = 0
            while position < length:
                char = text[position]
                if char == "(":
                    paren_depth += 1
                elif char == ")":
                    if paren_depth == 0:
                        break
                    paren_depth -= 1
                elif char in " \t\n" and paren_depth == 0:
                    break
                position += 1
            url = text[url_start:position]
            url_end = position
            after = position
        if not url:
            index = close_bracket + 2
            continue
        closing = text.find(")", after)
        if closing < 0:
            index = close_bracket + 2
            continue
        label = text[start + 1 : close_bracket]
        image = start > 0 and text[start - 1] == "!"
        yield {
            "start": start - 1 if image else start,
            "end": closing + 1,
            "image": image,
            "label": label,
            "url": url,
            "url_start": url_start,
            "url_end": url_end,
        }
        index = closing + 1


# ---------------------------------------------------------------------------
# clean()
# ---------------------------------------------------------------------------

_CLEAN_CONTAINER_RE = re.compile(r"(?is)<(script|style|svg)\b[^>]*>.*?</\1\s*>")
_CLEAN_CONTAINER_OPEN_RE = re.compile(r"(?is)<(script|style|svg)\b[^>]*/?>")
_COMMENT_RE = re.compile(r"(?s)<!--.*?-->")


def _url_blocked_for_load(url: str, domains: tuple[str, ...]) -> bool:
    """True when a URL would create a request the cleaner should remove."""
    raw = url.strip().strip("<>").strip()
    if not raw or raw.startswith("#"):
        return False
    if raw.startswith("data:"):
        return True
    info = _url_info(raw)
    if info["scheme"] in ("javascript", "vbscript", "file"):
        return True
    if info["remote"]:
        return not _host_allowed(info["host"], domains)
    return False


def _strip_attrs(raw_tag: str, names: set[str]) -> str:
    def replace(match: re.Match) -> str:
        return "" if match.group(1).lower() in names else match.group(0)

    return _HTML_ATTR_RE.sub(replace, raw_tag)


def _tag_url_values(name: str, attrs: dict[str, str]) -> list[str]:
    values: list[str] = []
    for attribute in TAG_URL_ATTRS.get(name, ()):
        value = attrs.get(attribute, "")
        if not value:
            continue
        if attribute == "srcset":
            for candidate in value.split(","):
                candidate = candidate.strip().split(" ")[0]
                if candidate:
                    values.append(candidate)
        else:
            values.append(value)
    return values


def _clean_tag(match: re.Match, domains: tuple[str, ...], removed: dict, state: dict) -> str:
    name = match.group(1).lower()
    raw = match.group(0)
    attr_text = match.group(2) if match.re.groups >= 2 else ""
    if name not in HTML_TAGS:
        return raw
    attrs = _parse_attrs(attr_text)

    def count(key: str) -> None:
        removed[key] = removed.get(key, 0) + 1

    if name in ("script", "style", "svg"):
        count("block element (<%s>)" % name)
        return ""
    if name == "base":
        count("<base> rebasing tag")
        return ""
    if name == "meta":
        if attrs.get("http-equiv", "").strip().lower() == "refresh":
            count("<meta> refresh navigation")
            return ""
        return raw
    if name in ("template", "noscript"):
        # Inert containers: never loaded when the page is rendered, keep the text.
        return raw
    if name == "link":
        rel_tokens = set(re.split(r"\s+", attrs.get("rel", "").strip().lower())) if attrs.get("rel") else set()
        if rel_tokens and rel_tokens.issubset(NON_RESOURCE_LINK_RELS):
            return raw  # metadata link, not a resource load

    urls = _tag_url_values(name, attrs)
    blocked = any(_url_blocked_for_load(url, domains) for url in urls)
    active = any(_url_info(url)["scheme"] in ("javascript", "vbscript", "data") for url in urls)
    if name in AUTO_LOAD_TAGS and (blocked or active):
        if name == "link":
            count("remote <link> resource")
            return ""
        elif name == "img":
            count("remote <img> beacon")
            alt = attrs.get("alt", "")
            return alt if alt else ""
        elif name == "input":
            count("remote <input> resource")
            return ""
        else:
            count("remote <%s> resource" % name)
            return ""
    if name in UNWRAP_TAGS and (blocked or active):
        count("remote <%s> embed" % name)
        state["unwrap"][name] = state["unwrap"].get(name, 0) + 1
        return ""
    if name == "a" or name == "area":
        href = attrs.get("href", "")
        changed = raw
        if href and _url_info(href)["scheme"] in ("javascript", "vbscript", "data"):
            count("active-scheme link")
            changed = _strip_attrs(changed, {"href"})
        if "ping" in attrs:
            count("ping attribute")
            changed = _strip_attrs(changed, {"ping"})
        return changed
    if "ping" in attrs:
        count("ping attribute")
        raw = _strip_attrs(raw, {"ping"})
        attrs = _parse_attrs(attr_text)
    style = attrs.get("style", "")
    if style and _css_urls(style):
        count("CSS url() in style attribute")
        raw = _strip_attrs(raw, {"style"})
        attrs = {key: value for key, value in attrs.items() if key != "style"}
    handlers = {attribute for attribute in attrs if EVENT_HANDLER_RE.match(attribute)}
    if handlers:
        count("inline event handler attribute")
        raw = _strip_attrs(raw, handlers)
    return raw


def _clean_close_tag(match: re.Match, removed: dict, state: dict) -> str:
    name = match.group(1).lower()
    if name in ("script", "style", "svg"):
        return ""
    if name in UNWRAP_TAGS and state["unwrap"].get(name, 0) > 0:
        state["unwrap"][name] -= 1
        removed["remote <%s> embed" % name] = removed.get("remote <%s> embed" % name, 0) + 1
        return ""
    return match.group(0)


def _strip_hidden_attack_containers(segment: str, removed: dict) -> str:
    """Remove hidden elements whose content is an instruction/exfiltration payload.

    The content is invisible to the human reader, so removing it preserves the
    visible text exactly. Accessibility-only hiding classes are left alone.
    """
    edits: list[tuple[int, int, str]] = []
    for match in _HTML_TAG_RE.finditer(segment):
        name = match.group(1).lower()
        if name not in HTML_TAGS or name in VOID_TAGS or name in CONTAINER_TAGS_REMOVED_WHOLE:
            continue
        attr_text = match.group(2) if match.re.groups >= 2 else ""
        attrs = _parse_attrs(attr_text)
        class_attr = attrs.get("class", "").lower()
        if any(token in A11Y_SR_ONLY_CLASSES for token in re.split(r"\s+", class_attr) if token):
            continue
        reasons = _css_hiding_reasons(attrs.get("style", ""))
        aria_hidden = attrs.get("aria-hidden", "").strip().lower() == "true"
        hidden_attr = _has_boolean_attr(attr_text, "hidden") or _has_boolean_attr(attr_text, "inert")
        if not (reasons or aria_hidden or hidden_attr):
            continue
        inner = _element_inner_text(segment, name, match.end())
        if not (_looks_instructional(inner) or _looks_instructional(attrs.get("style", ""))):
            continue
        closing = re.search(r"</" + re.escape(name) + r"\s*>", segment[match.end() :], re.I)
        if not closing:
            continue
        edits.append((match.start(), match.end() + closing.end(), "hidden instruction container (<%s>)" % name))
    if not edits:
        return segment
    pieces: list[str] = []
    cursor = 0
    for start, end, key in edits:
        if start < cursor:
            continue
        pieces.append(segment[cursor:start])
        cursor = end
        removed[key] = removed.get(key, 0) + 1
    pieces.append(segment[cursor:])
    return "".join(pieces)


def _clean_segment(segment: str, domains: tuple[str, ...], removed: dict) -> str:
    state: dict = {"unwrap": {}}

    # 0a) Hidden instruction containers: invisible text, removed to preserve
    #     the visible text while disarming the payload the agent would read.
    segment = _strip_hidden_attack_containers(segment, removed)

    # 0b) Stash comments so their content is never treated as live markup. They
    #     are restored afterwards unless they carry a blocked remote URL.
    comments: list[str] = []

    def stash_comment(match: re.Match) -> str:
        comments.append(match.group(0))
        return "\x00CMT%d\x00" % (len(comments) - 1)

    segment = _COMMENT_RE.sub(stash_comment, segment)

    # 1) Whole-block removals first (script/style/svg content is not visible text).
    segment = _CLEAN_CONTAINER_RE.sub(lambda m: _clean_tag(m, domains, removed, state), segment)
    segment = _CLEAN_CONTAINER_OPEN_RE.sub(lambda m: _clean_tag(m, domains, removed, state), segment)

    # 2) Tags, and tags that need attribute surgery.
    segment = _HTML_TAG_RE.sub(lambda m: _clean_tag(m, domains, removed, state), segment)
    segment = _HTML_CLOSE_TAG_RE.sub(lambda m: _clean_close_tag(m, removed, state), segment)

    # 3) Reference definitions and their uses.
    definitions = _reference_definitions(segment)
    def_removal_spans: list[tuple[int, int]] = []
    for definition in definitions.values():
        if _url_blocked_for_load(definition["url"], domains):
            def_removal_spans.append((definition["start"], definition["end"]))
            removed["remote reference definition"] = removed.get("remote reference definition", 0) + 1

    # Remove definition lines first: the spans are computed on the current text
    # and would otherwise go stale once reference usages are rewritten below.
    if def_removal_spans:
        pieces = []
        cursor = 0
        for start, end in def_removal_spans:
            pieces.append(segment[cursor:start])
            cursor = end
        pieces.append(segment[cursor:])
        segment = "".join(pieces)

    def use_replacement(match: re.Match) -> str:
        image = match.group(1) == "!"
        ref_key = _norm_ref(match.group(3) or match.group(2))
        definition = definitions.get(ref_key)
        if not definition:
            return match.group(0)
        if _url_blocked_for_load(definition["url"], domains):
            key = "remote reference image" if image else "remote reference link target"
            removed[key] = removed.get(key, 0) + 1
            return match.group(2)
        return match.group(0)

    segment = _MD_REF_USE_RE.sub(use_replacement, segment)

    # 4) Inline Markdown images: replace a blocked image with its alt text.
    pieces = []
    cursor = 0
    for target in _iter_markdown_targets(segment):
        url = target["url"]
        blocked = target["image"] and _url_blocked_for_load(url, domains)
        active_link = (not target["image"]) and _url_info(url)["scheme"] in ("javascript", "vbscript", "data")
        if not blocked and not active_link:
            continue
        pieces.append(segment[cursor : target["start"]])
        pieces.append(target["label"])
        cursor = target["end"]
        key = "remote Markdown image" if blocked else "active-scheme Markdown link"
        removed[key] = removed.get(key, 0) + 1
    if pieces:
        pieces.append(segment[cursor:])
        segment = "".join(pieces)

    # 5) Restore safe comments; drop comments with hidden instructions or
    #    blocked remote URLs (comments are invisible, so nothing visible is lost).
    def restore_comment(match: re.Match) -> str:
        body = comments[int(match.group(1))]
        urls = _BARE_URL_RE.findall(body)
        if any(_url_blocked_for_load(url, domains) for url in urls):
            removed["HTML comment carrying a remote URL"] = (
                removed.get("HTML comment carrying a remote URL", 0) + 1
            )
            return ""
        if _looks_instructional(body):
            removed["HTML comment with hidden instruction"] = (
                removed.get("HTML comment with hidden instruction", 0) + 1
            )
            return ""
        return body

    return re.sub(r"\x00CMT(\d+)\x00", restore_comment, segment)


def _strip_text(text: str, domains: tuple[str, ...]) -> tuple[str, dict]:
    removed: dict[str, int] = {}
    code = _code_regions(text)
    result: list[str] = []
    cursor = 0
    for start, end in code:
        if cursor < start:
            result.append(_clean_segment(text[cursor:start], domains, removed))
        result.append(text[start:end])
        cursor = end
    if cursor < len(text):
        result.append(_clean_segment(text[cursor:], domains, removed))
    return "".join(result), removed


def clean(text: str, mode: str = "strip", allow_domains=()) -> str | dict:
    """Remove or neutralize remote loads in rendered Markdown/HTML output.

    ``mode="strip"``       remove every remote/external load, return the text.
    ``mode="allowlist"``   keep loads only for ``allow_domains``; remove others.
    ``mode="report"``      return a dict with findings, cleaned text and counts.
    """
    if mode not in ("strip", "allowlist", "report"):
        raise ValueError("mode must be one of: strip, allowlist, report")
    domains = _normalize_domains(allow_domains)
    if mode == "report":
        findings = scan(text, allow_domains=domains)
        cleaned, removed = _strip_text(text, domains)
        return {
            "tool": "exfil-guard",
            "version": VERSION,
            "mode": "report",
            "characters": len(text),
            "lines": text.count("\n") + 1,
            "summary": summarize(findings),
            "findings": [finding.to_dict() for finding in findings],
            "cleaned": cleaned,
            "removed": removed,
        }
    effective = domains if mode == "allowlist" else ()
    cleaned, _ = _strip_text(text, effective)
    return cleaned


# ---------------------------------------------------------------------------
# CLI formatting helpers
# ---------------------------------------------------------------------------


def format_finding_line(finding: Finding) -> str:
    return "%s %-20s line %d col %d  %s" % (
        finding.severity.upper().ljust(6),
        finding.code,
        finding.line,
        finding.column,
        finding.message,
    )
