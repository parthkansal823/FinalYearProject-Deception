"""
Injection channels and the rendered-output comparator (spec §6.7, §3.2).

The whole safety claim of this project rests on one property: bait must be
invisible to a normal user. Spec §3.2 states the mechanism precisely -- "A real
user sees a generic message. Somebody hunting for database structure sees a
name worth querying." The bait therefore lives in parts of the response a
browser does NOT display, while the rendered page is byte-for-byte what it
would have been.

This module provides:

  * the three non-rendered injection CHANNELS every bait is allowed to use,
    each chosen because a browser ignores it when painting the page:
      - html_comment    : <!-- ... -->, never rendered
      - json_field      : an additive key a client that reads by name ignores
      - response_header : visible only in raw traffic
  * `rendered_signature`, which reduces an HTTP response to exactly what a user
    would perceive -- visible text plus the interactive structure (forms,
    inputs, links) -- so the invisibility gate can compare "what the browser
    displays" rather than raw bytes.

No bait may write into a rendered channel. A hidden <input>, a visible error
string, a changed field value -- all are forbidden and the gate rejects them.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from bs4 import BeautifulSoup, Comment

# Channels a bait may use. Anything else is a rendered channel and is banned.
CHANNELS = ("html_comment", "json_field", "response_header")


@dataclass
class BaitedResponse:
    """A response after (possibly) injecting bait. Mirrors the small slice of
    an HTTP response the bait engine and gate care about."""

    body: str
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str = "text/html"
    status: int = 200

    def clone(self) -> "BaitedResponse":
        return BaitedResponse(body=self.body, headers=dict(self.headers),
                              content_type=self.content_type, status=self.status)


# ---------------------------------------------------------------------------
# Injection
# ---------------------------------------------------------------------------


def inject_html_comment(response: BaitedResponse, payload: str) -> BaitedResponse:
    """Append an HTML comment carrying the bait, just before </body> (or at the
    end if there is no body tag). Comments are never rendered, so an attacker
    reading source sees the payload while the page is visually unchanged."""
    out = response.clone()
    comment = f"<!-- {payload} -->"
    lower = out.body.lower()
    idx = lower.rfind("</body>")
    if idx == -1:
        out.body = out.body + comment
    else:
        out.body = out.body[:idx] + comment + out.body[idx:]
    return out


def inject_json_field(response: BaitedResponse, key: str, value: Any) -> BaitedResponse:
    """Add a top-level key to a JSON object response. A client that reads the
    fields it knows by name never sees the addition; only somebody editing the
    raw response by hand would (spec §6.6, B-IDOR-1)."""
    out = response.clone()
    doc = json.loads(out.body)
    if not isinstance(doc, dict):
        raise BaitInjectionError("json_field channel requires a top-level JSON object")
    if key in doc:
        raise BaitInjectionError(f"json_field key {key!r} already exists; would overwrite a real field")
    doc[key] = value
    out.body = json.dumps(doc)
    return out


def inject_response_header(response: BaitedResponse, name: str, value: str) -> BaitedResponse:
    """Add an HTTP response header. Not rendered; visible only in raw traffic."""
    out = response.clone()
    if name.lower() in {k.lower() for k in out.headers}:
        raise BaitInjectionError(f"response header {name!r} already present; would overwrite")
    out.headers[name] = value
    return out


class BaitInjectionError(RuntimeError):
    """Raised when an injection cannot be performed safely (e.g. it would
    overwrite real content). A bait that cannot inject safely is rejected."""


# ---------------------------------------------------------------------------
# Rendered-output comparison (the invisibility measurement)
# ---------------------------------------------------------------------------

_WS = re.compile(r"\s+")


@dataclass(frozen=True)
class RenderedSignature:
    """What a browser would actually present to a user. Two responses with
    equal signatures are, by definition of §6.7, indistinguishable on screen."""

    visible_text: str
    forms: tuple           # (action, method, (input-name, input-type)...)
    links: tuple           # hrefs in document order
    # For JSON responses, the parsed content the client consumes.
    json_shape: tuple | None = None


def rendered_signature(response: BaitedResponse) -> RenderedSignature:
    ctype = (response.content_type or "").lower()
    if "json" in ctype or _looks_like_json(response.body):
        return _json_signature(response.body)
    return _html_signature(response.body)


def _looks_like_json(body: str) -> bool:
    s = body.lstrip()
    return s[:1] in ("{", "[")


def _json_signature(body: str) -> RenderedSignature:
    try:
        doc = json.loads(body)
    except json.JSONDecodeError:
        # not actually JSON; fall back to treating it as text
        return RenderedSignature(visible_text=_WS.sub(" ", body).strip(), forms=(), links=())
    return RenderedSignature(visible_text="", forms=(), links=(), json_shape=_freeze(doc))


def _html_signature(body: str) -> RenderedSignature:
    soup = BeautifulSoup(body, "html.parser")

    # Strip everything a browser does not paint: comments, scripts, styles, and
    # explicitly hidden elements.
    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
        comment.extract()
    for tag in soup(["script", "style", "template"]):
        tag.decompose()
    for tag in soup.find_all(_is_hidden):
        tag.decompose()

    visible_text = _WS.sub(" ", soup.get_text(separator=" ")).strip()

    forms = []
    for form in soup.find_all("form"):
        inputs = tuple(
            (i.get("name", ""), i.get("type", i.name))
            for i in form.find_all(["input", "select", "textarea", "button"])
        )
        forms.append((form.get("action", ""), (form.get("method", "get") or "get").lower(), inputs))

    links = tuple(a.get("href", "") for a in soup.find_all("a"))
    return RenderedSignature(visible_text=visible_text, forms=tuple(forms), links=links)


def _is_hidden(tag) -> bool:
    if tag.has_attr("hidden"):
        return True
    if tag.get("aria-hidden") == "true":
        return True
    if tag.get("type") == "hidden":
        return True
    style = (tag.get("style") or "").replace(" ", "").lower()
    return "display:none" in style or "visibility:hidden" in style


def _freeze(obj: Any) -> Any:
    """A hashable, order-independent shape for a JSON document, used to compare
    what a client consumes."""
    if isinstance(obj, dict):
        return tuple(sorted((k, _freeze(v)) for k, v in obj.items()))
    if isinstance(obj, list):
        return tuple(_freeze(v) for v in obj)
    return obj


# ---------------------------------------------------------------------------
# The invisibility comparison itself
# ---------------------------------------------------------------------------


@dataclass
class InvisibilityDiff:
    """Why (or that) a baited response differs from the clean one on screen."""

    identical: bool
    reasons: list[str] = field(default_factory=list)


def compare_rendered(clean: BaitedResponse, baited: BaitedResponse) -> InvisibilityDiff:
    """Are the two responses indistinguishable to a user (spec §6.7)?

    For HTML: identical visible text, forms and links.
    For JSON: the baited response may only ADD top-level keys; every key the
    clean response contained must survive unchanged, because a client reads the
    fields it knows and an additive key is precisely what it ignores.
    """
    reasons: list[str] = []
    cs, bs = rendered_signature(clean), rendered_signature(baited)

    if (cs.json_shape is not None) or (bs.json_shape is not None):
        return _compare_json(clean.body, baited.body)

    if cs.visible_text != bs.visible_text:
        reasons.append("visible text differs")
    if cs.forms != bs.forms:
        reasons.append("form/input structure differs")
    if cs.links != bs.links:
        reasons.append("links differ")
    return InvisibilityDiff(identical=not reasons, reasons=reasons)


def _compare_json(clean_body: str, baited_body: str) -> InvisibilityDiff:
    reasons: list[str] = []
    try:
        clean = json.loads(clean_body)
        baited = json.loads(baited_body)
    except json.JSONDecodeError:
        return InvisibilityDiff(identical=False, reasons=["response is not valid JSON after injection"])

    if not isinstance(clean, dict) or not isinstance(baited, dict):
        # non-object JSON: must be byte-identical, since there is no additive
        # key to hide behind
        identical = _freeze(clean) == _freeze(baited)
        return InvisibilityDiff(identical=identical,
                                reasons=[] if identical else ["non-object JSON changed"])

    for key, value in clean.items():
        if key not in baited:
            reasons.append(f"clean key {key!r} was removed")
        elif _freeze(baited[key]) != _freeze(value):
            reasons.append(f"clean key {key!r} was modified")
    return InvisibilityDiff(identical=not reasons, reasons=reasons)
