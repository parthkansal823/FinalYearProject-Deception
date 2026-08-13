"""
Session identification for the proxy (spec §5.2 step 2).

The proxy groups requests into sessions using a cookie, falling back to a
client fingerprint when no cookie is carried (FR-02). The fingerprint matters
for the threat model: an attack tool that does not persist cookies would
otherwise get a fresh session per request and never accumulate a score, which
is precisely the evasion the accumulating meter exists to resist. So a
cookieless client is still tracked, by the stable parts of its request.
"""

from __future__ import annotations

import hashlib
import secrets

from fastapi import Request
from fastapi.responses import Response


class SessionRegistry:
    def __init__(self, *, cookie_name: str = "adf_sid", fingerprint_fallback: bool = True) -> None:
        self.cookie_name = cookie_name
        self.fingerprint_fallback = fingerprint_fallback
        # fingerprint -> synthetic session id, so a cookieless client keeps one
        # identity across requests
        self._by_fingerprint: dict[str, str] = {}

    def resolve(self, request: Request) -> tuple[str, str, bool]:
        """Return (session_id, fingerprint, is_new)."""
        fingerprint = self._fingerprint(request)

        cookie = request.cookies.get(self.cookie_name)
        if cookie:
            return cookie, fingerprint, False

        if self.fingerprint_fallback:
            existing = self._by_fingerprint.get(fingerprint)
            if existing:
                return existing, fingerprint, False
            sid = "fp-" + secrets.token_hex(12)
            self._by_fingerprint[fingerprint] = sid
            return sid, fingerprint, True

        return "sid-" + secrets.token_hex(12), fingerprint, True

    def attach(self, response: Response, session_id: str) -> None:
        # Only set a cookie for real (non-fingerprint) sessions, so that a
        # client that refuses cookies is not handed a new one every response.
        if not session_id.startswith("fp-"):
            response.set_cookie(self.cookie_name, session_id, httponly=True, samesite="lax", path="/")

    @staticmethod
    def _fingerprint(request: Request) -> str:
        """A stable-ish identity from headers a tool tends to keep constant.

        Deliberately coarse. It is not meant to be unforgeable — an attacker who
        rotates every header defeats it — only to stop the trivial evasion of
        dropping cookies. The remote address anchors it so unrelated clients do
        not collide.
        """
        parts = [
            request.client.host if request.client else "",
            request.headers.get("user-agent", ""),
            request.headers.get("accept-language", ""),
            request.headers.get("accept-encoding", ""),
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:24]
