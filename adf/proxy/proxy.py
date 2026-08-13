"""
The reverse proxy (spec §5, FR-01, NFR-04, NFR-10).

Every request passes through here before reaching anything real. This is the
one component that sees the whole pipeline, and the architecture is built
around it for three reasons spec §5.3 spells out:

  * the target application never needs to know the security system exists, so
    it can be swapped without touching detection code (NFR-10);
  * turning scoring/bait off (via `mode`) converts the system into an ordinary
    passive classifier — the same code path serves the contribution and every
    baseline (§5.3, FR-12);
  * it is a single point of failure, so it MUST fail open: if any detection
    component raises, the request is still forwarded to the real application
    rather than dropped (NFR-04). The security layer must never be able to
    take the site down.

WHAT THIS FILE DOES TODAY (Phase 3)
-----------------------------------
Forwards to the target, scores each request with the dual meter, applies the
cost-weighted policy, and logs the full record. In `b2_passive` that is the
entire behaviour and it is baseline B2. Bait injection (Phase 4) and decoy
routing (Phase 5) are left as explicit, empty hooks — `_maybe_inject_bait`
and `_route_upstream` — so those phases extend rather than rewrite this.

The proxy holds per-session state (the streaming feature extractor and the
running scores) in memory. A single worker keeps that state coherent and the
corpus reproducible, which is why the app is meant to run unreplicated.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response

from adf.config import system
from adf.features import SessionFeatureExtractor
from adf.logstore import LogStore, default_log_path
from adf.meter import DualMeter
from adf.policy.engine import DecisionPolicy
from adf.schema import Record, ReasonItem
from adf.proxy.session import SessionRegistry

# Hop-by-hop headers must not be forwarded verbatim (RFC 7230 §6.1); doing so
# corrupts the proxied response.
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length", "content-encoding",
}


@dataclass
class SessionState:
    """Per-session detection state. Scores accumulate; they do not reset each
    request (spec §5.2, §6.4)."""

    extractor: SessionFeatureExtractor = field(default_factory=SessionFeatureExtractor)
    automation: float = 0.0
    malice: float = 0.0
    request_index: int = 0
    diverted: bool = False          # once true, the session lives in the decoy (Phase 5)


class Proxy:
    """Holds the wiring. Kept as a class so tests can construct one with a
    stub meter and a temporary log rather than the process-wide singletons."""

    def __init__(
        self,
        *,
        meter: DualMeter | None = None,
        policy: DecisionPolicy | None = None,
        target_upstream: str | None = None,
        decoy_upstream: str | None = None,
        log: LogStore | None = None,
    ) -> None:
        self.cfg = system()
        self.mode = self.cfg.mode
        self.scoring_enabled = self.cfg.scoring_enabled
        self.fail_open = bool(self.cfg.get("proxy.fail_open", True))
        self.timeout = float(self.cfg.get("proxy.upstream_timeout_seconds", 10.0))

        self.target_upstream = target_upstream or self.cfg.get("network.target_upstream", "http://127.0.0.1:8001")
        self.decoy_upstream = decoy_upstream or self.cfg.get("network.decoy_upstream", "http://127.0.0.1:8002")

        self.meter = meter
        self.policy = policy
        self.sessions = SessionRegistry(
            cookie_name=self.cfg.get("session.cookie_name", "adf_sid"),
            fingerprint_fallback=bool(self.cfg.get("session.fingerprint_fallback", True)),
        )
        self._state: dict[str, SessionState] = {}
        self.log = log or LogStore(default_log_path("proxy", self.cfg.log_dir))
        self._client = httpx.AsyncClient(timeout=self.timeout)

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- the request path (spec §5.2) -------------------------------------

    async def handle(self, request: Request) -> Response:
        started = time.perf_counter()
        body = await request.body()
        session_id, fingerprint, is_new = self.sessions.resolve(request)
        state = self._state.setdefault(session_id, SessionState())
        state.request_index += 1

        # Forward FIRST. Detection must never delay or block the response path
        # in a way that could fail closed; scoring happens around the forward
        # and, if it raises, we have already served the user (NFR-04).
        upstream = self._route_upstream(state)
        try:
            upstream_response = await self._forward(request, body, upstream)
        except httpx.HTTPError as exc:
            # Upstream itself failed. This is not a detection failure; surface a
            # 502 but still log it so the corpus is complete.
            elapsed = (time.perf_counter() - started) * 1000.0
            self._log(request, body, None, state, session_id, fingerprint,
                      decision=None, elapsed_ms=elapsed, fail_open=False,
                      note=f"upstream error: {exc}")
            return Response(content=b"upstream unavailable", status_code=502)

        # Score and decide, wrapped so a detection bug fails open.
        decision = None
        fail_open_triggered = False
        try:
            if self.scoring_enabled and self.meter is not None and self.policy is not None:
                decision = self._score_and_decide(request, body, upstream_response,
                                                   state, session_id)
        except Exception as exc:  # noqa: BLE001 - fail open is the whole point
            fail_open_triggered = True
            if not self.fail_open:
                raise
            # swallow: the response is already in hand, the user is unaffected
            decision = None
            _ = exc

        response = self._build_response(upstream_response)
        response = self._maybe_inject_bait(response, decision, state)   # Phase 4 hook
        self.sessions.attach(response, session_id)

        elapsed = (time.perf_counter() - started) * 1000.0
        self._log(request, body, upstream_response, state, session_id, fingerprint,
                  decision=decision, elapsed_ms=elapsed, fail_open=fail_open_triggered)
        return response

    # -- forwarding --------------------------------------------------------

    def _route_upstream(self, state: SessionState) -> str:
        """Where this request goes. Once a session is diverted it stays in the
        decoy (Phase 5); until then, the real application."""
        if state.diverted and self.cfg.decoy_enabled:
            return self.decoy_upstream
        return self.target_upstream

    async def _forward(self, request: Request, body: bytes, upstream: str) -> httpx.Response:
        url = upstream.rstrip("/") + request.url.path
        if request.url.query:
            url += "?" + request.url.query
        fwd_headers = {k: v for k, v in request.headers.items()
                       if k.lower() not in _HOP_BY_HOP and k.lower() != "host"}
        return await self._client.request(
            request.method, url, headers=fwd_headers, content=body,
            cookies=request.cookies, follow_redirects=False,
        )

    def _build_response(self, upstream: httpx.Response) -> Response:
        headers = {k: v for k, v in upstream.headers.items() if k.lower() not in _HOP_BY_HOP}
        return Response(content=upstream.content, status_code=upstream.status_code,
                        headers=headers, media_type=upstream.headers.get("content-type"))

    # -- scoring + decision (spec §5.2 steps 3-5) -------------------------

    def _score_and_decide(self, request: Request, body: bytes, upstream: httpx.Response,
                          state: SessionState, session_id: str):
        record = self._to_record(request, body, upstream, state, session_id)
        vector = state.extractor.observe(record)

        scores = self.meter.score(vector)
        state.automation = scores.automation
        state.malice = scores.malice

        contributions = [
            ReasonItem(feature=c.feature, value=c.value, weight=c.weight, contribution=c.contribution)
            for c in scores.malice_expl.top(5)
        ]
        decision = self.policy.decide(
            session_id=session_id,
            automation=scores.automation,
            malice=scores.malice,
            suspected_categories=self._suspected_categories(vector),
            feature_contributions=contributions,
        )
        if decision.action == "divert":
            state.diverted = True   # subsequent requests route to the decoy (Phase 5)
        # stash for logging
        state._last_scores = scores  # type: ignore[attr-defined]
        return decision

    @staticmethod
    def _suspected_categories(vector: dict[str, float]) -> list[str]:
        """A cheap guess at what the visitor is attempting, used only to pick
        which baits are relevant (spec §6.6). Not a classification — the meter
        does that — just routing."""
        cats = []
        if vector.get("mal_db_keyword_hits", 0) > 0 or vector.get("mal_special_char_ratio", 0) > 0.1:
            cats.append("sqli")
        if vector.get("mal_seq_id_run", 0) >= 2:
            cats.append("idor")
        if vector.get("mal_failed_auth", 0) >= 2:
            cats.append("auth")
        return cats

    # -- Phase 4/5 hooks (intentionally inert now) ------------------------

    def _maybe_inject_bait(self, response: Response, decision, state: SessionState) -> Response:
        """Phase 4 will inject the selected bait here, behind the invisibility
        gate. Until then this is a pass-through: no bait exists yet, and the
        spec is emphatic that the gate is built before any bait (§6.7)."""
        return response

    # -- logging (spec §6.11) ---------------------------------------------

    def _to_record(self, request, body, upstream, state, session_id) -> Record:
        rec = Record(source="proxy")
        rec.run.mode = self.mode
        rec.run.seed = self.cfg.seed
        rec.session.session_id = session_id
        rec.session.request_index = state.request_index - 1
        rec.session.in_decoy = state.diverted
        rec.request.method = request.method
        rec.request.path = request.url.path
        rec.request.query = request.url.query
        rec.request.query_params = {k: request.query_params.getlist(k) for k in request.query_params}
        rec.request.headers = {k.lower(): v for k, v in request.headers.items() if k.lower() in _LOGGED_HEADERS}
        rec.request.header_order = [k.lower() for k, _ in request.headers.items()]
        rec.request.body = body.decode("utf-8", "replace")[: int(self.cfg.get("logging.max_body_capture_bytes", 8192))]
        rec.request.content_type = request.headers.get("content-type", "")
        rec.request.user_agent = request.headers.get("user-agent", "")
        rec.request.remote_addr = request.client.host if request.client else ""
        if upstream is not None:
            rec.response.status = upstream.status_code
            rec.response.content_type = upstream.headers.get("content-type", "")
            rec.response.bytes = len(upstream.content)
        return rec

    def _log(self, request, body, upstream, state, session_id, fingerprint, *,
             decision, elapsed_ms, fail_open, note="") -> None:
        rec = self._to_record(request, body, upstream, state, session_id)
        rec.session.fingerprint = fingerprint
        rec.response.elapsed_ms = round(elapsed_ms, 3)
        rec.run.notes = note

        scores = getattr(state, "_last_scores", None)
        rec.scores.after.automation = round(state.automation, 6)
        rec.scores.after.malice = round(state.malice, 6)
        if decision is not None:
            rec.scores.p_attack = round(decision.p_attack, 6)
            rec.decision.action = decision.action
            rec.decision.reason = decision.reason
            rec.decision.expected_costs = decision.effective_costs
            rec.decision.evsi = round(decision.evsi, 6)
            rec.decision.bait_assignment = decision.bait_assignment
            rec.decision.policy_version = decision.policy_version
            rec.decision.fail_open_triggered = fail_open
        else:
            rec.decision.fail_open_triggered = fail_open
        self.log.append(rec)


_LOGGED_HEADERS = {
    "user-agent", "accept", "accept-language", "accept-encoding",
    "referer", "connection", "cache-control", "content-type", "cookie",
}


# ---------------------------------------------------------------------------
# FastAPI app factory
# ---------------------------------------------------------------------------


def create_app(proxy: Proxy | None = None) -> FastAPI:
    app = FastAPI(title="ADF reverse proxy", docs_url=None, redoc_url=None)

    @app.on_event("startup")
    async def _startup() -> None:
        if getattr(app.state, "proxy", None) is None:
            # Lazy default wiring: load the frozen meter if present, else run
            # in forward-only mode. A proxy that cannot find a model must still
            # serve traffic (fail open), so a missing meter is not fatal.
            meter = None
            policy = None
            from pathlib import Path
            model_path = Path("data/models/meter.json")
            if system().scoring_enabled and model_path.exists():
                meter = DualMeter.load(model_path)
                policy = DecisionPolicy.from_config()
            app.state.proxy = Proxy(meter=meter, policy=policy)

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        p = getattr(app.state, "proxy", None)
        if p is not None:
            await p.aclose()

    if proxy is not None:
        app.state.proxy = proxy

    @app.api_route("/{full_path:path}",
                   methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    async def _catch_all(request: Request, full_path: str) -> Response:
        return await request.app.state.proxy.handle(request)

    return app


app = create_app()
