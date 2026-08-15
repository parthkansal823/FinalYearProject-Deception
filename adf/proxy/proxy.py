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

import re
import time
from dataclasses import dataclass, field

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response

from adf.config import system
from adf.features import SessionFeatureExtractor
from adf.logstore import LogStore, default_log_path
from adf.meter import DualMeter
from adf.policy.engine import DecisionPolicy, _logit, _sigmoid
from adf.schema import Record, ReasonItem, PROVENANCE_HEADER
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
    authenticated: bool = False     # did the session authenticate on the TARGET before diverting?

    #: Extra malice evidence, in log-odds, accumulated from bait bites. A bite
    #: is manufactured evidence (spec §5.2); its weight is the bait's calibrated
    #: likelihood ratio, added here and folded into the malice logit so the
    #: score "jumps sharply" on a bite -- derived, not a hand-set constant.
    bite_logodds: float = 0.0

    #: How many times each bait has been shown to this session WITHOUT a bite.
    #: Feeds the EVSI decay so the policy stops paying full price to re-ask a
    #: question the session has already declined to answer -- without this, a
    #: bait-aware adversary is baited forever instead of diverted (spec §18).
    bait_exposures: dict = field(default_factory=dict)

    #: Scores as they stood BEFORE this request's update. FR-11 requires the
    #: record to carry both, because "the score moved from 0.26 to 0.96 on this
    #: request" is what makes a decision auditable after the fact; the after
    #: value alone does not show what the request itself contributed.
    prev_automation: float = 0.0
    prev_malice: float = 0.0


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

        # The bait engine is only wired in when the mode allows bait (b4_full);
        # in every baseline it stays None, so the proxy is provably bait-free
        # there rather than relying on the policy alone (spec §10.1).
        self.bait_engine = None
        if self.cfg.bait_enabled:
            from adf.bait.engine import BaitEngine
            self.bait_engine = BaitEngine(
                seed=self.cfg.seed,
                require_certificate=bool(self.cfg.get("bait.require_invisibility_certificate", True)),
            )

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- the request path (spec §5.2) -------------------------------------

    async def handle(self, request: Request) -> Response:
        started = time.perf_counter()
        body = await request.body()
        session_id, fingerprint, _is_new = self.sessions.resolve(request)
        state = self._state.setdefault(session_id, SessionState())
        state.request_index += 1
        # Reset per-request scratch so stale values from the previous request
        # cannot be logged against this one if scoring is skipped (b0 mode, or
        # a fail-open fault).
        state._last_bait = None      # type: ignore[attr-defined]
        state._last_bite = None      # type: ignore[attr-defined]
        state._last_vector = None    # type: ignore[attr-defined]

        # Forward FIRST. Detection must never delay or block the response path
        # in a way that could fail closed; scoring happens around the forward
        # and, if it raises, we have already served the user (NFR-04).
        upstream = self._route_upstream(state)
        try:
            upstream_response = await self._forward(request, body, upstream, state)
        except httpx.HTTPError as exc:
            # Upstream itself failed. This is not a detection failure; surface a
            # 502 but still log it so the corpus is complete.
            elapsed = (time.perf_counter() - started) * 1000.0
            self._log(request, body, None, state, session_id, fingerprint,
                      decision=None, elapsed_ms=elapsed, fail_open=False,
                      note=f"upstream error: {exc}")
            return Response(content=b"upstream unavailable", status_code=502)

        # Track whether the session authenticated on the TARGET, so that if it
        # is later diverted the decoy can keep it logged in (no re-login tell).
        # The canonical signal is the post-login landing page served 200, or a
        # successful OTP redirect off /otp.
        if not state.diverted:
            path = request.url.path
            if (path == "/dashboard" and upstream_response.status_code == 200) or (
                path == "/otp" and request.method == "POST"
                and upstream_response.status_code in (302, 303)
            ):
                state.authenticated = True

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
        # Bait injection runs on the OUTBOUND response, outside the scoring
        # try/except, so it needs its own fail-open guard: a fault in injection
        # must degrade to the clean response, never break it (NFR-04). The
        # clean upstream response is already in hand, so we simply keep it.
        try:
            response = self._maybe_inject_bait(response, decision, state, session_id)
        except Exception:  # noqa: BLE001 - fail open on the response path too
            fail_open_triggered = True
            if not self.fail_open:
                raise
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

    async def _forward(self, request: Request, body: bytes, upstream: str,
                       state: "SessionState") -> httpx.Response:
        url = upstream.rstrip("/") + request.url.path
        if request.url.query:
            url += "?" + request.url.query
        # The client's Cookie header is forwarded as-is via fwd_headers (cookie
        # is not a hop-by-hop header), so passing cookies= as well would send
        # them twice and is the deprecated httpx path. Headers alone is enough.
        fwd_headers = {k: v for k, v in request.headers.items()
                       if k.lower() not in _HOP_BY_HOP and k.lower() != "host"}
        # Vouch to the decoy that a diverted session was already authenticated
        # on the real site, so it does not force a re-login (which would itself
        # be a tell). Trusted because this path is localhost-only (NFR-14).
        if upstream == self.decoy_upstream and state.authenticated:
            fwd_headers["X-ADF-Authenticated"] = "1"
        return await self._client.request(
            request.method, url, headers=fwd_headers, content=body,
            follow_redirects=False,
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
        # FR-11: the record must carry the extracted feature vector and the
        # scores as they stood before this request's update.
        state._last_vector = vector          # type: ignore[attr-defined]
        state.prev_automation = state.automation
        state.prev_malice = state.malice

        # Bite detection happens BEFORE scoring, so a request that acts on a
        # previously planted bait raises malice on this very request rather than
        # the next one (spec §5.2 "the malice score jumps sharply").
        bite = None
        if self.bait_engine is not None:
            bite = self.bait_engine.check_bite(
                session_id=session_id, method=request.method,
                path=request.url.path, query=request.url.query,
                body=body.decode("utf-8", "replace"),
            )
            if bite is not None:
                state.bite_logodds += bite.logodds
        state._last_bite = bite  # type: ignore[attr-defined]

        scores = self.meter.score(vector)
        state.automation = scores.automation
        # Fold the accumulated bite evidence into malice, in log-odds. With no
        # bites this is exactly the meter's malice; a bite shifts it upward by
        # the bait's calibrated weight.
        eps = float(self.policy.fusion.get("epsilon", 1e-6)) if self.policy else 1e-6
        effective_malice = _sigmoid(_logit(scores.malice, eps) + state.bite_logodds)
        state.malice = effective_malice

        contributions = [
            ReasonItem(feature=c.feature, value=c.value, weight=c.weight, contribution=c.contribution)
            for c in scores.malice_expl.top(5)
        ]
        if bite is not None:
            contributions.append(ReasonItem(
                feature=f"bite[{bite.bait_id}]", value=1.0, weight=1.0,
                contribution=round(bite.logodds, 4),
            ))
        decision = self.policy.decide(
            session_id=session_id,
            automation=scores.automation,
            malice=effective_malice,
            suspected_categories=self._suspected_categories(vector, request.url.path),
            feature_contributions=contributions,
            exposures=state.bait_exposures,
            applicable_baits=_applicable_baits(upstream.headers.get("content-type", "")),
        )
        if decision.action == "divert":
            state.diverted = True   # subsequent requests route to the decoy (Phase 5)
        # stash for logging
        state._last_scores = scores  # type: ignore[attr-defined]
        state._last_decision = decision  # type: ignore[attr-defined]
        return decision

    @staticmethod
    def _suspected_categories(vector: dict[str, float], path: str = "") -> list[str]:
        """A cheap guess at what the visitor is attempting, used only to pick
        which baits are relevant (spec §6.6). Not a classification — the meter
        does that — just routing.

        Routing considers BOTH the accumulated malice features AND the surface
        being probed. The surface half matters for the case the meter is least
        sure about: an attacker walking object-reference endpoints
        (/profile/{id}, /records/{id}) leaves almost no malice signal, so a
        purely feature-based router would hand them an SQL bait they would never
        take. Matching the bait to the endpoint they are actually poking is what
        lets a probe resolve the uncertain IDOR case at all (see docs/RESULTS.md
        — this was a real routing gap the evaluation exposed)."""
        cats = []
        if vector.get("mal_db_keyword_hits", 0) > 0 or vector.get("mal_special_char_ratio", 0) > 0.1:
            cats.append("sqli")
        if _OBJECT_REF.search(path):
            cats.append("idor")
        if vector.get("mal_failed_auth", 0) >= 2 or path in ("/login", "/otp"):
            cats.append("auth")
        return cats   # empty -> the policy considers all baits and lets EVSI choose

    # -- bait injection (spec §6.6, §6.7) ---------------------------------

    def _maybe_inject_bait(self, response: Response, decision, state: SessionState,
                           session_id: str) -> Response:
        """Inject the policy-selected bait into the outgoing response, through
        the bait engine's certificate guard and non-rendered channels.

        The engine never breaks a response: an uncertified, inapplicable or
        un-injectable bait degrades to the clean response (the fail-open spirit
        of NFR-04). A successful injection is recorded on the session for the
        log and so bite detection can watch for the token later."""
        state._last_bait = None  # type: ignore[attr-defined]
        if self.bait_engine is None or decision is None or decision.action != "bait":
            return response
        if not getattr(decision, "bait_id", ""):
            return response

        baited = self._to_baited(response)
        new_baited, issued = self.bait_engine.serve(
            session_id=session_id,
            bait_id=decision.bait_id,
            response=baited,
            likelihood_ratio=decision.likelihood_ratio,
        )
        if issued is None:
            return response
        state._last_bait = issued  # type: ignore[attr-defined]
        # Count the exposure. This is what decays the EVSI on later requests, so
        # a session that keeps declining the bait stops being paid for as though
        # its answer were still unknown (spec §18 robustness).
        bid = issued.bait.bait_id
        state.bait_exposures[bid] = state.bait_exposures.get(bid, 0) + 1
        return self._from_baited(new_baited, response)

    @staticmethod
    def _to_baited(response: Response):
        from adf.bait.channels import BaitedResponse
        body = response.body.decode("utf-8", "replace") if isinstance(response.body, (bytes, bytearray)) else str(response.body)
        return BaitedResponse(
            body=body,
            headers={k: v for k, v in response.headers.items()},
            content_type=response.headers.get("content-type", response.media_type or ""),
            status=response.status_code,
        )

    @staticmethod
    def _from_baited(baited, original: Response) -> Response:
        new_body = baited.body.encode("utf-8")
        headers = dict(original.headers)
        # carry any header-channel bait, drop the length so it is recomputed
        headers.update(baited.headers)
        headers.pop("content-length", None)
        headers.pop("Content-Length", None)
        return Response(content=new_body, status_code=baited.status,
                        headers=headers, media_type=original.media_type)

    # -- logging (spec §6.11) ---------------------------------------------

    def _to_record(self, request, body, upstream, state, session_id) -> Record:
        rec = Record(source="proxy")
        rec.run.mode = self.mode
        rec.run.seed = self.cfg.seed
        rec.session.session_id = session_id
        rec.session.request_index = state.request_index - 1
        rec.session.in_decoy = state.diverted
        # Generator marker, if this is synthetic traffic. It is what joins the
        # proxy's DECISIONS (divert/bait, keyed by the proxy's own cookie
        # session id) back to the ground-truth label the generator wrote in
        # advance -- without it the Phase 7 evaluation cannot be scored. Kept
        # out of request.headers so it can never reach a feature vector
        # (adf.schema.NEVER_FEATURE_FIELDS); a real client never sends it.
        rec.session.provenance_id = request.headers.get(PROVENANCE_HEADER, "")
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

        # FR-11 / spec §6.11: the extracted features and BOTH score pairs.
        vector = getattr(state, "_last_vector", None)
        if vector:
            rec.features = {k: round(float(v), 6) for k, v in vector.items()}
        rec.scores.before.automation = round(state.prev_automation, 6)
        rec.scores.before.malice = round(state.prev_malice, 6)
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

        # bait injected on this response (spec §6.11)
        issued = getattr(state, "_last_bait", None)
        if issued is not None:
            rec.bait.injected = True
            rec.bait.bait_id = issued.bait.bait_id
            rec.bait.category = issued.bait.category
            rec.bait.token = issued.bait.token
            rec.bait.location = issued.bait.spec.channel

        # bite detected on this request
        bite = getattr(state, "_last_bite", None)
        if bite is not None:
            rec.bite.occurred = True
            rec.bite.bait_id = bite.bait_id
            rec.bite.matched_token = bite.token
            rec.bite.evidence = bite.evidence
            rec.bite.cross_session = bite.cross_session
            rec.bite.issued_to_session = bite.issued_to_session
            rec.bite.likelihood_ratio = round(bite.likelihood_ratio, 4)

        self.log.append(rec)


_LOGGED_HEADERS = {
    "user-agent", "accept", "accept-language", "accept-encoding",
    "referer", "connection", "cache-control", "content-type", "cookie",
}

# Object-reference endpoints — the IDOR surface. An attacker walking these by
# id is doing IDOR whether or not the ids are sequential, so bait routing keys
# on the surface, not only on the sequential-access feature.
_OBJECT_REF = re.compile(r"^/(?:api/)?(?:profile|records)/\d+")


def _applicable_baits(content_type: str) -> set[str]:
    """Which baits can be injected into a response of this content-type, by
    channel. A json_field bait needs a JSON body; an html_comment bait needs
    HTML; a response_header bait fits anything. Computed from the bait specs so
    it cannot drift from the injection code."""
    from adf.bait.baits import BAIT_SPECS
    is_json = "json" in (content_type or "").lower()
    is_html = "html" in (content_type or "").lower()
    out = set()
    for bid, spec in BAIT_SPECS.items():
        if spec.channel == "json_field" and is_json:
            out.add(bid)
        elif spec.channel == "html_comment" and is_html:
            out.add(bid)
        elif spec.channel == "response_header":
            out.add(bid)
    return out


# ---------------------------------------------------------------------------
# FastAPI app factory
# ---------------------------------------------------------------------------


def create_app(proxy: Proxy | None = None) -> FastAPI:
    from contextlib import asynccontextmanager
    from pathlib import Path

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if getattr(app.state, "proxy", None) is None:
            # Lazy default wiring: load the frozen meter if present, else run
            # in forward-only mode. A proxy that cannot find a model must still
            # serve traffic (fail open), so a missing meter is not fatal.
            meter = None
            policy = None
            model_path = Path("data/models/meter.json")
            if system().scoring_enabled and model_path.exists():
                meter = DualMeter.load(model_path)
                policy = DecisionPolicy.from_config()
            app.state.proxy = Proxy(meter=meter, policy=policy)
        try:
            yield
        finally:
            p = getattr(app.state, "proxy", None)
            if p is not None:
                await p.aclose()

    app = FastAPI(title="ADF reverse proxy", docs_url=None, redoc_url=None, lifespan=lifespan)

    if proxy is not None:
        app.state.proxy = proxy

    @app.api_route("/{full_path:path}",
                   methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    async def _catch_all(request: Request, full_path: str) -> Response:
        return await request.app.state.proxy.handle(request)

    return app


app = create_app()
