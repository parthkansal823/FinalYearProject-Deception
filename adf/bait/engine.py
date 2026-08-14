"""
The bait engine (spec §6.6): selection is done by the policy; this component
does the mechanics -- serving the selected bait into a response, remembering
what was planted, and watching every later request for a bite.

Two guards enforce the project's safety rules at run time, not just at build
time:

  * a bait is served ONLY if it holds a passing invisibility certificate
    (spec §6.6 require_invisibility_certificate, §6.7). A bait that never went
    through the gate cannot reach a user.
  * bait content is unique per session (spec §16), so if a token ever appears
    in a DIFFERENT session it is either a leaked/published bait or an attacker
    rotating identity -- both more informative than an ordinary bite, and both
    flagged via `cross_session`.

A bite is manufactured evidence (spec §5.2, §21). Its weight is the bait's
likelihood ratio -- P(bite|attacker)/P(bite|benign) -- which the caller adds to
the session's malice in log-odds. That is the derived, calibrated form of the
spec's "the malice score jumps sharply"; nothing here is a hand-set constant.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from adf.bait.baits import Bait, build_bait, BAIT_SPECS
from adf.bait.channels import BaitedResponse, BaitInjectionError
from adf.bait.gate import is_certified


@dataclass
class BiteEvent:
    bait_id: str
    token: str
    issued_to_session: str
    biting_session: str
    cross_session: bool
    evidence: str
    likelihood_ratio: float

    @property
    def logodds(self) -> float:
        """The evidence weight of this bite in log-odds, to be added to the
        session's malice logit. Derived from the calibrated bite rates."""
        return math.log(max(self.likelihood_ratio, 1e-9))


@dataclass
class _Issued:
    bait: Bait
    likelihood_ratio: float
    session_id: str


class BaitEngine:
    def __init__(self, *, seed: int = 0, require_certificate: bool = True) -> None:
        self.seed = seed
        self.require_certificate = require_certificate
        # session -> {bait_id: _Issued}
        self._by_session: dict[str, dict[str, _Issued]] = {}
        # token -> _Issued, for cross-session detection
        self._by_token: dict[str, _Issued] = {}

    # -- serving -----------------------------------------------------------

    def serve(
        self,
        *,
        session_id: str,
        bait_id: str,
        response: BaitedResponse,
        likelihood_ratio: float = 0.0,
    ) -> tuple[BaitedResponse, _Issued | None]:
        """Inject the selected bait into the response, if it is certified and
        applicable. Returns (possibly modified response, issued record or None).

        Never raises on a bait problem: a failure to bait must degrade to
        serving the clean response, never to breaking it (the same fail-open
        spirit as the proxy, NFR-04)."""
        if bait_id not in BAIT_SPECS:
            return response, None
        if self.require_certificate and not is_certified(bait_id):
            # Refuse to serve an uncertified bait. This is the run-time
            # enforcement of the invisibility rule (spec §6.6).
            return response, None

        bait = build_bait(bait_id, session_id=session_id, seed=self.seed)
        if not bait.applicable(response):
            return response, None

        # Re-issuing the same bait to the same session keeps the same token.
        existing = self._by_session.get(session_id, {}).get(bait_id)
        if existing is not None:
            bait = existing.bait

        try:
            baited = bait.inject(response)
        except BaitInjectionError:
            return response, None

        issued = existing or _Issued(bait=bait, likelihood_ratio=likelihood_ratio,
                                     session_id=session_id)
        self._by_session.setdefault(session_id, {})[bait_id] = issued
        self._by_token[bait.token] = issued
        return baited, issued

    # -- bite detection ----------------------------------------------------

    def check_bite(self, *, session_id: str, method: str, path: str,
                   query: str, body: str) -> BiteEvent | None:
        """Has this request acted on any planted token (spec §21)?

        Checks the requesting session's own baits first, then every other
        session's tokens -- a token seen outside the session it was issued to
        is a cross-session bite (spec §16)."""
        # own baits
        for issued in self._by_session.get(session_id, {}).values():
            if issued.bait.detect_bite(method=method, path=path, query=query, body=body):
                return self._event(issued, session_id, cross=False, path=path, query=query, body=body)

        # Other sessions' baits -- but ONLY those whose token is unique to a
        # session. A name bait (`ref_uid`, `mfa_debug_token`) shows every session
        # the same generic string, so seeing it in another session proves nothing
        # about identity rotation: a second attacker could simply have guessed
        # the same plausible parameter name. Reporting that as a cross-session
        # bite would put false evidence in the released dataset (spec §11).
        for issued in self._by_token.values():
            if issued.session_id == session_id:
                continue
            if not issued.bait.token_is_session_unique:
                continue
            if issued.bait.detect_bite(method=method, path=path, query=query, body=body):
                return self._event(issued, session_id, cross=True, path=path, query=query, body=body)
        return None

    def _event(self, issued: _Issued, biting_session: str, *, cross: bool,
               path: str, query: str, body: str) -> BiteEvent:
        where = "path" if issued.bait.spec.bite_kind == "path" else (
            "param" if issued.bait.spec.bite_kind == "name" else "value")
        return BiteEvent(
            bait_id=issued.bait.bait_id,
            token=issued.bait.token,
            issued_to_session=issued.session_id,
            biting_session=biting_session,
            cross_session=cross,
            evidence=f"{where}:{issued.bait.token}",
            likelihood_ratio=issued.likelihood_ratio,
        )

    # -- introspection -----------------------------------------------------

    def issued_baits(self, session_id: str) -> list[str]:
        return list(self._by_session.get(session_id, {}))
