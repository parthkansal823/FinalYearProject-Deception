"""Bait library and the invisibility gate (spec §6.6, §6.7)."""

from adf.bait.baits import Bait, BaitSpec, BAIT_SPECS, build_bait, make_token
from adf.bait.channels import (
    BaitedResponse,
    BaitInjectionError,
    compare_rendered,
    rendered_signature,
)
from adf.bait.gate import (
    InvisibilityGate,
    GateResult,
    certify_all,
    is_certified,
    load_certificates,
)

__all__ = [
    "BAIT_SPECS",
    "Bait",
    "BaitInjectionError",
    "BaitSpec",
    "BaitedResponse",
    "GateResult",
    "InvisibilityGate",
    "build_bait",
    "certify_all",
    "compare_rendered",
    "is_certified",
    "load_certificates",
    "make_token",
    "rendered_signature",
]
