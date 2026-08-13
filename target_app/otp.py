"""
Second-factor code generation for the target application.

DELIBERATELY WEAK (spec §6.1): codes are predictable, never expire, and are
reusable. This is the OTP-bypass attack surface, and it lives in its own
module so that the benign traffic generator can import the same function --
a legitimate user has received the code by another channel, so simulating one
correctly means computing it rather than guessing it.

The weakness is that the code is a pure function of the user id and the day,
with no secret and no randomness. An attacker who observes two codes can
recover the scheme.
"""

from __future__ import annotations

from datetime import date

#: Arbitrary primes. Their only job is to make the codes look unrelated to
#: one another at a glance, which is exactly the sort of false comfort that
#: makes this class of flaw survive code review in real systems.
_USER_MULTIPLIER = 7919
_DAY_MULTIPLIER = 104729


def otp_for(user_id: int, on: date | None = None) -> str:
    """The six-digit code currently valid for `user_id`.

    No expiry window and no per-issue nonce: the same code is valid for the
    whole day and can be replayed any number of times.
    """
    day = (on or date.today()).toordinal()
    value = (user_id * _USER_MULTIPLIER + day * _DAY_MULTIPLIER) % 1_000_000
    return f"{value:06d}"


def is_valid(user_id: int, code: str, on: date | None = None) -> bool:
    return code.strip() == otp_for(user_id, on)
