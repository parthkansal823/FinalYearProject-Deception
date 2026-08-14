"""
The planted credential (spec §6.10).

Inside the decoy, in a location a determined attacker would eventually find,
sits a fake API key in a configuration file. The key grants nothing. Its only
function is that the system watches for it: if it ever appears in a subsequent
request, three things are proven at once -- the attacker explored the decoy
deeply, harvested credentials, and attempted to use what they harvested.

This upgrades the logs from a record of what the attacker CLICKED to a record
of what the attacker INTENDED, which is what threat intelligence is actually
for (spec §6.10).

The key is per-deployment (derived from the seed) so it is stable within a run
and reproducible across runs (NFR-08), but not a fixed constant that could be
published. It is deliberately shaped like a real secret so it is tempting.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class PlantedCredential:
    key_id: str
    secret: str

    def as_config_ini(self) -> str:
        """How the key appears where the attacker finds it: a plausible service
        config, the kind of file left readable by mistake."""
        return (
            "[service]\n"
            "name = reporting-sync\n"
            "region = eu-west-1\n"
            f"api_key_id = {self.key_id}\n"
            f"api_key_secret = {self.secret}\n"
            "endpoint = https://internal-api.northbridge.example/v2\n"
            "timeout = 30\n"
        )

    def appears_in(self, *fragments: str) -> bool:
        """Did the attacker present the harvested secret back to us?"""
        hay = " ".join(f or "" for f in fragments)
        return self.secret in hay or self.key_id in hay


def planted_credential(seed: int = 0) -> PlantedCredential:
    """Derive the deployment's planted credential from the seed. Stable within
    a run, reproducible across runs, never a fixed published string."""
    digest = hashlib.sha256(f"planted-credential:{seed}".encode("utf-8")).hexdigest()
    key_id = "AKIA" + digest[:16].upper()
    secret = digest[16:56]
    return PlantedCredential(key_id=key_id, secret=secret)
