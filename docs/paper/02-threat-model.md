# 2  Threat Model and Scope

We consider an attacker who interacts with a web application over HTTP and whose
intent cannot be settled from any single request. This is the case that makes the
middle action worth having, so it is worth being precise about.

**In scope.** The attacker sends ordinary-looking HTTP requests to a public
application. Some carry payloads that can be obfuscated — SQL injection split
across comments or double-encoded, cross-site scripting with mixed case and
entities, path traversal — so that a signature written for the canonical form
misses the variant \cite{amouei2022rat}. Others carry no payload at all. The clearest example, and the
one we lean on throughout, is an insecure direct object reference: a request for
`/records/5` is syntactically indistinguishable from a request for `/records/6`,
and if the second object is not yours the request is an attack, yet nothing in its
bytes says so. A signature cannot catch it, because there is no signature to
write; and a behavioural detector struggles, because a benign integration that
reads its own records in order produces the same request shape. This is the region
where a passive score is genuinely uncertain, and where manufacturing evidence has
value.

The attacker may be a person driving a browser or a script, and may be automated
or manual; these are separate axes, which is why the detector scores automation
and malice separately (Section 3). A scripted vulnerability scanner is automated
and hostile; a price-comparison bot is automated and harmless; a careful human
probing by hand is manual and hostile. Advanced bots imitate browser fingerprints and human pacing closely enough that
automation signals alone stop separating them from people \cite{iliou2019towards,iliou2021detection}, so a detector that collapses these onto
one score cannot tell the second from the third, and we show in Section 8 that this is
not a hypothetical concern.

**Out of scope.** We do not defend against network- or transport-layer attacks,
denial of service, or anything that never reaches the application as a
well-formed request. We do not consider client-side attacks against other users
of the application. And we state plainly the one assumption that a determined
adversary could break: we assume the attacker does not have prior knowledge of the
exact decoy world it would be moved into. An attacker who has previously mapped
the decoy could in principle recognise it; honeypots and honeytokens have both
been fingerprinted at scale \cite{vetterl2018bitter,srinivasa2020honeytoken}. Countering that fully is out of scope —
but rather than leave the adaptive adversary as a sentence in a threat model, we
measure a weaker version of it: an attacker who knows the *defence* exists and
refuses every probe on principle, the leaky-deception setting studied
game-theoretically in \cite{pawlick2019leaky}. Section 9 reports what the system does against
that adversary, and shows it degrades to passive detection rather than below it.

**Assumptions about the defender.** The defender runs a reverse proxy in front of
the real application and can add invisible content to responses and route a
session to a decoy. The defender has a cost model for its errors — how bad a
missed attack is relative to a wrongly diverted user — fixed in advance
\cite{elkan2001foundations}. It does
not have labelled production traffic; the detector is trained on traffic the
defender generates and characterises itself, which is a limitation we return to in
Section 10, not a claim of realism.
