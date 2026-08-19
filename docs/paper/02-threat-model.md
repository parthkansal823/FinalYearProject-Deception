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

Our simulated adversary reflects this rather than assuming it away. Half of the
attack sessions drive a real browser: they send browser headers and fetch the page
sub-resources a browser fetches, because a great deal of current tooling is built
on Selenium, Playwright or Puppeteer and inherits that behaviour whatever the
operator intends. The other half speak raw HTTP. An earlier version of this corpus
had none of the first kind, and the consequence is instructive enough that we
report it in Section 10: no attack session fetched a sub-resource while almost
every human-paced benign one did, which let a classifier separate the two
populations at an out-of-sample AUC of 0.99 on a property of our generators rather
than of hostility.

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

Two consequences of deploying a probe at all belong here rather than in a
discussion. First, **the probe is itself a signal**. An attacker who recognises a
planted token learns that the site is defended, which is information we have given
away in exchange for the information a bite would buy. This is why the probes are
written to read as a plausible slip rather than as an obvious trap, and why the
policy prefers the most informative probe applicable to the response in hand rather
than showing several: every additional probe raises the chance that one of them
looks wrong. We do not claim the exchange is always favourable, and against an
attacker who never bites the rule's own arithmetic withdraws the probe.

Second, an attacker may **rotate identity** — drop a cookie, change address — to
reset an accumulating score. Some probes can detect this and some cannot, and the
distinction is worth stating because it bounds what the evidence is allowed to mean.
Probes whose payload is a *value* — a fabricated table name, a deprecated endpoint —
carry a random per-session suffix, so the same string arriving from a client the
system considers new really is that session's token, and the system records it as a
cross-session sighting rather than an ordinary bite. Probes whose payload is a
*field name* cannot: `ref_uid` and `internal_view` have to be plausible generic
names to be worth planting at all, so every session is shown the same string, and a
second sighting is indistinguishable from a second attacker guessing a common
parameter. The system therefore refuses to report cross-session evidence for those,
and Section 8 shows what an off-the-shelf tool that drops its cookie looks like when
the fingerprint fallback is the thing that catches it instead.

The adversaries we actually evaluate against are therefore of three kinds: the
scripted round-2 attackers of Section 8, whose curiosity we set; the probe-refusing
adversary above; and autonomous language-model agents that choose their own next
request and are told nothing about the probes (Section 9.6). The third exists
precisely because the first has a parameter we chose.

**Assumptions about the defender.** The defender runs a reverse proxy in front of
the real application and can add invisible content to responses and route a
session to a decoy. The defender has a cost model for its errors — how bad a
missed attack is relative to a wrongly diverted user — fixed in advance
\cite{elkan2001foundations}. It does
not have labelled production traffic; the detector is trained on traffic the
defender generates and characterises itself, which is a limitation we return to in
Section 10, not a claim of realism.
