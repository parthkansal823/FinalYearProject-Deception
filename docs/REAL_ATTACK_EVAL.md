# L2 — evaluation against off-the-shelf attack tooling

Addresses the sharpest surviving reviewer objection: `beta_attack`, and the
recall gain that follows from it, are measured against an attacker-curiosity
model *we chose* (LIMITATIONS §2). This runs real, third-party attack tools —
tools we did not write and cannot bias — against the full system, and measures
the same two quantities the synthetic evaluation reports: does the session reach
**DIVERT**, and does it **BITE** a bait.

> **The one-line result.** Every cookie-persistent tool is diverted to `p → 1.0`
> within a handful of requests; **not one tool bites a bait**. That is exactly
> what the synthetic model predicted and what the scope claim requires: automated
> tooling is caught by the *passive* meter, and the *probe* is for the human and
> semi-automated adversary a scanner is not. The one evasion a tool did achieve —
> refusing cookies to reset its score — is closed by a switch the system already
> ships.

Tools, all current at time of writing: **sqlmap 1.10.8**, **ghauri 1.4.3**,
**wapiti 3.2.3**. Run against the full system (`b4_full`) on an isolated local
stack. Nothing here retrains or re-freezes; the frozen v4 model is read exactly
as every other arm reads it.

---

## Results

### Full system (`b4_full`), default configuration

| tool | client behaviour | sessions | divert rate | median req→divert | **bite rate** | peak p |
|---|---|---|---|---|---|---|
| **sqlmap** | persists cookie | 1 | **1.00** | 3 | **0.00** | 1.00 |
| **wapiti** | persists cookie | 1 | **1.00** | 13 | **0.00** | 1.00 |
| **ghauri** | *refuses* cookie | 1321¹ | 0.46 / request | 1 | **0.00** | 1.00 |

¹ ghauri's session count is not 1 by accident — see the evasion below.

- **sqlmap** hammered the injectable `/search` endpoint (990 requests). The
  accumulating meter reached certainty and diverted it on the **3rd request**;
  everything after that talked to the decoy. Bite rate 0.
- **wapiti** crawled and fuzzed from the root (356 requests, concentrated on the
  login form once it hit the auth gate). Diverted on the **13th request**,
  driven by the auth features — `mal_distinct_usernames` (the v4 feature) fires
  hard on a fuzzer trying many account names. Bite rate 0.
- **ghauri** — see below; it is the interesting one.

### The cookie-refusing evasion, and its countermeasure

ghauri does **not** carry the proxy's `Set-Cookie`, so every one of its 1321
requests arrives cookieless. With `fingerprint_fallback` **off** (the default,
for the good reason documented in `config/system.yaml`), each cookieless request
mints a fresh session id, so the accumulating meter is **reset every request** and
can never build a case. This is precisely the score-resetting evasion spec §5.2
anticipates. Even so, ghauri's payloads are lexically damning enough that **46 %
of its individual requests are diverted on the spot**, and `p` still reaches 1.0.

The system already ships the counter. Turning `fingerprint_fallback` **on** links
the cookieless requests by client fingerprint:

| ghauri (`b4_full`) | sessions | divert rate | bite rate |
|---|---|---|---|
| `fingerprint_fallback` **off** (default) | 1321 | 0.46 / request | 0.00 |
| `fingerprint_fallback` **on** (§5.2 counter) | **1** | **1.00** | 0.00 |

With the fingerprint fallback on, ghauri collapses to a single session and is
fully diverted, exactly like sqlmap. The evasion is real, it was anticipated, and
the mitigation is a config flag rather than a redesign. Reproduce with
`--fingerprint-fallback`.

### The bite rate is the point

**Zero bites, every tool, every configuration.** This is not a weakness — it is
the scope claim, measured. A blind SQL-injection engine does not read a planted
HTML comment and decide to chase a deprecated-endpoint hint; it follows its own
fixed logic. So the response-side probe does nothing against pure automation —
and it does not need to, because the passive meter diverts these tools on their
own behaviour (`p → 1.0` above). The probe exists for the adversary the scanner
is not: the human or semi-automated attacker whose intent is genuinely uncertain
from the request alone, which is the whole premise of the paper.

### SQL-injection confirmation (secondary)

Neither SQLi engine confirmed exploitation of `/search` (`reported_injectable:
false` for both). This holds for sqlmap even with **no defence in front of it**
(`--mode b0_no_defence`), so it is a property of how these tools probe this
particular string-concatenation under SQLite — not evidence of the deception
defeating them. We report it rather than lean on it: the load-bearing L2 result
is the divert/bite behaviour above, not a claim about denied exploitation.

Raw per-session detail and full tool stdout:
`data/eval/real_attack.json` (default) and `data/eval/real_attack_fpfallback.json`
(fingerprint fallback on).

---

## L3 — transfer to a second, structurally different application

Does the frozen meter — trained *only* on our server-rendered Python target —
divert real attacks against an application it has never seen? We put the proxy in
front of **OWASP Juice Shop** (a Node/Express + Angular single-page app with a
JSON REST API — structurally as unlike our target as a web app gets, running in
its official Docker container) and pointed the same tools at it *through the
proxy*, with the same frozen v4 model.

| tool | what it did | sessions | divert | median req→divert | bite | peak p |
|---|---|---|---|---|---|---|
| **sqlmap** → `/rest/products/search` | pure SQLi on the real endpoint | 1 | **1.00** | **2** | 0 | 1.00 |
| **ghauri** → `/rest/products/search` | SQLi, cookie-refusing | 231 | 0.97 / request | 1 | 0 | 1.00 |
| **ZAP** full browser scan | 589 endpoints crawled + fuzzed | 682 | 0.38 / request¹ | — | 0 | 1.00 |

¹ Correctly *below* 1.0 — see the selectivity note below; this is the meter
working, not failing.

- **sqlmap** attacking Juice Shop's genuine SQLi endpoint is diverted on the
  **second request**, `p → 1.0`. The app-agnostic features (SQL lexical context,
  error ratio, request timing, header shape) fire on a completely foreign app.
- **ZAP is the tool wapiti could not be.** wapiti, a non-JS crawler, saw Juice
  Shop's SPA as a single empty page (3 requests, 1 path) and could not attack it
  at all — so we switched to **OWASP ZAP**, whose AJAX spider drives a real
  browser. It crawled **589 distinct endpoints** (`/rest/user/login`,
  `/api/Users/`, `/rest/products/search`, …) and fuzzed them, generating ~10,800
  requests through the proxy.
- **The meter is selective, which is the point.** ZAP mixes benign crawling
  (static assets, `node_modules`, socket.io) with attack payloads. The meter
  diverted the attack traffic and passed the crawl: diverted requests carry a
  mean of **0.91 SQL-keyword hits**, passed requests **0.00**. It reaches
  `p → 1.0` on the injections while leaving the benign spidering alone — on an
  application it was never trained on.

**What transfers, and what does not (stated honestly).** The *app-agnostic*
features transfer cleanly — lexical SQL context, error ratio, automation timing,
header shape — which is why the SQLi tools are caught. The *app-specific* auth
features do **not**: `mal_distinct_usernames` and `mal_failed_auth` key on our
target's form-POST `/login`, whereas Juice Shop authenticates via a JSON body to
`/rest/user/login`, so those two features stay silent here. That is the expected
shape of the transfer: the lexical/behavioural core generalises to a new app; the
endpoint-specific features would need re-pointing. The recall *magnitude* is
target-specific (LIMITATIONS §3); the *mechanism* — the meter fires where the
attack signal is, on an app it never saw — transfers.

Raw detail: `data/eval/real_attack_juiceshop.json` (sqlmap, ghauri),
`data/eval/real_attack_juiceshop_zap.json` (ZAP). Juice Shop runs as
`docker run -d -p 3000:3000 bkimminich/juice-shop`; the harness takes
`--external-upstream http://127.0.0.1:3000` and `--inject-path`.

---

## How it is run (isolation and reproducibility)

Two properties matter for a paper: the run must not touch anything else on the
machine, and the tool versions must be pinned.

### Isolated stack

`tools/real_attack_eval.py` stands up its **own** target + proxy + decoy on
private ports (8010/8011/8012) with a private database, decoy notebook, and log
directory under `data/l2/`, all via `ADF_*` environment overrides. It therefore
runs safely alongside a concurrent Phase-7 or multi-seed run on the default ports
— which is how it was in fact run here. It refuses to point at anything but
loopback (SAFETY.md).

### Two virtual environments (why, and how)

The attack tools are installed in **dedicated virtual environments, never the
system Python** — both to keep the OS clean and because the tools conflict with
the project's own pins (wapiti requires `httpx==0.27`, the project requires
`0.28.1`; the two cannot coexist in one environment):

```bash
# venv 1 — the project stack plus the tools that are pin-compatible with it
python -m venv .venv-l2
.venv-l2/Scripts/python -m pip install -r requirements.txt \
    sqlmap "git+https://github.com/r0oth3x49/ghauri.git"

# venv 2 — wapiti alone (it is a standalone client; it needs none of the project)
python -m venv .venv-wapiti
.venv-wapiti/Scripts/python -m pip install "wapiti3==3.2.3"
```

The harness always runs from `.venv-l2`, and resolves each tool from its own
venv's `Scripts/` directory first (`_tool_path`), so it never falls back to a
system-wide copy. Both venvs are git-ignored.

ZAP (L3's SPA crawler) needs no venv — it runs from its official container, so
Docker is the only requirement:

```bash
docker pull ghcr.io/zaproxy/zaproxy:stable
```

```bash
# L2 — the full suite against our own target (the full system)
.venv-l2/Scripts/python -m tools.real_attack_eval --tools sqlmap,ghauri,wapiti

# L2 — the cookie-refusing countermeasure demonstration
.venv-l2/Scripts/python -m tools.real_attack_eval --tools ghauri --fingerprint-fallback

# L2 — the no-defence control (does a tool confirm the injection unaided?)
.venv-l2/Scripts/python -m tools.real_attack_eval --tools sqlmap --mode b0_no_defence

# L3 — transfer study against a second app (Juice Shop in Docker)
docker run -d --name adf-juiceshop -p 3000:3000 bkimminich/juice-shop
.venv-l2/Scripts/python -m tools.real_attack_eval --tools sqlmap,ghauri \
    --external-upstream http://127.0.0.1:3000 \
    --inject-path "/rest/products/search?q=1" --mode b2_passive --tag juiceshop
.venv-l2/Scripts/python -m tools.real_attack_eval --tools zap \
    --external-upstream http://127.0.0.1:3000 --mode b2_passive --tag juiceshop_zap
```

(For a ZAP run the harness binds the proxy to `0.0.0.0` so the ZAP container can
reach it via `host.docker.internal`; every other run stays loopback-only.)

---

## What this does and does not add to the paper

**Adds.** A direct answer to "your attacker is your own": real tools, run blind,
behave exactly as the synthetic model assumed — caught by the passive layer,
indifferent to the bait. Plus a measured evasion (cookie refusal) and a working
countermeasure, which is a stronger position than not raising the point.

**Does not add.** A measurement of `beta_attack` for a *human* attacker. These
tools are the automated end of the spectrum by construction; the bite rate they
establish is the floor (zero), not the human rate the recall gain depends on.
That still requires the human study (L7). L2 narrows the honest claim — the probe
is for human/semi-automated intent — rather than replacing the assumption.
