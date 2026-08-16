# Safety, ethics and legal notice

> **This repository contains a web application with intentional, unpatched
> security vulnerabilities. It must never be deployed anywhere reachable from
> a network you do not fully control.**

This is a research artefact for an academic project on active deception
defences (see [docs/OVERVIEW.md](docs/OVERVIEW.md) for what it does and
`docs/PROJECT_SPEC.txt` for the full specification). The vulnerabilities are
not oversights awaiting a fix; each one is a required attack surface for a
measured category of the study, and "fixing" one deletes a category from the
results. The tests in `tests/test_target_app.py` therefore assert that the
weaknesses are still present.

## Before you run anything — the short checklist

1. You are on a machine you control, not a shared or production host.
2. Nothing in `config/system.yaml` binds to anything other than `127.0.0.1`.
3. No tunnel, port-forward, or reverse proxy exposes ports **8000** (the
   deception proxy), **8001** (the deliberately weak app) or **8002** (the
   decoy) beyond this machine.
4. You understand that `tools/attack_traffic.py` performs **real attacks**, and
   that it must only ever be pointed at the bundled application.

If any of those four is not true, stop.

## The intentional vulnerabilities

Located exclusively in `target_app/` (spec §6.1):

| Component                                                     | Weakness                                                                            | Category           |
| ------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ------------------ |
| `POST /login`                                                 | no rate limiting, no lockout, verbose failure messages (username enumeration)       | credential attack  |
| `POST /otp`                                                   | codes predictable from user id and date, no attempt cap, reusable, no expiry        | OTP bypass         |
| `GET /search`                                                 | user input concatenated directly into SQL; raw driver errors returned to the client | SQL injection      |
| `GET /profile/{id}`, `GET /records/{id}` and their JSON twins | sequential numeric ids with no ownership check                                      | IDOR               |
| `target_app/seed.py`                                          | unsalted SHA-256 password hashes, weak passwords                                    | supports the above |

The injection surface is deliberately confined to a single `query_raw()` call
site, and a test enforces that it stays that way. A second injection point
would widen the threat model and make the attack-category labels wrong.

## The attack tooling in this repository

`tools/attack_traffic.py` is not a simulation. It performs genuine SQL
injection, IDOR sweeps, credential stuffing, brute force and OTP-bypass attacks
over HTTP, and it exists because the study needs labelled attack traffic
(spec §7.2).

- It defaults to `http://127.0.0.1:8001` — the bundled application — and
  `--base-url` must never be pointed anywhere else. Every attack in this
  project is performed against the researcher's own instance (spec §17).
- The credentials it uses are the synthetic ones in `target_app/seed.py`. It
  holds a deliberately "compromised" low-privilege account (`a.mirza`) because
  a realistic attacker escalating from a foothold reaches the same endpoints an
  ordinary user does; that is what forces the detector to separate them by
  _behaviour_ rather than by which URLs exist.
- It writes ground-truth labels before each session runs, so nothing it does is
  unlabelled or unaccounted for.

Running it against any system you do not own is unlawful in most
jurisdictions, and is outside both the ethics approval and the point of this
project.

## Operating rules

These follow directly from spec §7.3 and §17 and are not optional.

1. **Isolated environment only.** Everything binds to `127.0.0.1` by default.
   Do not change `network.bind_host` in `config/system.yaml` to `0.0.0.0`, and
   do not port-forward, tunnel, or expose any service in this repository.
2. **No public internet deployment.** Spec §15.1 cut this from scope
   deliberately: it is legally grey and internet background noise is
   overwhelmingly low-quality scanner traffic.
3. **Attack only your own instance.** Every attack in this project targets the
   researcher's own application. No third-party system is touched at any point.
4. **No real data, ever.** All content in both the real and decoy applications
   is synthetic (`target_app/seed.py`). No real personal data is used anywhere.
5. **The planted credential is fake** and grants access to nothing. Its only
   function is to be watched for (spec §6.10).
6. **The decoy is isolated** from the real application and its database, so an
   attacker inside the decoy cannot reach real data even in principle (NFR-06).
7. **Review before release.** Before any dataset is published, logs must be
   reviewed for credentials, personal data and host-identifying information
   (spec §11, §17). The exporter refuses to run without this check.

## If human participants are involved

Spec §10.4 allows a small supporting deception assessment. If anyone other
than the researcher takes part:

- they are told they are participating in a security experiment;
- no personal data is collected from them;
- the sample size is stated plainly in the paper rather than left for a
  reviewer to discover.

## Reporting

This code is not production software and has no security contact. If you have
found this repository outside its intended context, the correct action is not
to report a vulnerability — they are all intentional — but to ensure no
instance is running on a reachable host.
