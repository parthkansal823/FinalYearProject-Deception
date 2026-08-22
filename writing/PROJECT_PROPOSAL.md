# DEPARTMENT OF APEX INSTITUTE OF TECHNOLOGY
## PROJECT PROPOSAL

---

### 1. Project Title

**An Active Deception Framework for Web Attack Detection Using Response-Side
Probes and State-Consistent Decoys**

---

### 2. Project Scope — (Max 500 words)

Protecting web applications from attackers is one of the most critical challenges
in cybersecurity. A Web Application Firewall (WAF) must make a binary choice on
every request — allow or block — using only the evidence that single request
carries. This creates an unpleasant trade-off: acting early on thin evidence
blocks legitimate users, while waiting for evidence strong enough to be safe gives
the attacker several requests of head start. Machine-learned detectors soften
this trade-off but do not escape it; they still watch, wait, and then commit.

Deception is the usual answer to this passivity. Honeypots and honeytokens give
the defender something to do other than wait. But in almost every deployment the
deception happens *after* the decision has been made: a session is judged hostile,
and only then moved into a honeypot. Deception is therefore a consequence of
detection rather than an instrument of it.

**Why Deception and Decision Theory?**

This project treats deception as a move the detector can make *while it is still
unsure*. When intent is uncertain, the system adds an invisible, inert probe to
the response — a fake database error naming a non-existent table, an unused JSON
field, a hint at a deprecated endpoint. An honest user's browser never renders it;
someone reading the raw response acts on it, and the moment they do they reveal
hostile intent a passive score could only wait for.

The central problem is deciding *when* to deploy such a probe. Probing has no
immediate benefit, because the request still reaches the real application; its
entire value is the information a bite reveals. We price that value using the
expected value of sample information (EVSI) from decision theory, making probing
the cost-optimal action over a belief band whose edges are *derived* from a frozen
cost table and *measured* probe effectiveness rather than tuned. Under ordinary
cost accounting that band is empty, so the middle action is not a threshold that
could have been fitted to the results.

Once confirmed hostile, a session is moved silently into a state-consistent decoy
environment, where a Fact Notebook keeps the fake world from contradicting itself
and every action is recorded on an append-only, hash-chained log.

**Research Objectives**

1. Design a reverse-proxy detection engine that scores every session on two
   independent axes — automation and malice — rather than a single score.
2. Derive a three-way decision rule (pass / probe / divert) in which the probing
   band is computed from cost and measured evidence, not chosen.
3. Build a library of response-side probes that provably never alter what a real
   browser renders, enforced by an automated invisibility gate.
4. Construct a state-consistent decoy environment and measure its contradiction
   rate, including consistency across the divert boundary itself.
5. Evaluate the system against baselines, off-the-shelf attack tools and a
   randomised holdout that identifies the probe's causal effect, and report
   safety on deliberately hard benign traffic.

---

### 3. Requirements

#### Hardware Requirements

1. **Processor:** Intel Core i5 (10th Gen or above) / AMD Ryzen 5 or higher
2. **RAM:** Minimum 16 GB (32 GB recommended for multi-seed parallel evaluation)
3. **Storage:** 512 GB SSD or higher (evaluation logs and corpora are large)
4. **GPU (Optional):** NVIDIA GPU with at least 4 GB VRAM — required only for the
   optional language-model attacker experiments, not for the framework itself

#### Software Requirements

1. **Operating System:** Windows 10/11 or Linux
2. **Programming Language:** Python 3.11
3. **Web Framework:** FastAPI 0.115 with Uvicorn (ASGI server), Jinja2 templates
4. **Machine Learning:** scikit-learn 1.6, NumPy, pandas, joblib
5. **Statistical Analysis:** SciPy (McNemar, Fisher exact), Matplotlib for figures
6. **Databases:** PostgreSQL 16 (primary) and SQLite (isolated test runs)
7. **HTTP Client / Proxying:** httpx 0.28
8. **Testing:** pytest 8.3 with pytest-asyncio, BeautifulSoup4 (invisibility gate)
9. **Containerisation:** Docker and Docker Compose (reproducible environment)
10. **Security Tooling (evaluation):** sqlmap, ghauri, OWASP ZAP, Wapiti,
    OWASP ModSecurity Core Rule Set, OWASP Juice Shop (second target application)
11. **Optional:** Ollama (local language-model attacker experiments)
12. **Development Tools:** VS Code, Git, LaTeX (Springer LNNS paper preparation)

---

### STUDENTS DETAILS

| Name | UID | Signature |
|---|---|---|
| Parth Kansal | 23BIS70035 | |
| Amrit Singh Nijjar | 23BIS70062 | |
| Siddhant Mehta | 23BIS70162 | |

---

### APPROVAL AND AUTHORITY TO PROCEED

We approve the project as described above and authorize the team to proceed.

| Name | Title | Signature (With Date) |
|---|---|---|
| Ms. Sheetal Laroiya | | |
