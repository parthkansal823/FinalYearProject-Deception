"""
The decoy application (spec §6.8).

A parallel copy of the target, containing no real data. Visually AND
behaviourally it must be indistinguishable from the real site: same layout,
same error messages, same response timings, same headers, same auth flow. It
reuses the target's own templates and static assets and serves every fact from
the Fact Notebook, so it never contradicts itself under repeat probing (§6.9).

INDISTINGUISHABILITY IS ADVERSARIAL. An initial version of this decoy was
"permissive" -- every page served without auth, login always advanced, search
never errored, ids were infinite. A careful attacker (the §10.4 checklist)
detects every one of those: the real site gates /dashboard, rejects bad
credentials verbosely, leaks a DB error on injection, and has finite data. So
this decoy MIRRORS the target's observable behaviour instead:

  * auth is gated exactly as the target gates it; a diverted-but-authenticated
    session stays authenticated because the proxy vouches for it via a trusted
    internal header (X-ADF-Authenticated), set only on the localhost-only path
    from proxy to decoy;
  * /login returns the target's verbose errors -- a stuffing attacker fails
    here just as they would on the real site, which keeps them trapped without
    tipping them off;
  * /search reproduces the target's error-based SQL-injection surface with a
    fake but CONSISTENT database error, so the decoy looks as injectable as the
    real thing;
  * the id space is bounded, so probing beyond it 404s like real finite data.

The only intended differences from the target are the DATA (fake, from the
notebook) and that nothing real can be exfiltrated (NFR-06). Capture of the
planted credential is recorded INTERNALLY only -- never signalled to the
attacker, or they would learn they were caught (spec executive summary, §6.10).
"""

from __future__ import annotations

import re
import secrets
import threading
import time
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from adf.config import system
from adf.decoy.credential import planted_credential
from adf.decoy.notebook import FactNotebook
from adf.decoy.observed import HEADER as OBSERVED_HEADER
from adf.decoy.observed import apply_overlay
from adf.decoy.observed import decode as decode_observed
from adf.decoy.world import gen_notice, gen_record, gen_user, populate
from adf.logstore import LogStore, default_log_path
from adf.schema import Record
from target_app.otp import is_valid as otp_is_valid
from target_app.seed import USERS as _TARGET_USERS

# The seeded staff credentials and identities, imported so the decoy accepts the
# SAME logins as the target. A visitor handed a real credential -- the human
# study gives every participant a.mirza/Summer2024!, and a diverted attacker has
# harvested one on the target -- must be able to log in here too. A copy that
# rejects the site's own credential is both broken for the study and a glaring
# tell (given valid credentials, you cannot get in). Only the seeded users'
# IDENTITY is mirrored (username/name/email/department, ids 1..N); every other
# person and all record content stays fabricated.
_CREDS = {u[0]: (i, u[1]) for i, u in enumerate(_TARGET_USERS, start=1)}  # username -> (uid, password)
_SEED_IDENTITY = {
    i: {"username": u[0], "full_name": u[3],
        "email": f"{u[0]}@northbridge-internal.example", "department": u[4]}
    for i, u in enumerate(_TARGET_USERS, start=1)
}

TARGET_DIR = Path(__file__).resolve().parent.parent / "target_app"
COOKIE_NAME = "portal_sid"   # SAME cookie name as the target (indistinguishability)

# The decoy presents a plausibly larger organisation than the target's seed, so
# its exact size is not a fingerprint, but it is still FINITE -- probing beyond
# it 404s, like real data (parity with the target, which 404s past its rows).
MAX_USER_ID = 240
MAX_RECORD_ID = 900
# How many records `adf.decoy.world.populate` actually seeds. MAX_RECORD_ID is
# the 404 boundary (probing beyond it 404s like real data); this is the range
# that exists, and the only one worth scanning.
_POPULATED_RECORDS = 60

# Trusted only because the decoy is reachable only via the proxy on localhost
# (NFR-14); a real client cannot set it.
AUTH_SIGNAL_HEADER = "x-adf-authenticated"

cfg = system()
SEED = cfg.seed
notebook = FactNotebook(cfg.get("databases.fact_notebook_dsn", "sqlite:///data/decoy/notebook.sqlite3"),
                        seed=SEED)
CRED = planted_credential(SEED)

app = FastAPI(title="Northbridge Staff Portal", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=TARGET_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(TARGET_DIR / "templates"))
decoy_log = LogStore(default_log_path("decoy-access", cfg.log_dir))

if notebook.count() == 0:
    populate(notebook, seed=SEED)


# ---------------------------------------------------------------------------
# Sessions -- mirror the target's cookie + auth state machine
# ---------------------------------------------------------------------------


@dataclass
class DecoySession:
    sid: str
    authenticated: bool = False
    otp_pending: bool = False
    username: str = ""
    user_id: int = 0
    failed_logins: int = 0
    otp_attempts: int = 0


_sessions: dict[str, DecoySession] = {}
_sessions_lock = threading.Lock()


def get_session(request: Request) -> DecoySession:
    cached = getattr(request.state, "decoy_session", None)
    if cached is not None:
        return cached
    sid = request.cookies.get(COOKIE_NAME)
    with _sessions_lock:
        if sid and sid in _sessions:
            session = _sessions[sid]
        else:
            sid = secrets.token_hex(16)
            session = DecoySession(sid=sid)
            _sessions[sid] = session
    # The proxy vouches that this diverted session was already authenticated on
    # the real site, so it does not have to re-authenticate here (which would
    # itself be a tell -- "why am I suddenly logged out?").
    if request.headers.get(AUTH_SIGNAL_HEADER) == "1":
        session.authenticated = True
    request.state.decoy_session = session
    return session


def attach(response: Response, session: DecoySession) -> Response:
    response.set_cookie(COOKIE_NAME, session.sid, httponly=True, samesite="lax", path="/")
    return response


def _require_auth(request: Request, session: DecoySession):
    """Mirror the target: an unauthenticated request to a gated page is
    redirected to /login, not served."""
    if not session.authenticated:
        return attach(RedirectResponse("/login", status_code=303), session)
    return None


# ---------------------------------------------------------------------------
# Credential watch + access logging -- INTERNAL ONLY (spec §6.10)
# ---------------------------------------------------------------------------


@app.middleware("http")
async def decoy_middleware(request: Request, call_next):
    started = time.perf_counter()
    body = (await request.body()).decode("utf-8", "replace")
    captured = CRED.appears_in(request.url.path, request.url.query, body)

    # What the attacker already saw on the target, handed over by the proxy.
    # Only the proxy sets this header, only on a diverted session (localhost
    # trust, like AUTH_SIGNAL_HEADER); a direct client cannot.
    # Overlay the proxy-observed facts, and -- for a session that logged in via
    # the form (the human study) -- the logged-in user's OWN real identity, so
    # every surface greets them by the name they signed in as. ONLY their own id
    # is made real; every other person stays fabricated, so the decoy is still a
    # fake world for everyone the visitor did not already know they were.
    overlay = decode_observed(request.headers.get(OBSERVED_HEADER, ""))
    _sess = get_session(request)
    if _sess.user_id and _sess.user_id in _SEED_IDENTITY:
        u = overlay.setdefault("user", {})
        u[_sess.user_id] = {**_SEED_IDENTITY[_sess.user_id], **u.get(_sess.user_id, {})}
    token = _overlay.set(overlay)
    try:
        response = await call_next(request)
    finally:
        _overlay.reset(token)

    rec = Record(source="decoy-access")
    rec.run.mode = cfg.mode
    rec.run.seed = SEED
    rec.session.in_decoy = True
    rec.request.method = request.method
    rec.request.path = request.url.path
    rec.request.query = request.url.query
    rec.request.user_agent = request.headers.get("user-agent", "")
    rec.response.status = response.status_code
    rec.response.elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
    if captured:
        # Recorded here and NOWHERE the attacker can see it. No response header,
        # no body change -- they must never learn they were caught (§6.10).
        rec.planted_credential.used = True
        rec.planted_credential.key_id = CRED.key_id
    decoy_log.append(rec)
    return response


# ---------------------------------------------------------------------------
# Public + auth surfaces -- behaviour mirrors target_app/main.py exactly
# ---------------------------------------------------------------------------


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "app": "decoy"}


# Well-known files, identical to the target's, so the decoy's route surface and
# crawler behaviour match (spec §6.8) and it does not 404 where the real site
# would answer.
@app.get("/robots.txt", response_class=Response)
async def robots():
    return Response("User-agent: *\nDisallow: /api/\nDisallow: /files/\n", media_type="text/plain")


@app.get("/sitemap.xml", response_class=Response)
async def sitemap():
    body = ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            '<url><loc>/</loc></url><url><loc>/login</loc></url></urlset>')
    return Response(body, media_type="application/xml")


@app.get("/favicon.ico", response_class=Response)
async def favicon():
    return Response((TARGET_DIR / "static" / "logo.svg").read_bytes(), media_type="image/svg+xml")


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    session = get_session(request)
    notices = [notebook.get_or_generate("notice", i, gen_notice) for i in range(1, 9)]
    return attach(templates.TemplateResponse(request, "home.html",
                                             {"notices": notices, "session": session}), session)


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    session = get_session(request)
    return attach(templates.TemplateResponse(request, "login.html",
                                             {"error": None, "session": session}), session)


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, username: str = Form(""), password: str = Form("")):
    session = get_session(request)
    # Mirror the target's login EXACTLY: the same seeded credentials succeed here
    # (so a visitor with a real credential can get in and be trapped), the same
    # verbose failures otherwise (unknown username vs wrong password -- the
    # enumeration weakness the target deliberately has). A stuffing attacker who
    # does not know a password still fails identically to the real site.
    cred = _CREDS.get(username)
    if cred is None:
        session.failed_logins += 1
        error = f"No account found for username '{username}'."
        return attach(templates.TemplateResponse(
            request, "login.html",
            {"error": error, "session": session, "failed": session.failed_logins},
            status_code=401), session)
    uid, real_password = cred
    if password != real_password:
        session.failed_logins += 1
        error = (f"Incorrect password for user '{username}'. "
                 f"{session.failed_logins} failed attempt(s) recorded for this session.")
        return attach(templates.TemplateResponse(
            request, "login.html",
            {"error": error, "session": session, "failed": session.failed_logins},
            status_code=401), session)
    # Correct credential -> second factor, exactly like the target.
    session.user_id = uid
    session.username = username
    session.otp_pending = True
    session.authenticated = False
    return attach(RedirectResponse("/otp", status_code=303), session)


@app.get("/otp", response_class=HTMLResponse)
async def otp_form(request: Request):
    session = get_session(request)
    if not session.otp_pending and not session.authenticated:
        return attach(RedirectResponse("/login", status_code=303), session)
    return attach(templates.TemplateResponse(request, "otp.html",
                                             {"error": None, "session": session}), session)


@app.post("/otp", response_class=HTMLResponse)
async def otp_submit(request: Request, code: str = Form("")):
    session = get_session(request)
    # The same predictable OTP scheme as the target (the OTP-bypass surface), so
    # a visitor who was handed the code -- or worked the scheme out -- gets in.
    if session.user_id and otp_is_valid(session.user_id, code):
        session.authenticated = True
        session.otp_pending = False
        return attach(RedirectResponse("/dashboard", status_code=303), session)
    session.otp_attempts += 1
    error = (f"Verification code not recognised. Attempt {session.otp_attempts}. "
             "Codes remain valid until the end of the day.")
    return attach(templates.TemplateResponse(
        request, "otp.html", {"error": error, "session": session}, status_code=401), session)


@app.get("/logout")
async def logout(request: Request):
    # Mirror the target: /logout must exist, or clicking it 404s and reveals
    # the decoy (route-surface parity, spec §6.8).
    session = get_session(request)
    with _sessions_lock:
        _sessions.pop(session.sid, None)
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    session = get_session(request)
    if (r := _require_auth(request, session)) is not None:
        return r
    # Personalise to whoever logged in (the human study, direct access) so the
    # dashboard greets them by the name they signed in as. In the proxy flow no
    # form login happened (user_id stays 0) and the attacker's real dashboard is
    # replayed anyway, so a default keeps that path working.
    uid = session.user_id or 1
    profile = _user(uid)
    # "Your records" must contain only records this user actually OWNS. It used
    # to be a hardcoded 1..6, which contradicts anything the visitor already
    # knows about ownership: an attacker who read /records/6 on the target (owned
    # by profile #2) and is then shown it under "Your records" here has caught
    # the swap. Found by re-pentesting after the login surface was added
    # (docs/LIMITATIONS.md §7). Selecting by owner keeps the claim true in the
    # decoy's own world, and consistent with any record the proxy has overlaid.
    # Scanned over the POPULATED range only (adf.decoy.world.populate seeds 60
    # records); MAX_RECORD_ID is the 404 boundary, not a range to generate, and
    # walking it would fabricate 900 records on every dashboard load.
    records = [r for r in (_record_view(i) for i in range(1, _POPULATED_RECORDS + 1))
               if r["owner_id"] == uid][:6]
    # If this fake world assigned them none, show none. An empty "Your records"
    # is ordinary (a new starter has none); falling back to an arbitrary few
    # would re-introduce exactly the ownership contradiction fixed above.
    return attach(templates.TemplateResponse(request, "dashboard.html",
                                             {"records": records, "profile": profile, "session": session}), session)


@app.get("/directory", response_class=HTMLResponse)
async def directory(request: Request):
    session = get_session(request)
    if (r := _require_auth(request, session)) is not None:
        return r
    people = _users(list(range(1, 25)))
    return attach(templates.TemplateResponse(request, "directory.html",
                                             {"people": people, "session": session}), session)


# ---------------------------------------------------------------------------
# IDOR surfaces -- consistent fake entities within a FINITE id space
# ---------------------------------------------------------------------------


@app.get("/profile/{profile_id}", response_class=HTMLResponse)
async def profile_page(request: Request, profile_id: int):
    session = get_session(request)
    if (r := _require_auth(request, session)) is not None:
        return r
    if not 1 <= profile_id <= MAX_USER_ID:
        return attach(templates.TemplateResponse(request, "not_found.html",
                                                 {"what": "profile", "session": session}, status_code=404), session)
    p = _user(profile_id)
    return attach(templates.TemplateResponse(request, "profile.html", {"p": p, "session": session}), session)


@app.get("/api/profile/{profile_id}")
async def profile_api(request: Request, profile_id: int):
    session = get_session(request)
    if not session.authenticated:
        return attach(JSONResponse({"error": "authentication required"}, status_code=401), session)
    if not 1 <= profile_id <= MAX_USER_ID:
        return attach(JSONResponse({"error": "not found"}, status_code=404), session)
    return attach(JSONResponse({"profile": _user(profile_id)}), session)


@app.get("/records/{record_id}", response_class=HTMLResponse)
async def record_page(request: Request, record_id: int):
    session = get_session(request)
    if (r := _require_auth(request, session)) is not None:
        return r
    if not 1 <= record_id <= MAX_RECORD_ID:
        return attach(templates.TemplateResponse(request, "not_found.html",
                                                 {"what": "record", "session": session}, status_code=404), session)
    return attach(templates.TemplateResponse(request, "record.html",
                                             {"r": _record_view(record_id), "session": session}), session)


@app.get("/api/records/{record_id}")
async def record_api(request: Request, record_id: int):
    session = get_session(request)
    if not session.authenticated:
        return attach(JSONResponse({"error": "authentication required"}, status_code=401), session)
    if not 1 <= record_id <= MAX_RECORD_ID:
        return attach(JSONResponse({"error": "not found"}, status_code=404), session)
    return attach(JSONResponse({"record": _record_view(record_id)}), session)


# Per-request overlay of facts the attacker already saw on the target, decoded
# from the proxy's header (docs/LIMITATIONS.md §7). Empty for any request that is
# not a diverted session. A ContextVar so _record_view, which has no request in
# hand, can reach it without threading it through every call site.
_overlay: ContextVar[dict | None] = ContextVar("_overlay", default=None)


def _user(uid: int) -> dict:
    return apply_overlay("user", notebook.get_or_generate("user", uid, gen_user), _overlay.get() or {})


def _users(ids: list[int]) -> list[dict]:
    ov = _overlay.get() or {}
    return [apply_overlay("user", u, ov) for u in notebook.get_many_or_generate("user", ids, gen_user)]


def _record_view(record_id: int) -> dict:
    ov = _overlay.get() or {}
    rec = apply_overlay("record", notebook.get_or_generate("record", record_id, gen_record), ov)
    owner_id = min(max(rec["owner_id"], 1), MAX_USER_ID)
    owner = apply_overlay("user", notebook.get_or_generate("user", owner_id, gen_user), ov)
    view = dict(rec)
    view["owner_id"] = owner_id
    view["owner_name"] = owner["full_name"]
    return view


# ---------------------------------------------------------------------------
# SQL surface -- reproduce the target's error-based injection tell
# ---------------------------------------------------------------------------

# The trigger the target's concatenated query trips on: a quote/comment char.
_SQL_TRIGGER = re.compile(r"['\"#;]|--|/\*")


@app.get("/search", response_class=HTMLResponse)
async def search(request: Request, q: str = ""):
    session = get_session(request)
    if (r := _require_auth(request, session)) is not None:
        return r
    if not q:
        return attach(templates.TemplateResponse(request, "search.html",
                                                 {"q": q, "rows": [], "error": None, "session": session}), session)

    # Injection-shaped input reproduces the target's verbose DB error, so the
    # decoy looks exactly as injectable as the real site. The error is drawn
    # from the notebook keyed by the query, so the SAME payload always yields
    # the SAME error (consistency, §6.9).
    if _SQL_TRIGGER.search(q):
        err = notebook.get_or_generate("sql_error", q, _gen_sql_error)
        return attach(templates.TemplateResponse(
            request, "search.html",
            {"q": q, "rows": [], "error": err, "session": session}, status_code=500), session)

    result = notebook.get_or_generate("search", q, _gen_search_result)
    return attach(templates.TemplateResponse(request, "search.html",
                                             {"q": q, "rows": result["rows"], "error": None, "session": session}), session)


def _gen_sql_error(rng, key: str) -> dict:
    # Same SQLite error phrasings the real target leaks, so the tell matches.
    templates_ = [
        'near "{tok}": syntax error',
        'unrecognized token: "{tok}"',
        'no such column: {tok}',
        'SELECTs to the left and right of UNION do not have the same number of result columns',
    ]
    tok = (key.strip()[:12] or "'").replace('"', "")
    msg = rng.choice(templates_).format(tok=tok)
    statement = ("SELECT id, title, body, posted_at FROM notices "
                 f"WHERE title LIKE '%{key}%' OR body LIKE '%{key}%' ORDER BY id DESC")
    return {"message": msg, "sqlstate": "", "statement": statement}


def _gen_search_result(rng, key: str) -> dict:
    rows = []
    for _ in range(rng.randint(0, 3)):
        notice = notebook.get_or_generate("notice", rng.randint(1, 8), gen_notice)
        rows.append({"title": notice["title"], "body": notice["body"], "posted_at": notice["posted_at"]})
    return {"rows": rows}


# ---------------------------------------------------------------------------
# File / config surfaces -- where the planted credential lives (spec §6.10)
# ---------------------------------------------------------------------------


# The decoy's file area mirrors the target's EXACTLY -- same names, same
# mundane content -- except that service.ini carries the planted credential
# (spec §6.10). That single difference is the bait; everything else matching is
# what stops the file area itself from betraying the decoy (spec §6.8).
_MUNDANE_FILES = {
    "readme.txt": "Northbridge internal service bundle. Contact the service desk for access.\n",
    "changelog.txt": "v2.4.1 storage migration\nv2.4.0 directory refresh\nv2.3.9 login hardening\n",
    "maintenance.log": "scheduled maintenance completed; no action required\n",
}


def _decoy_service_ini() -> str:
    fact = notebook.get("config", "service.ini")
    return fact["content"] if fact else CRED.as_config_ini()


@app.get("/files", response_class=HTMLResponse)
async def files_listing(request: Request):
    session = get_session(request)
    if (r := _require_auth(request, session)) is not None:
        return r
    listing = dict(_MUNDANE_FILES)
    listing["service.ini"] = _decoy_service_ini()
    # order to match the target: readme, changelog, service.ini, maintenance
    order = ["readme.txt", "changelog.txt", "service.ini", "maintenance.log"]
    items = "".join(
        f"<li><a href='/files/{name}'>{name}</a> "
        f"<span class='meta'>-rw-r--r-- {len(listing[name])}b 2026-08-01</span></li>"
        for name in order
    )
    html = ("<!DOCTYPE html><html><head><title>Index</title>"
            "<link rel='stylesheet' href='/static/app.css'></head><body><main>"
            f"<section class='card'><h1>Service files</h1><ul class='notice-list'>{items}</ul>"
            "</section></main></body></html>")
    return attach(HTMLResponse(html), session)


@app.get("/files/{name}", response_class=Response)
async def file_content(request: Request, name: str):
    session = get_session(request)
    if not session.authenticated:
        return attach(Response(content="authentication required", status_code=401), session)
    if name == "service.ini":
        return attach(Response(content=_decoy_service_ini(), media_type="text/plain"), session)
    body = _MUNDANE_FILES.get(name)
    if body is None:
        return attach(Response(content="not found", status_code=404), session)
    return attach(Response(content=body, media_type="text/plain"), session)
