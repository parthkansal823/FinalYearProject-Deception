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
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from adf.config import system
from adf.decoy.credential import planted_credential
from adf.decoy.notebook import FactNotebook
from adf.decoy.world import gen_user, gen_record, gen_notice, populate
from adf.decoy.observed import HEADER as OBSERVED_HEADER, apply_overlay, decode as decode_observed
from contextvars import ContextVar
from adf.logstore import LogStore, default_log_path
from adf.schema import Record

TARGET_DIR = Path(__file__).resolve().parent.parent / "target_app"
COOKIE_NAME = "portal_sid"   # SAME cookie name as the target (indistinguishability)

# The decoy presents a plausibly larger organisation than the target's seed, so
# its exact size is not a fingerprint, but it is still FINITE -- probing beyond
# it 404s, like real data (parity with the target, which 404s past its rows).
MAX_USER_ID = 240
MAX_RECORD_ID = 900

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
    token = _overlay.set(decode_observed(request.headers.get(OBSERVED_HEADER, "")))
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
    # Mirror the target's verbose failures. The decoy's users are fake and the
    # attacker does not know their passwords, so a stuffing/guessing attacker
    # fails here EXACTLY as they would on the real site -- indistinguishable,
    # and still trapped. Usernames are matched against the notebook world.
    known = {u.value["username"]: u.value for u in notebook.all("user")}
    if username not in known:
        session.failed_logins += 1
        error = f"No account found for username '{username}'."
        return attach(templates.TemplateResponse(
            request, "login.html",
            {"error": error, "session": session, "failed": session.failed_logins},
            status_code=401), session)
    session.failed_logins += 1
    error = (f"Incorrect password for user '{username}'. "
             f"{session.failed_logins} failed attempt(s) recorded for this session.")
    return attach(templates.TemplateResponse(
        request, "login.html",
        {"error": error, "session": session, "failed": session.failed_logins},
        status_code=401), session)


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
    records = [_record_view(i) for i in range(1, 7)]
    profile = _user(8)
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
_overlay: ContextVar[dict] = ContextVar("_overlay", default={})


def _user(uid: int) -> dict:
    return apply_overlay("user", notebook.get_or_generate("user", uid, gen_user), _overlay.get())


def _users(ids: list[int]) -> list[dict]:
    ov = _overlay.get()
    return [apply_overlay("user", u, ov) for u in notebook.get_many_or_generate("user", ids, gen_user)]


def _record_view(record_id: int) -> dict:
    ov = _overlay.get()
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
