"""
The target application: a small internal staff portal, deliberately weak.

  *** THIS APPLICATION CONTAINS INTENTIONAL VULNERABILITIES.        ***
  *** IT MUST NEVER BE DEPLOYED ANYWHERE REACHABLE. See SAFETY.md.  ***

Each weakness is here because spec §6.1 assigns it an attack category:

  login form      no rate limit, no lockout, verbose errors   -> auth
  OTP step        predictable, uncapped, reusable codes       -> auth (otp)
  search box      user input concatenated into SQL            -> sqli
  profile/records sequential ids, no ownership check          -> idor
  static assets   none -- present so that scripted traffic
                  looks different from browser traffic        -> automation signal

That last one is easy to overlook and load-bearing (spec §6.1): a real
browser fetches the CSS, the JS and the logo; a scripted attack tool usually
does not, and that difference is one of the strongest automation features
available. It only exists if the site has assets worth fetching.

This module knows nothing about the deception framework (NFR-10). The only
`adf` import is the shared log schema, which is ordinary access logging --
if the whole `adf` package were deleted, this app would still serve traffic.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from adf.config import system
from adf.logstore import LogStore, default_log_path
from adf.schema import Record
from target_app.db import Database, DatabaseError
from target_app.otp import otp_for, is_valid as otp_is_valid
from target_app.seed import password_hash

APP_DIR = Path(__file__).resolve().parent
COOKIE_NAME = "portal_sid"

cfg = system()
db = Database(cfg.get("databases.target_dsn", "sqlite:///data/target.sqlite3"))

app = FastAPI(title="Northbridge Staff Portal", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

access_log = LogStore(default_log_path("target-access", cfg.log_dir))


# ---------------------------------------------------------------------------
# Session state (in-process; single-worker by design so the corpus stays
# reproducible and sessions do not need a shared store)
# ---------------------------------------------------------------------------


@dataclass
class Session:
    sid: str
    user_id: int | None = None
    username: str = ""
    authenticated: bool = False      # passed BOTH password and OTP
    otp_pending: bool = False        # passed password, awaiting second factor
    failed_logins: int = 0
    otp_attempts: int = 0            # counted but never enforced -- that is the flaw
    request_index: int = 0
    created_at: float = field(default_factory=time.time)


_sessions: dict[str, Session] = {}
_sessions_lock = threading.Lock()


def get_session(request: Request) -> Session:
    """Resolve the session for this request, creating one if needed.

    The resolved session is cached on `request.state` because this is called
    both by the access-log middleware and by the route handler. Without the
    cache, a client arriving with no cookie yet gets one session from the
    middleware and a second from the handler; the first is logged, orphaned
    and never seen again, while the cookie carries the second. That splits
    the first request of every session away from the rest of it -- fatal for
    a project whose scores accumulate per session.
    """
    cached = getattr(request.state, "portal_session", None)
    if cached is not None:
        return cached

    sid = request.cookies.get(COOKIE_NAME)
    with _sessions_lock:
        if sid and sid in _sessions:
            session = _sessions[sid]
        else:
            sid = secrets.token_hex(16)
            session = Session(sid=sid)
            _sessions[sid] = session

    request.state.portal_session = session
    return session


def attach_session(response: Response, session: Session) -> Response:
    response.set_cookie(
        COOKIE_NAME, session.sid, httponly=True, samesite="lax", path="/"
    )
    return response


# ---------------------------------------------------------------------------
# Access logging. Ordinary web-server logging, not detection: it records what
# was served and nothing about suspicion. In Phase 1 this is the corpus; from
# Phase 3 the proxy log supersedes it and this becomes a cross-check that the
# proxy is not dropping or duplicating requests.
# ---------------------------------------------------------------------------


@app.middleware("http")
async def access_log_middleware(request: Request, call_next):
    started = time.perf_counter()
    session = get_session(request)
    session.request_index += 1

    try:
        response = await call_next(request)
    except Exception:
        _write_access_record(request, None, session, started)
        raise

    _write_access_record(request, response, session, started)
    return response


def _write_access_record(request: Request, response: Response | None, session: Session, started: float) -> None:
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    rec = Record(source="target-access")
    rec.run.mode = cfg.mode
    rec.run.seed = cfg.seed
    rec.session.session_id = session.sid
    rec.session.request_index = session.request_index - 1

    rec.request.method = request.method
    rec.request.path = request.url.path
    rec.request.query = request.url.query
    rec.request.query_params = {k: request.query_params.getlist(k) for k in request.query_params}
    rec.request.headers = {k.lower(): v for k, v in request.headers.items()
                           if k.lower() in _LOGGED_HEADERS}
    rec.request.header_order = [k.lower() for k, _ in request.headers.items()]
    rec.request.content_type = request.headers.get("content-type", "")
    rec.request.remote_addr = request.client.host if request.client else ""
    rec.request.user_agent = request.headers.get("user-agent", "")

    if response is not None:
        rec.response.status = response.status_code
        rec.response.content_type = response.headers.get("content-type", "")
        rec.response.bytes = int(response.headers.get("content-length") or 0)
    rec.response.elapsed_ms = round(elapsed_ms, 3)

    access_log.append(rec)


#: Header allow-list. Header presence and ordering are automation features
#: (spec §6.3), so the set is fixed here rather than logging everything --
#: capturing arbitrary headers risks pulling credentials into the released
#: dataset (spec §11 pre-release review).
_LOGGED_HEADERS = {
    "user-agent", "accept", "accept-language", "accept-encoding",
    "referer", "connection", "cache-control", "content-type", "cookie",
}


# ---------------------------------------------------------------------------
# Public pages
# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    session = get_session(request)
    notices = db.query("SELECT id, title, body, posted_at FROM notices ORDER BY id DESC")
    response = templates.TemplateResponse(
        request, "home.html", {"notices": notices, "session": session}
    )
    return attach_session(response, session)


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "app": "target"}


# ---------------------------------------------------------------------------
# WEAKNESS 1 -- login: no rate limiting, no lockout, verbose failures
# ---------------------------------------------------------------------------


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    session = get_session(request)
    return attach_session(
        templates.TemplateResponse(request, "login.html", {"error": None, "session": session}),
        session,
    )


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, username: str = Form(""), password: str = Form("")):
    session = get_session(request)

    rows = db.query("SELECT id, username, password_hash, role FROM users WHERE username = %s", (username,))

    # The verbosity below is the vulnerability: distinguishing "no such user"
    # from "wrong password" hands an attacker free username enumeration, and
    # reporting the running failure count tells them nothing is throttling
    # them. Both are also what makes B-AUTH-1 plausible when it fires here.
    if not rows:
        session.failed_logins += 1
        error = f"No account found for username '{username}'."
        return attach_session(
            templates.TemplateResponse(
                request, "login.html",
                {"error": error, "session": session, "failed": session.failed_logins},
                status_code=401,
            ),
            session,
        )

    user = rows[0]
    if user["password_hash"] != password_hash(password):
        session.failed_logins += 1
        error = (
            f"Incorrect password for user '{username}'. "
            f"{session.failed_logins} failed attempt(s) recorded for this session."
        )
        return attach_session(
            templates.TemplateResponse(
                request, "login.html",
                {"error": error, "session": session, "failed": session.failed_logins},
                status_code=401,
            ),
            session,
        )

    # Password correct -> second factor. No lockout was ever applied, and the
    # failure counter is not even reset.
    session.user_id = int(user["id"])
    session.username = str(user["username"])
    session.otp_pending = True
    session.authenticated = False

    _deliver_otp(session.user_id, session.username)
    return attach_session(RedirectResponse("/otp", status_code=303), session)


def _deliver_otp(user_id: int, username: str) -> None:
    """Stands in for the SMS/email channel. Writing the code to a local file
    keeps the delivery channel out of the HTTP responses, so a client can only
    obtain a code by holding it legitimately -- or by working out the scheme."""
    path = Path(cfg.log_dir) / "otp_delivery.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(f"{datetime.now(timezone.utc).isoformat()} to={username} code={otp_for(user_id)}\n")


# ---------------------------------------------------------------------------
# WEAKNESS 2 -- OTP: predictable, uncapped, reusable
# ---------------------------------------------------------------------------


@app.get("/otp", response_class=HTMLResponse)
async def otp_form(request: Request):
    session = get_session(request)
    if not session.otp_pending and not session.authenticated:
        return attach_session(RedirectResponse("/login", status_code=303), session)
    return attach_session(
        templates.TemplateResponse(request, "otp.html", {"error": None, "session": session}),
        session,
    )


@app.post("/otp", response_class=HTMLResponse)
async def otp_submit(request: Request, code: str = Form("")):
    session = get_session(request)
    if session.user_id is None:
        return attach_session(RedirectResponse("/login", status_code=303), session)

    session.otp_attempts += 1  # counted, never enforced: no cap, no lockout

    if otp_is_valid(session.user_id, code):
        # Nor is the code invalidated on use -- it stays valid all day and can
        # be replayed by anyone who has it.
        session.authenticated = True
        session.otp_pending = False
        return attach_session(RedirectResponse("/dashboard", status_code=303), session)

    error = (
        f"Verification code not recognised. Attempt {session.otp_attempts}. "
        "Codes remain valid until the end of the day."
    )
    return attach_session(
        templates.TemplateResponse(
            request, "otp.html", {"error": error, "session": session}, status_code=401
        ),
        session,
    )


@app.get("/logout")
async def logout(request: Request):
    session = get_session(request)
    with _sessions_lock:
        _sessions.pop(session.sid, None)
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


# ---------------------------------------------------------------------------
# Authenticated area
# ---------------------------------------------------------------------------


def _require_auth(request: Request, session: Session):
    if not session.authenticated:
        return attach_session(RedirectResponse("/login", status_code=303), session)
    return None


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    session = get_session(request)
    if (redirect := _require_auth(request, session)) is not None:
        return redirect

    records = db.query(
        "SELECT id, title, amount, classification, created_at FROM records WHERE owner_id = %s ORDER BY id",
        (session.user_id,),
    )
    profile = db.query("SELECT * FROM profiles WHERE user_id = %s", (session.user_id,))
    return attach_session(
        templates.TemplateResponse(
            request, "dashboard.html",
            {"records": records, "profile": profile[0] if profile else None, "session": session},
        ),
        session,
    )


# ---------------------------------------------------------------------------
# WEAKNESS 3 -- search: user input concatenated straight into SQL
# ---------------------------------------------------------------------------


@app.get("/search", response_class=HTMLResponse)
async def search(request: Request, q: str = ""):
    session = get_session(request)
    if (redirect := _require_auth(request, session)) is not None:
        return redirect

    if not q:
        return attach_session(
            templates.TemplateResponse(
                request, "search.html", {"q": q, "rows": [], "error": None, "session": session}
            ),
            session,
        )

    # ------------------------------------------------------------------
    # THE INJECTION POINT. Concatenation is intentional (spec §6.1).
    # This is the only `query_raw` call in the application.
    # ------------------------------------------------------------------
    sql = (
        "SELECT id, title, body, posted_at FROM notices "
        f"WHERE title LIKE '%{q}%' OR body LIKE '%{q}%' ORDER BY id DESC"
    )

    try:
        rows = db.query_raw(sql)
        error = None
    except DatabaseError as exc:
        # Leaking the driver's message is the second half of the weakness:
        # it turns blind injection into error-based injection, and it is the
        # response B-SQL-1 later impersonates.
        rows = []
        error = {"message": exc.raw, "sqlstate": exc.sqlstate, "statement": sql}

    return attach_session(
        templates.TemplateResponse(
            request, "search.html",
            {"q": q, "rows": rows, "error": error, "session": session},
            status_code=200 if error is None else 500,
        ),
        session,
    )


# ---------------------------------------------------------------------------
# WEAKNESS 4 -- IDOR: sequential numeric ids, no ownership check
# ---------------------------------------------------------------------------


@app.get("/profile/{profile_id}", response_class=HTMLResponse)
async def profile_page(request: Request, profile_id: int):
    session = get_session(request)
    if (redirect := _require_auth(request, session)) is not None:
        return redirect

    rows = db.query("SELECT * FROM profiles WHERE id = %s", (profile_id,))
    if not rows:
        return attach_session(
            templates.TemplateResponse(
                request, "not_found.html", {"what": "profile", "session": session}, status_code=404
            ),
            session,
        )
    # No `AND user_id = session.user_id`. Any authenticated user can read any
    # profile simply by changing the number in the URL.
    return attach_session(
        templates.TemplateResponse(request, "profile.html", {"p": rows[0], "session": session}),
        session,
    )


@app.get("/api/profile/{profile_id}")
async def profile_api(request: Request, profile_id: int):
    """JSON twin of the profile page.

    This endpoint is where B-IDOR-1 injects its unused `ref_uid` field
    (spec §6.6): no button on the site produces that field, so only somebody
    editing requests by hand would ever send it back.
    """
    session = get_session(request)
    if not session.authenticated:
        return attach_session(JSONResponse({"error": "authentication required"}, status_code=401), session)

    rows = db.query("SELECT * FROM profiles WHERE id = %s", (profile_id,))
    if not rows:
        return attach_session(JSONResponse({"error": "not found"}, status_code=404), session)
    return attach_session(JSONResponse({"profile": rows[0]}), session)


@app.get("/records/{record_id}", response_class=HTMLResponse)
async def record_page(request: Request, record_id: int):
    session = get_session(request)
    if (redirect := _require_auth(request, session)) is not None:
        return redirect

    rows = db.query("SELECT * FROM records WHERE id = %s", (record_id,))
    if not rows:
        return attach_session(
            templates.TemplateResponse(
                request, "not_found.html", {"what": "record", "session": session}, status_code=404
            ),
            session,
        )
    return attach_session(
        templates.TemplateResponse(request, "record.html", {"r": rows[0], "session": session}),
        session,
    )


@app.get("/api/records/{record_id}")
async def record_api(request: Request, record_id: int):
    session = get_session(request)
    if not session.authenticated:
        return attach_session(JSONResponse({"error": "authentication required"}, status_code=401), session)
    rows = db.query("SELECT * FROM records WHERE id = %s", (record_id,))
    if not rows:
        return attach_session(JSONResponse({"error": "not found"}, status_code=404), session)
    return attach_session(JSONResponse({"record": rows[0]}), session)


@app.get("/directory", response_class=HTMLResponse)
async def directory(request: Request):
    """Staff directory -- the legitimate route to profiles, so that browsing
    them is normal behaviour and only the *pattern* of access distinguishes
    an IDOR sweep from ordinary use."""
    session = get_session(request)
    if (redirect := _require_auth(request, session)) is not None:
        return redirect
    people = db.query("SELECT id, full_name, department, location FROM profiles ORDER BY full_name")
    return attach_session(
        templates.TemplateResponse(request, "directory.html", {"people": people, "session": session}),
        session,
    )
