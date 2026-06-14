"""FastAPI admin panel + JSON API.

UI: server-rendered Jinja + Tailwind (CDN) + Alpine.js + Chart.js — no Node
build step. Cookie-session login for the UI; the JSON API under /api accepts
either the session cookie or HTTP basic auth.
"""
from __future__ import annotations

import base64
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import (
    HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .. import db
from ..config import get_config
import random

from ..modems import control, manager
from ..proxy import generator
from ..services import bandwidth, metrics, openvpn, quota, tests

BASE = Path(__file__).parent
_cfg = get_config()


@asynccontextmanager
async def _lifespan(app: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="modemproxy", docs_url="/api/docs", lifespan=_lifespan)
app.add_middleware(SessionMiddleware, secret_key=_cfg.session_secret,
                   session_cookie="modemproxy_session", max_age=86400 * 7)
templates = Jinja2Templates(directory=str(BASE / "templates"))


def _humanbytes(n) -> str:
    try:
        n = float(n or 0)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _ts(epoch) -> str:
    import datetime as _dt
    try:
        return _dt.datetime.fromtimestamp(int(epoch)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return "—"


templates.env.filters["bytes"] = _humanbytes
templates.env.filters["ts"] = _ts
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")


# --- auth ------------------------------------------------------------------

def _check_credentials(user: str, pw: str) -> bool:
    cfg = get_config()
    return (secrets.compare_digest(user, cfg.admin_user)
            and secrets.compare_digest(pw, cfg.admin_password))


def ui_auth(request: Request):
    """UI guard: redirect to /login when no valid session."""
    if not request.session.get("user"):
        raise _RedirectToLogin()
    return request.session["user"]


def api_auth(request: Request) -> str:
    """API guard: accept session cookie, API key, or HTTP basic auth."""
    if request.session.get("user"):
        return request.session["user"]
    header = request.headers.get("authorization", "")
    api_key = request.headers.get("x-api-key", "")
    if header.startswith("Bearer "):
        api_key = header[7:].strip()
    if api_key and db.api_key_valid(api_key):
        return "apikey"
    if header.startswith("Basic "):
        try:
            raw = base64.b64decode(header[6:]).decode()
            user, _, pw = raw.partition(":")
        except Exception:
            raw = ""
            user = pw = ""
        if _check_credentials(user, pw):
            return user
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized",
        headers={"WWW-Authenticate": "Basic"},
    )


def admin_auth(request: Request) -> str:
    """Stricter guard for sensitive ops: session or basic admin only (no API key)."""
    if request.session.get("user"):
        return request.session["user"]
    header = request.headers.get("authorization", "")
    if header.startswith("Basic "):
        try:
            user, _, pw = base64.b64decode(header[6:]).decode().partition(":")
        except Exception:
            user = pw = ""
        if _check_credentials(user, pw):
            return user
    raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Basic"})


class _RedirectToLogin(Exception):
    pass


@app.exception_handler(_RedirectToLogin)
async def _redirect_login(request: Request, exc: _RedirectToLogin):
    return RedirectResponse("/login", status_code=303)


# --- login -----------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if request.session.get("user"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login", response_class=HTMLResponse)
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    if _check_credentials(username, password):
        request.session["user"] = username
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request, "login.html", {"error": "Invalid credentials"},
        status_code=401,
    )


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# --- UI pages --------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: str = Depends(ui_auth)):
    return templates.TemplateResponse(
        request, "dashboard.html",
        {"user": user, "cfg": get_config(),
         "modems": db.list_modems(), "bw": bandwidth.report()},
    )


@app.get("/bandwidth", response_class=HTMLResponse)
def bandwidth_page(request: Request, user: str = Depends(ui_auth)):
    return templates.TemplateResponse(
        request, "bandwidth.html",
        {"user": user, "modems": db.list_modems(),
         "bw": bandwidth.report()},
    )


@app.get("/pool", response_class=HTMLResponse)
def pool_page(request: Request, user: str = Depends(ui_auth)):
    return templates.TemplateResponse(
        request, "pool.html",
        {"user": user, "proxies": _live_proxies(request)},
    )


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: str = Depends(ui_auth)):
    return templates.TemplateResponse(
        request, "settings.html", {"user": user, "keys": db.api_key_list()},
    )


@app.get("/activity", response_class=HTMLResponse)
def activity_page(request: Request, user: str = Depends(ui_auth)):
    names = {m["imei"]: (m.get("name") or m["imei"]) for m in db.list_modems()}
    log = db.rotation_log(limit=200)
    for r in log:
        r["name"] = names.get(r["imei"], r["imei"])
    return templates.TemplateResponse(
        request, "activity.html", {"user": user, "log": log},
    )


# --- JSON API --------------------------------------------------------------

@app.get("/api/modems")
def api_modems(_: str = Depends(api_auth)):
    return db.list_modems()


@app.get("/api/modems/{imei}")
def api_modem(imei: str, _: str = Depends(api_auth)):
    m = db.get_modem(imei)
    if not m:
        raise HTTPException(404, "not found")
    return {**m, "port": db.get_port(imei)}


@app.post("/api/discover")
def api_discover(_: str = Depends(api_auth)):
    return manager.discover()


@app.post("/api/modems/{imei}/rotate")
def api_rotate(imei: str, _: str = Depends(api_auth)):
    return manager.rotate(imei, reason="api")


@app.post("/api/modems/{imei}/apply-port")
def api_apply(imei: str, _: str = Depends(api_auth)):
    return generator.apply_port(imei)


@app.post("/api/modems/{imei}/password")
async def api_set_password(imei: str, request: Request, _: str = Depends(api_auth)):
    body = await request.json()
    pw = (body or {}).get("password", "")
    if not pw:
        raise HTTPException(400, "password required")
    return generator.set_password(imei, pw)


@app.post("/api/modems/{imei}/regenerate")
def api_regen(imei: str, _: str = Depends(api_auth)):
    return generator.regenerate_credentials(imei)


@app.post("/api/modems/{imei}/rotation-interval")
async def api_set_interval(imei: str, request: Request, _: str = Depends(api_auth)):
    body = await request.json()
    return generator.set_rotation_interval(imei, int((body or {}).get("seconds", 0)))


@app.post("/api/modems/{imei}/whitelist")
async def api_set_whitelist(imei: str, request: Request, _: str = Depends(api_auth)):
    body = await request.json()
    ips = (body or {}).get("ips", [])
    if isinstance(ips, str):
        ips = [s for s in ips.replace(",", "\n").splitlines()]
    return generator.set_whitelist(imei, ips)


@app.delete("/api/modems/{imei}/port")
def api_purge(imei: str, _: str = Depends(api_auth)):
    generator.purge_port(imei)
    return {"ok": True}


@app.post("/api/modems/{imei}/reset")
def api_reset(imei: str, _: str = Depends(api_auth)):
    manager.reset_modem(imei)
    return {"ok": True}


@app.post("/api/modems/{imei}/ussd")
async def api_ussd(imei: str, request: Request, _: str = Depends(api_auth)):
    body = await request.json()
    code = (body or {}).get("code", "")
    if not code:
        raise HTTPException(400, "code required")
    try:
        return {"imei": imei, "response": manager.send_ussd(imei, code)}
    except control.MMError as e:
        raise HTTPException(503, str(e))


@app.post("/api/modems/{imei}/conn-test")
def api_conn_test(imei: str, _: str = Depends(api_auth)):
    return tests.conn_test(imei)


@app.post("/api/modems/{imei}/speedtest")
def api_speedtest(imei: str, _: str = Depends(api_auth)):
    return tests.speedtest(imei)


@app.post("/api/modems/{imei}/quota")
async def api_set_quota(imei: str, request: Request, _: str = Depends(api_auth)):
    body = await request.json() or {}
    return quota.set_quota(
        imei, int(body.get("quota_bytes", 0)), body.get("quota_direction", "both")
    )


@app.get("/api/modems/{imei}/quota")
def api_quota_status(imei: str, _: str = Depends(api_auth)):
    return quota.status(imei)


@app.post("/api/modems/{imei}/vpn/enable")
def api_vpn_enable(imei: str, _: str = Depends(api_auth)):
    try:
        return openvpn.enable_vpn(imei)
    except openvpn.VPNError as e:
        raise HTTPException(400, str(e))


@app.post("/api/modems/{imei}/vpn/disable")
def api_vpn_disable(imei: str, _: str = Depends(api_auth)):
    openvpn.disable_vpn(imei)
    return {"ok": True}


@app.get("/api/modems/{imei}/vpn/export")
def api_vpn_export(imei: str, _: str = Depends(api_auth)):
    try:
        text = openvpn.export_client(imei)
    except openvpn.VPNError as e:
        raise HTTPException(400, str(e))
    m = db.get_modem(imei) or {}
    fname = f"modemproxy-{m.get('name') or imei}.ovpn"
    return PlainTextResponse(text, headers={
        "Content-Disposition": f'attachment; filename="{fname}"'})


# --- allocation pool -------------------------------------------------------

def _live_proxies(request: Request) -> list[dict]:
    host = request.url.hostname
    out = []
    for m in db.list_modems():
        if (m.get("status") == "online" and m.get("http_port")
                and m.get("enabled") and not m.get("quota_locked")):
            cred = f"{m['username']}:{m['password']}@" if m.get("username") else ""
            out.append({
                "imei": m["imei"], "name": m.get("name"),
                "operator": m.get("operator"), "ip": m.get("ip"),
                "host": host, "http_port": m["http_port"], "socks_port": m["socks_port"],
                "http": f"http://{cred}{host}:{m['http_port']}",
                "socks5": f"socks5h://{cred}{host}:{m['socks_port']}",
            })
    return out


@app.get("/api/pool")
def api_pool(request: Request, operator: str | None = None, _: str = Depends(api_auth)):
    proxies = _live_proxies(request)
    if operator:
        proxies = [p for p in proxies if (p.get("operator") or "").lower() == operator.lower()]
    return proxies


@app.get("/api/pool/random")
def api_pool_random(request: Request, operator: str | None = None, _: str = Depends(api_auth)):
    proxies = api_pool(request, operator, _)
    if not proxies:
        raise HTTPException(503, "no live proxy available")
    return random.choice(proxies)


@app.get("/api/pool/sticky/{key}")
def api_pool_sticky(key: str, request: Request, ttl: int = 600,
                    operator: str | None = None, _: str = Depends(api_auth)):
    """Return the same live proxy for a given session key within its TTL."""
    proxies = api_pool(request, operator, _)
    if not proxies:
        raise HTTPException(503, "no live proxy available")
    by_imei = {p["imei"]: p for p in proxies}
    imei = db.sticky_get(key)
    if imei not in by_imei:                 # unset, expired, or no longer live
        imei = random.choice(proxies)["imei"]
    db.sticky_set(key, imei, max(1, ttl))
    return by_imei[imei]


# Public rotation hook — token-authenticated, no session. Lets external tools
# rotate a single proxy's IP by hitting a secret URL (link rotation).
@app.get("/hook/rotate/{token}")
@app.post("/hook/rotate/{token}")
def rotation_hook(token: str):
    port = db.get_port_by_token(token)
    if not port:
        raise HTTPException(404, "invalid token")
    try:
        return manager.rotate(port["imei"], reason="hook")
    except control.MMError as e:
        raise HTTPException(503, str(e))


@app.get("/api/bandwidth")
def api_bandwidth(imei: str | None = None, _: str = Depends(api_auth)):
    return bandwidth.report(imei)


@app.get("/api/bandwidth/{imei}/series")
def api_bw_series(imei: str, hours: int = 24, _: str = Depends(api_auth)):
    return bandwidth.series(imei, hours=hours)


@app.get("/api/rotation-log")
def api_rotlog(imei: str | None = None, limit: int = 100, _: str = Depends(api_auth)):
    return db.rotation_log(imei, limit)


@app.get("/api/keys")
def api_keys_list(_: str = Depends(admin_auth)):
    return db.api_key_list()


@app.post("/api/keys")
async def api_keys_create(request: Request, _: str = Depends(admin_auth)):
    body = await request.json() if await request.body() else {}
    return {"key": db.api_key_create((body or {}).get("label", ""))}


@app.delete("/api/keys/{key}")
def api_keys_revoke(key: str, _: str = Depends(admin_auth)):
    if not db.api_key_revoke(key):
        raise HTTPException(404, "not found")
    return {"ok": True}


@app.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics():
    return metrics.render()


@app.get("/healthz")
def healthz():
    return JSONResponse({"ok": True})
