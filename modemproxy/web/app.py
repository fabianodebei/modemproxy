"""FastAPI admin panel + JSON API.

UI is server-rendered Jinja + HTMX (no Node build step). The same routes back
both the dashboard and a small REST API under /api.
"""
from __future__ import annotations

import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import db
from ..config import get_config
from ..modems import manager
from ..proxy import generator

BASE = Path(__file__).parent
app = FastAPI(title="modemproxy", docs_url="/api/docs")
templates = Jinja2Templates(directory=str(BASE / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
security = HTTPBasic()


def auth(creds: HTTPBasicCredentials = Depends(security)) -> str:
    cfg = get_config()
    ok_user = secrets.compare_digest(creds.username, cfg.admin_user)
    ok_pass = secrets.compare_digest(creds.password, cfg.admin_password)
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
    return creds.username


@app.on_event("startup")
def _startup() -> None:
    db.init_db()


# --- UI --------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, _: str = Depends(auth)):
    modems = db.list_modems()
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "modems": modems, "cfg": get_config()},
    )


@app.post("/ui/discover", response_class=HTMLResponse)
def ui_discover(request: Request, _: str = Depends(auth)):
    manager.discover()
    return templates.TemplateResponse(
        "_modem_rows.html", {"request": request, "modems": db.list_modems()}
    )


@app.post("/ui/rotate/{imei}", response_class=HTMLResponse)
def ui_rotate(request: Request, imei: str, _: str = Depends(auth)):
    manager.rotate(imei, reason="web")
    return templates.TemplateResponse(
        "_modem_rows.html", {"request": request, "modems": db.list_modems()}
    )


@app.post("/ui/apply/{imei}", response_class=HTMLResponse)
def ui_apply(request: Request, imei: str, _: str = Depends(auth)):
    generator.apply_port(imei)
    return templates.TemplateResponse(
        "_modem_rows.html", {"request": request, "modems": db.list_modems()}
    )


# --- JSON API --------------------------------------------------------------

@app.get("/api/modems")
def api_modems(_: str = Depends(auth)):
    return db.list_modems()


@app.post("/api/discover")
def api_discover(_: str = Depends(auth)):
    return manager.discover()


@app.post("/api/modems/{imei}/rotate")
def api_rotate(imei: str, _: str = Depends(auth)):
    return manager.rotate(imei, reason="api")


@app.post("/api/modems/{imei}/apply-port")
def api_apply(imei: str, _: str = Depends(auth)):
    return generator.apply_port(imei)


@app.delete("/api/modems/{imei}/port")
def api_purge(imei: str, _: str = Depends(auth)):
    generator.purge_port(imei)
    return {"ok": True}


@app.get("/api/rotation-log")
def api_rotlog(imei: str | None = None, limit: int = 100, _: str = Depends(auth)):
    return db.rotation_log(imei, limit)


@app.get("/healthz")
def healthz():
    return JSONResponse({"ok": True})
