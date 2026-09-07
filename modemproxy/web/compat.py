"""proxysmart-compatible API for the Proxybet storefront.

Proxybet's Supabase functions were written against proxysmart's HTTP API
(HTTP Basic auth; ``/apix/*``, ``/modem/*``, ``/crud/*``). This router serves
the subset those functions actually call, backed by modemproxy, so the
storefront needs no code change — only ``PROXYSMART_ENDPOINT`` and
``PROXYSMART_PASSWORD`` in its Supabase secrets.

Storefront credentials are EXTRA logins (owner = ``cfg.compat_owner``) on each
modem proxy, so a modem's main login (e.g. the scraper's) is never touched.
Port ids exposed to the storefront are the modem imei (stable).
"""
from __future__ import annotations

import json
import secrets
import threading
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from .. import db
from ..config import get_config, update_config
from ..modems import manager, netdev
from ..proxy import generator
from ..services import bandwidth, tests

router = APIRouter()
_basic = HTTPBasic(auto_error=False)


# --- auth ------------------------------------------------------------------

_generated: str | None = None


def api_password() -> str:
    """The storefront's API password: generated once and persisted.

    Re-reads the config file when the cached copy has no password (it may
    have been written by another process, e.g. an admin CLI) and keeps the
    generated value in memory if the file is not writable, so the password
    stays stable for the life of the process either way.
    """
    global _generated
    cfg = get_config()
    if not cfg.compat_api_password:
        cfg = get_config(reload=True)
    if cfg.compat_api_password:
        return cfg.compat_api_password
    if _generated is None:
        _generated = secrets.token_urlsafe(18)
        try:
            update_config({"compat_api_password": _generated})
        except Exception:
            pass
    return _generated


def compat_auth(creds: HTTPBasicCredentials | None = Depends(_basic)) -> str:
    cfg = get_config()
    if not cfg.compat_api_enable:
        raise HTTPException(404, "not found")
    ok = (creds is not None
          and secrets.compare_digest(creds.username, cfg.compat_api_user)
          and secrets.compare_digest(creds.password, api_password()))
    if not ok:
        raise HTTPException(401, "Unauthorized",
                            headers={"WWW-Authenticate": 'Basic realm="modemproxy"'})
    return creds.username


# --- helpers ---------------------------------------------------------------

def _resolve(arg: str | None) -> dict:
    """Modem by imei, proxy service slug, or name -> modem dict (404 if none)."""
    if not arg:
        raise HTTPException(400, "missing modem id")
    m = db.get_modem(arg)
    if m:
        return m
    for cand in db.list_modems():
        if generator._svc(cand["imei"]) == arg or (cand.get("name") or "") == arg:
            return cand
    raise HTTPException(404, f"unknown modem {arg}")


def _split_operator(op: str | None) -> tuple[str, str]:
    """'Wind · 5G' -> ('Wind', '5G'); 'WINDTRE' -> ('WINDTRE', '')."""
    if not op:
        return "", ""
    if " · " in op:
        a, b = op.rsplit(" · ", 1)
        return a.strip(), b.strip()
    return op, ""


def _modem_status(m: dict) -> dict:
    online = m.get("status") == "online"
    op, rat = _split_operator(m.get("operator"))
    sig = int(m.get("signal") or 0)
    name = m.get("name") or m["imei"]
    return {
        "modem_details": {"IMEI": m["imei"], "NICK": name, "nickname": name,
                          "MODEL": m.get("model") or "", "PHONE_NUMBER": ""},
        "net_details": {
            "SimStatus": "ready",
            "IS_ONLINE": "yes" if online else "no",
            "ConnectionStatus": "connected" if online else "disconnected",
            # proxysmart reports 0-5 bars; Proxybet multiplies by 20.
            "SIGNAL_STRENGTH": str(max(0, min(5, round(sig / 20)))),
            "CurrentNetworkType": rat,
            "CELLOP": op,
            "EXT_IP": m.get("ip") or "",
            "LOCAL_IP": m.get("bind_ip") or "",
            "WAN_IP": m.get("ip") or "",
            "GEO": m.get("geo") or "",
        },
        "MSGS": [],
    }


def _ensure_storefront_user(m: dict) -> dict:
    """The storefront login for a modem, created (and loaded) on first use."""
    cfg = get_config()
    u = generator.get_extra_user(m["imei"], cfg.compat_owner)
    if u:
        return u
    u = generator.set_extra_user(m["imei"], cfg.compat_owner,
                                 f"{cfg.compat_owner}-{generator._svc(m['imei'])}",
                                 secrets.token_hex(8))
    generator.apply_port(m["imei"])          # load the new login into 3proxy
    return u


def _port_entry(m: dict, host: str) -> dict:
    import time
    u = _ensure_storefront_user(m)
    expired = bool(m.get("expires_at") and m["expires_at"] <= int(time.time()))
    http_port, socks_port = m["http_port"], m["socks_port"]
    return {
        "portID": m["imei"], "portName": m.get("name") or m["imei"],
        "HTTP_PORT": str(http_port), "SOCKS_PORT": str(socks_port),
        "LOGIN": u["username"], "PASSWORD": u["password"],
        "OWNER": get_config().compat_owner, "IMEI": m["imei"],
        # proxysmart format: "http://host:port:user:pass" for BOTH entries
        # (Proxybet's Export page parses them with that exact prefix).
        "http_creds": f"http://{host}:{http_port}:{u['username']}:{u['password']}",
        "socks5_creds": f"http://{host}:{socks_port}:{u['username']}:{u['password']}",
        "conns_stats": {"http": 0, "socks5": 0, "total": 0, "xray": 0},
        "IS_EXPIRED": 1 if expired else 0,
        "IS_OVER_QUOTA": 1 if m.get("quota_locked") else 0,
        "bw_quota": int((m.get("quota_bytes") or 0) / 1048576),
        "QUOTA_TYPE": "monthly", "QUOTA_DIRECTION": "inout",
    }


def _bg(fn, *args) -> None:
    threading.Thread(target=lambda: _swallow(fn, *args), daemon=True).start()


def _swallow(fn, *args) -> None:
    try:
        fn(*args)
    except Exception:
        pass


def _ok() -> PlainTextResponse:
    return PlainTextResponse("OK")


# --- modem status ----------------------------------------------------------

@router.get("/apix/show_status_json")
def show_status_json(_: str = Depends(compat_auth)):
    return [_modem_status(m) for m in db.list_modems()]


@router.get("/apix/show_single_status_json")
def show_single_status_json(arg: str | None = None, IMEI: str | None = None,
                            _: str = Depends(compat_auth)):
    return _modem_status(_resolve(arg or IMEI))


# --- ports (storefront credentials) ----------------------------------------

@router.get("/apix/list_ports_json")
def list_ports_json(request: Request, _: str = Depends(compat_auth)):
    """proxysmart shape: {imei: [port, ...]} — one storefront port per modem."""
    host = get_config().public_host or request.url.hostname
    out: dict[str, list[dict]] = {}
    for m in db.list_modems():
        if m.get("http_port") and m.get("enabled"):
            out[m["imei"]] = [_port_entry(m, host)]
    return out


@router.post("/crud/store_port")
async def store_port(request: Request, data: str | None = Form(None),
                     _: str = Depends(compat_auth)):
    """Set the storefront login for a port. proxysmart takes a form field
    ``data`` holding JSON; JSON bodies are accepted too. Followed by
    /apix/apply_port on the storefront side (as with proxysmart)."""
    payload: dict[str, Any] = {}
    if data:
        try:
            payload = json.loads(data)
        except ValueError:
            raise HTTPException(400, "data is not JSON")
    else:
        try:
            body = await request.json()
            payload = body.get("data", body) if isinstance(body, dict) else {}
            if isinstance(payload, str):
                payload = json.loads(payload)
        except Exception:
            raise HTTPException(400, "missing data")
    m = _resolve(payload.get("portID") or payload.get("IMEI"))
    login, pw = payload.get("proxy_login"), payload.get("proxy_password")
    if login and pw:
        generator.set_extra_user(m["imei"], get_config().compat_owner, str(login), str(pw))
    return _ok()


@router.get("/apix/apply_port")
def apply_port(arg: str | None = None, _: str = Depends(compat_auth)):
    generator.apply_port(_resolve(arg)["imei"])
    return _ok()


@router.get("/apix/purge_port")
def purge_port(arg: str | None = None, _: str = Depends(compat_auth)):
    """Storefront 'delete port' only drops its own login — never the modem."""
    m = _resolve(arg)
    generator.remove_extra_user(m["imei"], get_config().compat_owner)
    generator.apply_port(m["imei"])
    return _ok()


@router.get("/apix/get_free_tcp_ports")
def get_free_tcp_ports(_: str = Depends(compat_auth)):
    return []


# --- rotation / reset ------------------------------------------------------

@router.get("/apix/reset_modem_by_imei")
def reset_modem_by_imei(IMEI: str | None = None, arg: str | None = None,
                        _: str = Depends(compat_auth)):
    """Rotate the public IP (proxysmart returns at once; so do we)."""
    m = _resolve(IMEI or arg)
    _bg(manager.rotate, m["imei"], "proxybet")
    return _ok()


@router.get("/apix/reboot_modem_by_imei")
@router.get("/apix/usb_reset_modem_json")
def reboot_modem(IMEI: str | None = None, arg: str | None = None,
                 _: str = Depends(compat_auth)):
    m = _resolve(IMEI or arg)
    _bg(manager.reset_modem, m["imei"])
    return _ok()


@router.get("/apix/get_rotation_log")
def get_rotation_log(arg: str | None = None, _: str = Depends(compat_auth)):
    m = _resolve(arg)
    return [dict(r) for r in db.rotation_log(m["imei"], limit=100)]


@router.get("/apix/unique_ips_json")
def unique_ips_json(_: str = Depends(compat_auth)):
    out = []
    for m in db.list_modems():
        ips = []
        for r in db.rotation_log(m["imei"], limit=500):
            for ip in (r.get("new_ip"), r.get("old_ip")):
                if ip and ip not in ips:
                    ips.append(ip)
        if m.get("ip") and m["ip"] not in ips:
            ips.insert(0, m["ip"])
        out.append({"IMEI": m["imei"], "NICK": m.get("name") or m["imei"],
                    "unique_ips": len(ips), "ips": ips})
    return out


# --- SMS -------------------------------------------------------------------

@router.get("/modem/sms/{imei}")
def modem_sms(imei: str, _: str = Depends(compat_auth)):
    """Inbound SMS as proxysmart lists them: [{Phone, Content, Date}]."""
    m = _resolve(imei)
    try:
        msgs = netdev.sms_list(m)
    except netdev.NetdevError as e:
        raise HTTPException(503, str(e))
    return [{"Phone": s.get("number", ""), "Content": s.get("text", ""),
             "Date": s.get("date", ""), "ID": s.get("id", "")}
            for s in msgs if s.get("direction") == "in"]


@router.post("/modem/send-sms")
async def modem_send_sms(request: Request, _: str = Depends(compat_auth)):
    body = await request.json()
    m = _resolve(body.get("imei"))
    phone, text = (body.get("phone") or body.get("number") or "").strip(), body.get("sms") or body.get("message") or ""
    if not phone or not text:
        raise HTTPException(400, "phone and sms required")
    try:
        ok = netdev.sms_send(m, phone, text)
    except netdev.NetdevError as e:
        raise HTTPException(503, str(e))
    if not ok:
        raise HTTPException(502, "send failed")
    return _ok()


@router.get("/apix/purge_sms_json")
def purge_sms_json(arg: str | None = None, _: str = Depends(compat_auth)):
    m = _resolve(arg)
    try:
        ids = [s["id"] for s in netdev.sms_list(m) if s.get("id")]
        if ids:
            netdev.sms_delete(m, ids)
    except netdev.NetdevError as e:
        raise HTTPException(503, str(e))
    return _ok()


@router.post("/modem/send-ussd")
async def modem_send_ussd(request: Request, _: str = Depends(compat_auth)):
    body = await request.json()
    m = _resolve(body.get("imei"))
    code = body.get("ussd") or body.get("code") or ""
    if not code:
        raise HTTPException(400, "ussd code required")
    try:
        return {"response": manager.send_ussd(m["imei"], code)}
    except Exception as e:
        raise HTTPException(503, str(e))


@router.post("/modem/settings")
async def modem_settings(request: Request, _: str = Depends(compat_auth)):
    body = await request.json()
    m = _resolve(body.get("imei"))
    return {"IMEI": m["imei"], "NICK": m.get("name"), "model": m.get("model"),
            "rotation_interval": m.get("rotation_interval")}


# --- diagnostics / bandwidth ----------------------------------------------

@router.get("/apix/speedtest")
def speedtest(arg: str | None = None, _: str = Depends(compat_auth)):
    m = _resolve(arg)
    r = tests.speedtest(m["imei"])
    c = tests.conn_test(m["imei"])
    if not r.get("ok"):
        raise HTTPException(502, r.get("error") or "speedtest failed")
    return {"download": f"{r['mbps']} mbps", "upload": "0 mbps",
            "ping": f"{c.get('latency_ms', 'N/A')} ms" if c.get("ok") else "N/A"}


def _bw_entry(m: dict) -> dict:
    rep = bandwidth.report(m["imei"])
    return {"IMEI": m["imei"], "portID": m["imei"], "portName": m.get("name") or m["imei"],
            **rep, "today": rep["day_in"] + rep["day_out"],
            "month": rep["month_in"] + rep["month_out"]}


@router.get("/apix/bandwidth_report_all")
def bandwidth_report_all(_: str = Depends(compat_auth)):
    rows = [_bw_entry(m) for m in db.list_modems()]
    tot = bandwidth.report()
    return {"ports": rows, "total": {**tot, "today": tot["day_in"] + tot["day_out"],
                                     "month": tot["month_in"] + tot["month_out"]}}


@router.get("/apix/bandwidth_report_json")
@router.get("/apix/get_counters_port")
def bandwidth_report_json(arg: str | None = None, PORTID: str | None = None,
                          _: str = Depends(compat_auth)):
    return _bw_entry(_resolve(arg or PORTID))


@router.get("/apix/bandwidth_reset_counter")
def bandwidth_reset_counter(arg: str | None = None, _: str = Depends(compat_auth)):
    _resolve(arg)
    return _ok()


@router.get("/apix/top_hosts")
def top_hosts(arg: str | None = None, _: str = Depends(compat_auth)):
    _resolve(arg)
    return []
