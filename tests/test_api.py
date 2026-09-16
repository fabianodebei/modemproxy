import base64

import pytest
from fastapi.testclient import TestClient

from modemproxy import db
from modemproxy.web.app import app

AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:testpass").decode()}
BAD = {"Authorization": "Basic " + base64.b64encode(b"admin:wrong").decode()}


@pytest.fixture
def client():
    return TestClient(app)


def test_healthz(client):
    assert client.get("/healthz").json() == {"ok": True}


def test_metrics_public(client, modem):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "modemproxy_modems_total" in r.text


def test_api_requires_auth(client):
    assert client.get("/api/modems", headers=BAD).status_code == 401


def test_api_modems(client, modem):
    r = client.get("/api/modems", headers=AUTH)
    assert r.status_code == 200
    assert r.json()[0]["imei"] == modem


def test_dashboard_redirects_without_session(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_login_then_dashboard(client):
    r = client.post("/login", data={"username": "admin", "password": "testpass"},
                    follow_redirects=False)
    assert r.status_code == 303
    r2 = client.get("/")          # cookie carried by TestClient
    assert r2.status_code == 200
    assert "Dashboard" in r2.text
    # Customer-facing hosts come from public_host, never from the address the
    # admin is browsing from (LAN IP / VPN 10.66.66.1).
    assert 'const SERVER_HOST = "proxy.example.net"' in r2.text
    assert 'const HOOK_BASE = "https://proxy.example.net"' in r2.text


def test_login_bad_password(client):
    r = client.post("/login", data={"username": "admin", "password": "nope"})
    assert r.status_code == 401


def test_pool_excludes_offline(client, modem):
    from modemproxy import db
    r = client.get("/api/pool", headers=AUTH)
    assert any(p["imei"] == modem for p in r.json())
    db.upsert_modem(modem, status="offline")
    r2 = client.get("/api/pool", headers=AUTH)
    assert all(p["imei"] != modem for p in r2.json())


def test_pool_random_503_when_empty(client):
    r = client.get("/api/pool/random", headers=AUTH)
    assert r.status_code == 503


def test_sticky_is_consistent(client, modem):
    a = client.get("/api/pool/sticky/sess1", headers=AUTH).json()
    b = client.get("/api/pool/sticky/sess1", headers=AUTH).json()
    assert a["imei"] == b["imei"] == modem


def test_rotation_hook_bad_token(client):
    assert client.get("/hook/rotate/bad").status_code == 404


def test_rotation_hook_returns_before_slow_rotation_ends(client, modem, monkeypatch):
    import threading
    import time
    from modemproxy.web import app as web_app
    from modemproxy.modems import manager
    from modemproxy import db

    token = db.get_port(modem)["rotation_token"]
    started = threading.Event()

    def slow_rotate(imei, reason="manual"):
        started.set()
        time.sleep(1.0)
        return {"imei": imei, "new_ip": "1.2.3.4"}

    monkeypatch.setattr(manager, "rotate", slow_rotate)
    monkeypatch.setattr(web_app, "HOOK_WAIT_SECONDS", 0.2)
    t0 = time.monotonic()
    r = client.get(f"/hook/rotate/{token}")
    assert time.monotonic() - t0 < 0.9
    assert r.status_code == 200
    assert r.json()["status"] == "rotating" and r.json()["imei"] == modem
    assert started.is_set()

    # fast rotation -> full result returned
    monkeypatch.setattr(manager, "rotate", lambda imei, reason="manual": {"imei": imei, "new_ip": "5.6.7.8"})
    r = client.get(f"/hook/rotate/{token}")
    assert r.status_code == 200 and r.json()["new_ip"] == "5.6.7.8"


def test_api_key_auth_flow(client, modem):
    # create a key via admin basic auth
    r = client.post("/api/keys", headers=AUTH, json={"label": "scraper"})
    key = r.json()["key"]
    assert key.startswith("mk_")
    # use the key (no admin creds) on a normal API endpoint
    r2 = client.get("/api/modems", headers={"Authorization": f"Bearer {key}"})
    assert r2.status_code == 200
    # x-api-key header form also works
    r3 = client.get("/api/pool", headers={"X-API-Key": key})
    assert r3.status_code == 200


def test_api_key_cannot_manage_keys(client, modem):
    key = client.post("/api/keys", headers=AUTH, json={}).json()["key"]
    # an API key must not be able to list/create keys (admin-only)
    assert client.get("/api/keys", headers={"Authorization": f"Bearer {key}"}).status_code == 401


def test_revoked_key_rejected(client):
    key = client.post("/api/keys", headers=AUTH, json={}).json()["key"]
    client.delete(f"/api/keys/{key}", headers=AUTH)
    assert client.get("/api/modems", headers={"X-API-Key": key}).status_code == 401


def test_rotation_hook_excluded_modem(client, modem, monkeypatch):
    from modemproxy import db
    from modemproxy.config import get_config, update_config
    from modemproxy.modems import manager

    called = []
    monkeypatch.setattr(manager, "rotate", lambda imei, reason="manual": called.append(imei) or {})
    update_config({"rotation_hook_exclude": [modem]})
    try:
        token = db.get_port(modem)["rotation_token"]
        r = client.get(f"/hook/rotate/{token}")
        assert r.status_code == 403 and called == []
    finally:
        update_config({"rotation_hook_exclude": []})
        assert get_config().rotation_hook_exclude == []


def test_router_cookies_are_namespaced_per_modem():
    from modemproxy.web.app import (_cookies_for_router, _namespace_set_cookie,
                                    _router_cookie_prefix)
    p1, p2 = _router_cookie_prefix("net-mp1"), _router_cookie_prefix("net-mp2")
    assert p1 != p2 and p1.startswith("mpr_")
    hdr = f"modemproxy_session=abc; mp_router=net-mp1; {p1}stok=\"AAA\"; {p2}stok=\"BBB\"; {p1}lang=it"
    assert _cookies_for_router(hdr, p1) == 'stok="AAA"; lang=it'
    assert _cookies_for_router(hdr, p2) == 'stok="BBB"'
    assert _cookies_for_router(None, p1) == ""
    assert _namespace_set_cookie('stok="CCC";path=/;HttpOnly', p1) == f'{p1}stok="CCC";path=/;HttpOnly'


def test_router_proxy_shares_one_session_with_modemproxy(client, monkeypatch, tmp_path):
    """ZTE firmware honours only the latest login, so the browser (via the
    panel) and modemproxy must use the same stok: the browser's login is
    adopted, and the shared stok is what gets sent to the router."""
    import subprocess as sp
    from modemproxy.modems import netdev
    from modemproxy.web import app as webapp
    db.upsert_modem("net-mp9", kind="netdev", manual=1, iface="mp9",
                    mgmt_host="192.168.10.9", bind_ip="192.168.10.209")
    jar = netdev.zte_session_jar_for(db.get_modem("net-mp9"))
    sent = []

    def fake_run(args, input=None, capture_output=True, timeout=None):
        sent.append(args)
        if input and b"goformId=LOGIN" in input:
            out = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n'
                   b'Set-Cookie: stok="NEWSESSION";path=/;HttpOnly\r\n\r\n{"result":"0"}')
        else:
            out = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{"loginfo":"ok"}'
        return sp.CompletedProcess(args, 0, out, b"")

    monkeypatch.setattr(webapp.subprocess, "run", fake_run)
    app.dependency_overrides[webapp.ui_auth] = lambda: "admin"
    try:
        client.cookies.set("mp_router", "net-mp9")
        client.cookies.set(webapp._router_cookie_prefix("net-mp9") + "stok", '"OLDBROWSER"')
        r = client.post("/goform/goform_set_cmd_process",
                        content=b"isTest=false&goformId=LOGIN&password=x",
                        headers={"content-type": "application/x-www-form-urlencoded"})
        assert r.status_code == 200
        assert netdev.zte_session_cookie(jar) == 'stok="NEWSESSION"'   # adopted
        client.get("/goform/goform_get_cmd_process?multi_data=1&cmd=loginfo")
        cookie_hdr = [a[i + 1] for a in sent[-1:] for i, x in enumerate(a) if x == "-H"
                      and a[i + 1].startswith("Cookie:")]
        assert cookie_hdr == ['Cookie: stok="NEWSESSION"']              # shared, not the browser's
    finally:
        app.dependency_overrides.clear()
