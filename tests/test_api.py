import base64

import pytest
from fastapi.testclient import TestClient

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
