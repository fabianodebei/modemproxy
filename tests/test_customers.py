"""Customer accounts + read-only user panel."""
import base64

import pytest
from fastapi.testclient import TestClient

from modemproxy import db
from modemproxy.services import customers
from modemproxy.web.app import app

ADMIN = {"Authorization": "Basic " + base64.b64encode(b"admin:testpass").decode()}


@pytest.fixture
def client():
    return TestClient(app)


def test_password_hash_roundtrip():
    h = customers.hash_password("s3cret")
    assert customers.verify_password("s3cret", h)
    assert not customers.verify_password("wrong", h)


def test_create_and_authenticate():
    customers.create("alice", "pw123", label="Acme")
    assert customers.authenticate("alice", "pw123")
    assert not customers.authenticate("alice", "nope")
    assert not customers.authenticate("ghost", "pw123")


def test_proxies_for_only_assigned(modem):
    customers.create("bob", "pw")
    # nothing assigned yet
    assert customers.proxies_for("bob") == []
    db.customer_assign("bob", modem)
    out = customers.proxies_for("bob")
    assert len(out) == 1 and out[0]["imei"] == modem
    assert out[0]["http"]  # endpoint string present


def test_panel_login_required(client):
    r = client.get("/panel", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/panel/login"


def test_panel_login_and_view(client, modem):
    customers.create("carol", "pw")
    db.customer_assign("carol", modem)
    r = client.post("/panel/login", data={"username": "carol", "password": "pw"},
                    follow_redirects=False)
    assert r.status_code == 303
    page = client.get("/panel")
    assert page.status_code == 200
    assert "My proxies" in page.text
    assert (db.get_modem(modem)["name"] or "")[:3] in page.text or "dongle1" in page.text


def test_panel_bad_login(client):
    customers.create("dave", "pw")
    r = client.post("/panel/login", data={"username": "dave", "password": "x"})
    assert r.status_code == 401


def test_customer_cannot_rotate_unassigned(client, modem):
    customers.create("eve", "pw")
    client.post("/panel/login", data={"username": "eve", "password": "pw"})
    r = client.post(f"/panel/rotate/{modem}")     # not assigned to eve
    assert r.status_code == 403
