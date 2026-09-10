import re
"""proxysmart-compatible API (/apix, /modem, /crud) used by Proxybet."""
import json

import pytest
from fastapi.testclient import TestClient

from modemproxy import db
from modemproxy.config import get_config
from modemproxy.modems import manager, netdev
from modemproxy.proxy import generator
from modemproxy.web import compat
from modemproxy.web.app import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth():
    cfg = get_config()
    return (cfg.compat_api_user, compat.api_password())


def test_requires_basic_auth(client, auth):
    assert client.get("/apix/show_status_json").status_code == 401
    assert client.get("/apix/show_status_json", auth=("proxy", "wrong")).status_code == 401
    assert client.get("/apix/show_status_json", auth=auth).status_code == 200


def test_password_generated_once_and_persisted():
    pw = compat.api_password()
    assert len(pw) >= 20
    assert get_config(reload=True).compat_api_password == pw
    assert compat.api_password() == pw


def test_show_status_json_shape(client, auth, modem):
    db.upsert_modem(modem, operator="WINDTRE · 5G", signal=83, ip="1.2.3.4")
    r = client.get("/apix/show_status_json", auth=auth)
    assert r.status_code == 200
    (row,) = r.json()
    assert row["modem_details"]["IMEI"] == modem
    nd = row["net_details"]
    assert nd["IS_ONLINE"] == "yes" and nd["ConnectionStatus"] == "connected"
    assert nd["CELLOP"] == "WINDTRE" and nd["CurrentNetworkType"] == "5G"
    assert nd["SIGNAL_STRENGTH"] == "4"      # 83/20 -> 4 bars; Proxybet x20
    assert nd["EXT_IP"] == "1.2.3.4"
    assert row["MSGS"] == []
    single = client.get("/apix/show_single_status_json", params={"arg": modem}, auth=auth)
    assert single.json()["modem_details"]["IMEI"] == modem
    assert client.get("/apix/show_single_status_json", params={"arg": "nope"}, auth=auth).status_code == 404


def test_list_ports_creates_storefront_login_without_touching_main(client, auth, modem):
    generator.allocate_port(modem, username="odds_a", password="scraperpw")
    r = client.get("/apix/list_ports_json", auth=auth)
    assert r.status_code == 200
    (entry,) = r.json()[modem]
    assert entry["portID"] == modem and entry["IMEI"] == modem
    assert entry["HTTP_PORT"] == str(db.get_port(modem)["http_port"])
    assert entry["LOGIN"].startswith("proxybet-") and len(entry["PASSWORD"]) == 16
    assert entry["LOGIN"] != "odds_a"
    assert entry["http_creds"].endswith(f":{entry['LOGIN']}:{entry['PASSWORD']}")
    # Proxybet parses creds with /http:\/\/([^:]+):(\d+):([^:]+):(.+)/
    assert re.match(r"http://[^:]+:\d+:[^:]+:.+", entry["http_creds"])
    assert entry["socks5_creds"].startswith("http://")
    assert entry["IS_EXPIRED"] == 0 and entry["IS_OVER_QUOTA"] == 0
    # main login untouched; both logins present in the 3proxy config
    port = db.get_port(modem)
    assert port["username"] == "odds_a"
    cfg = generator.render_modem(modem).read_text()
    assert "users odds_a:CL:scraperpw" in cfg
    assert f"users {entry['LOGIN']}:CL:{entry['PASSWORD']}" in cfg
    assert f"allow odds_a,{entry['LOGIN']}" in cfg
    # stable across calls
    assert client.get("/apix/list_ports_json", auth=auth).json()[modem][0]["LOGIN"] == entry["LOGIN"]


def test_store_port_and_apply_set_storefront_login(client, auth, modem):
    data = json.dumps({"portID": modem, "IMEI": modem, "portName": "Proxybet01",
                       "http_port": 18001, "socks_port": 19001,
                       "proxy_login": "Proxybet01", "proxy_password": "s3cret"})
    r = client.post("/crud/store_port", data={"data": data}, auth=auth)
    assert r.status_code == 200 and r.text == "OK"
    r = client.get("/apix/apply_port", params={"arg": modem}, auth=auth)
    assert r.status_code == 200 and r.text == "OK"
    assert generator.get_extra_user(modem, "proxybet") == {
        "owner": "proxybet", "username": "Proxybet01", "password": "s3cret"}
    assert client.get("/apix/list_ports_json", auth=auth).json()[modem][0]["LOGIN"] == "Proxybet01"
    # purge_port only removes the storefront login
    assert client.get("/apix/purge_port", params={"arg": modem}, auth=auth).text == "OK"
    assert generator.get_extra_user(modem, "proxybet") is None
    assert db.get_modem(modem) is not None


def test_reset_and_reboot_call_manager(client, auth, modem, monkeypatch):
    import threading
    calls, done = [], threading.Event()

    def fake_rotate(imei, reason="manual"):
        calls.append(("rotate", imei, reason)); done.set()
        return {"ok": True}

    monkeypatch.setattr(manager, "rotate", fake_rotate)
    r = client.get("/apix/reset_modem_by_imei", params={"IMEI": modem}, auth=auth)
    assert r.status_code == 200 and r.text == "OK"
    assert done.wait(2) and calls == [("rotate", modem, "proxybet")]
    assert client.get("/apix/reset_modem_by_imei", params={"IMEI": "x"}, auth=auth).status_code == 404

    done.clear(); calls.clear()
    monkeypatch.setattr(manager, "reset_modem", lambda imei: (calls.append(("reset", imei)), done.set()))
    assert client.get("/apix/reboot_modem_by_imei", params={"IMEI": modem}, auth=auth).text == "OK"
    assert done.wait(2) and calls == [("reset", modem)]


def test_sms_endpoints(client, auth, modem, monkeypatch):
    inbox = [{"id": "1", "direction": "in", "number": "+39333", "text": "ciao", "date": "2026-09-07 10:00"},
             {"id": "2", "direction": "out", "number": "+39444", "text": "sent", "date": "2026-09-07 10:01"}]
    sent, deleted = [], []
    monkeypatch.setattr(netdev, "sms_list", lambda m: inbox)
    monkeypatch.setattr(netdev, "sms_send", lambda m, n, t: (sent.append((n, t)), True)[1])
    monkeypatch.setattr(netdev, "sms_delete", lambda m, ids: (deleted.extend(ids), True)[1])

    r = client.get(f"/modem/sms/{modem}", auth=auth)
    assert r.status_code == 200
    assert r.json() == [{"Phone": "+39333", "Content": "ciao", "Date": "2026-09-07 10:00", "ID": "1"}]

    r = client.post("/modem/send-sms", json={"imei": modem, "phone": "+39555", "sms": "hello"}, auth=auth)
    assert r.status_code == 200 and r.text == "OK" and sent == [("+39555", "hello")]
    assert client.post("/modem/send-sms", json={"imei": modem, "phone": ""}, auth=auth).status_code == 400

    assert client.get("/apix/purge_sms_json", params={"arg": modem}, auth=auth).text == "OK"
    assert deleted == ["1", "2"]


def test_bandwidth_and_stubs(client, auth, modem):
    r = client.get("/apix/bandwidth_report_all", auth=auth)
    assert r.status_code == 200
    body = r.json()
    assert body[modem]["IMEI"] == modem and "today" in body[modem]
    # proxysmart-style strings Proxybet parses ("12.3 MB")
    assert body[modem]["bandwidth_bytes_month_in"].endswith((" KB", " MB", " GB", " TB"))
    one = client.get("/apix/get_counters_port", params={"PORTID": modem}, auth=auth).json()
    assert one["portID"] == modem and "bandwidth_bytes_day_out" in one
    assert client.get("/apix/unique_ips_json", auth=auth).json()[0]["ips"] == ["79.30.11.2"]
    assert client.get("/apix/get_rotation_log", params={"arg": modem}, auth=auth).json() == []
    assert client.get("/apix/get_free_tcp_ports", auth=auth).json() == []
    assert client.get("/apix/top_hosts", params={"arg": modem}, auth=auth).json() == []


def test_disabled_api_hides_endpoints(client, auth, monkeypatch):
    from modemproxy import config as cfgmod
    cfg = get_config()
    monkeypatch.setattr(cfg, "compat_api_enable", False)
    assert client.get("/apix/show_status_json", auth=auth).status_code == 404


def test_reset_refused_for_excluded_modem(client, modem, auth, monkeypatch):
    from modemproxy.config import update_config
    from modemproxy.modems import manager

    called = []
    monkeypatch.setattr(manager, "rotate", lambda imei, reason="manual": called.append(imei) or {})
    update_config({"rotation_hook_exclude": [modem]})
    try:
        r = client.get("/apix/reset_modem_by_imei", params={"IMEI": modem}, auth=auth)
        assert r.status_code == 403 and called == []
    finally:
        update_config({"rotation_hook_exclude": []})


def test_speedtest_reports_download_upload_ping(client, auth, modem, monkeypatch):
    from modemproxy.services import tests as svc
    monkeypatch.setattr(svc, "speedtest", lambda imei, timeout=30: {"ok": True, "mbps": 12.5})
    monkeypatch.setattr(svc, "speedtest_upload", lambda imei, timeout=30: {"ok": True, "mbps": 3.25})
    monkeypatch.setattr(svc, "latency", lambda imei, host="1.1.1.1", timeout=5: {"ok": True, "ms": 41})
    r = client.get("/apix/speedtest", params={"arg": modem}, auth=auth)
    assert r.status_code == 200
    assert r.json() == {"download": "12.5 mbps", "upload": "3.25 mbps", "ping": "41 ms"}


def test_human_sizes():
    from modemproxy.web.compat import _human
    assert _human(0) == "0.0 KB"
    assert _human(254 * 1024 * 1024) == "254.0 MB"
    assert _human(3.7 * 1024 ** 3) == "3.7 GB"
