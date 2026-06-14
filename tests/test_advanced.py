"""HiLink auth, TTL, rotation retry/uniqueness, auto-reboot scoring."""
import hashlib

from modemproxy import db
from modemproxy.config import Config
from modemproxy.modems import manager, netdev
from modemproxy.services import autoreboot, ttl


def test_zte_login_uses_ld_hash(monkeypatch):
    monkeypatch.setattr(netdev, "get_config",
                        lambda *a, **k: Config(default_hilink_password="secret"))
    posted = {}

    class FakeClient:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url):
            class R:
                def json(self_): return {"LD": "ABCD"}
            return R()
        def post(self, url, data=None):
            posted.update(data or {})
            class R: status_code = 200
            return R()
        def close(self): pass

    monkeypatch.setattr(netdev.httpx, "Client", FakeClient)
    netdev._zte_client("192.168.0.1")
    h1 = hashlib.sha256(b"secret").hexdigest().upper()
    expected = hashlib.sha256((h1 + "ABCD").encode()).hexdigest().upper()
    assert posted["goformId"] == "LOGIN"
    assert posted["password"] == expected


def test_ttl_disabled_is_noop(monkeypatch):
    monkeypatch.setattr(ttl, "get_config", lambda *a, **k: Config(custom_ttl=0))
    called = []
    monkeypatch.setattr(ttl, "_iptables", lambda args: called.append(args) or 0)
    assert ttl.ensure_ttl("eth0") is False
    assert called == []


def test_ttl_adds_rule(monkeypatch):
    monkeypatch.setattr(ttl, "get_config", lambda *a, **k: Config(custom_ttl=65))
    calls = []

    def fake(args):
        calls.append(args)
        return 1 if args[0] == "-C" else 0   # not present, then add succeeds

    monkeypatch.setattr(ttl, "_iptables", fake)
    assert ttl.ensure_ttl("eth0") is True
    assert any(a[0] == "-A" and "65" in a for a in calls)


def test_rotation_retries_until_ip_changes(modem, monkeypatch):
    monkeypatch.setattr(manager, "get_config",
                        lambda *a, **k: Config(rotation_unique=True, rotation_max_retry=3))
    db.upsert_modem(modem, ip="1.1.1.1")
    seq = iter(["1.1.1.1", "1.1.1.1", "2.2.2.2"])   # changes on 3rd try
    monkeypatch.setattr(manager, "_reconnect_once", lambda imei, old: next(seq))
    monkeypatch.setattr("modemproxy.services.alerts.rotation_ok", lambda *a, **k: None)
    res = manager.rotate(modem)
    assert res["new_ip"] == "2.2.2.2"


def test_rotation_min_interval_skips(modem, monkeypatch):
    monkeypatch.setattr(manager, "get_config",
                        lambda *a, **k: Config(rotation_min_interval=3600))
    db.upsert_modem(modem, ip="1.1.1.1")
    db.log_rotation(modem, "0.0.0.0", "1.1.1.1", "manual")   # just now
    called = []
    monkeypatch.setattr(manager, "_reconnect_once", lambda i, o: called.append(1) or "9.9.9.9")
    res = manager.rotate(modem)
    assert res.get("skipped") == "min_interval"
    assert called == []


def test_autoreboot_triggers_at_threshold(modem, monkeypatch):
    monkeypatch.setattr(autoreboot, "get_config",
                        lambda *a, **k: Config(autoreboot_enable=True, autoreboot_max_score=30,
                                               autoreboot_window=3600, autoreboot_min_uptime=0))
    rebooted = []
    monkeypatch.setattr(autoreboot, "_reboot", lambda imei, m: rebooted.append(imei))
    autoreboot.record(modem, 10)
    autoreboot.record(modem, 10)
    assert rebooted == []                 # 20 < 30
    autoreboot.record(modem, 10)
    assert rebooted == [modem]            # 30 >= 30
