"""Rotating pool port rendering + GeoIP labelling."""
from modemproxy import db
from modemproxy.proxy import generator
from modemproxy.services import geoip


def _second_modem():
    imei = "353211099999999"
    db.upsert_modem(imei, name="dongle2", iface="wwan1", operator="VERY",
                    ip="79.30.11.3", signal=60, status="online")
    generator.allocate_port(imei)
    return imei


def test_migration_adds_geo_column_and_cache_table():
    with db.db() as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(modems)")}
        tables = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "geo" in cols
    assert "geoip" in tables


def test_geoip_refresh_labels_modem_and_caches(modem, monkeypatch):
    calls = []

    def fake_fetch(ip):
        calls.append(ip)
        return "IT · Milano"

    monkeypatch.setattr(geoip, "_fetch", fake_fetch)
    assert geoip.refresh_modems() == 1
    assert db.get_modem(modem)["geo"] == "IT · Milano"
    # Same IP again: label unchanged -> no write, and served from cache -> no fetch.
    assert geoip.refresh_modems() == 0
    assert calls == ["79.30.11.2"]


def test_geoip_failed_lookup_keeps_previous_label(modem, monkeypatch):
    db.upsert_modem(modem, geo="IT · Roma")
    monkeypatch.setattr(geoip, "_fetch", lambda ip: None)
    assert geoip.refresh_modems() == 0
    assert db.get_modem(modem)["geo"] == "IT · Roma"


def test_pool_render_parents_and_weights(modem):
    _second_modem()
    text = generator.render_pool().read_text()
    parents = [l for l in text.splitlines() if l.startswith("parent ")]
    # 2 members x (http service + socks service), all CONNECT tunnels to the
    # per-modem HTTP port ("http" parents can't carry CONNECT/HTTPS).
    assert len(parents) == 4
    assert all(" connect 127.0.0.1 " in l for l in parents)
    assert sum(int(l.split()[1]) for l in parents[:2]) == 1000
    assert sum(int(l.split()[1]) for l in parents[2:]) == 1000
    for m in (modem, "353211099999999"):
        port = db.get_port(m)
        assert f"connect 127.0.0.1 {port['http_port']} {port['username']} {port['password']}" in text
    cfg = db.get_config()
    assert f"proxy -p{cfg.http_port_base}" in text
    assert f"socks -p{cfg.socks_port_base}" in text
    assert "auth strong" in text and "users pool:CL:" in text


def test_pool_excludes_disabled_and_offline(modem):
    other = _second_modem()
    generator.stop_proxy(other)                      # disabled -> out of the pool
    db.upsert_modem(modem, status="offline")         # offline -> out of the pool
    assert generator.render_pool() is None
    st = generator.pool_status()
    assert st["active"] is False and st["members"] == []


def test_pool_status_lists_members(modem):
    st = generator.pool_status()
    assert st["enabled"] is True and st["active"] is True
    assert [m["imei"] for m in st["members"]] == [modem]
    assert st["members"][0]["weight"] == 1000
