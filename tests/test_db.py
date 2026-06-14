from modemproxy import db


def test_upsert_and_list(modem):
    modems = db.list_modems()
    assert len(modems) == 1
    assert modems[0]["imei"] == modem
    assert modems[0]["name"] == "dongle1"
    assert modems[0]["http_port"]  # port joined in


def test_upsert_updates_not_duplicates(modem):
    db.upsert_modem(modem, signal=99)
    rows = db.list_modems()
    assert len(rows) == 1
    assert rows[0]["signal"] == 99


def test_rotation_log(modem):
    db.log_rotation(modem, "1.1.1.1", "2.2.2.2", "manual")
    log = db.rotation_log(modem)
    assert log[0]["new_ip"] == "2.2.2.2"
    assert log[0]["reason"] == "manual"


def test_due_for_rotation(modem):
    db.set_port(modem, rotation_interval=60)
    # no prior rotation -> due immediately
    assert modem in db.due_for_rotation()
    db.log_rotation(modem, None, "3.3.3.3", "x")
    # just rotated -> not due
    assert modem not in db.due_for_rotation()


def test_due_skips_offline(modem):
    db.set_port(modem, rotation_interval=60)
    db.upsert_modem(modem, status="offline")
    assert modem not in db.due_for_rotation()


def test_sticky_roundtrip(modem):
    db.sticky_set("k1", modem, ttl=100)
    assert db.sticky_get("k1") == modem


def test_sticky_expires(modem):
    db.sticky_set("k2", modem, ttl=-1)  # already expired
    assert db.sticky_get("k2") is None


def test_port_by_token(modem):
    token = db.get_port(modem)["rotation_token"]
    assert db.get_port_by_token(token)["imei"] == modem
    assert db.get_port_by_token("nope") is None
