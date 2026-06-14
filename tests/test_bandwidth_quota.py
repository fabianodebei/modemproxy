from modemproxy import db
from modemproxy.services import bandwidth, quota


def _inject(imei, samples):
    with db.db() as c:
        for ts, rx, tx in samples:
            c.execute("INSERT INTO bandwidth(imei,ts,rx_bytes,tx_bytes) VALUES(?,?,?,?)",
                      (imei, ts, rx, tx))


def test_report_positive_deltas(modem):
    t = db.now()
    _inject(modem, [(t - 100, 1000, 0), (t - 10, 6000, 500)])
    rep = bandwidth.report(modem)
    assert rep["month_in"] == 5000
    assert rep["month_out"] == 500


def test_report_ignores_counter_reset(modem):
    t = db.now()
    # counter resets (unplug): 6000 -> 100 should not count as negative
    _inject(modem, [(t - 100, 1000, 0), (t - 50, 6000, 0), (t - 10, 100, 0)])
    rep = bandwidth.report(modem)
    assert rep["month_in"] == 5000  # only the +5000 step


def test_quota_locks_when_over(modem):
    db.set_port(modem, quota_bytes=1000, quota_direction="both")
    t = db.now()
    _inject(modem, [(t - 100, 0, 0), (t - 10, 5000, 0)])
    actions = quota.check()
    assert any(a["action"] == "locked" for a in actions)
    assert db.get_port(modem)["quota_locked"] == 1


def test_quota_unlocks_when_under(modem):
    db.set_port(modem, quota_bytes=10**9, quota_locked=1, enabled=0)
    actions = quota.check()
    assert any(a["action"] == "unlocked" for a in actions)
    assert db.get_port(modem)["quota_locked"] == 0


def test_quota_status(modem):
    db.set_port(modem, quota_bytes=1000)
    st = quota.status(modem)
    assert st["quota_bytes"] == 1000
    assert st["over_quota"] is False
