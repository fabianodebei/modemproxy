"""Health check: self-healing, alert-on-change, boot report."""
from modemproxy import db
from modemproxy.services import healthcheck


def _modem(imei="net-hc1", name="Modem HC", port=18099):
    db.upsert_modem(imei, kind="netdev", name=name, status="online",
                    bind_ip="192.168.10.202", iface="mp9")
    with db.db() as conn:
        conn.execute("INSERT OR REPLACE INTO ports (imei, http_port, username, password, enabled)"
                     " VALUES (?,?,?,?,1)", (imei, port, "u9", "pw9"))
    return imei


def _stub(monkeypatch, *, proxy_ip=None, restarts=None):
    """Make every external command succeed, with the proxy answering or not."""
    def curl(args, timeout=20):
        if any("api.ipify.org" in a for a in args) and "-x" in args:
            return proxy_ip
        if any("api.ipify.org" in a for a in args):
            return "1.2.3.4"
        return "200"
    monkeypatch.setattr(healthcheck, "_curl", curl)
    def run(args, timeout=30):
        if args[:2] == ["ip", "-4"]:
            return 0, "wlo1  UP  192.168.1.114/24"
        if args[:2] == ["ip", "route"]:
            return 0, "default via 192.168.1.1 dev wlo1"
        return 0, "1.2.3.4"
    monkeypatch.setattr(healthcheck, "_run", run)
    monkeypatch.setattr(healthcheck, "_systemctl",
                        lambda *a: (restarts.append(a) if restarts is not None else None) or True)


def test_failing_proxy_is_restarted_then_reported(monkeypatch, tmp_path):
    imei = _modem()
    restarts = []
    _stub(monkeypatch, proxy_ip=None, restarts=restarts)
    monkeypatch.setattr(healthcheck, "STATE_FILE", tmp_path / "hc.json")
    sent = []
    monkeypatch.setattr(healthcheck.alerts, "notify", lambda t, **k: sent.append(t))

    res = healthcheck.run()
    assert res["ok"] is False
    assert any("restart" in " ".join(r) for r in restarts)      # tried to heal
    assert sent and "Modem HC" in sent[0]
    db.upsert_modem(imei, status="offline")


def test_alerts_only_when_state_changes(monkeypatch, tmp_path):
    _modem("net-hc2", "Modem HC2", 18098)
    _stub(monkeypatch, proxy_ip="5.6.7.8")
    monkeypatch.setattr(healthcheck, "STATE_FILE", tmp_path / "hc.json")
    sent = []
    monkeypatch.setattr(healthcheck.alerts, "notify", lambda t, **k: sent.append(t))

    assert healthcheck.run()["ok"]          # first run: all good, nothing changed
    assert healthcheck.run()["ok"]
    assert sent == []
    healthcheck.run(boot=True)              # a boot always reports
    assert len(sent) == 1 and "Ripartenza" in sent[0]


def test_report_lists_failures_and_repairs():
    checks = [{"key": "proxy:x", "name": "Modem 03", "ok": False, "detail": "nessuna uscita"},
              {"key": "dns", "name": "DNS", "ok": True, "detail": "8.8.8.8"}]
    text = healthcheck._report(checks, ["Modem 01"], boot=False)
    assert "Modem 03" in text and "nessuna uscita" in text
    assert "Modem 01" in text and "DNS" not in text
