"""Subscription expiry + alert muting."""
import time

from modemproxy import db
from modemproxy.config import Config
from modemproxy.services import alerts, subscriptions


def test_extend_sets_future_expiry(modem):
    st = subscriptions.extend(modem, 30)
    assert st["expires_at"] > int(time.time())
    assert 29 <= st["days_left"] <= 30
    assert st["expired"] is False


def test_clear_expiry(modem):
    subscriptions.extend(modem, 30)
    st = subscriptions.set_expiry(modem, None)
    assert st["expires_at"] is None
    assert st["expired"] is False


def test_check_disables_expired(modem, monkeypatch):
    calls = []
    monkeypatch.setattr("modemproxy.proxy.generator.stop_proxy",
                        lambda imei, **k: calls.append(imei))
    db.set_port(modem, expires_at=int(time.time()) - 10)   # already expired
    actions = subscriptions.check()
    assert {"imei": modem, "action": "disabled-expired"} in actions
    assert modem in calls


def test_check_warns_before_expiry(modem, monkeypatch):
    sent = []
    monkeypatch.setattr(alerts, "expiring", lambda imei, name, days: sent.append(days))
    db.set_port(modem, expires_at=int(time.time()) + 2 * 86400)   # 2 days out
    actions = subscriptions.check()
    assert any(a["action"] == "expiring" for a in actions)
    assert sent and sent[0] == 2


def test_alert_mute_dedupes(monkeypatch):
    cfg = Config(tg_alerts_enable=True, tg_bot_token="t", tg_chat_id="1",
                 alert_mute_minutes=5)
    monkeypatch.setattr(alerts, "get_config", lambda *a, **k: cfg)
    sent = []
    monkeypatch.setattr(alerts, "_send_raw", lambda text: sent.append(text) or True)
    assert alerts.notify("hi", key="k1") is True
    assert alerts.notify("hi", key="k1") is False     # muted within window
    assert len(sent) == 1


def test_alert_disabled_when_off(monkeypatch):
    cfg = Config(tg_alerts_enable=False)
    monkeypatch.setattr(alerts, "get_config", lambda *a, **k: cfg)
    assert alerts.notify("hi") is False
