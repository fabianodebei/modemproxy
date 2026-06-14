"""Remote-access (direct / relay) address building + frpc config."""
from modemproxy.config import Config
from modemproxy.services import publish


def _cfg(**kw):
    base = dict(access_mode="direct", public_host="", relay_host="",
                relay_port=7000, relay_token="", relay_remote_offset=0)
    base.update(kw)
    return Config(**base)


def _modem(**kw):
    m = dict(imei="net-eth0", name="zte1", operator="WINDTRE",
             http_port=8001, socks_port=9001, username="u1", password="pw",
             enabled=1)
    m.update(kw)
    return m


def test_direct_endpoints(monkeypatch):
    monkeypatch.setattr(publish, "get_config",
                        lambda *a, **k: _cfg(access_mode="direct", public_host="203.0.113.5"))
    ep = publish.customer_endpoints(_modem())
    assert ep["host"] == "203.0.113.5"
    assert ep["http"] == "http://u1:pw@203.0.113.5:8001"
    assert ep["socks5"] == "socks5://u1:pw@203.0.113.5:9001"


def test_relay_endpoints_apply_offset(monkeypatch):
    monkeypatch.setattr(publish, "get_config",
                        lambda *a, **k: _cfg(access_mode="relay", relay_host="vps.example",
                                             relay_remote_offset=100))
    ep = publish.customer_endpoints(_modem())
    assert ep["host"] == "vps.example"
    assert ep["http"] == "http://u1:pw@vps.example:8101"   # 8001 + 100
    assert ep["socks_port"] == 9101


def test_render_frpc_lists_each_proxy(monkeypatch):
    monkeypatch.setattr(publish, "get_config",
                        lambda *a, **k: _cfg(access_mode="relay", relay_host="vps.example",
                                             relay_token="secret"))
    monkeypatch.setattr(publish, "_live", lambda: [_modem(), _modem(imei="net-x", name="zte2",
                                                            http_port=8002, socks_port=9002)])
    out = publish.render_frpc()
    assert 'serverAddr = "vps.example"' in out
    assert 'auth.token = "secret"' in out
    assert out.count("[[proxies]]") == 4          # 2 modems x (http+socks)
    assert "remotePort = 8001" in out
    assert 'name = "modemproxy-zte2-socks"' in out


def test_status_reports_mode(monkeypatch):
    monkeypatch.setattr(publish, "get_config",
                        lambda *a, **k: _cfg(access_mode="direct", public_host="1.2.3.4"))
    monkeypatch.setattr(publish, "_live", lambda: [_modem()])
    st = publish.status()
    assert st["mode"] == "direct"
    assert st["host"] == "1.2.3.4"
    assert st["proxies"][0]["http"] == "http://u1:pw@1.2.3.4:8001"
