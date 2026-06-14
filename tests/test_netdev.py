"""Net-mode (HiLink/RNDIS) dongle support."""
import json

import pytest

from modemproxy import db
from modemproxy.modems import netdev
from modemproxy.proxy import generator


def test_list_netdevs_filters_by_driver(monkeypatch):
    addr_json = json.dumps([
        {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
        {"ifname": "wlp2s0", "address": "aa:bb:cc:dd:ee:ff",
         "addr_info": [{"family": "inet", "local": "192.168.1.10", "prefixlen": 24}]},
        {"ifname": "enx344b50800000", "address": "34:4b:50:80:00:00",
         "addr_info": [{"family": "inet", "local": "192.168.0.203", "prefixlen": 24}]},
        {"ifname": "enx344b50800001", "address": "34:4b:50:80:00:01",
         "addr_info": [{"family": "inet", "local": "192.168.0.170", "prefixlen": 24}]},
    ])

    def fake_run(args, timeout=20):
        if args[:3] == ["ip", "-j", "addr"]:
            return 0, addr_json, ""
        if args[:4] == ["ip", "-j", "route", "show"]:
            return 0, json.dumps([{"dst": "default", "dev": "wlp2s0"}]), ""
        return 0, "", ""

    monkeypatch.setattr(netdev, "_run", fake_run)
    # wlp2s0 uses a wifi driver -> excluded; the two enx are cdc_ether dongles
    monkeypatch.setattr(netdev, "_driver",
                        lambda i: "cdc_ether" if i.startswith("enx") else "iwlwifi")

    devs = netdev.list_netdevs()
    ifaces = {d["iface"] for d in devs}
    assert ifaces == {"enx344b50800000", "enx344b50800001"}
    d0 = next(d for d in devs if d["iface"] == "enx344b50800000")
    assert d0["bind_ip"] == "192.168.0.203"
    assert d0["gateway"] == "192.168.0.1"
    assert d0["id"] == "net-enx344b50800000"
    assert d0["is_primary"] is False


def test_setup_routing_emits_rules(monkeypatch):
    calls = []
    monkeypatch.setattr(netdev, "_run", lambda args, timeout=20: calls.append(args) or (0, "", ""))
    netdev.setup_routing("enx0", "192.168.0.203", "192.168.0.1", 100)
    flat = [" ".join(c) for c in calls]
    assert any("ip route flush table 100" in f for f in flat)
    assert any("default via 192.168.0.1 dev enx0 table 100" in f for f in flat)
    assert any("ip rule add from 192.168.0.203 table 100" in f for f in flat)


def test_discover_upserts_netdev_modem(monkeypatch):
    monkeypatch.setattr(netdev, "list_netdevs", lambda: [{
        "iface": "enx344b50800000", "driver": "cdc_ether",
        "bind_ip": "192.168.0.203", "subnet": "192.168.0.0/24",
        "gateway": "192.168.0.1", "mac": "344b50800000",
        "id": "net-344b50800000", "is_primary": False,
    }])
    monkeypatch.setattr(netdev, "setup_routing", lambda *a, **k: None)
    monkeypatch.setattr(netdev, "_detect_gateway", lambda d: "192.168.0.1")
    monkeypatch.setattr(netdev, "public_ip", lambda i: "5.6.7.8")
    monkeypatch.setattr(netdev, "_usb_ids", lambda i: ("19d2", "1405"))

    out = netdev.discover()
    assert out[0]["public_ip"] == "5.6.7.8"
    m = db.get_modem("net-344b50800000")
    assert m["kind"] == "netdev"
    assert m["bind_ip"] == "192.168.0.203"
    assert m["ip"] == "5.6.7.8"
    assert m["status"] == "online"
    assert m["rt_table"] == 100
    assert "ZTE" in m["model"]


def test_generator_binds_netdev_to_local_ip():
    """3proxy egress must bind to the dongle's local interface IP, not its
    public WAN IP (which lives behind the dongle's own NAT)."""
    imei = "net-aabbccddeeff"
    db.upsert_modem(imei, name="zte1", kind="netdev", iface="enx0",
                    bind_ip="192.168.0.203", ip="5.6.7.8", status="online")
    generator.allocate_port(imei)
    cfg_text = generator.render_modem(imei).read_text()
    assert "-e192.168.0.203" in cfg_text       # egress = local iface IP
    assert "5.6.7.8" not in cfg_text           # never bind to the public IP


def test_rotate_netdev_uses_web_api(monkeypatch):
    imei = "net-aabbccddeeff"
    db.upsert_modem(imei, kind="netdev", iface="enx0",
                    bind_ip="192.168.0.203", mgmt_host="192.168.0.1",
                    rt_table=100, ip="5.6.7.8", status="online")
    from modemproxy.modems import manager
    monkeypatch.setattr(netdev, "_rotate_zte", lambda host: True)
    monkeypatch.setattr(netdev, "_rotate_huawei", lambda host: False)
    monkeypatch.setattr(netdev, "public_ip", lambda i: "9.9.9.9")
    import modemproxy.modems.netdev as nd
    monkeypatch.setattr(nd, "_rotate_zte", lambda host: True)
    monkeypatch.setattr("time.sleep", lambda s: None)

    res = manager.rotate(imei)
    assert res["old_ip"] == "5.6.7.8"
    assert res["new_ip"] == "9.9.9.9"
    assert db.get_modem(imei)["ip"] == "9.9.9.9"
    # rotation was logged
    assert db.rotation_log(imei)[0]["new_ip"] == "9.9.9.9"
