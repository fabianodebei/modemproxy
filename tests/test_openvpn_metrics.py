import shutil

import pytest

from modemproxy.services import metrics, openvpn

requires_openssl = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl not installed"
)


def test_metrics_render(modem):
    out = metrics.render()
    assert "modemproxy_modems_total 1" in out
    assert "modemproxy_modem_signal" in out
    assert modem in out


@requires_openssl
def test_ca_and_export(modem):
    info = openvpn.enable_vpn(modem)
    assert info["port"] == openvpn.BASE_PORT + 1
    assert info["subnet"].startswith("10.8.")
    ovpn = openvpn.export_client(modem)
    assert "remote 203.0.113.50" in ovpn
    assert "BEGIN CERTIFICATE" in ovpn
    assert "BEGIN EC PRIVATE KEY" in ovpn
    assert "<ca>" in ovpn and "<cert>" in ovpn and "<key>" in ovpn


@requires_openssl
def test_export_requires_known_modem():
    with pytest.raises(openvpn.VPNError):
        openvpn.export_client("000000000000000")
