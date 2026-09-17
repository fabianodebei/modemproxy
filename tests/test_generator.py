from modemproxy import db
from modemproxy.proxy import generator


def test_allocate_assigns_ports_and_token(modem):
    port = db.get_port(modem)
    assert port["http_port"] and port["socks_port"]
    assert port["username"] and port["password"]
    assert port["rotation_token"]


def test_render_contains_egress_ip(modem):
    path = generator.render_modem(modem)
    text = path.read_text()
    assert "79.30.11.2" in text          # bound to modem IP
    assert f"-p{db.get_port(modem)['http_port']}" in text


def test_render_auth_with_user(modem):
    text = generator.render_modem(modem).read_text()
    assert "auth strong" in text
    assert db.get_port(modem)["username"] in text


def test_whitelist_acl(modem):
    generator.set_whitelist(modem, ["203.0.113.4", "198.51.100.0/24"])
    text = generator.render_modem(modem).read_text()
    assert "allow" in text and "203.0.113.4,198.51.100.0/24" in text


def test_set_password(modem):
    generator.set_password(modem, "newsecret")
    assert db.get_port(modem)["password"] == "newsecret"


def test_regenerate_changes_password(modem):
    old = db.get_port(modem)["password"]
    generator.regenerate_credentials(modem)
    assert db.get_port(modem)["password"] != old


def test_stop_sets_disabled(modem):
    generator.stop_proxy(modem, locked=True)
    p = db.get_port(modem)
    assert p["enabled"] == 0 and p["quota_locked"] == 1


def test_config_lists_several_dns_servers_one_per_line(modem):
    from modemproxy.proxy import generator
    generator.allocate_port(modem)
    text = generator.render_modem(modem).read_text()
    lines = [l for l in text.splitlines() if l.startswith("nserver")]
    assert len(lines) >= 2 and all(len(l.split()) == 2 for l in lines)
