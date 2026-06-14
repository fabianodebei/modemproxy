"""Test fixtures.

Environment is pointed at a throwaway temp tree *before* any modemproxy module
is imported, because config.py resolves its paths at import time.
"""
import os
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="modemproxy-test-"))
(_TMP / "autogen").mkdir()
(_TMP / "vpn").mkdir()
(_TMP / "config.yaml").write_text(
    "admin_user: admin\n"
    "admin_password: testpass\n"
    "session_secret: testsecret\n"
    "vpn_public_host: 203.0.113.50\n"
    f"db_path: {_TMP / 'test.db'}\n"
)

os.environ["MODEMPROXY_CONFIG"] = str(_TMP / "config.yaml")
os.environ["MODEMPROXY_STATE_DIR"] = str(_TMP)
os.environ["MODEMPROXY_AUTOGEN_DIR"] = str(_TMP / "autogen")
os.environ["MODEMPROXY_VPN_DIR"] = str(_TMP / "vpn")

import pytest  # noqa: E402

from modemproxy import db  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_db():
    """Recreate an empty schema before each test."""
    dbfile = Path(db.get_config().db_path)
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(dbfile) + suffix)
        if p.exists():
            p.unlink()
    db.init_db()
    yield


@pytest.fixture
def modem():
    """Insert one modem + proxy port, return its imei."""
    from modemproxy.proxy import generator
    imei = "353211012345678"
    db.upsert_modem(imei, name="dongle1", iface="wwan0", operator="TIM",
                    ip="79.30.11.2", signal=70, status="online")
    generator.allocate_port(imei)
    return imei
