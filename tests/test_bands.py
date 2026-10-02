"""Band lock: masks, lock/unlock round-trip, scan ranking, auto-unlock guard."""
import json

import pytest

from modemproxy import db
from modemproxy.modems import bands


def _modem(imei="net-band1"):
    db.upsert_modem(imei, kind="netdev", name="Modem Band", manual=1, iface="mp9",
                    mgmt_host="192.168.10.9", bind_ip="192.168.10.209",
                    model="ZTE MC801A", status="online")
    return db.get_modem(imei)


def _fake_device(monkeypatch, state, *, fail_set=False):
    """Pretend to be a ZTE: remember the mask it was given, answer status."""
    monkeypatch.setattr(bands, "_zte", lambda m: ("192.168.10.9", None, "jar", {}, "hash"))

    def zte_set(host, iface, cj, headers, base_hash, **params):
        if fail_set:
            return '{"result":"failure"}'
        if params.get("goformId") == "BAND_SELECT":
            state["mask"] = params["lte_band_mask"]
        if params.get("goformId") == "WAN_PERFORM_NR5G_BAND_LOCK":
            state["nr"] = params["nr5g_band_mask"]
        return '{"result":"success"}'

    monkeypatch.setattr(bands.netdev, "zte_set", zte_set)
    monkeypatch.setattr(bands, "_get", lambda m, cmd: {
        "lte_band_lock": state["mask"], "nr5g_band_lock": state.get("nr", "1,3,78"),
        "wan_active_band": "LTE BAND " + str(bands.mask_to_bands(state["mask"])[0]),
        "network_type": "LTE-NSA", "lte_rsrp": "-70", "lte_snr": "10",
    })
    monkeypatch.setattr(bands.time, "sleep", lambda *_: None)


def test_mask_round_trip():
    assert bands.bands_to_mask([1]) == "0x1"
    assert bands.bands_to_mask([3]) == "0x4"
    assert bands.bands_to_mask([7]) == "0x40"
    assert bands.bands_to_mask([20]) == "0x80000"
    assert bands.mask_to_bands("0x1e7ffffdf3fff")[:4] == [1, 2, 3, 4]
    assert bands.mask_to_bands("0x4") == [3]
    with pytest.raises(bands.BandError):
        bands.bands_to_mask([])


def test_lock_then_unlock_restores_the_original_mask(monkeypatch):
    m = _modem()
    state = {"mask": "0x1e7ffffdf3fff"}
    _fake_device(monkeypatch, state)

    out = bands.apply(m, [3])
    assert state["mask"] == "0x4"                       # locked to B3 only
    assert out["locked"] and out["lte"] == [3]

    bands.clear(db.get_modem(m["imei"]))
    assert state["mask"] == "0x1e7ffffdf3fff"           # device's own mask back
    assert bands.read(db.get_modem(m["imei"]))["locked"] is False


def test_lock_is_refused_when_the_modem_says_failure(monkeypatch):
    m = _modem("net-band2")
    _fake_device(monkeypatch, {"mask": "0x40"}, fail_set=True)
    with pytest.raises(bands.BandError):
        bands.apply(m, [3])


def test_scan_ranks_bands_and_restores(monkeypatch):
    m = _modem("net-band3")
    state = {"mask": "0x1e7ffffdf3fff"}
    _fake_device(monkeypatch, state)
    samples = {1: {"rsrp": -100, "sinr": 2, "online": True},
               3: {"rsrp": -62, "sinr": 14, "online": True},
               7: {"rsrp": -88, "sinr": 5, "online": True},
               20: {"rsrp": None, "sinr": None, "online": False}}
    monkeypatch.setattr(bands, "_sample",
                        lambda mm: dict(samples[bands.mask_to_bands(state["mask"])[0]]))

    out = bands.scan(m, [1, 3, 7, 20], settle=0)
    assert out["best"] == 3
    assert [r["band"] for r in out["results"]][0] == 3
    assert out["results"][-1]["band"] == 20             # offline ranks last
    assert state["mask"] == "0x1e7ffffdf3fff"           # left unlocked, as found


def test_guard_unlocks_after_repeated_failures(monkeypatch):
    m = _modem("net-band4")
    state = {"mask": "0x1e7ffffdf3fff"}
    _fake_device(monkeypatch, state)
    bands.apply(m, [3])
    assert state["mask"] == "0x4"

    monkeypatch.setattr(bands.netdev, "public_ip", lambda *a, **k: None)
    for _ in range(bands.GUARD_STRIKES - 1):
        assert bands.guard(db.get_modem(m["imei"])) is None
        assert state["mask"] == "0x4"                   # still locked, still patient
    msg = bands.guard(db.get_modem(m["imei"]))
    assert msg and "blocco rimosso" in msg
    assert state["mask"] == "0x1e7ffffdf3fff"           # freed to re-attach anywhere


def test_guard_keeps_the_lock_while_the_modem_is_online(monkeypatch):
    m = _modem("net-band5")
    state = {"mask": "0x1e7ffffdf3fff"}
    _fake_device(monkeypatch, state)
    bands.apply(m, [7])
    monkeypatch.setattr(bands.netdev, "public_ip", lambda *a, **k: "5.6.7.8")
    for _ in range(5):
        assert bands.guard(db.get_modem(m["imei"])) is None
    assert state["mask"] == "0x40"
    assert json.loads(db.get_modem(m["imei"])["band_lock"])["strikes"] == 0


def test_narrow_mask_never_becomes_the_restore_point(monkeypatch):
    """lte_band_lock reports the band in use while the radio re-attaches, so a
    single-band reading must not be stored as 'the device's own mask'."""
    m = _modem("net-band6")
    state = {"mask": "0xa3e2ab0908df"}
    _fake_device(monkeypatch, state)
    bands.read(m)                                   # wide mask learned
    state["mask"] = "0x4"                           # mid re-attach: one band
    bands.read(db.get_modem(m["imei"]))
    saved = json.loads(db.get_modem(m["imei"])["band_lock"])
    assert saved["default_mask"] == "0xa3e2ab0908df"

    bands.apply(db.get_modem(m["imei"]), [1])
    bands.clear(db.get_modem(m["imei"]))
    assert state["mask"] == "0xa3e2ab0908df"        # unlock really unlocks


def test_lock_refused_until_the_full_mask_is_known(monkeypatch):
    m = _modem("net-band7")
    _fake_device(monkeypatch, {"mask": "0x4"})      # only ever seen locked
    with pytest.raises(bands.BandError):
        bands.apply(m, [3])
