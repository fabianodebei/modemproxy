"""modemproxy command-line interface.

Subcommands mirror the operational surface of a modem-proxy box:
discovery, status, port allocation, rotation, SMS, bandwidth.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import db
from .modems import control, manager
from .proxy import generator
from .services import bandwidth, openvpn, publish, quota, tests


def _print_json(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def cmd_init_db(args) -> int:
    db.init_db()
    print("database initialised")
    return 0


def cmd_discover(args) -> int:
    found = manager.discover()
    _print_json(found) if args.json else print(f"discovered {len(found)} modem(s)")
    return 0


def cmd_list(args) -> int:
    modems = db.list_modems()
    if args.json:
        _print_json(modems)
        return 0
    if not modems:
        print("no modems (run: modemproxy discover)")
        return 0
    hdr = f"{'NAME':<12}{'IMEI':<18}{'OPERATOR':<16}{'IP':<16}{'SIG':<5}{'HTTP':<7}{'SOCKS':<7}{'STATUS'}"
    print(hdr)
    for m in modems:
        print(f"{(m.get('name') or '-'):<12}{(m.get('imei') or '-'):<18}"
              f"{(m.get('operator') or '-'):<16}{(m.get('ip') or '-'):<16}"
              f"{(m.get('signal') or 0):<5}{(m.get('http_port') or '-'):<7}"
              f"{(m.get('socks_port') or '-'):<7}{m.get('status') or '-'}")
    return 0


def cmd_status(args) -> int:
    manager.discover()
    return cmd_list(args)


def cmd_apply_port(args) -> int:
    port = generator.apply_port(
        args.imei,
        username=args.user,
        password=args.password,
        auth=not args.no_auth,
    )
    _print_json(port)
    return 0


def cmd_purge_port(args) -> int:
    generator.purge_port(args.imei)
    print(f"purged proxy for {args.imei}")
    return 0


def cmd_rotate(args) -> int:
    res = manager.rotate(args.imei, reason="cli")
    _print_json(res)
    return 0


def cmd_rotate_all(args) -> int:
    _print_json(manager.rotate_all(reason="cli"))
    return 0


def cmd_rotate_due(args) -> int:
    res = manager.rotate_due(reason="schedule")
    _print_json(res) if args.json else print(f"rotated {len(res)} modem(s)")
    return 0


def cmd_set_interval(args) -> int:
    _print_json(generator.set_rotation_interval(args.imei, args.seconds))
    return 0


def cmd_set_whitelist(args) -> int:
    _print_json(generator.set_whitelist(args.imei, args.ips))
    return 0


def cmd_reset(args) -> int:
    manager.reset_modem(args.imei)
    print(f"reset sent to {args.imei}")
    return 0


def cmd_rotation_log(args) -> int:
    _print_json(db.rotation_log(args.imei, args.limit))
    return 0


def cmd_name(args) -> int:
    db.upsert_modem(args.imei, name=args.name)
    print(f"{args.imei} -> {args.name}")
    return 0


def cmd_send_ussd(args) -> int:
    resp = manager.send_ussd(args.imei, args.code)
    print(resp)
    return 0


def cmd_conn_test(args) -> int:
    _print_json(tests.conn_test(args.imei))
    return 0


def cmd_speedtest(args) -> int:
    _print_json(tests.speedtest(args.imei))
    return 0


def cmd_vpn_enable(args) -> int:
    _print_json(openvpn.enable_vpn(args.imei))
    return 0


def cmd_vpn_disable(args) -> int:
    openvpn.disable_vpn(args.imei)
    print(f"vpn disabled for {args.imei}")
    return 0


def cmd_vpn_export(args) -> int:
    text = openvpn.export_client(args.imei)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text)
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


def cmd_list_sms(args) -> int:
    mid = manager._mm_id_for(args.imei)
    if not mid:
        print("modem not present", file=sys.stderr)
        return 1
    _print_json(control.list_sms(mid))
    return 0


def cmd_send_sms(args) -> int:
    mid = manager._mm_id_for(args.imei)
    if not mid:
        print("modem not present", file=sys.stderr)
        return 1
    control.send_sms(mid, args.number, args.text)
    print("sent")
    return 0


def cmd_apikey_create(args) -> int:
    print(db.api_key_create(args.label or ""))
    return 0


def cmd_apikey_list(args) -> int:
    _print_json(db.api_key_list())
    return 0


def cmd_apikey_revoke(args) -> int:
    ok = db.api_key_revoke(args.key)
    print("revoked" if ok else "not found")
    return 0 if ok else 1


def cmd_bw_sample(args) -> int:
    n = bandwidth.sample()
    print(f"sampled {n} interface(s)")
    return 0


def cmd_bw_report(args) -> int:
    _print_json(bandwidth.report(args.imei))
    return 0


def cmd_quota_check(args) -> int:
    actions = quota.check()
    _print_json(actions) if args.json else print(f"{len(actions)} change(s)")
    return 0


def cmd_set_quota(args) -> int:
    _print_json(quota.set_quota(args.imei, args.bytes, args.direction))
    return 0


def cmd_publish_status(args) -> int:
    st = publish.status()
    if args.json:
        _print_json(st)
        return 0
    print(f"mode: {st['mode']}   host: {st['host']}")
    if st["mode"] == "relay":
        print(f"relay: {st.get('relay_host')}:{st.get('relay_port')}  "
              f"frpc active={st.get('frpc_active')} installed={st.get('frpc_installed')}")
    for m in st["proxies"]:
        print(f"  {m.get('name') or m['imei']:<14} HTTP {m.get('http') or '-'}")
        if m.get("socks5"):
            print(f"  {'':<14} SOCKS {m['socks5']}")
    return 0


def cmd_publish_sync(args) -> int:
    _print_json(publish.sync())
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="modemproxy", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_):
        sp = sub.add_parser(name, help=help_)
        sp.set_defaults(func=fn)
        return sp

    add("init-db", cmd_init_db, "create database schema")

    sp = add("discover", cmd_discover, "scan ModemManager and sync DB")
    sp.add_argument("--json", action="store_true")

    sp = add("list", cmd_list, "list known modems")
    sp.add_argument("--json", action="store_true")

    sp = add("status", cmd_status, "discover then list (live)")
    sp.add_argument("--json", action="store_true")

    sp = add("apply-port", cmd_apply_port, "allocate + start proxy for a modem")
    sp.add_argument("imei")
    sp.add_argument("--user")
    sp.add_argument("--password")
    sp.add_argument("--no-auth", action="store_true", help="open proxy, no credentials")

    sp = add("purge-port", cmd_purge_port, "stop + remove proxy for a modem")
    sp.add_argument("imei")

    sp = add("rotate", cmd_rotate, "force new IP on one modem")
    sp.add_argument("imei")

    add("rotate-all", cmd_rotate_all, "force new IP on all online modems")

    sp = add("rotate-due", cmd_rotate_due, "rotate modems whose interval elapsed")
    sp.add_argument("--json", action="store_true")

    sp = add("set-interval", cmd_set_interval, "set per-port auto-rotation seconds (0=manual)")
    sp.add_argument("imei")
    sp.add_argument("seconds", type=int)

    sp = add("set-whitelist", cmd_set_whitelist, "restrict proxy to client IPs/CIDRs")
    sp.add_argument("imei")
    sp.add_argument("ips", nargs="*", help="IPs/CIDRs; omit to clear")

    sp = add("reset", cmd_reset, "soft-reset a modem")
    sp.add_argument("imei")

    sp = add("rotation-log", cmd_rotation_log, "show rotation history")
    sp.add_argument("imei", nargs="?")
    sp.add_argument("--limit", type=int, default=50)

    sp = add("name", cmd_name, "set a friendly nick for a modem")
    sp.add_argument("imei")
    sp.add_argument("name")

    sp = add("apikey-create", cmd_apikey_create, "create an API key for pool consumers")
    sp.add_argument("--label", help="note for this key")
    add("apikey-list", cmd_apikey_list, "list API keys")
    sp = add("apikey-revoke", cmd_apikey_revoke, "revoke an API key")
    sp.add_argument("key")

    add("bw-sample", cmd_bw_sample, "record one bandwidth counter sample")

    sp = add("bw-report", cmd_bw_report, "bandwidth usage report")
    sp.add_argument("imei", nargs="?")

    sp = add("quota-check", cmd_quota_check, "enforce monthly quotas (lock/unlock)")
    sp.add_argument("--json", action="store_true")

    sp = add("set-quota", cmd_set_quota, "set monthly traffic cap (bytes; 0=off)")
    sp.add_argument("imei")
    sp.add_argument("bytes", type=int)
    sp.add_argument("--direction", choices=["in", "out", "both"], default="both")

    sp = add("vpn-enable", cmd_vpn_enable, "start a per-modem OpenVPN server")
    sp.add_argument("imei")

    sp = add("vpn-disable", cmd_vpn_disable, "stop a per-modem OpenVPN server")
    sp.add_argument("imei")

    sp = add("vpn-export", cmd_vpn_export, "export a client .ovpn for a modem")
    sp.add_argument("imei")
    sp.add_argument("--out", help="write to file instead of stdout")

    sp = add("send-ussd", cmd_send_ussd, "send a USSD code (e.g. balance check)")
    sp.add_argument("imei")
    sp.add_argument("code", help="USSD string, e.g. '*123#'")

    sp = add("conn-test", cmd_conn_test, "check public IP via a modem")
    sp.add_argument("imei")

    sp = add("speedtest", cmd_speedtest, "measure download speed via a modem")
    sp.add_argument("imei")

    sp = add("list-sms", cmd_list_sms, "list SMS on a modem")
    sp.add_argument("imei")

    sp = add("send-sms", cmd_send_sms, "send an SMS from a modem")
    sp.add_argument("imei")
    sp.add_argument("number")
    sp.add_argument("text")

    sp = add("publish-status", cmd_publish_status, "show customer-facing proxy addresses")
    sp.add_argument("--json", action="store_true")
    add("publish-sync", cmd_publish_sync, "reconcile firewall / relay tunnel with live proxies")

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    db.init_db()
    try:
        return args.func(args)
    except control.MMError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
