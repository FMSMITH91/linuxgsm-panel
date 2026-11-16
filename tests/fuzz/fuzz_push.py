#!/usr/bin/env python3
"""Atheris fuzz harness: what a browser hands the push alerts (services.webpush, services.push_alerts).

The first byte of an input picks what the rest feeds:

0. `webpush.parse_endpoint` on the raw text, and on "https://<host><rest>" for each push service's
   host: an endpoint it accepts must name the same host to urllib's own parser, on https and port
   443, and rebuilding the request from (host, target) must give back that host; the host must be
   one of the push services. That is the claim in webpush's docstring (OWASP SSRF Prevention: no
   parser can read a different host out of it).
1. `webpush.address_refused` on an address made from the bytes, written each way an address can be
   (IPv4, IPv6 compressed or exploded, IPv4 inside IPv6, a zone) and on the raw text. An address it
   lets a push connect to must be a public unicast one, and so must any IPv4 address it carries.
2. `push_alerts.parse_subscription` on the text read as JSON, and on a subscription built from the
   bytes. A subscription it accepts has an endpoint parse_endpoint accepts and keys of the right sizes.
   `webpush.b64url_decode` runs on each key either way.

Run locally (from anywhere):
    pip install atheris
    python tests/fuzz/fuzz_push.py -max_total_time=60 tests/fuzz/corpus/push
"""
import base64
import importlib
import ipaddress
import json
import os
import sys
import urllib.parse

import atheris

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Pre-load the heavy dependencies uninstrumented (see fuzz_game_status); part29 holds the list.
# eventlet.tpool is the first eventlet import: greendns off, so no dnspython (panel/core/green_dns.py).
os.environ["EVENTLET_NO_GREENDNS"] = "yes"
for _dep in ("paramiko", "eventlet.tpool", "flask_sqlalchemy", "flask_login",
             "sqlalchemy.dialects.sqlite", "cryptography.hazmat.primitives.kdf.hkdf", "panel.core.config"):
    importlib.import_module(_dep)

with atheris.instrument_imports():
    from panel.services import push_alerts, webpush

_HOSTS = sorted(webpush.PUSH_HOSTS) + ["x" + s for s, _l in webpush.PUSH_HOST_SUFFIXES] + ["evil.com"]
# A point on P-256 (the generator, uncompressed): the keys a real browser sends are points like it.
_POINT = bytes.fromhex("04"
                       "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                       "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
_NETS = [ipaddress.ip_network(n) for n in ("::/96", "100.64.0.0/10")]


def _b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _is_push_host(host):
    return host in webpush.PUSH_HOSTS or any(host.endswith(s) and len(host) > len(s)
                                             for s, _l in webpush.PUSH_HOST_SUFFIXES)


def _endpoint(url):
    got = webpush.parse_endpoint(url)
    if got is None:
        return
    host, target, label = got
    parts = urllib.parse.urlsplit(url)
    assert parts.scheme == "https" and parts.hostname == host and parts.port in (None, 443), (url, got)
    assert parts.username is None and parts.password is None and not parts.fragment, url
    again = urllib.parse.urlsplit("https://" + host + target)
    assert again.hostname == host and again.port is None, (url, got)
    assert label is not None and webpush.service_label(host) == label and _is_push_host(host), (url, got)


def _judged(addr):
    """The addresses a connection to `addr` reaches, which must all be public.

    An IPv6 address that carries an IPv4 one (mapped, 6to4, NAT64) reaches that IPv4 address, so that
    is what is judged, as webpush does; any other IPv6 address is judged itself, with the two IPv4
    addresses a Teredo one carries.
    """
    if addr.version == 4:
        return [addr]
    nat64 = any(addr in ipaddress.ip_network(n) for n in ("64:ff9b::/96", "64:ff9b:1::/48"))
    wrapped = addr.ipv4_mapped or addr.sixtofour or (ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF) if nat64 else None)
    return [wrapped] if wrapped is not None else [addr] + list(addr.teredo or ())


def _address(text):
    if webpush.address_refused(text):
        return
    addr = ipaddress.ip_address(str(text).split("%", 1)[0])
    for a in _judged(addr):
        assert a.is_global and not a.is_multicast and not any(a in n for n in _NETS if n.version == a.version), \
            (text, str(a))


def _address_forms(fdp):
    if fdp.ConsumeBool():
        raw = fdp.ConsumeBytes(4).ljust(4, b"\0")
        a = ipaddress.IPv4Address(raw)
        forms = [str(a), "::ffff:" + str(a), "::" + str(a), "64:ff9b::" + str(a),
                 "2002:%02x%02x:%02x%02x::1" % tuple(raw)]
    else:
        a = ipaddress.IPv6Address(fdp.ConsumeBytes(16).ljust(16, b"\0"))
        forms = [str(a), a.exploded, str(a) + "%eth0", str(a).upper()]
    for f in forms:
        _address(f)


def _subscription(data):
    for k in ("p256dh", "auth"):
        v = (data.get("keys") or {}).get(k) if isinstance(data, dict) and isinstance(data.get("keys"), dict) else None
        webpush.b64url_decode(v)
    got, why = push_alerts.parse_subscription(data)
    if got is None:
        assert isinstance(why, str) and why, why
        return
    endpoint, p256dh, auth = got
    assert webpush.parse_endpoint(endpoint) is not None, endpoint
    assert len(webpush.b64url_decode(p256dh)) == 65 and len(webpush.b64url_decode(auth)) == 16, got


def _built_subscription(fdp):
    url = "https://" + fdp.PickValueInList(_HOSTS) + fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 60))
    point = bytearray(_POINT)
    if fdp.ConsumeBool() and point:
        point[fdp.ConsumeIntInRange(0, 64)] ^= fdp.ConsumeIntInRange(1, 255)
    auth = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 20))
    keys = {"p256dh": _b64(bytes(point)) + fdp.PickValueInList(["", "=", "=="]), "auth": _b64(auth)}
    if fdp.ConsumeBool():
        keys[fdp.PickValueInList(["p256dh", "auth"])] = fdp.ConsumeUnicodeNoSurrogates(30)
    _subscription({"endpoint": url, "keys": keys})


def _json(text):
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return
    _subscription(data)


def TestOneInput(data):
    if not data:
        return
    mode, rest = data[0] % 3, data[1:]
    text = rest.decode("utf-8", "replace")
    if mode == 0:
        _endpoint(text)
        for host in _HOSTS:
            _endpoint("https://" + host + text)
    elif mode == 1:
        _address(text)
        _address_forms(atheris.FuzzedDataProvider(rest))
    else:
        _json(text)
        _built_subscription(atheris.FuzzedDataProvider(rest))


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
