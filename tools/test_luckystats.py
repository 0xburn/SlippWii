"""Tests the loader's Lucky Stats uploads on this PC (Nintendont/loader/source/luckystats/).

    python tools/test_luckystats.py [--cc gcc] [--chain site.pem [storage.pem storage-host]] [-v]

The same C the Wii runs is built as a PC program (Nintendont/loader/tests/luckystats/) with BearSSL
(tools/build_bearssl.py --host builds it if it is not there). Two TLS servers on this PC play the site
and its file store, with a certificate authority made for the run; folders play the drives. Nothing
reaches luckystats.gg. --chain checks certificate chains captured before (openssl s_client -showcerts)
against the roots compiled in, at their own dates. Needs the openssl program; Linux or macOS.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'Nintendont/loader/source'
TESTS = ROOT / 'Nintendont/loader/tests/luckystats'
BEAR = ROOT / 'build/bearssl'
OUT = ROOT / 'build/luckystats-test'
KEY = 'l7u_' + '5'.zfill(64)
OK, NOTHING, CANCEL, LATER, BAD_KEY, CARD, NET, CLOCK, CERT, NOKEY, PREMIUM, QUOTA, BUSY, SERVER, REDO = range(15)
failures = checks = 0
verbose = False


def check(name, ok, detail=''):
    global failures, checks
    checks += 1
    failures += not ok
    if verbose or not ok:
        print(f'{"ok  " if ok else "FAIL"} {name}{"" if ok else ": " + str(detail)[:1500]}')


def build(cc):
    lib = BEAR / 'host/libbearssl.a'
    if not lib.exists():
        subprocess.run([sys.executable, str(ROOT / 'tools/build_bearssl.py'), '--host', '--cc', cc], check=True)
    OUT.mkdir(parents=True, exist_ok=True)
    exe = OUT / 'ls_test'
    cmd = [*cc.split(), '-std=gnu99', '-O1', '-g', '-Wall', '-Wextra', '-Wno-deprecated-declarations', '-fsanitize=address,undefined', '-DLS_TEST',
           '-I', str(SRC / 'luckystats'), '-I', str(SRC / 'update'), '-I', str(ROOT / 'build/bearssl-src/bearssl-0.6/inc'),
           str(SRC / 'luckystats/ls_core.c'), str(SRC / 'luckystats/ls_http.c'), str(TESTS / 'ls_test.c'), str(lib), '-o', str(exe)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode or r.stderr:
        sys.exit(f'the test program did not build cleanly:\n{r.stdout}{r.stderr}')
    return exe


def openssl(*args, data=None):
    r = subprocess.run(['openssl', *map(str, args)], input=data, capture_output=True)
    if r.returncode:
        sys.exit(f'openssl {args[0]}: {r.stderr.decode()[-400:]}')
    return r.stdout


class Authority:
    """A CA for the run and certificates from it."""

    def __init__(self, d, name='SlippWii Test CA'):
        self.d, self.name = d, name.replace(' ', '-')
        self.key, self.crt = d / f'{self.name}.key', d / f'{self.name}.pem'
        openssl('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', self.key)
        openssl('req', '-x509', '-new', '-key', self.key, '-sha256', '-days', '30', '-subj', f'/CN={name}', '-out', self.crt,
                '-addext', 'keyUsage=critical,keyCertSign')
        self.point = openssl('ec', '-in', self.key, '-pubout', '-outform', 'DER')[-65:].hex()
        der = openssl('x509', '-in', self.crt, '-outform', 'DER')
        self.dn = bytes([0x30, len(name) + 11, 0x31, len(name) + 9, 0x30, len(name) + 7, 6, 3, 0x55, 4, 3, 0x0C, len(name)]) + name.encode()
        assert self.dn in der
        self.dn = self.dn.hex()

    def issue(self, host):
        key, csr, crt, ext = (self.d / f'{self.name}-{host}.{x}' for x in ('key', 'csr', 'crt', 'ext'))
        openssl('genrsa', '-out', key, '2048')
        openssl('req', '-new', '-key', key, '-subj', f'/CN={host}', '-out', csr)
        ext.write_text(f'subjectAltName=DNS:{host}\n')
        openssl('x509', '-req', '-in', csr, '-CA', self.crt, '-CAkey', self.key, '-CAcreateserial', '-days', '20', '-sha256',
                '-extfile', ext, '-out', crt)
        return crt, key


class Server:
    """The site's upload routes and the file store, as lib/integrations/personal-upload.ts and S3 answer."""

    def __init__(self, authority, site_cert, store_cert):
        self.sessions, self.objects, self.log, self.fail = {}, {}, [], {}
        self.lock = threading.Lock()
        self.site = self.serve(site_cert, self.site_request)
        self.store = self.serve(store_cert, self.store_request)

    def serve(self, cert, handle):
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *a):
                pass

            def handle_expect_100(self):
                return True     # (told by the handler below)

            def any(self):
                with outer.lock:
                    handle(self)
            do_GET = do_POST = do_PUT = any

        s = ThreadingHTTPServer(('127.0.0.1', 0), H)
        s.handle_error = lambda *a: None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*map(str, cert))
        plain = s.get_request

        def get_request():
            sock, addr = plain()
            return ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr
        s.get_request = get_request
        threading.Thread(target=s.serve_forever, daemon=True).start()
        return s.server_address[1]

    def close(self, h):
        h.close_connection = True
        try:
            h.connection.shutdown(2)
        except OSError:
            pass

    def answer(self, h, status, body=None, headers=(), chunked=False):
        data = b'' if body is None else json.dumps(body, separators=(',', ':')).encode()
        h.send_response(status)
        for k, v in headers:
            h.send_header(k, v)
        h.send_header('Connection', 'close')
        if chunked:
            h.send_header('Transfer-Encoding', 'chunked')
            h.end_headers()
            for at in range(0, len(data), 777):
                part = data[at:at + 777]
                h.wfile.write(f'{len(part):x};x=y\r\n'.encode() + part + b'\r\n')
            h.wfile.write(b'0\r\n\r\n')
        else:
            h.send_header('Content-Length', str(len(data)))
            h.end_headers()
            h.wfile.write(data)
        h.close_connection = True

    def failing(self, what):
        left = self.fail.get(what)
        if left is None or left[0] <= 0:
            return None
        left[0] -= 1
        return left[1]

    def links(self, s):
        return [{'path': f['path'], 'method': 'PUT',
                 'url': f'https://store.test.example:{self.store}/b/{s["id"]}/{i}?X-Amz-Signature=' + 'a' * 900 + '&x=%2F',
                 'headers': {'Content-Type': 'application/octet-stream', 'note': 'a "quoted" \\ {value}'}} for i, f in enumerate(s['files'])]

    def site_request(self, h):
        body = h.rfile.read(int(h.headers.get('Content-Length', 0)))
        self.log.append((h.command, h.path, h.headers.get('Authorization'), body))
        assert h.headers['Host'].split(':')[0] == 'luckystats.gg'
        if h.headers.get('Authorization') != f'Bearer {KEY}' or h.headers.get('X-App-Id') != 'slippwii':
            return self.answer(h, 401, {'error': 'invalid_credentials'})
        what = 'ask' if h.path.endswith('/personal') else 'complete'
        f = self.failing(what)
        if f == 'drop':
            return self.close(h)
        if f == 'cut':
            h.send_response(200)
            h.send_header('Content-Length', '5000')
            h.end_headers()
            h.wfile.write(b'{"uploadId":"')
            return self.close(h)
        if f and f != 'lost':
            return self.answer(h, f[0], {'error': f[1]}, f[2] if len(f) > 2 else ())
        if what == 'ask':
            idem = h.headers['Idempotency-Key']
            assert re.fullmatch('[a-zA-Z0-9_-]{16,100}', idem)
            files = json.loads(body)['files']
            for x in files:
                assert set(x) == {'path', 'size', 'sha256'} and re.fullmatch('[a-f0-9]{64}', x['sha256']) and x['size'] > 0
            s = self.sessions.setdefault(idem, {'id': hashlib.md5(idem.encode()).hexdigest(), 'files': files, 'done': False, 'asked': 0})
            s['asked'] += 1
            i = s['id']
            s['uuid'] = f'{i[:8]}-{i[8:12]}-{i[12:16]}-{i[16:20]}-{i[20:]}'
            if s['files'] != files:
                return self.answer(h, 409, {'error': 'idempotency_conflict'})
            out = {'uploadId': s['uuid'], 'status': 'queued' if s['done'] else 'awaiting_upload', 'handoffAccepted': s['done'],
                   'batchId': '1' if s['done'] else None, 'statusUrl': '/x', 'pollAfterSeconds': None}
            if not s['done']:
                out['files'] = self.links(s)
                if f_url := self.fail.get('url'):
                    out['files'][0]['url'] = f_url
            return self.answer(h, 200, out, chunked=len(files) > 1)
        s = next(s for s in self.sessions.values() if f'/uploads/{s["uuid"]}/complete' in h.path)
        for i, x in enumerate(s['files']):
            o = self.objects.get(f'/b/{s["id"]}/{i}')
            if o is None:
                return self.answer(h, 409, {'error': 'upload_incomplete'})
            if len(o) != x['size'] or hashlib.sha256(o).hexdigest() != x['sha256']:
                return self.answer(h, 409, {'error': 'upload_verification_failed'})
        s['done'] = True
        if f == 'lost':
            return self.close(h)
        self.answer(h, 200, {'uploadId': s['uuid'], 'status': 'queued', 'handoffAccepted': True})

    def store_request(self, h):
        path = h.path.split('?')[0]
        self.log.append((h.command, path, h.headers.get('Authorization'), b''))
        n = int(h.headers['Content-Length'])
        assert h.headers['Content-Type'] == 'application/octet-stream' and h.headers['Expect'] == '100-continue'
        assert h.headers.get('X-App-Id') is None and h.headers['Host'] == f'store.test.example:{self.store}'
        f = self.failing('put')
        if f == 'drop':
            return self.close(h)
        if f and f not in ('lost', 'broken'):
            return self.answer(h, f[0])
        if path in self.objects and h.headers['If-None-Match'] == '*':
            return self.answer(h, 412)
        h.send_response_only(100)
        h.end_headers()
        if f == 'broken':
            h.rfile.read(n // 2)
            return self.close(h)
        body = h.rfile.read(n)
        if base64.b64encode(hashlib.sha256(body).digest()).decode() != h.headers['x-amz-checksum-sha256']:
            return self.answer(h, 400)
        self.objects[path] = body
        if f == 'lost':
            return self.close(h)
        self.answer(h, 200, None, [('ETag', '"x"')])


def slp(seed, size=60000, finished=True, end=True):
    raw = hashlib.shake_256(str(seed).encode()).digest(size)
    return (b'{U\x03raw[$U#l' + (len(raw) if finished else 0).to_bytes(4, 'big') + raw +
            (b'U\x08metadata{U\x07startAtSU\x132026-11-25T10:00:00U\x09lastFramel\x00\x00\x01\x00U\x07players{}U\x08playedOnSU\x0anintendont}}' if end else b''))


class Wii:
    def __init__(self, exe, authority, server, devs=1):
        self.exe, self.a, self.s, self.devs = exe, authority, server, devs
        self.root = Path(tempfile.mkdtemp(prefix='ls-'))
        self.now = int(time.time())
        for d in ('sd', 'usb'):
            (self.root / d / 'Slippi').mkdir(parents=True)

    def game(self, n, data=None, dev='sd', name=None):
        p = self.root / dev / 'Slippi' / (name or f'Game_0017AB001122_20261125T10{n // 60:02}{n % 60:02}.slp')
        p.write_bytes(slp(n) if data is None else data)
        return p

    def start(self, env=None, history=0, now=None, port=None):
        e = {**os.environ, **{k: str(v) for k, v in (env or {}).items()}}
        r = subprocess.run([str(self.exe), 'run', str(self.root), str(self.devs), str(now or self.now), str(port or self.s.site),
                            self.a.dn, self.a.point, str(history)], capture_output=True, text=True, env=e, timeout=300)
        self.out = r.stdout + r.stderr
        self.code = r.returncode
        if KEY in self.out or 'Signature' in self.out:
            check('nothing secret is said', False, self.out)
        m = re.search(r'RESULT (\d+) (\d+)', self.out)
        later = re.search(r'LATER (\d+)', self.out)
        self.later = int(later[1]) if later else None
        return (int(m[1]), int(m[2])) if m else None

    def state(self, dev='sd'):
        return (self.root / dev / 'slippwii/luckystats_sent.txt').read_text()


def uploaded(server):
    return sorted(hashlib.sha256(server.objects[f'/b/{s["id"]}/{i}']).hexdigest() for s in server.sessions.values() if s['done']
                  for i, _ in enumerate(s['files']))


def shas(*paths):
    return sorted(hashlib.sha256(p.read_bytes()).hexdigest() for p in paths)


def tests(exe, d):
    ca = Authority(d)
    site, store = ca.issue('luckystats.gg'), ca.issue('store.test.example')

    def fresh(**kw):
        s = Server(ca, kw.pop('site', site), kw.pop('store', store))
        return Wii(exe, kw.pop('authority', ca), s, **kw), s

    # the key's file
    good = f'key={KEY}'
    for name, text, want in (
            ('plain', good, (OK, KEY, 0)), ('Windows, with a mark', '﻿# mine\r\n' + good + ' \r\nhistory=yes\r\n', (OK, KEY, 1)),
            ('no key', 'key=\n', (BAD_KEY, '', 0)), ('short', good[:-1], (BAD_KEY, '', 0)), ('long', good + '0', (BAD_KEY, '', 0)),
            ('capitals', f'key=l7u_{"A" * 64}', (BAD_KEY, '', 0)), ('empty', '', (BAD_KEY, '', 0)),
            ('a header in it', f'key=l7u_{"a" * 60}\r\nX: y', (BAD_KEY, '', 0))):
        p = d / 'key.txt'
        p.write_bytes(text.encode())
        got = subprocess.run([str(exe), 'config', str(p)], capture_output=True, text=True).stdout.rstrip('\n').split(' ')
        check(f'key file: {name}', (int(got[0]), got[1], int(got[2])) == want, got)

    # what was there before stays; new games go, once; nothing new: no network at all
    w, s = fresh()
    old = [w.game(i) for i in range(5)]
    check('first start: nothing sent', w.start() == (OK, 0) and not s.log and w.state().count('\ns ') == 5, w.out)
    new = [w.game(10 + i) for i in range(3)]
    check('three games', w.start() == (OK, 3) and uploaded(s) == shas(*new), w.out)
    check('one upload of them', len(s.sessions) == 1, s.sessions)
    check('the key went to the site only', all((a == f'Bearer {KEY}') == (not p.startswith('/b/')) for _, p, a, _ in s.log), s.log)
    n = len(s.log)
    check('again: nothing, no connection', w.start() == (OK, 0) and len(s.log) == n, w.out)
    check('the rest with history=yes', w.start(history=1) == (OK, 5) and uploaded(s) == shas(*old, *new), w.out)
    check('and once', w.start(history=1) == (OK, 0) and w.start() == (OK, 0))

    # only finished games that the kernel named
    w, s = fresh()
    w.start()
    real = w.game(1)
    w.game(2, slp(2, finished=False))                    # the power went: no length, no metadata
    w.game(3, slp(3, finished=False, end=False))
    w.game(4, slp(4, end=False))
    w.game(5, slp(5)[:-1])
    w.game(6, b'')
    w.game(7, b'not a game at all' * 100)
    w.game(8, slp(8)[:15])
    w.game(8, name='My game.slp')
    w.game(8, name='Game_x.txt')
    w.game(8, name='Game_' + 'x' * 80 + '.slp')
    check('finished games only', w.start() == (OK, 1) and uploaded(s) == shas(real), w.out)
    check('the others are not read again', w.start() == (OK, 0) and 'Reading' not in w.out, w.out)
    w.game(2, slp(2, 61000))                             # (the same name, finished now: another size)
    check('a file that changed is looked at again', w.start() == (OK, 1), w.out)

    # sizes at the edges of the pieces it is read in
    w, s = fresh()
    w.start()
    edge = [w.game(i, slp(i, 0x8000 - 15 + k)) for i, k in enumerate((-12, -6, -1, 0, 1, 0x8000))]
    big = w.game(40, slp(40, 6_000_000))
    check('sizes at the edges, and a long game', w.start() == (OK, 7) and uploaded(s) == shas(*edge, big), w.out)

    # many: more than one upload, the oldest first
    w, s = fresh()
    w.start()
    many = [w.game(i, slp(i, 500)) for i in range(40)]
    check('forty games in three uploads', w.start() == (OK, 40) and uploaded(s) == shas(*many) and len(s.sessions) == 3, w.out)
    first = next(iter(s.sessions.values()))
    check('the oldest first', [f['path'] for f in first['files']] == [p.name for p in many[:16]])

    # both drives, each with its own history
    w, s = fresh(devs=1)
    w.start()
    w.devs = 3
    w.game(1, dev='usb')
    check('a drive seen for the first time', w.start() == (OK, 0) and not s.log, w.out)
    a, b = w.game(2), w.game(3, dev='usb')
    check('games on both drives', w.start() == (OK, 2) and uploaded(s) == shas(a, b), w.out)

    # power cuts: at every write, then starts until it is quiet: each game once, whole
    for die in range(1, 9):
        w, s = fresh()
        w.start()
        new = [w.game(i) for i in range(4)]
        check(f'power cut {die}: it died', w.start({'LS_DIE': die}) is None or die > 6, w.out)
        res = w.start()
        check(f'power cut {die}: the next start sends the rest', res and res[0] == OK and uploaded(s) == shas(*new), w.out)
        check(f'power cut {die}: in one upload', len(s.sessions) == 1, s.sessions.keys())
        check(f'power cut {die}: then nothing', w.start() == (OK, 0), w.out)
    w, s = fresh()
    w.game(0)
    w.start({'LS_DIE': 1})
    check('power cut while what is there is listed', w.start() == (OK, 0) and not s.log and w.state().count('\ns ') == 1)

    # B at any time, and on from there
    for n in (1, 2, 3, 5, 8, 12, 20):
        w, s = fresh()
        w.start()
        new = [w.game(i) for i in range(3)]
        check(f'skip {n}', w.start({'LS_CANCEL': n})[0] == CANCEL, w.out)
        check(f'skip {n}: nothing waits', ' w ' not in w.state())
        check(f'skip {n}: sent at the next start', w.start()[0] == OK and uploaded(s) == shas(*new) and len(s.sessions) == 1, w.out)

    # what can go wrong on the way, and come right in the same start
    for what, how in (('ask', 'drop'), ('ask', 'cut'), ('ask', (503, 'upload_service_unavailable')), ('put', 'drop'), ('put', 'broken'),
                      ('put', 'lost'), ('put', (403,)), ('put', (503,)), ('complete', 'drop'), ('complete', 'lost'),
                      ('complete', (503, 'x')), ('ask', (410, 'upload_expired')), ('complete', (409, 'upload_verification_failed')),
                      ('complete', (409, 'upload_incomplete')), ('ask', (409, 'upload_not_open')), ('put', (400,))):
        w, s = fresh()
        w.start()
        new = [w.game(i) for i in range(3)]
        s.fail[what] = [1, how]
        r = w.start()
        check(f'{what} {how}: gets through', r == (OK, 3) and uploaded(s) == shas(*new), w.out)

    # what does not come right: when it tries again
    for what, how, want in (('ask', (401, 'invalid_credentials'), NOKEY), ('ask', (403, 'not_supporter'), PREMIUM),
                            ('ask', (403, 'insufficient_scope'), NOKEY), ('ask', (413, 'storage_quota_exceeded'), QUOTA),
                            ('ask', (429, 'rate_limited'), BUSY), ('ask', (503, 'x'), BUSY), ('ask', 'drop', NET), ('put', 'drop', NET),
                            ('put', 'broken', NET), ('ask', (400, 'invalid_manifest'), SERVER), ('ask', (302, 'x'), SERVER),
                            ('complete', (409, 'upload_incomplete'), BUSY), ('complete', (410, 'upload_expired'), SERVER)):
        w, s = fresh()
        w.start()
        new = [w.game(i) for i in range(2)]
        s.fail[what] = [999, how]
        check(f'{what} {how}: says what', w.start() == (want, 0), w.out)
        n = len(s.log)
        check(f'{what} {how}: not at once again', w.start() == (LATER, 0) and len(s.log) == n, w.out)
        check(f'{what} {how}: says when', w.later == 300, w.out)
        s.fail.clear()
        check(f'{what} {how}: after five minutes', w.start(now=w.now + 301) == (OK, 2) and uploaded(s) == shas(*new), w.out)
        check(f'{what} {how}: forgotten', w.state().rstrip().endswith('w 0 0'), w.state())

    # the waits grow, to six hours; the server's own is kept; a clock set back does not hold it up
    w, s = fresh()
    w.start()
    w.game(1)
    s.fail['ask'] = [999, (503, 'x')]
    waits, t = [], w.now
    for _ in range(9):
        check('a failure', w.start(now=t)[0] == BUSY, w.out)
        until = int(re.findall(r'^w (\d+)', w.state(), re.M)[-1])
        waits.append(until - t)
        t = until
    check('waits', waits == [300, 600, 1200, 2400, 4800, 9600, 19200, 21600, 21600], waits)
    check('the clock set back years', w.start(now=t - 4 * 365 * 86400)[0] in (BUSY, CLOCK), w.out)
    w, s = fresh()
    w.start()
    w.game(1)
    s.fail['ask'] = [1, (429, 'rate_limited', [('Retry-After', '7200')])]
    w.start()
    check("the server's wait", w.start(now=w.now + 7199)[0] == LATER and w.later == 1, w.out)
    check("the server's wait: over", w.start(now=w.now + 7201) == (OK, 1) and w.later == 0, w.out)

    # a new key tries right away instead of waiting out an earlier key's failure
    w, s = fresh()
    w.start()
    g = w.game(1)
    bad_key = 'l7u_' + '9'.zfill(64)
    check('bad key refused', w.start({'LS_KEY': bad_key}) == (NOKEY, 0), w.out)
    check('same bad key waits', w.start({'LS_KEY': bad_key})[0] == LATER and w.later == 300, w.out)
    check('new key bypasses wait', w.start() == (OK, 1) and uploaded(s) == shas(g), w.out)
    check('new key clears wait', w.state().rstrip().endswith('w 0 0'), w.state())

    # no network, no drive
    w, s = fresh()
    w.start()
    w.game(1)
    check('no network', w.start({'LS_RESOLVE': 0})[0] == NET)
    w, s = fresh()
    w.start()
    w.game(1)
    check('a server that is not there', w.start(port=1)[0] == NET, w.out)
    w, s = fresh()
    w.game(1)
    check('a card that takes no writes: nothing sent', w.start({'LS_FAIL_APPEND': 1})[0] == CARD and not s.log)
    w.start()
    w.game(2)
    check('the same later', w.start({'LS_FAIL_APPEND': 1})[0] == CARD and not s.log)

    # a game deleted or replaced while its upload is under way
    w, s = fresh()
    w.start()
    new = [w.game(i) for i in range(3)]
    s.fail['put'] = [999, (503,)]
    w.start()
    s.fail.clear()
    new[1].unlink()
    new[2].write_bytes(slp(99, 70000))
    check('deleted and replaced since', w.start(now=w.now + 301) == (OK, 2) and uploaded(s) == shas(new[0], new[2]), w.out)

    # what was sent: damaged, another version's, with another's lines
    w, s = fresh()
    w.start()
    p = w.root / 'sd/slippwii/luckystats_sent.txt'
    p.write_text('SlippWii Lucky Stats 2\n')
    w.game(1)
    check("another version's file: left alone", w.start()[0] == CARD and not s.log and p.read_text() == 'SlippWii Lucky Stats 2\n')
    evil = '../slippwii/luckystats.txt'
    p.write_text(f'SlippWii Lucky Stats 1\np {"a" * 32} 1\nf 10 {"a" * 64} {evil}\nk 99\nk -1\np {"a" * 32} 99\nw x\ns\n\nf 1 2 3\n')
    (w.root / 'sd/slippwii/luckystats.txt').write_text('0123456789')
    check('a file of another folder in it', w.start() == (OK, 1) and not any(evil.encode() in x[3] for x in s.log), w.out)

    # the file store's host
    for url in ('http://store.test.example/x', 'https://a@store.test.example/x', 'https://store.test.example', 'ftp://x/y',
                'https://store.test.example/a b', 'https:///x'):
        w, s = fresh()
        w.start()
        w.game(1)
        s.fail['url'] = url
        check(f'a link to {url}', w.start() == (SERVER, 0) and not any(p.startswith('/b/') for _, p, _, _ in s.log), w.out)

    # the certificate: nothing is sent unless all of it is right
    def refused(name, want, now=None, **kw):
        w, s = fresh(**kw)
        w.start()
        w.game(1)
        r = w.start(now=now)
        check(f'certificate: {name}', r == (want, 0) and not [x for x in s.log if x[1].startswith('/b/') or want != CERT or 'store' not in kw
                                                              and 'storage' not in name], (r, s.log, w.out))
        if 'store' not in kw:
            check(f'certificate: {name}: the key was not sent', not s.log, s.log)
        return w
    other = Authority(d, 'Another CA')
    refused('another authority', CERT, site=other.issue('luckystats.gg'))
    refused("another site's", CERT, site=ca.issue('luckystats.gg.example.com'))
    refused("the store's", CERT, site=store)
    refused('a wild one', CERT, site=ca.issue('*.luckystats.gg'))
    refused('clock years back', CLOCK, now=1230768000)
    refused('clock years on', CLOCK, now=int(time.time()) + 400 * 86400)
    refused('the file store, another authority', CERT, store=other.issue('store.test.example'))
    refused("the file store, another site's", CERT, store=ca.issue('other.example'))
    w, s = fresh()
    w.start()
    w.game(1)
    w.start(now=1230768000)
    check('the clock put right', w.start() == (OK, 1), w.out)


def chains(exe, d, args):
    site = args.chain[0]
    sets = [(site, 'luckystats.gg', 'site')]
    if len(args.chain) == 3:
        sets.append((args.chain[1], args.chain[2], 'storage'))
    for n, (pem, host, kind) in enumerate(sets):
        ders = []
        for i, c in enumerate(re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', Path(pem).read_text(), re.S)):
            ders.append(d / f'chain{n}-{i}.der')
            ders[-1].write_bytes(ssl.PEM_cert_to_DER_cert(c))
        end = openssl('x509', '-inform', 'DER', '-in', ders[0], '-noout', '-enddate', '-startdate').decode()
        not_after, not_before = (int(ssl.cert_time_to_seconds(x)) for x in re.findall(r'=(.*)', end))

        def ask(host=host, now=(not_before + not_after) // 2, kind=kind, ders=ders):
            return int(subprocess.run([str(exe), 'chain', host, str(now), kind, *map(str, ders)], capture_output=True, text=True).stdout)
        other = 'storage' if kind == 'site' else 'site'
        check(f'{host}: its chain is trusted', ask() == 0 or ask() == 32, ask())
        check(f'{host}: not by the other list', ask(kind=other) == 62, ask(kind=other))
        check(f'{host}: not as another host', ask(host='example.com') == 56, ask(host='example.com'))
        check(f'{host}: not a subdomain of its own', ask(host='a.b.c.' + host) == 56)
        check(f'{host}: not before its date', ask(now=not_before - 5) == 54, ask(now=not_before - 5))
        check(f'{host}: not after it', ask(now=not_after + 5) == 54, ask(now=not_after + 5))
        check(f'{host}: not without its intermediate', ask(ders=ders[:1]) == 62, ask(ders=ders[:1]))
        bad = bytearray(ders[0].read_bytes())
        bad[-20] ^= 1
        broken = d / 'broken.der'
        broken.write_bytes(bad)
        check(f'{host}: not with a signature changed', ask(ders=[broken, *ders[1:]]) != 0, '')


def main():
    global verbose
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--cc', default=os.environ.get('CC', 'gcc'))
    ap.add_argument('--chain', nargs='+', metavar='PEM')
    ap.add_argument('-v', action='store_true')
    args = ap.parse_args()
    verbose = args.v
    exe = build(args.cc)
    d = Path(tempfile.mkdtemp(prefix='ls-ca-'))
    try:
        tests(exe, d)
        if args.chain:
            chains(exe, d, args)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    print(f'{checks} checks, {failures} failures')
    sys.exit(failures > 0)


if __name__ == '__main__':
    main()
