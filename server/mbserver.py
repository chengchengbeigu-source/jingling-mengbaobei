#!/usr/bin/env python3
"""MB 豆包萌宠 本地私服 (stdlib only)

  :4430  HTTPS   /apk/bootstrap  /launch  /pet05f/* (镜像+反代)
                 /demo/register|login|change-password  /demo/access-policy
                 /maintenance-status   —— 游戏页"账号中心"的本地账号体系
  :20311 WSS     本地游戏服务端（mbgame，协议仿真；官方关闭也可单人玩）
                 MB_WS_TUNNEL=1 时退回旧模式：TLS-bump 透传隧道 → mcbtc.cn:20311
"""
import base64, hashlib, hmac, json, os, re, secrets, socket, ssl, sys, threading, time
import urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, urlencode

import mbgame

HERE = os.path.dirname(os.path.abspath(__file__))
PEM = os.path.join(HERE, 'pem')
MIRROR = os.path.join(HERE, 'mirror')
os.makedirs(MIRROR, exist_ok=True)

PKG = 'com.localfirst.mb'
SECRET = 'Sang_rIvZNZf1bJkOwkLsC0bOKMll7oY-Juw81rzhZK_h1rgBx5cgl-jZ5GTSKdv'
ORIGIN = 'https://mcbtc.cn:20310'
ORIGIN_WS = ('mcbtc.cn', 20311)
LISTEN_HTTP = ('127.0.0.1', 4430)
LISTEN_WS = ('127.0.0.1', 20311)
SEED_ACCOUNT = ('123', '123')      # 本地账号库预置账号（官方不可达时的兜底）

SESSIONS = {}          # cookie -> expiry
ORIGIN_SESSION = []    # [cookie] maintained for origin fetches
ORIGIN_LOCK = threading.Lock()

PROXY_CTX = ssl.create_default_context()
PROXY_CTX.check_hostname = False
PROXY_CTX.verify_mode = ssl.CERT_NONE
UA_GAME = 'Mozilla/5.0 (Linux; Android 14) MBGameApp/1.0'

# ---------- 本地账号体系（游戏页 /demo/* 契约） ----------
ACCOUNTS_FILE = os.path.join(HERE, 'accounts.json')
ACC_LOCK = threading.Lock()

def _load_accounts():
    try:
        with open(ACCOUNTS_FILE, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def _save_accounts(accs):
    tmp = ACCOUNTS_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(accs, f, ensure_ascii=False, indent=1)
    os.replace(tmp, ACCOUNTS_FILE)

def _pw_hash(salt_hex, pw):
    return hashlib.scrypt(pw.encode('utf-8'), salt=bytes.fromhex(salt_hex),
                          n=16384, r=8, p=1).hex()

def seed_account(acc, pw):
    with ACC_LOCK:
        accounts = _load_accounts()
        if acc in accounts: return
        salt = secrets.token_hex(16)
        accounts[acc] = {'salt': salt, 'hash': _pw_hash(salt, pw), 'created': int(time.time())}
        _save_accounts(accounts)
        log('seeded demo account %r' % acc)

# ---------- origin session (用模拟客户端在源站开一个会话, 供反代携带) ----------
def b64f(b): return base64.urlsafe_b64encode(b).decode().rstrip('=')

def origin_bootstrap():
    install_salt = str(secrets.token_hex(16))
    android_id = secrets.token_hex(8)
    did = b64f(hashlib.sha256(('v1\n%s\n%s\n%s' % (PKG, android_id, install_salt)).encode()).digest())
    reg = b64f(hashlib.sha256(('mb-registration-v1\n%s\n%s' % (PKG, android_id.lower())).encode()).digest())
    ts = int(time.time()); nonce = b64f(os.urandom(18))
    msg = 'v2\n%s\n%s\n%s\n%d\n%s' % (PKG, did, reg, ts, nonce)
    proof = b64f(hmac.new(SECRET.encode(), msg.encode(), hashlib.sha256).digest())
    body = json.dumps({'packageName': PKG, 'deviceId': did, 'registrationDeviceId': reg,
                       'timestamp': ts, 'nonce': nonce, 'proof': proof}).encode()
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    class NR(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k): return None
    op = urllib.request.build_opener(NR, urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(ORIGIN + '/apk/bootstrap', data=body, method='POST',
        headers={'Content-Type': 'application/json; charset=utf-8', 'User-Agent': 'MBGameApp/1.0'})
    tok = json.loads(op.open(req, timeout=15).read())['launchToken']
    try:
        r = op.open(urllib.request.Request(ORIGIN + '/launch?apkToken=' + tok,
            headers={'User-Agent': 'Mozilla/5.0 (Linux; Android 14) MBGameApp/1.0'}), timeout=15)
        setc = r.headers.get('Set-Cookie', '')
    except urllib.error.HTTPError as e:
        if e.code not in (301, 302, 303, 307):
            raise
        setc = e.headers.get('Set-Cookie', '')
    ck = setc.split(';')[0].strip()
    if not ck.startswith('mb_apk_session='):
        raise RuntimeError('no origin session cookie: ' + setc[:120])
    with ORIGIN_LOCK:
        ORIGIN_SESSION.clear(); ORIGIN_SESSION.append(ck)
    log('origin session acquired (%d bytes)' % len(ck))

def origin_session():
    with ORIGIN_LOCK:
        if ORIGIN_SESSION: return ORIGIN_SESSION[0]
    try:
        origin_bootstrap()
        with ORIGIN_LOCK: return ORIGIN_SESSION[0]
    except Exception as e:
        log('origin bootstrap failed: %r' % e); return None

# ---------- logging ----------
PRL = threading.Lock()
def log(msg):
    with PRL:
        print('[%s] %s' % (time.strftime('%H:%M:%S'), msg), flush=True)

# ---------- HTTP handler ----------
MIME = {'.html':'text/html; charset=utf-8','.js':'application/javascript','.css':'text/css',
        '.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.gif':'image/gif',
        '.ico':'image/x-icon','.json':'application/json','.mp3':'audio/mpeg','.wav':'audio/wav',
        '.ttf':'font/ttf','.otf':'font/otf','.woff':'font/woff','.woff2':'font/woff2',
        '.atlas':'text/plain','.txt':'text/plain','.xml':'text/xml','.webp':'image/webp',
        '.plist':'application/xml','.fnt':'text/plain','.mp4':'video/mp4'}

class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *a):
        log('%s %s' % (self.address_string(), fmt % a))

    # ---- helpers ----
    def _send(self, code, body, ctype='application/octet-stream', extra=None):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD': self.wfile.write(body)

    def _redirect(self, location, cookie=None):
        extra = {'Location': location}
        if cookie: extra['Set-Cookie'] = cookie
        self._send(302, b'', 'text/plain', extra)

    # ---- routes ----
    def do_GET(self): self._route(False)
    def do_HEAD(self): self._route(True)

    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        raw = self.rfile.read(n) if n else b''
        p = urlparse(self.path).path
        if p == '/apk/bootstrap':
            return self._bootstrap(raw)
        if p in ('/demo/register', '/demo/login', '/demo/change-password'):
            if os.environ.get('MB_DEMO_OFFICIAL') == '1':   # 调试：透传官方
                return self._proxy_origin(p, raw)
            return self._demo_auth(p, raw)                  # 默认本地账号库
        if p.startswith('/client-'):          # 埋点上报：本地只收不传
            log('telemetry %s (%d B)' % (p, len(raw)))
            return self._send(200, b'{"ok":true}', 'application/json')
        return self._send(404, b'not found', 'text/plain')

    def _route(self, head):
        u = urlparse(self.path)
        path = u.path
        if path == '/':
            return self._send(200, '<h1>MB Private Server</h1>'.encode(), 'text/html')
        if path == '/launch':
            return self._launch(head)
        if path == '/ping':
            return self._send(200, b'pong', 'text/plain')
        if path in ('/demo/access-policy', '/maintenance-status'):
            if os.environ.get('MB_DEMO_OFFICIAL') == '1':
                return self._proxy_origin(path)
            return self._demo_local_get(path)   # 默认本地：全关校验，直接可玩
        if path.startswith('/pet05f/') or path.startswith('/sdkapi00.quicksdk.net/') or path == '/favicon.ico':
            return self._asset(path, u.query)
        if path.startswith('/client-'):       # 埋点（GET 形式）
            return self._send(200, b'{"ok":true}', 'application/json')
        return self._send(404, b'not found', 'text/plain')

    def _bootstrap(self, raw):
        try:
            j = json.loads(raw.decode('utf-8'))
            pkg = j.get('packageName', '')
            did = j.get('deviceId', '')
            ts = int(j.get('timestamp', 0))
            nonce = j.get('nonce', '')
            proof = j.get('proof', '')
            reg = j.get('registrationDeviceId', '')
            if not re.fullmatch(r'[A-Za-z0-9_.]{1,128}', pkg): raise ValueError('bad packageName')
            if reg:
                msg = 'v2\n%s\n%s\n%s\n%d\n%s' % (pkg, did, reg, ts, nonce)
            else:
                msg = 'v1\n%s\n%s\n%d\n%s' % (pkg, did, ts, nonce)
            expect = b64f(hmac.new(SECRET.encode(), msg.encode(), hashlib.sha256).digest())
            if not hmac.compare_digest(expect, proof): raise ValueError('bad proof')
            if abs(time.time() - ts) > 300: raise ValueError('timestamp skew')
        except Exception as e:
            log('bootstrap REJECT: %r' % e)
            return self._send(403, json.dumps({'ok': False, 'error': 'rejected'}).encode(), 'application/json')
        tok = 'v2.launch.%d.%s.%s.%s.%s' % (
            int(time.time()) + 86400,
            b64f(os.urandom(24)).replace('+','-').replace('/','_'),
            b64f(os.urandom(24)).replace('+','-').replace('/','_'),
            b64f(os.urandom(24)).replace('+','-').replace('/','_'),
            secrets.token_hex(20))
        log('bootstrap APPROVED deviceId=%s...' % did[:16])
        self._send(200, json.dumps({'ok': True, 'launchToken': tok, 'expiresAt': int(time.time()) + 86400}).encode(), 'application/json')

    def _proxy_origin(self, path, raw=None):
        """[MB_DEMO_OFFICIAL=1 时启用] 账号/维护接口透传官方。
        默认关闭：本地私服自成账号体系，不依赖官方可达性。"""
        ck = origin_session()
        hdrs = {'User-Agent': UA_GAME}
        if ck: hdrs['Cookie'] = ck
        method = 'POST' if raw is not None else 'GET'
        if raw is not None: hdrs['Content-Type'] = 'application/json; charset=utf-8'
        try:
            r = urllib.request.urlopen(urllib.request.Request(
                ORIGIN + path, data=raw, headers=hdrs, method=method),
                context=PROXY_CTX, timeout=15)
            code, body = r.status, r.read()
            setc = (r.headers.get_all('Set-Cookie') or [None])[0]
        except urllib.error.HTTPError as e:
            code, body = e.code, e.read()
            setc = (e.headers.get_all('Set-Cookie') or [None])[0]
        except Exception as e:
            log('origin %s unreachable (%r) -> local fallback' % (path, e))
            if raw is not None: return self._demo_auth(path, raw)
            return self._demo_local_get(path)
        extra = {'Set-Cookie': setc} if setc else None
        log('demo proxy %s -> HTTP %d' % (path, code))
        self._send(code, body, 'application/json', extra)

    def _demo_local_get(self, path):
        if path == '/demo/access-policy':
            return self._send(200, json.dumps({
                'ok': True, 'registrationCodeRequired': False,
                'deviceAccountBindingRequired': False,
                'appUpdateRequired': False}).encode(), 'application/json')
        if path == '/maintenance-status':
            return self._send(200, json.dumps(
                {'protocolVersion': 1, 'phase': 'open'}).encode(), 'application/json')
        return self._send(404, b'not found', 'text/plain')

    def _demo_auth(self, path, raw):
        """游戏页"账号中心"本地账号接口。JS 侧判定：HTTP 2xx 且 body.ok 为真
        才算成功，否则用 body.error 的错误码映射中文提示。"""
        try:
            j = json.loads(raw.decode('utf-8')) if raw else {}
        except Exception:
            j = {}
        acc = str(j.get('accountId') or '').strip()
        pw = str(j.get('password') or '')
        bad = lambda code, code401=400: self._send(
            code401, json.dumps({'ok': False, 'error': code}).encode(), 'application/json')
        with ACC_LOCK:
            accounts = _load_accounts()
            if path == '/demo/register':
                if not acc:   return bad('account_required')
                if not pw:    return bad('password_required')
                if acc in accounts: return bad('account_exists')
                salt = secrets.token_hex(16)
                accounts[acc] = {'salt': salt, 'hash': _pw_hash(salt, pw),
                                 'created': int(time.time())}
                _save_accounts(accounts)
                log('demo register account=%s' % acc)
                return self._send(200, json.dumps(
                    {'ok': True, 'accountId': acc}).encode(), 'application/json')
            rec = accounts.get(acc)
            if path == '/demo/login':
                if not acc:                    return bad('account_required')
                if not pw:                     return bad('password_required')
                if rec is None:                return bad('account_not_found', 401)
                if hmac.compare_digest(_pw_hash(rec['salt'], pw), rec['hash']):
                    log('demo login ok account=%s' % acc)
                    return self._send(200, json.dumps(
                        {'ok': True, 'accountId': acc}).encode(), 'application/json')
                return bad('invalid_password', 401)
            # /demo/change-password
            old = str(j.get('oldPassword') if j.get('oldPassword') is not None else pw)
            new = str(j.get('newPassword') or '')
            if not acc:                        return bad('account_required')
            if rec is None:                    return bad('account_not_found', 401)
            if not new:                        return bad('new_password_required')
            if not hmac.compare_digest(_pw_hash(rec['salt'], old), rec['hash']):
                return bad('invalid_password', 401)
            salt = secrets.token_hex(16)
            rec['salt'], rec['hash'] = salt, _pw_hash(salt, new)
            _save_accounts(accounts)
            log('demo change-password account=%s' % acc)
            return self._send(200, json.dumps(
                {'ok': True, 'accountId': acc}).encode(), 'application/json')

    def _launch(self, head):
        q = parse_qs(urlparse(self.path).query)
        tok = (q.get('apkToken') or [''])[0]
        ck = self.headers.get('Cookie', '')
        if 'mb_apk_session=' in ck:
            # 已有会话 → 进入游戏页 (serverIp 指向本地 WS 隧道)
            qs = urlencode({
                'scid': '11', 'sdkcname': 'H5_quikSDK', '_platform_': '304',
                'channel_id': '100304', 'game_channel_id': '100304',
                'protocal': 'ws', 'serverIp': '127.0.0.1:20311',
                'vvv': '1', 'vv': '20260327', 'bgurl': 'loading_newyear2.jpg',
                'initBg': 'loading_newyear2.jpg'})
            return self._redirect('/pet05f/index.html?' + qs)
        if not tok:
            return self._send(403, b'missing apkToken', 'text/plain')
        if not re.fullmatch(r'[A-Za-z0-9_.\-]{80,512}', tok):
            return self._send(403, b'invalid apkToken', 'text/plain')
        sess = 'mb_apk_session=' + secrets.token_hex(24)
        SESSIONS[sess.split('=',1)[1]] = time.time() + 86400
        return self._redirect('/launch', sess + '; Path=/; Max-Age=86400; HttpOnly; SameSite=Strict; Secure')

    def _asset(self, path, query):
        # 1) 本地镜像
        rel = path.lstrip('/')
        if '..' in rel: return self._send(400, b'bad path', 'text/plain')
        local = os.path.join(MIRROR, rel)
        if not os.path.isfile(local):
            self._fetch_origin(path, query, local)
        if os.path.isfile(local):
            ext = os.path.splitext(local)[1].lower()
            data = open(local, 'rb').read()
            return self._send(200, data, MIME.get(ext, 'application/octet-stream'))
        return self._send(404, b'asset not found', 'text/plain')

    def _fetch_origin(self, path, query, local):
        ck = origin_session()
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        url = ORIGIN + path + (('?' + query) if query else '')
        hdrs = {'User-Agent': 'Mozilla/5.0 (Linux; Android 14) MBGameApp/1.0'}
        if ck: hdrs['Cookie'] = ck
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, headers=hdrs), context=ctx, timeout=20)
            data = r.read()
            os.makedirs(os.path.dirname(local) or MIRROR, exist_ok=True)
            with open(local, 'wb') as f: f.write(data)
            log('mirror %s (%d B)' % (path, len(data)))
        except urllib.error.HTTPError as e:
            log('origin %s -> HTTP %d' % (path, e.code))
        except Exception as e:
            log('origin %s ERR %r' % (path, e))

# ---------- WS / WSS TLS-bump 隧道 ----------
WS_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
WS_CTX.load_cert_chain(os.path.join(PEM, 'server.crt'), os.path.join(PEM, 'server.key'))
UP_CTX = ssl.create_default_context()
UP_CTX.check_hostname = False; UP_CTX.verify_mode = ssl.CERT_NONE

RECORD = os.environ.get('MB_RECORD') == '1'      # MB_RECORD=1 时抓包游戏协议帧
REC_DIR = os.path.join(HERE, 'ws_record')
REC_SEQ = [0]

def record(tag, data):
    """把隧道里的明文 WS 帧落盘，供后续离线仿真/协议分析（MB_RECORD=1）。"""
    if not RECORD: return
    os.makedirs(REC_DIR, exist_ok=True)
    with ORIGIN_LOCK:
        REC_SEQ[0] += 1
        i = REC_SEQ[0]
    with open(os.path.join(REC_DIR, '%s_%04d_%s.bin' % (time.strftime('%H%M%S'), i, tag)), 'wb') as f:
        f.write(data)

def pipe(a, b, tag=''):
    try:
        while True:
            d = a.recv(65536)
            if not d: break
            if tag: record(tag, d)
            b.sendall(d)
    except Exception: pass
    finally:
        try: b.shutdown(socket.SHUT_RDWR)
        except Exception: pass
        try: a.close(); b.close()
        except Exception: pass

def ws_client(conn):
    try:
        conn.settimeout(10)
        first = conn.recv(1, socket.MSG_PEEK)
        if not first: conn.close(); return
        if first == b'\x16':   # TLS ClientHello → wss
            conn = WS_CTX.wrap_socket(conn, server_side=True)
        if os.environ.get('MB_WS_TUNNEL') == '1':
            # 旧模式：与源站建立 TLS, 透传（官方在线联调/抓包用）
            up = socket.create_connection(ORIGIN_WS, timeout=10)
            ups = UP_CTX.wrap_socket(up, server_hostname=ORIGIN_WS[0])
            conn.settimeout(None)
            log('WS tunnel established')
            threading.Thread(target=pipe, args=(conn, ups, 'c2s'), daemon=True).start()
            pipe(ups, conn, 's2c')
            return
        conn.settimeout(None)
        mbgame.serve(conn, conn.getpeername())
    except Exception as e:
        log('ws error: %r' % e)
        try: conn.close()
        except Exception: pass

def ws_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(LISTEN_WS); s.listen(16)
    log('game WS listening on %s:%d (tunnel=%s)' % (
        LISTEN_WS[0], LISTEN_WS[1], os.environ.get('MB_WS_TUNNEL') == '1'))
    while True:
        c, addr = s.accept()
        threading.Thread(target=ws_client, args=(c,), daemon=True).start()

# ---------- main ----------
def session_cleaner():
    while True:
        time.sleep(300)
        now = time.time()
        with ORIGIN_LOCK:
            for k in [k for k, v in SESSIONS.items() if v < now]:
                SESSIONS.pop(k, None)

def main():
    seed_account(*SEED_ACCOUNT)
    threading.Thread(target=ws_server, daemon=True).start()
    threading.Thread(target=origin_bootstrap, daemon=True).start()
    threading.Thread(target=session_cleaner, daemon=True).start()
    srv = ThreadingHTTPServer(LISTEN_HTTP, Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(PEM, 'server.crt'), os.path.join(PEM, 'server.key'))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    log('HTTPS listening on %s:%d' % LISTEN_HTTP)
    srv.serve_forever()

if __name__ == '__main__':
    main()
