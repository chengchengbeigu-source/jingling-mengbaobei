import base64, hashlib, hmac, json, os, ssl, time, urllib.request, uuid, http.cookiejar

PKG = 'com.localfirst.mb'
SECRET = 'Sang_rIvZNZf1bJkOwkLsC0bOKMll7oY-Juw81rzhZK_h1rgBx5cgl-jZ5GTSKdv'
install_salt = str(uuid.uuid4())
android_id = '%016x' % int.from_bytes(os.urandom(8), 'big')
def b64f(b): return base64.urlsafe_b64encode(b).decode().rstrip('=')
deviceId = b64f(hashlib.sha256(('v1\n%s\n%s\n%s' % (PKG, android_id, install_salt)).encode()).digest())
reg = b64f(hashlib.sha256(('mb-registration-v1\n%s\n%s' % (PKG, android_id.lower())).encode()).digest())
ts = int(time.time()); nonce = b64f(os.urandom(18))
msg = 'v2\n%s\n%s\n%s\n%d\n%s' % (PKG, deviceId, reg, ts, nonce)
proof = b64f(hmac.new(SECRET.encode(), msg.encode(), hashlib.sha256).digest())
body = json.dumps({'packageName': PKG, 'deviceId': deviceId, 'registrationDeviceId': reg,
                   'timestamp': ts, 'nonce': nonce, 'proof': proof}).encode()
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), urllib.request.HTTPSHandler(context=ctx))

req = urllib.request.Request('https://mcbtc.cn:20310/apk/bootstrap', data=body,
    headers={'Content-Type': 'application/json; charset=utf-8', 'User-Agent': 'MBGameApp/1.0'}, method='POST')
tok = json.loads(opener.open(req, timeout=15).read())['launchToken']

req2 = urllib.request.Request('https://mcbtc.cn:20310/launch?apkToken=' + tok,
    headers={'User-Agent': 'Mozilla/5.0 (Linux; Android 14; Mobile) AppleWebKit/537.36 MBGameApp/1.0'})
r = opener.open(req2, timeout=20)
html = r.read()
print('final HTTP', r.status, 'len', len(html), 'url', r.geturl())
open('launch_page.html','wb').write(html)
txt = html.decode('utf-8','replace')
print(txt[:4000])
