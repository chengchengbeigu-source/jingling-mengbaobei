import base64, hashlib, hmac, json, os, ssl, time, urllib.request, uuid

PKG = 'com.localfirst.mb'
SECRET = 'Sang_rIvZNZf1bJkOwkLsC0bOKMll7oY-Juw81rzhZK_h1rgBx5cgl-jZ5GTSKdv'

# emulate client: random install_salt + android_id
install_salt = str(uuid.uuid4())
android_id = '%016x' % int.from_bytes(os.urandom(8), 'big')

def b64f(data):  # URL_SAFE | NO_WRAP | NO_PADDING (flags=11)
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

deviceId = b64f(hashlib.sha256(('v1\n%s\n%s\n%s' % (PKG, android_id, install_salt)).encode()).digest())
reg = b64f(hashlib.sha256(('mb-registration-v1\n%s\n%s' % (PKG, android_id.lower())).encode()).digest())

ts = int(time.time())
nonce = b64f(os.urandom(18))
msg = 'v2\n%s\n%s\n%s\n%d\n%s' % (PKG, deviceId, reg, ts, nonce)
proof = b64f(hmac.new(SECRET.encode(), msg.encode(), hashlib.sha256).digest())

body = json.dumps({'packageName': PKG, 'deviceId': deviceId, 'registrationDeviceId': reg,
                   'timestamp': ts, 'nonce': nonce, 'proof': proof}).encode()

print('POST https://mcbtc.cn:20310/apk/bootstrap')
print('deviceId:', deviceId[:40] + '...')
print('registrationDeviceId:', reg[:40] + '...')

ctx = ssl.create_default_context()
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request('https://mcbtc.cn:20310/apk/bootstrap', data=body,
    headers={'Content-Type': 'application/json; charset=utf-8', 'Accept': 'application/json',
             'User-Agent': 'MBGameApp/1.0'}, method='POST')
try:
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        print('HTTP', resp.status)
        print(resp.read().decode()[:2000])
except urllib.error.HTTPError as e:
    print('HTTP', e.code)
    print(e.read().decode()[:2000])
except Exception as e:
    print('ERR', type(e).__name__, e)
