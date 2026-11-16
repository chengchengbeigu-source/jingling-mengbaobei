import socket, ssl, urllib.request
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

def probe(url, hdrs=None):
    try:
        req = urllib.request.Request(url, headers=hdrs or {'User-Agent':'Mozilla/5.0'})
        class NR(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*a,**k): return None
        op = urllib.request.build_opener(NR, urllib.request.HTTPSHandler(context=ctx))
        r = op.open(req, timeout=12)
        body = r.read()
        print(r.status, r.geturl(), 'len', len(body), r.headers.get('Content-Type'))
        return body
    except urllib.error.HTTPError as e:
        print('HTTP', e.code, url, 'loc:', e.headers.get('Location'))
        return None
    except Exception as e:
        print('ERR', url, type(e).__name__, e)
        return None

# 1. direct access to game page without session
probe('https://mcbtc.cn:20310/pet05f/index.html')
# 2. WS port TCP
try:
    s = socket.create_connection(('mcbtc.cn', 20311), timeout=6)
    print('WS port 20311: TCP open')
    s.close()
except Exception as e:
    print('WS port 20311:', type(e).__name__, e)
# 3. root path
probe('https://mcbtc.cn:20310/')
# 4. sample asset paths guessed from html
html = open('launch_page.html','rb').read().decode('utf-8','replace')
import re
assets = sorted(set(re.findall(r'(?:src|href)=[\"\']([^\"\']+)[\"\']', html)))
print('asset refs:', len(assets))
for a in assets[:25]: print(' ', a)
