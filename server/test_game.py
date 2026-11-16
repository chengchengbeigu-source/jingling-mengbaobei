#!/usr/bin/env python3
"""本地游戏服务端端到端自测：模拟手机端完整登录-建角-进游戏流程。"""
import base64, hashlib, json, os, socket, ssl, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
HOST, PORT = '127.0.0.1', 20311
SCHEMA = json.load(open(os.path.join(HERE, 'msg_schema.json'), encoding='utf-8'))
SCALARS = {'int8','uint8','int16','uint16','int32','uint32','int64','uint64','number','string'}

def wr(out, typ, v):
    if typ == 'string':
        raw = v.encode('utf-8'); out.extend(struct.pack('>H', len(raw)) + raw)
    elif typ == 'int8': out.extend(struct.pack('>b', v))
    elif typ == 'uint8': out.extend(struct.pack('>B', v))
    elif typ == 'int16': out.extend(struct.pack('>h', v))
    elif typ == 'uint16': out.extend(struct.pack('>H', v))
    elif typ == 'int32': out.extend(struct.pack('>i', v))
    elif typ == 'uint32': out.extend(struct.pack('>I', v))
    elif typ == 'int64': out.extend(struct.pack('>q', v))
    elif typ == 'uint64': out.extend(struct.pack('>Q', v))
    elif typ == 'number': out.extend(struct.pack('>d', v))

def body(opcode, values):
    out = bytearray()
    for f in SCHEMA[str(opcode)].get('c', []) or []:
        name, typ = f[0], f[1]
        v = values.get(name, 0 if typ != 'string' else '')
        if typ == 'array':
            elem = f[2]; out.extend(struct.pack('>h', len(v)))
            for it in v:
                if elem in SCALARS: wr(out, elem, it)
        else:
            wr(out, typ, v)
    return bytes(out)

def packet(opcode, values=None):
    b = body(opcode, values or {})
    return struct.pack('>IHB', 7 + len(b), opcode, 0) + b

class WS:
    def __init__(self):
        raw = socket.create_connection((HOST, PORT), timeout=10)
        self.s = ssl.create_default_context()
        self.s.check_hostname = False; self.s.verify_mode = ssl.CERT_NONE
        self.s = self.s.wrap_socket(raw, server_hostname=HOST)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall(('GET / HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n'
                        'Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n'
                        'Sec-WebSocket-Version: 13\r\nOrigin: https://127.0.0.1:4430\r\n'
                        'Cookie: mb_apk_session=testsession\r\n\r\n'
                        % (HOST, PORT, key)).encode())
        resp = b''
        while b'\r\n\r\n' not in resp:
            resp += self.s.recv(4096)
        assert b'101' in resp.split(b'\r\n')[0], resp[:200]
    def send(self, opcode, values=None):
        p = packet(opcode, values)
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(p))
        self.s.sendall(bytes([0x82, 0x80 | len(p)]) + mask + masked)
    def recv(self):
        h = self.s.recv(2)
        op = h[0] & 0xF; ln = h[1] & 0x7F
        if ln == 126: ln = struct.unpack('>H', self.s.recv(2))[0]
        elif ln == 127: ln = struct.unpack('>Q', self.s.recv(8))[0]
        d = b''
        while len(d) < ln: d += self.s.recv(ln - len(d))
        total, opc, stamp = struct.unpack('>IHB', d[:7])
        return opc, d[7:total]

def rd_scalar(b, typ):
    if typ == 'string':
        n = struct.unpack('>H', b[:2])[0]; return b[2:2+n].decode(), b[2+n:]
    sz = {'int8':1,'uint8':1,'int16':2,'uint16':2,'int32':4,'uint32':4,'int64':8,'uint64':8,'number':8}[typ]
    v = int.from_bytes(b[:sz], 'big', signed=(typ.startswith('i') or typ=='number'))
    return v, b[sz:]

def show(opcode, data):
    fields = SCHEMA[str(opcode)].get('s', []) or []
    out = {}
    for f in fields:
        name, typ = f[0], f[1]
        if typ == 'array':
            n = struct.unpack('>h', data[:2])[0]; data = data[2:]
            elem = f[2]
            items = []
            for _ in range(n):
                if elem in SCALARS:
                    v, data = rd_scalar(data, elem); items.append(v)
                else:
                    items.append('<struct %d B>' % len(data)); data = b''
            out[name] = items
        elif typ in SCALARS:
            v, data = rd_scalar(data, typ); out[name] = v
        else:
            out[name] = '<struct %s %d B>' % (typ, len(data)); data = b''
    print('  %d -> %s' % (opcode, json.dumps(out, ensure_ascii=False)[:220]))

def main():
    print('[1] auth connection')
    w = WS()
    w.send(2011, {'platformId': 304, 'channel': '100304', 'game_channel_id': '100304',
                  'keyId': '123', 'verify_time': 0, 'sign': '', 'isGuest': 0, 'OS': 1})
    show(*w.recv())
    w.send(2002); show(*w.recv())
    w.send(2003, {'serverId': 34001}); show(*w.recv())
    w.s.close()

    print('[2] gate connection (no role -> -52)')
    w = WS()
    w.send(3001, {'platformId': 304, 'accountId': '123', 'md5': 't', 'os': 1,
                  'osVersion': '17', 'relogin': 0, 'channel': '100304'})
    show(*w.recv())
    print('[3] create role')
    w.send(3002, {'name': '小萌新', 'face_id': 3})
    show(*w.recv())          # 3002 result
    show(*w.recv())          # 3003 push
    print('[4] enter game')
    w.send(3004); show(*w.recv())
    print('[5] misc + heartbeat')
    w.send(4004)
    try: show(*w.recv())
    except Exception as e: print('  4004:', e)
    w.send(3009); show(*w.recv())
    w.s.close()
    print('PASS')

if __name__ == '__main__':
    main()
