#!/usr/bin/env python3
"""本地游戏服务端端到端自测：模拟手机端完整登录-建角-进游戏-副本-引导流程。"""
import base64, json, os, socket, ssl, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
HOST, PORT = '127.0.0.1', 20311
SCHEMA = json.load(open(os.path.join(HERE, 'msg_schema.json'), encoding='utf-8'))
SCALARS = {'int8','uint8','int16','uint16','int32','uint32','int64','uint64','number','string'}

# ---------- 编码 ----------
def wr(out, typ, v):
    if typ == 'string':
        raw = str(v).encode('utf-8'); out.extend(struct.pack('>H', len(raw)) + raw)
    elif typ == 'int8': out.extend(struct.pack('>b', v))
    elif typ == 'uint8': out.extend(struct.pack('>B', v))
    elif typ == 'int16': out.extend(struct.pack('>h', v))
    elif typ == 'uint16': out.extend(struct.pack('>H', v))
    elif typ == 'int32': out.extend(struct.pack('>i', v))
    elif typ == 'uint32': out.extend(struct.pack('>I', v))
    elif typ == 'int64': out.extend(struct.pack('>q', v))
    elif typ == 'uint64': out.extend(struct.pack('>Q', v))
    elif typ == 'number': out.extend(struct.pack('>d', v))

def enc_struct(name, values):
    out = bytearray()
    for f in SCHEMA.get(name, []) or []:
        fname, typ = f[0], f[1]
        v = values.get(fname)
        if typ == 'array':
            elem = f[2]; v = v or []
            out.extend(struct.pack('>h', len(v)))
            for it in v:
                if elem in SCALARS: wr(out, elem, it)
                else: out.extend(enc_struct(elem, it or {}))
        elif typ in SCALARS:
            wr(out, typ, 0 if v is None else v)
        else:
            out.extend(enc_struct(typ, v or {}))
    return bytes(out)

def body(opcode, values):
    return enc_struct('__op%d' % opcode, values) if False else enc_fields(SCHEMA[str(opcode)].get('c', []) or [], values)

def enc_fields(fields, values):
    out = bytearray()
    for f in fields:
        name, typ = f[0], f[1]
        v = (values or {}).get(name)
        if typ == 'array':
            elem = f[2]; v = v or []
            out.extend(struct.pack('>h', len(v)))
            for it in v:
                if elem in SCALARS: wr(out, elem, it)
                else: out.extend(enc_struct(elem, it or {}))
        elif typ in SCALARS:
            wr(out, typ, 0 if v is None else v)
        else:
            out.extend(enc_struct(typ, v or {}))
    return bytes(out)

def packet(opcode, values=None):
    b = enc_fields(SCHEMA[str(opcode)].get('c', []) or [], values or {})
    return struct.pack('>IHB', 7 + len(b), opcode, 0) + b

# ---------- 传输 ----------
class WS:
    def __init__(self):
        raw = socket.create_connection((HOST, PORT), timeout=10)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        self.s = ctx.wrap_socket(raw, server_hostname=HOST)
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

# ---------- 解码 ----------
def rd_scalar(b, typ):
    if typ == 'string':
        n = struct.unpack('>H', b[:2])[0]; return b[2:2+n].decode(), b[2+n:]
    sz = {'int8':1,'uint8':1,'int16':2,'uint16':2,'int32':4,'uint32':4,'int64':8,'uint64':8,'number':8}[typ]
    v = int.from_bytes(b[:sz], 'big', signed=(typ.startswith('i') or typ == 'number'))
    return v, b[sz:]

def dec_fields(fields, data):
    out = {}
    for f in fields:
        name, typ = f[0], f[1]
        if typ == 'array':
            n = struct.unpack('>h', data[:2])[0]; data = data[2:]
            elem = f[2]; items = []
            for _ in range(n):
                if elem in SCALARS:
                    v, data = rd_scalar(data, elem); items.append(v)
                else:
                    v, data = dec_fields(SCHEMA.get(elem, []) or [], data); items.append(v)
            out[name] = items
        elif typ in SCALARS:
            v, data = rd_scalar(data, typ); out[name] = v
        else:
            v, data = dec_fields(SCHEMA.get(typ, []) or [], data); out[name] = v
    return out, data

def decode(opcode, data):
    out, rest = dec_fields(SCHEMA[str(opcode)].get('s', []) or [], data)
    assert not rest, 'opcode %d has %d trailing bytes' % (opcode, len(rest))
    return out

def expect(w, opcode):
    opc, d = w.recv()
    assert opc == opcode, 'expected %d got %d' % (opcode, opc)
    return decode(opcode, d)

def main():
    print('[1] auth connection')
    w = WS()
    w.send(2011, {'platformId': 304, 'channel': '100304', 'game_channel_id': '100304',
                  'keyId': 'test_bot', 'verify_time': 0, 'sign': '', 'isGuest': 0, 'OS': 1})
    r = expect(w, 2011); assert r['result'] == 0, r
    r = expect(w, 2002); assert r['platformList'], r
    print('  server list:', r['platformList'])
    w.send(2003, {'serverId': 34001})
    r = expect(w, 2003); assert r['result'] == 0, r
    w.s.close()

    print('[2] gate connection (no role -> -52)')
    w = WS()
    w.send(3001, {'platformId': 304, 'accountId': 'test_bot', 'md5': 't', 'os': 1,
                  'osVersion': '17', 'relogin': 0, 'channel': '100304'})
    r = expect(w, 3001); assert r['result'] == -52, r
    print('[3] create role')
    w.send(3002, {'name': '小萌新', 'face_id': 3})
    r = expect(w, 3002); assert r['result'] == 0, r
    expect(w, 3003)
    print('[4] enter game + init pushes')
    w.send(3004)
    r = expect(w, 3004)
    assert r['roleInfo']['name'] == '小萌新', r
    p = expect(w, 14001); assert p['type'] == 0, p
    p = expect(w, 11000); assert p['hero_list'], p
    print('  pet package: heroes=%d' % len(p['hero_list']))
    p = expect(w, 4009)
    print('[5] manual 11984 (探索手册)')
    w.send(11984)
    r = expect(w, 11984); assert r['result'] == 0 and '"tracks"' in r['data'], r
    print('  data =', r['data'])
    print('[6] dungeon begin 14002 (蓝方阵容)')
    w.send(14002, {'dungeonId': 100101})
    r = expect(w, 14002); mb = r['my_battle_info']
    assert r['result'] == 0 and r['dungeonId'] == 100101, r
    assert mb['heroList'] and mb['teamList'], r
    print('  heroes=%d team=%d attr0=%r first=%d' % (
        len(mb['heroList']), len(mb['teamList']), mb['heroList'][0]['attr_list'],
        mb['role_speed']))
    print('[7] dungeon end 14003')
    w.send(14003, {'dungeonId': 2110259, 'star': 3, 'dungeon_args': {'args_num': 0}})
    r = expect(w, 14003); assert r['result'] == 0 and r['dungeonId'] == 2110259, r
    print('[8] set team 11002 (上阵)')
    w.send(11002, {'team_list': [{'pos': 1, 'uid': 1}]})
    r = expect(w, 11002); assert r['result'] == 0 and r['team_list'], r
    print('  team =', json.dumps(r['team_list'], ensure_ascii=False))
    print('[9] misc + heartbeat')
    w.send(4004); expect(w, 4004)
    w.send(3009); expect(w, 3009)
    w.send(11985, {'kind': 1, 'track': 1, 'target': 0, 'amount': 0, 'requestId': 1})
    r = expect(w, 11985); assert r['result'] == 0, r
    w.s.close()
    print('PASS')

if __name__ == '__main__':
    main()
