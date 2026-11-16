#!/usr/bin/env python3
"""MB 豆包萌宠 本地游戏 WS 服务端（schema 驱动，stdlib only）

协议（逆向自 game.min.js 的 PacketCfg + patchPacket）：
  封包 = [4B 大端总长][2B 大端 opcode][1B stamp][body]
  标量 = 大端 int8/uint8/int16/uint16/int32/uint32/int64/uint64/number(float64)
  string = [2B 大端字节长][UTF-8]     array = [2B 大端个数][元素...]
  结构体 = 按 msg_schema.json 中定义的字段顺序排列

登录流程：
  2011 登录(keyId=账号) → 2002 区服列表 → 2003 选区(返回网关 ip:port=本机)
  → 重连网关 → 3001 网关登录(无角色=-52 → 客户端开建角面板)
  → 3002 建角 → 推 3003 就绪 → 3004 进游戏(返回 roleInfo)
  → 之后任意带 schema 的请求都按 schema 默认值应答(result=0)，3009 心跳回声。
"""
import base64, hashlib, json, os, struct, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_FILE = os.path.join(HERE, 'msg_schema.json')
ROLES_FILE = os.path.join(HERE, 'roles.json')
ROLE_LOCK = threading.Lock()

with open(SCHEMA_FILE, encoding='utf-8') as f:
    SCHEMA = json.load(f)

SCALARS = {'int8', 'uint8', 'int16', 'uint16', 'int32', 'uint32',
           'int64', 'uint64', 'number', 'string'}
SERVER_ID = 34001
SERVER_NAME = '本地一区'
PLATFORM_ID = 304
GATE = ('127.0.0.1', 20311)
WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


def log(msg):
    from mbserver import log as _log
    _log('[game] ' + msg)

# ---------- 角色库 ----------
def load_roles():
    try:
        with open(ROLES_FILE, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def save_roles(roles):
    tmp = ROLES_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(roles, f, ensure_ascii=False, indent=1)
    os.replace(tmp, ROLES_FILE)

def get_role(account):
    with ROLE_LOCK:
        return load_roles().get(account)

def upsert_role(account, patch):
    with ROLE_LOCK:
        roles = load_roles()
        r = roles.get(account) or {'roleId': 100000 + len(roles) + 1, 'lev': 1,
                                   'created': int(time.time())}
        r.update(patch)
        roles[account] = r
        save_roles(roles)
        return r

# ---------- 封包编解码 ----------
class Buf:
    def __init__(self, data=b''):
        self.b = bytearray(data)
        self.p = 0
    def take(self, n):
        if self.p + n > len(self.b):
            raise ValueError('packet truncated (need %d, have %d)' % (n, len(self.b) - self.p))
        v = self.b[self.p:self.p + n]; self.p += n; return bytes(v)
    def remaining(self):
        return len(self.b) - self.p

def rd_scalar(buf, typ):
    if typ == 'string':
        n = struct.unpack('>H', buf.take(2))[0]
        return buf.take(n).decode('utf-8', 'replace')
    if typ == 'int8':  return struct.unpack('>b', buf.take(1))[0]
    if typ == 'uint8': return struct.unpack('>B', buf.take(1))[0]
    if typ == 'int16': return struct.unpack('>h', buf.take(2))[0]
    if typ == 'uint16':return struct.unpack('>H', buf.take(2))[0]
    if typ == 'int32': return struct.unpack('>i', buf.take(4))[0]
    if typ == 'uint32':return struct.unpack('>I', buf.take(4))[0]
    if typ in ('int64', 'uint64'): return struct.unpack('>q' if typ == 'int64' else '>Q', buf.take(8))[0]
    if typ == 'number':return struct.unpack('>d', buf.take(8))[0]
    raise ValueError('unknown scalar type %r' % typ)

def wr_scalar(out, typ, v):
    if typ == 'string':
        raw = str(v if v is not None else '').encode('utf-8')
        out += struct.pack('>H', len(raw)) + raw
    elif typ == 'int8':   out += struct.pack('>b', int(v or 0))
    elif typ == 'uint8':  out += struct.pack('>B', int(v or 0))
    elif typ == 'int16':  out += struct.pack('>h', int(v or 0))
    elif typ == 'uint16': out += struct.pack('>H', int(v or 0))
    elif typ == 'int32':  out += struct.pack('>i', int(v or 0))
    elif typ == 'uint32': out += struct.pack('>I', int(v or 0) & 0xFFFFFFFF)
    elif typ == 'int64':  out += struct.pack('>q', int(v or 0))
    elif typ == 'uint64': out += struct.pack('>Q', int(v or 0) & 0xFFFFFFFFFFFFFFFF)
    elif typ == 'number': out += struct.pack('>d', float(v or 0))
    else: raise ValueError('unknown scalar type %r' % typ)

def read_fields(buf, schema):
    """按 schema 字段读取 body；返回 dict（未知多余字节忽略）。"""
    out = {}
    for f in schema:
        name, typ = f[0], f[1]
        if typ == 'array':
            elem = f[2]
            n = struct.unpack('>h', buf.take(2))[0]
            if elem in SCALARS:
                out[name] = [rd_scalar(buf, elem) for _ in range(max(0, n))]
            else:
                out[name] = [read_fields(buf, SCHEMA.get(elem, [])) for _ in range(max(0, n))]
        elif typ in SCALARS:
            out[name] = rd_scalar(buf, typ)
        else:
            out[name] = read_fields(buf, SCHEMA.get(typ, []))
    return out

def build_body(schema, overrides=None):
    """按 schema 生成默认 body（result=0、数值 0、串 ''、数组/结构递归默认），
    再用 overrides 覆盖。"""
    overrides = overrides or {}
    out = bytearray()

    def emit(fields, ov):
        for f in fields:
            name, typ = f[0], f[1]
            if name in ov:
                v = ov.pop(name)
                if typ == 'array':
                    elem = f[2]
                    out.extend(struct.pack('>h', len(v)))
                    for item in v:
                        if elem in SCALARS: wr_scalar(out, elem, item)
                        else: emit(SCHEMA.get(elem, []), item or {})
                elif typ in SCALARS:
                    wr_scalar(out, typ, v)
                else:
                    emit(SCHEMA.get(typ, []), v or {})
                continue
            if typ == 'array':
                elem = f[2]
                out.extend(struct.pack('>h', 0))
            elif typ in SCALARS:
                wr_scalar(out, typ, 0 if typ != 'string' else '')
            else:
                emit(SCHEMA.get(typ, []), {})
    # 覆盖项可能写在嵌套里，这里只支持顶层；剩余未用到的忽略
    emit(list(schema), dict(overrides))
    return bytes(out)

def pack_packet(opcode, body=b'', stamp=0):
    total = 7 + len(body)
    return struct.pack('>IHB', total, opcode, stamp) + body

# ---------- WebSocket 帧编解码 ----------
def ws_handshake(conn):
    """读取 HTTP Upgrade 请求并回复 101；返回 headers dict。"""
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = conn.recv(4096)
        if not chunk: raise ConnectionError('closed during handshake')
        data += chunk
        if len(data) > 65536: raise ValueError('handshake too large')
    head, _, _rest = data.partition(b'\r\n\r\n')
    headers = {}
    for line in head.decode('latin1').split('\r\n')[1:]:
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip().lower()] = v.strip()
    key = headers.get('sec-websocket-key', '')
    accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
    conn.sendall(('HTTP/1.1 101 Switching Protocols\r\n'
                  'Upgrade: websocket\r\nConnection: Upgrade\r\n'
                  'Sec-WebSocket-Accept: %s\r\n\r\n' % accept).encode())
    return headers

def ws_read_frame(conn):
    """返回 (opcode, payload)；自动处理分片与 ping/pong。"""
    buf = b''
    while True:
        h = conn.recv(2)
        if len(h) < 2: raise ConnectionError('ws closed')
        fin = h[0] & 0x80
        op = h[0] & 0x0F
        masked = h[1] & 0x80
        ln = h[1] & 0x7F
        if ln == 126:
            ext = conn.recv(2); ln = struct.unpack('>H', ext)[0]
        elif ln == 127:
            ext = conn.recv(8); ln = struct.unpack('>Q', ext)[0]
        mask = conn.recv(4) if masked else b''
        payload = b''
        while len(payload) < ln:
            d = conn.recv(min(65536, ln - len(payload)))
            if not d: raise ConnectionError('ws closed mid-frame')
            payload += d
        if masked:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        if op == 0x9:                     # ping → pong
            conn.sendall(bytes([0x8A, len(payload)]) + payload)
            continue
        if op == 0xA:                     # pong 忽略
            continue
        buf += payload
        if fin:
            return (op, buf)

def ws_write_frame(conn, payload):
    ln = len(payload)
    if ln < 126:
        conn.sendall(bytes([0x82, ln]) + payload)
    elif ln < 65536:
        conn.sendall(bytes([0x82, 126]) + struct.pack('>H', ln) + payload)
    else:
        conn.sendall(bytes([0x82, 127]) + struct.pack('>Q', ln) + payload)

# ---------- 业务处理 ----------
class GameSession:
    def __init__(self, peer):
        self.peer = peer
        self.account = None

    def reply(self, conn, opcode, overrides=None, schema=None):
        schema = schema if schema is not None else (SCHEMA.get(str(opcode), {}) or {}).get('s', [])
        body = build_body(schema, overrides)
        ws_write_frame(conn, pack_packet(opcode, body))
        log('-> %d (%d B body)' % (opcode, len(body)))

    STARTER = {'uid': 1, 'hero_id': 125, 'lev': 1, 'exp': 0,
               'card_id': 1250104, 'star': 1, 'stage': 0, 'qua_stage': 0,
               'favor_id': 0, 'favor_lev': 0, 'favor_exp': 0,
               'star_list': [], 'seer_list': [], 'eqm_list': []}
    # 战斗属性（AttrCfg：1=hp 2=atk 3=def 13=speed），保证新手战斗稳赢
    ATTRS = [(1, 20000), (2, 3000), (3, 1500), (13, 200)]

    @classmethod
    def _ensure_pets(cls, account):
        """角色名下宠物列表；没有就发放初始宠（小火龙）并持久化。"""
        role = get_role(account) or {}
        pets = role.get('pets')
        if not pets:
            pets = [dict(cls.STARTER)]
            upsert_role(account, {'pets': pets})
        return pets

    @classmethod
    def _pet_package(cls, account):
        """PET_GET_ALL_INFO(11000) 载荷：队伍+宠物+羁绊。"""
        pets = cls._ensure_pets(account)
        team = (get_role(account) or {}).get('team') or []
        team_list = [{'pos1': t['pos'], 'pos2': t.get('pos2', 0),
                      'uid': t['uid'], 'eqm_list': []} for t in team]
        return {'team_list': team_list, 'hero_list': pets, 'fate_list': []}

    @classmethod
    def _battle_info(cls, account):
        """14002 my_battle_info：蓝方=角色宠物（heroList+teamList）。
        官方流程 setTeamPets 用 heroList 建宠、teamList 摆位；
        队伍为空（新手还没上阵）时自动全员上阵，保证引导战能打。"""
        pets = cls._ensure_pets(account)
        team = (get_role(account) or {}).get('team') or []
        if not team:
            team = [{'pos': i + 1, 'uid': p['uid']} for i, p in enumerate(pets[:6])]
        uids = {p['uid'] for p in pets}
        hero_list = [{'uid': p['uid'], 'hero_id': p['hero_id'],
                      'lev': p.get('lev', 1), 'card_id': p['card_id'],
                      'star': p.get('star', 0), 'stage': p.get('stage', 0),
                      'attr_list': [{'attr_id': a, 'attr_value': v}
                                    for a, v in cls.ATTRS]}
                     for p in pets]
        team_list = [{'pos1': t['pos'], 'pos2': 0, 'uid': t['uid'], 'eqm_list': []}
                     for t in team if t['uid'] in uids]
        return {'role_speed': 200,
                'using_emblem': {'emblem_id': 0, 'refine': 0, 'level': 0},
                'teamList': team_list, 'heroList': hero_list}

    def handle(self, conn, opcode, body):
        schema_entry = SCHEMA.get(str(opcode)) or {}
        req_schema = schema_entry.get('c', [])
        buf = Buf(body)
        try:
            req = read_fields(buf, req_schema) if req_schema else {}
        except Exception as e:
            log('opcode %d request parse failed: %r' % (opcode, e))
            req = {}
        log('<- %d %r' % (opcode, {k: v for k, v in list(req.items())[:6]}))

        if opcode == 2011:                       # 登录
            self.account = str(req.get('keyId') or '')
            log('login account=%s' % self.account)
            self.reply(conn, 2011, {'result': 0})
            # 官方流程：登录成功后由服务端【主动推送】2002 区服列表，
            # 客户端 onLogin 成功分支不发 2002 请求，只等推送。
            return self.reply(conn, 2002, {'platformList': [
                {'serverId': SERVER_ID, 'serverName': SERVER_NAME, 'status': 1}]})
        if opcode == 2002:                       # 区服列表
            return self.reply(conn, 2002, {'platformList': [
                {'serverId': SERVER_ID, 'serverName': SERVER_NAME, 'status': 1}]})
        if opcode == 2003:                       # 选区 → 指回本机网关
            return self.reply(conn, 2003, {'result': 0, 'accountId': self.account or '123',
                                           'md5': 'local-' + str(int(time.time())),
                                           'ip': GATE[0], 'port': GATE[1],
                                           'platformId': PLATFORM_ID})
        if opcode == 2010:                       # 上次登录记录
            return self.reply(conn, 2010, {'loginLogList': []})
        if opcode == 3001:                       # 网关登录
            self.account = str(req.get('accountId') or self.account or '123')
            role = get_role(self.account)
            if not role:
                # 与官方一致：无角色回 -52，客户端弹出建角面板（选性别/起名）
                log('gate login no-role account=%s -> create panel' % self.account)
                return self.reply(conn, 3001, {'result': -52})
            log('gate login ok account=%s role=%r' % (self.account, role.get('name')))
            self.reply(conn, 3001, {'result': 0})
            return self.reply(conn, 3003, {})          # 就绪推送
        if opcode == 3002:                       # 建角
            name = str(req.get('name') or '训练师')[:16]
            face = int(req.get('face_id') or 1)
            role = upsert_role(self.account or '123',
                               {'name': name, 'face_id': face, 'faceID': face,
                                'init_faceID': face, 'lev': 1})
            log('role created: %r (face %d) for %s' % (name, face, self.account))
            self.reply(conn, 3002, {'result': 0})
            return self.reply(conn, 3003, {})
        if opcode == 3004:                       # 进游戏 → roleInfo
            role = get_role(self.account or '123') or {}
            log('enter game account=%s role=%r' % (self.account, role.get('name')))
            self.reply(conn, 3004, {'roleInfo': {
                'roleId': role.get('roleId', 100001),
                'name': role.get('name', '训练师'),
                'lev': role.get('lev', 1),
                'energy': role.get('energy', 999),
                'gold': role.get('gold', 1000000),
                'coin': role.get('coin', 10000),
                'faceID': role.get('faceID', 1),
                'init_faceID': role.get('init_faceID', 1)}})
            # 官方流程：进游戏后服务端主动推送副本初始化与新手引导列表。
            # GuideModel 等三个来源（ROLE_INIT/DUNGEON_INIT/GUIDE_LSIT）到齐后
            # 才会派发 NET_INIT_OK 并启动新手引导（领 starter 宠物等）。
            self.reply(conn, 14001, {'type': 0, 'dungeon_list': []})
            self.reply(conn, 11000, self._pet_package(self.account or '123'))   # PET_GET_ALL_INFO
            return self.reply(conn, 4009, {'guideList': role.get('guides_done', [])})
        if opcode == 11000:                      # 宠物全量信息（客户端请求）
            return self.reply(conn, 11000, self._pet_package(self.account or '123'))
        if opcode == 11002:                      # 上阵/换阵（set_team → team_hero）
            team = [{'pos': int(t.get('pos', 0)), 'uid': int(t.get('uid', 0))}
                    for t in (req.get('team_list') or [])]
            upsert_role(self.account or '123', {'team': team})
            log('team updated: %r' % team)
            return self.reply(conn, 11002, {'result': 0,
                                            'team_list': [{'pos1': t['pos'], 'pos2': 0,
                                                           'uid': t['uid'], 'eqm_list': []}
                                                          for t in team]})
        if opcode in (11984, 11985):             # 探索手册（本地扩展协议，data=JSON 字符串）
            return self.reply(conn, opcode, {'result': 0,
                                             'data': '{"tracks":[],"nextRequestId":1}'})
        if opcode == 14001:                      # 副本初始化（客户端请求/服务端推送同号）
            return self.reply(conn, 14001, {'type': int(req.get('type') or 0),
                                            'dungeon_list': []})
        if opcode == 14002:                      # 副本战斗开始 → 下发完整蓝方阵容
            return self.reply(conn, 14002, {'result': 0,
                                            'dungeonId': int(req.get('dungeonId') or 0),
                                            'my_battle_info': self._battle_info(self.account or '123')})
        if opcode == 14003:                      # 副本战斗结束（发奖励）
            return self.reply(conn, 14003, {'result': 0,
                                            'dungeonId': int(req.get('dungeonId') or 0),
                                            'base_reward': [], 'extra_reward': [],
                                            'coin_reward': [], 'new_team_list': []})
        if opcode == 4008:                       # 新手引导完成上报（无响应 schema）
            gid = int(req.get('guideId') or 0)
            role = get_role(self.account or '123')
            if role is not None and gid:
                done = role.setdefault('guides_done', [])
                if gid not in done:
                    done.append(gid)
                    upsert_role(self.account or '123', {'guides_done': done})
                log('guide finished id=%d (done=%r)' % (gid, done))
            return None                           # c-only 消息，不应答
        if opcode == 3009:                       # 心跳
            return self.reply(conn, 3009, {})
        # 通用：有响应 schema 就按默认值应答
        if schema_entry.get('s'):
            ov = {'result': 0} if any(f[0] == 'result' for f in schema_entry['s']) else {}
            return self.reply(conn, opcode, ov, schema_entry['s'])
        log('   (no response schema, silent)')

def serve(conn, peer):
    """TLS 连接 → WS 握手 → 消息循环（由 mbserver 的 ws_client 调用）。"""
    headers = ws_handshake(conn)
    log('ws session from %s (cookie=%s)' % (
        peer, (headers.get('cookie') or '')[:48]))
    sess = GameSession(peer)
    try:
        while True:
            op, payload = ws_read_frame(conn)
            if op != 0x2:                        # 只处理二进制帧
                continue
            if len(payload) < 7:
                log('short packet %d B' % len(payload)); continue
            total, opcode, stamp = struct.unpack('>IHB', payload[:7])
            if total < 7 or total > len(payload) + 0:
                log('bad packet length %d (payload %d)' % (total, len(payload))); continue
            body = payload[7:total]
            sess.handle(conn, opcode, body)
    except (ConnectionError, OSError) as e:
        log('ws session end: %r' % e)
    finally:
        try: conn.close()
        except Exception: pass
