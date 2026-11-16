#!/usr/bin/env python3
"""APK 原地补丁工具

1) res/yo.der → 本地 CA (zip 原始字节重写, 其余条目内容逐字节保留, 签名块不复存在亦无需)
2) DEX 线路 Base64 → https://127.0.0.1:4430/launch (等长替换, DEX 内偏移零变化)

用法: python3 patch_apk.py <原apk> <输出apk>
"""
import base64, struct, sys, zlib, os

OLD_LINES_B64 = ('aHR0cHM6Ly9tY2J0Yy5jbjoyMDMxMC9sYXVuY2gKaHR0cHM6Ly9uYWxhbnF1ZWRlLnRvcDoyMDMx'
                 'MC9sYXVuY2gKaHR0cHM6Ly9uYWxhbnF1ZWRlLmNuOjIwMzEwL2xhdW5jaA==')
NEW_URL = 'https://127.0.0.1:4430/launch'


def build_new_b64() -> str:
    old = base64.b64decode(OLD_LINES_B64)
    n = len(old)                       # 88
    payload = NEW_URL.encode()
    assert len(payload) <= n, 'URL too long'
    payload += b'?x=' + b'a' * (n - len(payload) - 3)
    assert len(payload) == n
    new = base64.b64encode(payload).decode()
    assert len(new) == len(OLD_LINES_B64)
    return new


def patch_dex(dex: bytes) -> bytes:
    old = OLD_LINES_B64.encode()
    new = build_new_b64().encode()
    cnt = dex.count(old)
    if cnt == 0:
        print('[!] dex: 未找到线路常量（可能已补丁）')
        return dex
    assert len(old) == len(new)
    print('[+] dex: 命中线路常量 x%d → 等长替换' % cnt)
    return dex.replace(old, new)


# ---------------- zip 解析 (标准 CD 布局) ----------------
def find_eocd(data: bytes) -> int:
    i = data.rfind(b'PK\x05\x06')
    assert i >= 0, 'no EOCD'
    return i


class Entry:
    __slots__ = ('name', 'method', 'mtime', 'mdate', 'crc', 'csize', 'usize', 'raw')

    def __init__(self, name, method, mtime, mdate, crc, csize, usize, raw):
        self.name, self.method = name, method
        self.mtime, self.mdate = mtime, mdate
        self.crc, self.csize, self.usize = crc, csize, usize
        self.raw = raw


def raw_entries(data: bytes):
    eocd = find_eocd(data)
    n = struct.unpack_from('<H', data, eocd + 10)[0]
    cd_size, cd_off = struct.unpack_from('<II', data, eocd + 12)
    p = cd_off
    for _ in range(n):
        assert data[p:p+4] == b'PK\x01\x02', 'bad CD sig'
        flags, method = struct.unpack_from('<HH', data, p + 8)
        assert flags & 0x8 == 0, 'data descriptor entries not supported'
        mtime, mdate = struct.unpack_from('<HH', data, p + 12)
        crc, csize, usize = struct.unpack_from('<III', data, p + 16)
        nlen, elen, clen = struct.unpack_from('<HHH', data, p + 28)
        lho = struct.unpack_from('<I', data, p + 42)[0]
        name = data[p+46:p+46+nlen]
        # local header 校验并定位数据
        assert data[lho:lho+4] == b'PK\x03\x04', 'bad LFH sig'
        lcsize = struct.unpack_from('<I', data, lho + 18)[0]
        lnlen, lelen = struct.unpack_from('<HH', data, lho + 26)
        data_off = lho + 30 + lnlen + lelen
        raw = data[data_off:data_off+lcsize]
        assert len(raw) == lcsize
        yield Entry(name, method, mtime, mdate, crc, lcsize,
                    struct.unpack_from('<I', data, lho + 22)[0], raw)
        p += 46 + nlen + elen + clen


def rebuild(entries) -> bytes:
    out = bytearray()
    cd = bytearray()
    for e in entries:
        lho = len(out)
        out += struct.pack('<IHHHHHIIIHH', 0x04034b50, 20, 0, e.method,
                           e.mtime, e.mdate, e.crc, e.csize, e.usize, len(e.name), 0)
        out += e.name + e.raw
        cd += struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, 20, 20, 0, e.method,
                          e.mtime, e.mdate, e.crc, e.csize, e.usize,
                          len(e.name), 0, 0, 0, 0, 0x81a40000, lho)
        cd += e.name
    cd_off = len(out)
    out += cd
    out += struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, len(entries), len(entries),
                       len(cd), cd_off, 0)
    return bytes(out)


def patch_apk(src: str, dst: str, new_ca_der: bytes):
    data = open(src, 'rb').read()
    new_entries = []
    n_dex = n_ca = 0
    for e in raw_entries(data):
        if e.name == b'res/yo.der':
            print('[+] zip: res/yo.der %d B → %d B (CA 替换)' % (e.usize, len(new_ca_der)))
            e.raw = new_ca_der
            e.method = 0
            e.crc = zlib.crc32(e.raw) & 0xffffffff
            e.csize = e.usize = len(e.raw)
            n_ca += 1
        elif e.name == b'classes.dex':
            dex = zlib.decompress(e.raw, -15) if e.method == 8 else e.raw
            patched = patch_dex(dex)
            if patched is not dex:
                n_dex += 1
                comp = zlib.compressobj(9, zlib.DEFLATED, -15)
                e.raw = comp.compress(patched) + comp.flush()
                e.crc = zlib.crc32(patched) & 0xffffffff
                e.csize, e.usize = len(e.raw), len(patched)
        new_entries.append(e)
    out = rebuild(new_entries)
    open(dst, 'wb').write(out)
    print('[+] 写出 %s (%d B, 原 %d B)' % (dst, len(out), len(data)))
    print('[i] dex补丁: %d, CA替换: %d' % (n_dex, n_ca))
    return n_dex, n_ca


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    ca = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           '../server/pem/ca.crt'), 'rb').read()
    patch_apk(sys.argv[1], sys.argv[2], ca)
