#!/usr/bin/env python3
"""MB APK 补丁核心库（供 build_coexist.py / verify_apk.py 共用）

三个精确补丁：
  1. 包名字符串替换 —— 边界锚定（仅匹配「后随 NUL 终止符」的独立字符串），
     UTF-8 与 UTF-16LE 两种字符串池都处理。绝不动 com.localfirst.mb.MainActivity
     等全限定组件名（dex 里的类还是 com.localfirst.mb.*，改了必崩）。
  2. dex 线路常量替换 —— 字符串表重定位：在文件尾追加新 string_data_item，
     改写对应 string_id 的 offset，再修 header 的 SHA-1 + Adler32。
     新串长度任意，不垫垃圾字符。
  3. 资源指纹字符串替换 —— 64 位 hex 等长替换（新旧都是 64 字符）。
"""
import hashlib
import struct
import zlib

OLD_PKG = 'com.localfirst.mb'
NEW_PKG = 'com.localfirst.Mb'          # 等长 case 翻转，合法且与原包名不同
OLD_FP = '89290d81c7abe96a090ba4323811068e227d5b68e20e91f5c60b21c342ac37a0'
OLD_LINES_B64 = ('aHR0cHM6Ly9tY2J0Yy5jbjoyMDMxMC9sYXVuY2gKaHR0cHM6Ly9uYWxhbnF1ZWRlLnRvcDoyMDMx'
                 'MC9sYXVuY2gKaHR0cHM6Ly9uYWxhbnF1ZWRlLmNuOjIwMzEwL2xhdW5jaA==')


# ---------------------------------------------------------------- 包名替换
def _pkg_patterns(old, new):
    """返回 [(旧字节串, 新字节串), ...]，覆盖 UTF-8 与 UTF-16LE 两种存储形态。
    边界锚定：字符串池里每条字符串以 NUL 结尾，因此「old + NUL」只会命中
    独立的 old 串，不会命中 old 开头的更长串（如 old+'.MainActivity'）。"""
    pats = []
    o8, n8 = old.encode('utf-8'), new.encode('utf-8')
    pats.append((o8 + b'\x00', n8 + b'\x00'))
    o16, n16 = old.encode('utf-16-le'), new.encode('utf-16-le')
    pats.append((o16 + b'\x00\x00', n16 + b'\x00\x00'))
    return pats


def patch_pkg_string(data: bytes, old: str = OLD_PKG, new: str = NEW_PKG):
    """边界锚定替换包名字符串。返回 (新数据, 命中次数)。"""
    total = 0
    out = data
    for opat, npat in _pkg_patterns(old, new):
        c = out.count(opat)
        if c:
            out = out.replace(opat, npat)
            total += c
    return out, total


def patch_fp_string(data: bytes, old_fp: str, new_fp: str):
    """等长 hex 指纹替换（UTF-8 与 UTF-16LE 两种形态）。返回 (新数据, 命中次数)。"""
    total = 0
    out = data
    for enc in ('utf-8', 'utf-16-le'):
        o = old_fp.encode(enc)
        n = new_fp.encode(enc)
        assert len(o) == len(n)
        c = out.count(o)
        if c:
            out = out.replace(o, n)
            total += c
    return out, total


# ---------------------------------------------------------------- dex 补丁
def _uleb128(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _read_uleb128(data: bytes, off: int):
    result = 0
    shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7


def patch_dex_string(dex: bytes, old_str: str, new_str: str):
    """dex 字符串表重定位：追加新 string_data_item 并把引用它的 string_id
    指向新项，最后修 header SHA-1/Adler32。返回 (新 dex, 命中次数)。"""
    if dex[0:4] != b'dex\n':
        raise ValueError('not a dex file')
    str_ids_size = struct.unpack_from('<I', dex, 56)[0]
    str_ids_off = struct.unpack_from('<I', dex, 60)[0]

    new_payload = _uleb128(len(new_str)) + new_str.encode('utf-8') + b'\x00'
    hits = []
    for i in range(str_ids_size):
        item_off = struct.unpack_from('<I', dex, str_ids_off + 4 * i)[0]
        _, s = _read_uleb128(dex, item_off)          # utf16_size（纯 ASCII 时=字节数）
        end = dex.index(b'\x00', s)
        if dex[s:end] == old_str.encode('utf-8'):
            hits.append((i, item_off, end + 1))       # 连 NUL 一起记录旧项范围
    if len(hits) != 1:
        raise ValueError('expect exactly 1 dex string hit, got %d' % len(hits))
    idx, old_off, old_end = hits[0]

    # 追加到文件尾，4 字节对齐
    new_off = (len(dex) + 3) & ~3
    out = bytearray(dex + b'\x00' * (new_off - len(dex)) + new_payload)
    # 旧 string_data_item 已无引用 → 整段清零（防止旧线路常量残留在包内）
    out[old_off:old_end] = b'\x00' * (old_end - old_off)
    struct.pack_into('<I', out, str_ids_off + 4 * idx, new_off)
    # header: file_size(32), data_size(104) 同步扩容；SHA-1(12..32) 对 bytes[32:]；Adler32(8..12) 对 bytes[12:]
    struct.pack_into('<I', out, 32, len(out))
    old_data_size = struct.unpack_from('<I', dex, 104)[0]
    struct.pack_into('<I', out, 104, old_data_size + (len(out) - len(dex)))
    out[12:32] = hashlib.sha1(bytes(out[32:])).digest()
    struct.pack_into('<I', out, 8, zlib.adler32(bytes(out[12:])) & 0xFFFFFFFF)
    return bytes(out), 1


def dex_selfcheck(dex: bytes) -> bool:
    """校验 dex header 的 SHA-1 与 Adler32 是否自洽。"""
    return (hashlib.sha1(dex[32:]).digest() == dex[12:32]
            and (zlib.adler32(dex[12:]) & 0xFFFFFFFF) == struct.unpack_from('<I', dex, 8)[0])
