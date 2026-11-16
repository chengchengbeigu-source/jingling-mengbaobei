#!/usr/bin/env python3
"""共存版 APK 构建工具 v2（原版与共存版可同时安装）

在官方原版 APK 基础上做四处精确补丁，再以本地私有 CA 重签 v2：
  1. classes.dex      线路常量（Base64 三行 URL）→ https://127.0.0.1:4430/launch ×3
                      （字符串表重定位，不垫垃圾字符；修 SHA-1/Adler32）
  2. AndroidManifest.xml  仅改 applicationId 字符串 com.localfirst.mb → com.localfirst.Mb
                      （边界锚定；组件全限定名 com.localfirst.mb.* 保持不变）
  3. resources.arsc   包名字符串 + 内置预期签名指纹 → 新签名证书指纹
  4. res/yo.der       内置私有 CA → 本地私有 CA（信任我们的 server 证书）

签名：仅 v2（APK Signing Block，0x7109871a / RSA-SHA256）。原版即 v2+v3 无 v1，
minSdk 24 全平台支持 v2，无需构造 v1。

用法: python3 tools/build_coexist.py <原apk> <输出apk>
前置: server/pem/ 下需有 ca/ca.crt、coexist.key/coexist.crt（tools/gen_certs.py 生成）
"""
import base64
import hashlib
import os
import struct
import sys
import zlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mbpatch  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
PEM = os.path.join(HERE, '..', 'server', 'pem')

NEW_LAUNCH_URL = 'https://127.0.0.1:4430/launch'
CHUNK = 1024 * 1024


# ---------------------------------------------------------------- pem 加载
def load_pem():
    need = ['ca.crt', 'coexist.key', 'coexist.crt']
    missing = [f for f in need if not os.path.exists(os.path.join(PEM, f))]
    if missing:
        raise SystemExit('[!] server/pem 缺少 %s —— 先运行 python3 tools/gen_certs.py'
                         '（CI 中用 gh secret 注入 *.key 后解包）' % missing)
    ca_cert = x509.load_pem_x509_certificate(open(os.path.join(PEM, 'ca.crt'), 'rb').read())
    skey = serialization.load_pem_private_key(open(os.path.join(PEM, 'coexist.key'), 'rb').read(), None)
    scert = x509.load_pem_x509_certificate(open(os.path.join(PEM, 'coexist.crt'), 'rb').read())
    return ca_cert, skey, scert


# ---------------------------------------------------------------- zip 读写
def parse_zip(data: bytes):
    eocd = data.rfind(b'PK\x05\x06')
    if eocd < 0:
        raise ValueError('EOCD not found')
    n = struct.unpack_from('<H', data, eocd + 10)[0]
    cd_off = struct.unpack_from('<I', data, eocd + 16)[0]
    p = cd_off
    entries = []
    for _ in range(n):
        assert data[p:p + 4] == b'PK\x01\x02', 'bad central directory'
        _ver, _vneed, flags, method = struct.unpack_from('<HHHH', data, p + 4)
        mtime, mdate = struct.unpack_from('<HH', data, p + 12)
        _crc, _cs, _us = struct.unpack_from('<III', data, p + 16)
        nlen, elen, clen = struct.unpack_from('<HHH', data, p + 28)
        lho = struct.unpack_from('<I', data, p + 42)[0]
        name = data[p + 46:p + 46 + nlen]
        lcsize = struct.unpack_from('<I', data, lho + 18)[0]
        lnlen, lelen = struct.unpack_from('<HH', data, lho + 26)
        raw = data[lho + 30 + lnlen + lelen: lho + 30 + lnlen + lelen + lcsize]
        if flags & 0x8:  # data descriptor：以 central directory 的值为准
            crc, cs, us = struct.unpack_from('<III', data, p + 16)
        else:
            crc, cs, us = struct.unpack_from('<III', data, lho + 14)
        entries.append({'name': name, 'method': method, 'mtime': mtime, 'mdate': mdate,
                        'crc': crc, 'csize': cs, 'usize': us, 'raw': raw})
        p += 46 + nlen + elen + clen
    return entries


def build_zip(entries):
    """全部 STORED + 4 字节对齐（resources.arsc 在 targetSdk 30+ 必须未压缩且 4 对齐）。"""
    out = bytearray()
    cd = bytearray()
    for e in entries:
        name, raw = e['name'], e['raw']
        while len(out) % 4:
            out += b'\x00'
        lho = len(out)
        crc = zlib.crc32(raw) & 0xFFFFFFFF
        out += struct.pack('<IHHHHHIIIHH', 0x04034b50, 20, 0, 0, e['mtime'], e['mdate'],
                           crc, len(raw), len(raw), len(name), 0)
        out += name + raw
        cd += struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, 20, 20, 0, 0, e['mtime'], e['mdate'],
                          crc, len(raw), len(raw), len(name), 0, 0, 0, 0, 0, lho)
        cd += name
    while len(out) % 4:
        out += b'\x00'
    cd_off = len(out)
    out += cd
    out += struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, len(entries), len(entries), len(cd), cd_off, 0)
    return bytes(out), cd_off


# ---------------------------------------------------------------- v2 签名块
def v2_sign(zip_bytes: bytes, cd_off: int, key, cert_der: bytes) -> bytes:
    """在 cd_off 处插入 APK Signing Block（覆盖 entries+CD+EOCD 的 SHA-256 分块摘要）。"""
    eocd_pos = zip_bytes.rfind(b'PK\x05\x06')
    eocd_mod = bytearray(zip_bytes[eocd_pos:])
    struct.pack_into('<I', eocd_mod, 16, cd_off)          # EOCD 的 CD offset 指向签名块起点
    sec1 = zip_bytes[:cd_off]
    sec3 = zip_bytes[cd_off:eocd_pos]
    chunks = []
    for sec in (sec1, sec3, bytes(eocd_mod)):
        for i in range(0, len(sec), CHUNK):
            chunks.append(sec[i:i + CHUNK])
    chunk_digests = b''.join(hashlib.sha256(b'\xa5' + struct.pack('<I', len(c)) + c).digest()
                             for c in chunks)
    top = hashlib.sha256(b'\x5a' + struct.pack('<I', len(chunks)) + chunk_digests).digest()

    def lp(b: bytes) -> bytes:
        return struct.pack('<I', len(b)) + b

    digests_seq = lp(lp(struct.pack('<I', 0x0103) + lp(top)))       # 0x0103 = RSA PKCS#1 v1.5 SHA-256
    certs_seq = lp(lp(cert_der))
    attrs_seq = lp(lp(struct.pack('<I', 0xbeeff00d) + lp(b'')))
    signed_data = digests_seq + certs_seq + attrs_seq
    signature = key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    signatures_seq = lp(lp(struct.pack('<I', 0x0103) + lp(signature)))
    pubkey_der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    signer = lp(signed_data) + signatures_seq + lp(pubkey_der)
    pair = struct.pack('<I', 0x7109871a) + lp(lp(signer))
    pair = struct.pack('<Q', len(pair)) + pair
    sob = len(pair) + 8 + 16
    ssb = struct.pack('<Q', sob) + pair + struct.pack('<Q', sob) + b'APK Sig Block 42'
    final = bytearray(zip_bytes[:cd_off] + ssb + zip_bytes[cd_off:])
    struct.pack_into('<I', final, final.rfind(b'PK\x05\x06') + 16, cd_off + len(ssb))
    return bytes(final)


# ---------------------------------------------------------------- 主流程
def main():
    src, dst = sys.argv[1], sys.argv[2]
    data = open(src, 'rb').read()
    ca_cert, skey, scert = load_pem()
    ca_der = ca_cert.public_bytes(serialization.Encoding.DER)
    cert_der = scert.public_bytes(serialization.Encoding.DER)
    new_fp = hashlib.sha256(cert_der).hexdigest()
    print('[*] 新签名证书指纹:', new_fp)

    entries = parse_zip(data)
    patched = {}
    for e in entries:
        name = e['name']
        raw = e['raw']
        if e['method'] == 8:
            raw = zlib.decompress(raw, -15)
        if name == b'classes.dex':
            new_b64 = base64.standard_b64encode(
                ((NEW_LAUNCH_URL + '\n') * 2 + NEW_LAUNCH_URL).encode()).decode()
            raw, n = mbpatch.patch_dex_string(raw, mbpatch.OLD_LINES_B64, new_b64)
            assert mbpatch.dex_selfcheck(raw), 'dex checksum self-check failed'
            patched[name] = '线路常量重定位 (%d), 新串 %d 字符' % (n, len(new_b64))
        elif name == b'AndroidManifest.xml':
            raw, n = mbpatch.patch_pkg_string(raw)
            assert n >= 1, 'manifest: package string not found'
            patched[name] = '包名边界锚定替换 %d 处（组件全限定名未动）' % n
        elif name == b'resources.arsc':
            raw, n1 = mbpatch.patch_pkg_string(raw)
            raw, n2 = mbpatch.patch_fp_string(raw, mbpatch.OLD_FP, new_fp)
            assert n2 >= 1, 'arsc: fingerprint string not found'
            patched[name] = '包名 %d 处 + 指纹 %d 处' % (n1, n2)
        elif name == b'res/yo.der':
            patched[name] = '内置 CA 替换 (%d → %d B)' % (len(raw), len(ca_der))
            raw = ca_der
        e['raw'] = raw
        e['method'] = 0

    for k, v in patched.items():
        print('    [patch] %-22s %s' % (k.decode(), v))

    zip_bytes, cd_off = build_zip(entries)
    final = v2_sign(zip_bytes, cd_off, skey, cert_der)
    open(dst, 'wb').write(final)
    print('[+] 共存包已写出:', dst, '(%d bytes, v2 signed)' % len(final))
    print('[!] 请用 tools/verify_apk.py 复核后再安装')


if __name__ == '__main__':
    main()
