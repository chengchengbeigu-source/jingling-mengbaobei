#!/usr/bin/env python3
"""共存包 APK 独立复核：结构、补丁、v2 签名、指纹一致性全部重验。

用法: python3 tools/verify_apk.py <coexist.apk> [pem目录=server/pem]
退出码 0 = 全部通过。
"""
import base64
import hashlib
import os
import struct
import sys
import zlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mbpatch  # noqa: E402

CHUNK = 1024 * 1024

NEW_B64 = base64.standard_b64encode(
    (('https://127.0.0.1:4430/launch\n') * 2 + 'https://127.0.0.1:4430/launch').encode()).decode()


def rd_lp(buf, off):
    n = struct.unpack_from('<I', buf, off)[0]
    return buf[off + 4: off + 4 + n], off + 4 + n


def read_zip(data):
    eocd = data.rfind(b'PK\x05\x06')
    n = struct.unpack_from('<H', data, eocd + 10)[0]
    cd_off = struct.unpack_from('<I', data, eocd + 16)[0]
    p, entries = cd_off, {}
    for _ in range(n):
        assert data[p:p + 4] == b'PK\x01\x02'
        method = struct.unpack_from('<H', data, p + 10)[0]
        nlen, elen, clen = struct.unpack_from('<HHH', data, p + 28)
        lho = struct.unpack_from('<I', data, p + 42)[0]
        name = data[p + 46:p + 46 + nlen]
        lcsize = struct.unpack_from('<I', data, lho + 18)[0]
        lnlen, lelen = struct.unpack_from('<HH', data, lho + 26)
        raw = data[lho + 30 + lnlen + lelen: lho + 30 + lnlen + lelen + lcsize]
        if method == 8:
            raw = zlib.decompress(raw, -15)
        entries[name] = raw
        if name == b'resources.arsc':
            assert method == 0, 'resources.arsc must be STORED'
            assert lho % 4 == 0, 'resources.arsc not 4-byte aligned (lho=%d)' % lho
        p += 46 + nlen + elen + clen
    return entries


def find_v2_block(data):
    """签名块插在中央目录之前：块尾 = CD 起点处（尾size8+magic16）。"""
    eocd = data.rfind(b'PK\x05\x06')
    cd_off = struct.unpack_from('<I', data, eocd + 16)[0]
    trailing = struct.unpack_from('<Q', data, cd_off - 24)[0]
    blk = data[cd_off - trailing - 8: cd_off]
    assert blk[-16:] == b'APK Sig Block 42', 'signing block magic mismatch'
    p = 8                                     # 跳过前导 size 字段
    while p < len(blk) - 24:
        plen = struct.unpack_from('<Q', blk, p)[0]
        pid = struct.unpack_from('<I', blk, p + 8)[0]
        if pid == 0x7109871a:
            return blk[p + 12: p + 8 + plen]
        p += 8 + plen
    raise AssertionError('no v2 signature block (id 0x7109871a)')


def main():
    apk = sys.argv[1]
    pem = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', 'server', 'pem')
    data = open(apk, 'rb').read()
    entries = read_zip(data)
    print('[ok] zip 结构 / resources.arsc STORED + 4 字节对齐')

    # --- manifest ---
    mf = entries[b'AndroidManifest.xml']
    new16 = mbpatch.NEW_PKG.encode('utf-16-le') + b'\x00\x00'
    old16 = mbpatch.OLD_PKG.encode('utf-16-le') + b'\x00\x00'
    assert new16 in mf, 'manifest 缺少新包名'
    assert old16 not in mf, 'manifest 仍含旧包名独立串'
    for comp in ('MainActivity', 'MbApplication'):
        want = ('com.localfirst.mb.' + comp).encode('utf-16-le')
        assert want in mf, 'manifest 组件名被误改: ' + comp
    print('[ok] manifest: applicationId=%s，组件全限定名保持 com.localfirst.mb.*' % mbpatch.NEW_PKG)

    # --- dex ---
    dex = entries[b'classes.dex']
    assert mbpatch.OLD_LINES_B64.encode() not in dex, 'dex 仍含旧线路常量'
    assert NEW_B64.encode() in dex, 'dex 缺少新线路常量'
    assert mbpatch.dex_selfcheck(dex), 'dex SHA-1/Adler32 不自洽'
    print('[ok] dex: 线路常量已重定位（127.0.0.1:4430），校验和自洽')

    # --- v2 签名块：取证书、验签 ---
    v2 = find_v2_block(data)
    signers, _ = rd_lp(v2, 0)
    signer, _ = rd_lp(signers, 0)
    signed_data, off = rd_lp(signer, 0)
    sigs_seq, _ = rd_lp(signer, off)
    sig_algo = struct.unpack_from('<I', sigs_seq, 4)[0]
    assert sig_algo == 0x0103, 'sig algo 0x%x' % sig_algo
    sig, _ = rd_lp(sigs_seq, 8)
    # signed_data = digests_seq + certs_seq + attrs_seq；certs 内容 = [cert_len:4][cert_der]
    _digests, off_dg = rd_lp(signed_data, 0)
    certs_seq, _ = rd_lp(signed_data, off_dg)
    first_cert_len = struct.unpack_from('<I', certs_seq, 0)[0]
    cert_der = certs_seq[4: 4 + first_cert_len]
    cert = x509.load_der_x509_certificate(cert_der)
    try:
        cert.public_key().verify(sig, signed_data, padding.PKCS1v15(), hashes.SHA256())
    except Exception as e:
        raise AssertionError('v2 signature INVALID: %r' % e)
    fp = hashlib.sha256(cert_der).hexdigest()
    print('[ok] v2 签名有效（RSA-SHA256, 0x0103），证书 CN=%s' % cert.subject.rfc4514_string())
    print('[ok] 签名证书指纹:', fp)

    # --- 内容摘要复核（签名覆盖的就是当前 APK 的字节）---
    dg_seq, _ = rd_lp(signed_data, 0)          # digests: lp( [algo:4][dlen:4][digest] )
    dg_content, _ = rd_lp(dg_seq, 0)
    assert struct.unpack_from('<I', dg_content, 0)[0] == 0x0103, 'digest algo mismatch'
    dlen = struct.unpack_from('<I', dg_content, 4)[0]
    digest_in = dg_content[8: 8 + dlen]
    eocd = data.rfind(b'PK\x05\x06')
    cd_off = struct.unpack_from('<I', data, eocd + 16)[0]
    trailing = struct.unpack_from('<Q', data, cd_off - 24)[0]
    bstart, bend = cd_off - trailing - 8, cd_off
    eocd_mod = bytearray(data[eocd:])
    struct.pack_into('<I', eocd_mod, 16, bstart)
    chunks = []
    for sec in (data[:bstart], data[bend:eocd], bytes(eocd_mod)):
        for i in range(0, len(sec), CHUNK):
            chunks.append(sec[i:i + CHUNK])
    chunk_dg = b''.join(hashlib.sha256(b'\xa5' + struct.pack('<I', len(c)) + c).digest()
                        for c in chunks)
    top = hashlib.sha256(b'\x5a' + struct.pack('<I', len(chunks)) + chunk_dg).digest()
    assert top == digest_in, 'v2 content digest MISMATCH'
    print('[ok] v2 内容摘要与 APK 字节一致（%d chunks）' % len(chunks))

    # --- arsc ---
    arsc = entries[b'resources.arsc']
    assert fp.encode() in arsc, 'arsc 未写入新指纹'
    assert mbpatch.OLD_FP.encode() not in arsc, 'arsc 仍含旧指纹'
    assert new16 in arsc, 'arsc 缺少新包名'
    print('[ok] arsc: 指纹与签名证书一致，包名已更新')

    # --- yo.der ---
    ca_pem = open(os.path.join(pem, 'ca.crt'), 'rb').read()
    ca_der = x509.load_pem_x509_certificate(ca_pem).public_bytes(Encoding.DER)
    assert entries[b'res/yo.der'] == ca_der, 'yo.der 与本地 CA 不一致'
    print('[ok] res/yo.der = 本地私有 CA')

    print('\n[PASS] 全部复核通过:', apk)


if __name__ == '__main__':
    main()
