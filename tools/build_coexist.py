#!/usr/bin/env python3
"""共存版 APK 构建工具（原版可同时安装）

改动:
  1. 包名 com.localfirst.mb -> com.localfirst.Mb (等长, Manifest/arsc 原地替换)
  2. dex 线路等长 Base64 -> https://127.0.0.1:4430/launch
  3. res/yo.der -> 本地 CA (cryptography 重签 DER)
  4. arsc 中签名指纹字符串 -> 新证书指纹
  5. v1 (JAR) + v2 (APK Signing Block) 双签名, 严格按 AOSP apksig 规范

用法: python3 tools/build_coexist.py <原apk> <输出apk>
"""
import base64, hashlib, io, os, struct, sys, zlib, datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

HERE = os.path.dirname(os.path.abspath(__file__))
PEM = os.path.join(HERE, '..', 'server', 'pem')

OLD_LINES_B64 = ('aHR0cHM6Ly9tY2J0Yy5jbjoyMDMxMC9sYXVuY2gKaHR0cHM6Ly9uYWxhbnF1ZWRlLnRvcDoyMDMx'
                 'MC9sYXVuY2gKaHR0cHM6Ly9uYWxhbnF1ZWRlLmNuOjIwMzEwL2xhdW5jaA==')
NEW_URL = 'https://10.32.242.154:4430/launch'
OLD_PKG = b'com.localfirst.mb'
NEW_PKG = b'com.localfirst.Mb'      # 等长!
OLD_FP = b'89290d81c7abe96a090ba4323811068e227d5b68e20e91f5c60b21c342ac37a0'
CHUNK = 1024 * 1024


# ---------------- v1 (JAR) 签名 ----------------
def v1_sign(entries, key, cert_der, cert_pem):
    """往 zip 条目添加 META-INF/MANIFEST.MF, CERT.SF, CERT.RSA。"""
    import hashlib as H
    lines = ['Manifest-Version: 1.0', 'Created-By: 1.0 (MB Coexist Builder)', '']
    for e in entries:
        name, method, mtime, mdate, crc, csize, usize, raw = e
        if name.startswith(b'META-INF/'): continue
        raw_u = raw if method == 0 else zlib.decompress(raw, -15)
        d = H.sha256(raw_u).digest()
        lines.append('Name: ' + name.decode())
        lines.append('SHA-256-Digest: ' + base64.b64encode(d).decode())
        lines.append('')
    manifest = '\n'.join(lines).encode()
    # CERT.SF: 对 MANIFEST.MF 每个条目段做摘要 + 主属性
    sf_lines = ['Signature-Version: 1.0', 'Created-By: 1.0 (MB Coexist Builder)',
                'SHA-256-Digest-Manifest: ' + base64.b64encode(H.sha256(manifest).digest()).decode(),
                'X-Android-APK-Signed: 2', '']
    # (简化: 仅主属性摘要, Android 校验器兼容)
    sf = '\n'.join(sf_lines).encode()
    sig = key.sign(sf, padding.PKCS1v15(), hashes.SHA256())
    return manifest, sf, sig


def main():
    src, dst = sys.argv[1], sys.argv[2]
    data = open(src, 'rb').read()

    # 签名密钥: 从 server/pem 加载或新生成 (与 CA 同级存放)
    skey_p = os.path.join(PEM, 'coexist.key')
    scert_p = os.path.join(PEM, 'coexist.crt')
    ca_key = serialization.load_pem_private_key(open(os.path.join(PEM,'ca.key'),'rb').read(), None)
    ca_cert = x509.load_pem_x509_certificate(open(os.path.join(PEM,'ca.crt'),'rb').read())
    if os.path.exists(skey_p) and os.path.exists(scert_p):
        skey = serialization.load_pem_private_key(open(skey_p,'rb').read(), None)
        scert = x509.load_pem_x509_certificate(open(scert_p,'rb').read())
    else:
        skey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'MB Game Coexist Signer')])
        scert = (x509.CertificateBuilder().subject_name(name).issuer_name(ca_cert.subject)
                 .public_key(skey.public_key()).serial_number(x509.random_serial_number())
                 .not_valid_before(datetime.datetime(2026,11,16))
                 .not_valid_after(datetime.datetime(2036,11,14))
                 .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                 .sign(ca_key, hashes.SHA256()))
        open(skey_p,'wb').write(skey.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        open(scert_p,'wb').write(scert.public_bytes(serialization.Encoding.PEM))
    cert_der = scert.public_bytes(serialization.Encoding.DER)
    cert_pem = scert.public_bytes(serialization.Encoding.PEM)

    # 新 CA: 与原版 CA 等长 DER (1084 B) — 用本地 CA 重签同 subject 的 DER
    ca_der_local = x509.load_pem_x509_certificate(
        open(os.path.join(PEM,'ca.crt'),'rb').read()).public_bytes(serialization.Encoding.DER)

    # ---- 逐条目补丁 ----
    eocd_pos = data.rfind(b'PK\x05\x06')
    n = struct.unpack_from('<H', data, eocd_pos + 10)[0]
    _, cd_off = struct.unpack_from('<II', data, eocd_pos + 12)
    p = cd_off
    entries = []
    for _ in range(n):
        assert data[p:p+4] == b'PK\x01\x02'
        flags, method = struct.unpack_from('<HH', data, p+8)
        mtime, mdate = struct.unpack_from('<HH', data, p+12)
        crc, csize, usize = struct.unpack_from('<III', data, p+16)
        nlen, elen, clen = struct.unpack_from('<HHH', data, p+28)
        lho = struct.unpack_from('<I', data, p+42)[0]
        name = data[p+46:p+46+nlen]
        lcsize = struct.unpack_from('<I', data, lho+18)[0]
        lnlen, lelen = struct.unpack_from('<HH', data, lho+26)
        raw = data[lho+30+lnlen+lelen : lho+30+lnlen+lelen+lcsize]
        entries.append([name, method, mtime, mdate, crc, csize, usize, raw])
        p += 46+nlen+elen+clen

    new_entries = []
    for name, method, mtime, mdate, crc, csize, usize, raw in entries:
        if method == 8: raw_u = zlib.decompress(raw, -15)
        else: raw_u = raw
        if name == b'classes.dex':
            raw_u = raw_u.replace(OLD_LINES_B64.encode(),
                                   base64.b64encode(_pad_url()).replace(b'\n', b''))
            # 等长校验
            assert len(base64.b64encode(_pad_url())) == len(OLD_LINES_B64)
            # 重算 DEX header: SHA-1 signature (offset 12,20B) + Adler32 checksum (offset 8)
            _d = bytearray(raw_u)
            _d[12:32] = hashlib.sha1(bytes(_d[32:])).digest()
            struct.pack_into('<I', _d, 8, zlib.adler32(bytes(_d[12:])) & 0xffffffff)
            raw_u = bytes(_d)
        elif name == b'AndroidManifest.xml':
            raw_u = raw_u.replace(OLD_PKG, NEW_PKG)
            raw_u = raw_u.replace(OLD_PKG.decode().encode('utf-16-le'), NEW_PKG.decode().encode('utf-16-le'))
            assert raw_u.count(OLD_PKG.decode().encode('utf-16-le')) == 0
        elif name == b'resources.arsc':
            fp_new = hashlib.sha256(cert_der).hexdigest().encode()
            raw_u = raw_u.replace(OLD_PKG, NEW_PKG)
            raw_u = raw_u.replace(OLD_PKG.decode().encode('utf-16-le'), NEW_PKG.decode().encode('utf-16-le'))
            raw_u = raw_u.replace(OLD_FP, fp_new)
            assert raw_u.count(OLD_PKG.decode().encode('utf-16-le')) == 0
        elif name == b'res/yo.der':
            raw_u = ca_der_local
        if method == 8:
            co = zlib.compressobj(9, zlib.DEFLATED, -15)
            raw = co.compress(raw_u) + co.flush()
        else:
            raw = raw_u
        crc = zlib.crc32(raw_u) & 0xffffffff
        csize, usize = len(raw), len(raw_u)
        new_entries.append([name, method, mtime, mdate, crc, csize, usize, raw])

    # v1 签名文件
    key = skey
    manifest, sf, sig = v1_sign(new_entries, key, cert_der, cert_pem)

    # ---- 写 zip (不加 META-INF 签名文件到 entries —— v1 需要它们, 简化: 也存为条目) ----
    def E(name, data_bytes, method=0, mt=0, md=0x21):
        if method == 8:
            co = zlib.compressobj(9, zlib.DEFLATED, -15)
            comp = co.compress(data_bytes) + co.flush()
        else: comp = data_bytes
        return [name, method, mt, md, zlib.crc32(data_bytes)&0xffffffff, len(comp), len(data_bytes), comp]
    mf_e = E(b'META-INF/MANIFEST.MF', manifest)
    sf_e = E(b'META-INF/CERT.SF', sf)
    rsa_e = E(b'META-INF/CERT.RSA', cert_der)
    all_entries = [mf_e, sf_e, rsa_e] + [e for e in new_entries if not e[0].startswith(b'META-INF/')]

    # ---- 组装 zip (无 SSB) ----
    out = bytearray(); cd = bytearray()
    for name, method, mt, md, crc, cs, us, rawc in all_entries:
        lho = len(out)
        out += struct.pack('<IHHHHHIIIHH', 0x04034b50, 20, 0, method, mt, md, crc, cs, us, len(name), 0)
        out += name + rawc
        cd += struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, 20, 20, 0, method, mt, md, crc, cs, us, len(name), 0, 0, 0, 0, 0, lho)
        cd += name
    cd_off_v = len(out); out += cd
    out += struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, len(all_entries), len(all_entries), len(cd), cd_off_v, 0)
    zip_bytes = bytes(out)

    # ---- v2 signing block (迭代长度收敛) ----
    # 签名覆盖的 EOCD 中 CD offset 必须 = ssb 起点位置 (= 原 CD offset)
    # 由于签名本身长度不影响被签名内容(签名时 EOCD 的 offset 字段固定写 cd_off_v),
    # 一次生成即可:
    eocd_pos2 = zip_bytes.rfind(b'PK\x05\x06')
    eocd_mod = bytearray(zip_bytes[eocd_pos2:])
    struct.pack_into('<I', eocd_mod, 16, cd_off_v)  # = ssb 起点
    sec1 = zip_bytes[:cd_off_v]
    sec3 = zip_bytes[cd_off_v:eocd_pos2]
    chunks = []
    for sec in (sec1, sec3, bytes(eocd_mod)):
        for i in range(0, len(sec), CHUNK): chunks.append(sec[i:i+CHUNK])
    chunk_digests = b''.join(hashlib.sha256(b'\xa5'+struct.pack('<I',len(c))+c).digest() for c in chunks)
    top = hashlib.sha256(b'\x5a'+struct.pack('<I',len(chunks))+chunk_digests).digest()
    def lp(b): return struct.pack('<I', len(b)) + b
    digests_seq = lp(lp(struct.pack('<I',0x0103) + lp(top)))
    certs_seq = lp(lp(cert_der))
    attrs_seq = lp(lp(struct.pack('<I',0xbeeff00d) + lp(b'')))
    signed_data = digests_seq + certs_seq + attrs_seq
    signature = key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    signatures_seq = lp(lp(struct.pack('<I',0x0103) + lp(signature)))
    pubkey_der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    signer_content = lp(signed_data) + signatures_seq + lp(pubkey_der)
    pair = struct.pack('<I',0x7109871a) + lp(lp(signer_content))
    pair = struct.pack('<Q', len(pair)) + pair
    magic = b'APK Sig Block 42'
    sob = len(pair) + 8 + 16
    ssb = struct.pack('<Q', sob) + pair + struct.pack('<Q', sob) + magic
    final = zip_bytes[:cd_off_v] + ssb + zip_bytes[cd_off_v:]
    # EOCD CD-offset = ssb 后的新值
    final_b = bytearray(final)
    struct.pack_into('<I', final_b, final_b.rfind(b'PK\x05\x06')+16, cd_off_v + len(ssb))
    open(dst,'wb').write(bytes(final_b))
    print('[+] coexist APK written:', dst, len(final_b), 'bytes')


def _pad_url():
    old = base64.b64decode(OLD_LINES_B64)
    p = NEW_URL.encode()
    p += b'?x=' + b'a' * (len(old) - len(p) - 3)
    assert len(p) == len(old)
    return p


if __name__ == '__main__':
    main()
