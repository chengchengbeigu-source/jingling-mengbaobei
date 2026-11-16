#!/usr/bin/env python3
"""生成本地私服证书三件套（幂等，已存在则跳过；--force 强制重生成）

  server/pem/ca.key       + ca.crt        私有根 CA（替代官方 "MB Game Private Root CA"）
  server/pem/server.key   + server.crt    本地 HTTPS/WSS 服务证书（SAN: 127.0.0.1/localhost/三官方域名）
  server/pem/coexist.key  + coexist.crt   共存包 v2 签名证书（由私有 CA 签发）

CI 环境不在此生成，而是用 gh secret 注入 *.key（base64 PEM），*.crt 已入库。
"""
import datetime
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
PEM = os.path.join(HERE, '..', 'server', 'pem')

OFFICIAL_DOMAINS = ['mcbtc.cn', 'nalanquede.top', 'nalanquede.cn']
# notBefore 提前半个月：避免设备时区/时钟偏差导致 "certificate is not yet valid"
NOW = datetime.datetime(2026, 11, 1)
TEN_YEARS = datetime.datetime(2036, 11, 1)


def _write(name, data):
    path = os.path.join(PEM, name)
    with open(path, 'wb') as f:
        f.write(data)
    os.chmod(path, 0o600)
    return path


def _load_key(name):
    return serialization.load_pem_private_key(open(os.path.join(PEM, name), 'rb').read(), None)


def _load_cert(name):
    return x509.load_pem_x509_certificate(open(os.path.join(PEM, name), 'rb').read())


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def gen_all(force=False):
    os.makedirs(PEM, exist_ok=True)
    have_all = all(os.path.exists(os.path.join(PEM, f)) for f in
                   ('ca.key', 'ca.crt', 'server.key', 'server.crt', 'coexist.key', 'coexist.crt'))
    if have_all and not force:
        print('[=] pem 已齐全，跳过生成（--force 可强制）')
        return

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_cert = (x509.CertificateBuilder()
               .subject_name(_name('MB Game Private Root CA'))
               .issuer_name(_name('MB Game Private Root CA'))
               .public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(NOW).not_valid_after(TEN_YEARS)
               .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                            content_commitment=False, key_encipherment=False,
                                            data_encipherment=False, key_agreement=False,
                                            encipher_only=False, decipher_only=False), critical=True)
               .sign(ca_key, hashes.SHA256()))

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    san = x509.SubjectAlternativeName(
        [x509.IPAddress(ipaddress_module('127.0.0.1')), x509.DNSName('localhost')]
        + [x509.DNSName(d) for d in OFFICIAL_DOMAINS])
    server_cert = (x509.CertificateBuilder()
                   .subject_name(_name('127.0.0.1'))
                   .issuer_name(ca_cert.subject)
                   .public_key(server_key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(NOW).not_valid_after(TEN_YEARS)
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(san, critical=False)
                   .sign(ca_key, hashes.SHA256()))

    coexist_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    coexist_cert = (x509.CertificateBuilder()
                    .subject_name(_name('MB Game Coexist Signer'))
                    .issuer_name(ca_cert.subject)
                    .public_key(coexist_key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(NOW).not_valid_after(TEN_YEARS)
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .sign(ca_key, hashes.SHA256()))

    for name, key in (('ca', ca_key), ('server', server_key), ('coexist', coexist_key)):
        _write(name + '.key', key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    for name, cert in (('ca', ca_cert), ('server', server_cert), ('coexist', coexist_cert)):
        _write(name + '.crt', cert.public_bytes(serialization.Encoding.PEM))
    print('[+] 证书已生成到', PEM)


def ipaddress_module(addr):
    import ipaddress
    return ipaddress.IPv4Address(addr)


if __name__ == '__main__':
    gen_all(force='--force' in sys.argv)
