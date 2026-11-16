import socket, ssl, hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes
host = 'mcbtc.cn'
ctx = ssl.create_default_context()
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
s = socket.create_connection((host, 20310), timeout=8)
ss = ctx.wrap_socket(s, server_hostname=host)
der = ss.getpeercert(True)
cert = x509.load_der_x509_certificate(der)
print('subject:', cert.subject.rfc4514_string())
print('issuer:', cert.issuer.rfc4514_string())
print('notBefore:', cert.not_valid_before_utc)
print('notAfter:', cert.not_valid_after_utc)
try:
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    print('SAN:', san.value.get_values_for_type(x509.DNSName))
except Exception:
    print('SAN: none')
print('leaf cert SHA256:', cert.fingerprint(hashes.SHA256()).hex())
ss.close()

# verify leaf is signed by bundled CA
ca_der = open('apk_ext/res/yo.der','rb').read()
ca = x509.load_der_x509_certificate(ca_der)
from cryptography.hazmat.primitives.asymmetric import padding
try:
    ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
    print('LEAF IS SIGNED BY BUNDLED CA: YES')
except Exception as e:
    print('LEAF IS SIGNED BY BUNDLED CA: NO -', type(e).__name__)
