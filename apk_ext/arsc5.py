import logging
logging.disable(logging.CRITICAL)
from androguard.core.apk import APK
a = APK('../doubao_pet_1.1.4.apk')
ar = a.get_android_resources()
# string table entries are in table:string, id 0x0a; walk values via resource_values
import json
for rid in range(0x7f0a0000, 0x7f0a0010):
    try:
        name = ar.get_resource_xml_name(rid)
    except Exception:
        continue
    # resource_values / resource_keys to fetch
    try:
        keys = list(ar.resource_keys())
    except Exception as e:
        keys = []
    # direct value via get_string
    try:
        v = ar.get_string(rid)
    except Exception as e:
        v = 'ERR %r' % e
    print(name, '=', repr(v))
