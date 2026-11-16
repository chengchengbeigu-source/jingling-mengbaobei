import logging, struct
logging.disable(logging.CRITICAL)
from androguard.core.apk import APK
a = APK('../doubao_pet_1.1.4.apk')
ar = a.get_android_resources()
# Resolve resource IDs referenced in code to names+values
ids = [0x7f0a0000,0x7f0a0001,0x7f0a0002,0x7f0a0003,0x7f0a0004,0x7f0a0005,0x7f0a0006,0x7f0a0007,
       0x7f0d0000,0x7f0d0001,0x7f090000,0x7f0b0005,0x7f080000]
for rid in ids:
    try:
        name = ar.get_resource_xml_name(rid)
    except Exception as e:
        name = 'err:%r' % e
    # try every getter
    vals = []
    for getter in ['get_resource_string','get_resource_integer','get_resource_bool','get_resource_id']:
        try:
            v = getattr(ar, getter)(rid)
            if v is not None:
                vals.append((getter, v))
        except Exception:
            pass
    print(hex(rid), name, vals)
