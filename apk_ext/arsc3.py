import logging
logging.disable(logging.CRITICAL)
from androguard.core.apk import APK
a = APK('../doubao_pet_1.1.4.apk')
ar = a.get_android_resources()
p = ar.get_packages_names()[0]
print('package:', p)
res = ar.get_string_resources(p)
print(type(res))
if isinstance(res, dict):
    for k, v in res.items():
        kk = k
        if isinstance(kk, str):
            try: kk = int(kk.replace('@',''), 16)
            except: pass
        if isinstance(kk, int): kk = hex(kk)
        print(kk, '=', repr(v))
