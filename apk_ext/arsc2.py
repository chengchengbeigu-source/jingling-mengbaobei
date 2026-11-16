import logging
logging.disable(logging.CRITICAL)
from androguard.core.apk import APK
a = APK('../doubao_pet_1.1.4.apk')
ar = a.get_android_resources()
res = ar.get_string_resources()  # try without args
if isinstance(res, dict):
    for k, v in sorted(res.items(), key=lambda kv: kv[0] if isinstance(kv[0], int) else 0):
        print(hex(k) if isinstance(k, int) else k, '=', repr(v))
else:
    print(type(res), repr(res)[:200])
