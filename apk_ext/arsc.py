import logging, struct
logging.disable(logging.CRITICAL)
from androguard.core.apk import APK
a = APK('../doubao_pet_1.1.4.apk')
ar = a.get_android_resources()
print('METHODS:', [m for m in dir(ar) if 'string' in m.lower() or 'resour' in m.lower()])
try:
    sr = ar.get_strings_resources()
    for pkg, data in sr.items():
        print('PKG:', pkg)
        if isinstance(data, dict):
            for k2, v2 in data.items():
                print(' ', k2, type(v2))
except Exception as e:
    import traceback; traceback.print_exc()
