import logging
logging.disable(logging.CRITICAL)
from androguard.core.apk import APK
a = APK('../doubao_pet_1.1.4.apk')
ar = a.get_android_resources()
p = ar.get_packages_names()[0]
res = ar.get_string_resources(p)
for k, v in res.items():
    print(repr(k), '=', repr(v))
