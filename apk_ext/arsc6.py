import logging
logging.disable(logging.CRITICAL)
from androguard.core.apk import APK
a = APK('../doubao_pet_1.1.4.apk')
ar = a.get_android_resources()
p = 'com.localfirst.mb'
names = ['apk_signer_sha256','app_name','choose_line','device_pending','device_revoked',
         'enter_game','exit_game','invalid_app_signature','line_mobile','line_telecom',
         'line_unicom','load_failed','navigation_blocked','retry','webview_outdated']
for n in names:
    try:
        v = ar.get_string(p, n)
    except Exception as e:
        v = 'ERR %r' % e
    print(n, '=', repr(v))
