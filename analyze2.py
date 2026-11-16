import re
html = open('launch_page.html', encoding='utf-8', errors='replace').read()
iframes = re.findall(r'<iframe[^>]+>', html)
for i in iframes: print('IFRAME:', i[:500])
# quicksdk config
qs = re.findall(r'(quickSdk\.[A-Za-z]+\([^)]{0,200}\))', html)
for q in qs[:10]: print('QS:', q)
# look for login/pay/api calls
apis = re.findall(r'[\"\']([^\"\']*(?:login|pay|createOrder|getUserInfo|init)[^\"\']{0,80})[\"\']', html, re.I)
print('apis:', sorted(set(apis))[:20])
# find the html head meta + title
t = re.search(r'<title>([^<]*)</title>', html)
print('title:', t.group(1) if t else None)
# search where pet05f appears
for m in re.finditer(r'pet05f', html):
    s = max(0, m.start()-200)
    print('CTX:', html[s:m.start()+300].replace('\n',' ')[:480])
    break
