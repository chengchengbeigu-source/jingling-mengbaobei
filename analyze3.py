import re
html = open('launch_page.html', encoding='utf-8', errors='replace').read()
# all script blocks (inline) short summary: find cocos loading
for kw in ['main.js','game.js','cocos','cocos2d','settings.js','project','js-list','loadScript','document.write','quickSdk.init','quicksdk']:
    idxs = [m.start() for m in re.finditer(kw, html, re.I)][:3]
    for i in idxs:
        seg = html[max(0,i-150):i+250].replace('\n',' ')
        print('KW[%s] @%d: %s' % (kw, i, seg[:380]))
        print()
