import re
html = open('launch_page.html', encoding='utf-8', errors='replace').read()
# find the section around 188668 onwards: the real page head
print(html[188000:196000])
