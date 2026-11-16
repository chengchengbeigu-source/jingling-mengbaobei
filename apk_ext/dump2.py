import logging
logging.disable(logging.CRITICAL)

from androguard.core.dex import DEX

d = DEX(open('classes.dex','rb').read())

# strings: in this version get_strings returns str directly
out = open('strings.txt','w')
ss = set()
for s in d.get_strings():
    if len(s) > 3:
        ss.add(s)
out.write('=== STRINGS (%d) ===\n' % len(ss))
for s in sorted(ss):
    out.write(repr(s) + '\n')
out.close()

# methods: attach DAD decompiler
from androguard.misc import AnalyzeDex
from androguard.decompiler.decompiler import DecompilerDAD
h, d2, dx = AnalyzeDex('classes.dex')
d2.set_decompiler(DecompilerDAD(d2, dx))
out2 = open('methods.txt','w')
for c in d2.get_classes():
    n = c.get_name()
    if n.startswith('Lcom/localfirst/mb/'):
        out2.write('## CLASS %s\n' % n)
        for f in c.get_fields():
            out2.write('  FIELD %s %s %s\n' % (f.get_access_flags_string(), f.get_descriptor(), f.get_name()))
        for m in c.get_methods():
            out2.write('--- METHOD %s %s %s\n' % (m.get_access_flags_string(), m.get_name(), m.get_descriptor()))
            try:
                src = m.get_source()
                if src:
                    out2.write(src + '\n')
            except Exception as e:
                out2.write('  [decompile error: %r]\n' % e)
out2.close()
print('done')
