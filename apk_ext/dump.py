import logging
logging.disable(logging.CRITICAL)
from androguard.core.dex import DEX

d = DEX(open('classes.dex','rb').read())
out = open('strings.txt','w')
ss = set()
for s in d.get_strings():
    v = s.get_value()
    if len(v) > 3:
        ss.add(v)
out.write('=== STRINGS (%d) ===\n' % len(ss))
for s in sorted(ss):
    out.write(repr(s) + '\n')
out.close()

# decompile with DAD
from androguard.decompiler.decompiler import DecompilerDAD
dx = d  # use decompiler attached to DEX
decompiler = DecompilerDAD(d, dx)
out2 = open('methods.txt','w')
for c in d.get_classes():
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
                out2.write('  [decompile error: %s]\n' % e)
out2.close()
print('done')
