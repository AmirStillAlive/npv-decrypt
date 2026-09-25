# -*- coding: utf-8 -*-
"""معادل پایتونی verify.mjs: هش خروجی هر فایل را چاپ می‌کند."""
import hashlib, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
import decrypt_npvt as D

src = sys.argv[1]
ok = fail = 0
for f in sorted(os.listdir(src)):
    if not f.lower().endswith('.npvt'):
        continue
    parts = D.decrypt_file(os.path.join(src, f))
    joined = '\n'.join(D.pretty(p) for p in parts)
    h = hashlib.sha256(joined.encode('utf-8')).hexdigest()
    if parts:
        ok += 1
    else:
        fail += 1
    print(f'{h}  {f}  ({len(parts)} blob)')
print(f'SUMMARY {ok} ok / {fail} fail')
