#!/usr/bin/env python3
"""Rebuild the encrypted data.enc from an ArtifactData export dir (out_dir/stmts/*.json, out_dir/reports/*.json).
Usage: INCOME_PW=<password> python3 tools/sync.py <export_dir>   -> prints CHANGED / UNCHANGED / NO_DATA"""
import json, sys, os, glob, datetime, hashlib, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
src = sys.argv[1]; pw = os.environ.get('INCOME_PW')
if not pw: print('ERROR: INCOME_PW not set'); sys.exit(2)
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def load(col):
    out = []
    for f in sorted(glob.glob(os.path.join(src, col, '*.json'))):
        d = json.load(open(f, encoding='utf-8'))
        if col == 'reports': d = dict(d, id=os.path.basename(f)[:-5])
        out.append(d)
    return out
stmts = [s for s in load('stmts') if s.get('br') and s.get('month')]
reps = load('reports')
if not stmts: print('NO_DATA'); sys.exit(1)
canon = lambda l: sorted(l, key=lambda x: json.dumps(x, sort_keys=True, ensure_ascii=False))
h = hashlib.sha256((pw + json.dumps({'s': canon(stmts), 'r': canon(reps)}, sort_keys=True, ensure_ascii=False)).encode()).hexdigest()
hp = os.path.join(root, 'data.hash')
if os.path.exists(hp) and open(hp).read().strip() == h: print('UNCHANGED'); sys.exit(0)
now = datetime.datetime.utcnow() + datetime.timedelta(hours=3)
pt = json.dumps({'stmts': stmts, 'reports': reps, 'updated': now.strftime('%d/%m/%Y')}, ensure_ascii=False).encode()
salt, iv, it = os.urandom(16), os.urandom(12), 250000
key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=it).derive(pw.encode())
ct = AESGCM(key).encrypt(iv, pt, None)
e = lambda b: base64.b64encode(b).decode()
json.dump({'v': 1, 'iter': it, 'salt': e(salt), 'iv': e(iv), 'ct': e(ct)}, open(os.path.join(root, 'data.enc'), 'w'))
open(hp, 'w').write(h)
print('CHANGED', len(stmts), len(reps))
