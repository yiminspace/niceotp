#!/usr/bin/env python3
"""Collect public dependency license declarations and bundled notice files.

Run after cargo metadata has resolved Cargo.lock. No private paths are emitted.
"""
import hashlib
import json
from pathlib import Path
import subprocess

root=Path(__file__).resolve().parents[1]
metadata=json.loads(subprocess.check_output(['cargo','metadata','--locked','--format-version','1'],cwd=root))
packages=sorted((p for p in metadata['packages'] if p.get('source')),key=lambda p:(p['name'],p['version']))
texts={};listing=[];missing=[]
upstream=json.loads((root/'licenses/upstream-notices.json').read_text())
for p in packages:
    base=Path(p['manifest_path']).parent
    candidates=[]
    for path in base.iterdir():
        if path.name.lower().startswith(('license','licence','copying','notice','unlicense')):
            candidates.extend(path.rglob('*') if path.is_dir() else [path])
    if p.get('license_file'):candidates.append(base/p['license_file'])
    refs=[]
    for path in sorted(set(candidates)):
        if not path.is_file():continue
        try:text=path.read_text()
        except (UnicodeDecodeError,OSError):continue
        if len(text)>200000:continue
        key=hashlib.sha256(text.encode()).hexdigest()[:16]
        texts[key]=text
        refs.append(key)
    extra=upstream.get(p['name']+'@'+p['version'])
    if not refs and extra:
        text=extra['text'];key=hashlib.sha256(text.encode()).hexdigest()[:16];texts[key]=text;refs.append(key)
    label=f"{p['name']} {p['version']} — {p.get('license') or 'SEE LICENSE FILE'}"
    if extra:label+='\nUpstream notice: '+extra['source']
    listing.append(label+'\nSource: https://crates.io/crates/'+p['name']+'/'+p['version']+'\nBundled notice IDs: '+(', '.join(dict.fromkeys(refs)) or 'No standalone file in package; see source declaration')+'\n')
    if not refs:missing.append(p['name'])
header='''NiceOTP third-party dependency license inventory
Generated from Cargo.lock by scripts/licenses.py. Includes build and target-specific
packages as a conservative superset. Alternative license expressions are preserved;
this file does not relicense dependencies. Notice text is reproduced unchanged.
The NiceOTP project itself is licensed under Apache-2.0.

'''
output=header+'\n'.join(listing)+'\n\nBUNDLED LICENSE / NOTICE TEXTS\n'
for key,text in sorted(texts.items()):output+='\n'+('='*72)+'\nNOTICE '+key+'\n'+('='*72)+'\n'+text+'\n'
(root/'THIRD_PARTY_LICENSES.txt').write_text(output)
print(f'{len(packages)} packages; {len(texts)} unique notice files; {len(output)} characters')
if missing:print('Packages without standalone notices: '+', '.join(missing))
