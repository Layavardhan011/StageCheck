import sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from common import *


def findings(path, text):
    found = []
    denied = re.fullmatch(r'(?:\.env(?:\..*)?|.*\.(?:pem|key|p12|pfx)|credentials(?:\.json)?|keystore(?:\.json)?|id_rsa|id_ed25519)', Path(path).name, re.I)
    if denied:
        found.append(('secret.filename',1))
    for line, content in enumerate(text.splitlines(),1):
        if re.search(r'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----',content):
            found.append(('secret.pem',line))
        # Hash-valued identifiers are explicitly excluded. A key assignment needs
        # a credential name AND a non-placeholder value, not a bare digest.
        assignment = re.search(r'(?i)["\']?\b(?:api[_-]?key|private[_-]?key|secret[_-]?key|password|access[_-]?token)\b["\']?\s*[:=]\s*["\']?([^\s,"\'}]+)',content)
        if assignment and assignment[1].lower() not in ('null','none','unknown','unset','example','placeholder','changeme') and not assignment[1].startswith(('$','<')):
            found.append(('secret.assignment',line))
    if re.search(r'"(?:crypto|Crypto)"\s*:',text) and re.search(r'"(?:ciphertext|kdfparams|cipherparams)"\s*:',text):
        found.append(('secret.keystore',1))
    return sorted(set(found))


def check(ctx, value):
    paths = list(ctx.run['changed_paths'])
    if ctx.run.get('response'):
        paths += [ctx.run['report'],ctx.run['claims']]
        # The complete claims JSON includes every quote, including escaped text.
        # Scan decoded quote strings as well so line breaks cannot hide PEMs.
        data=claims(ctx)
        for c in data['claims']:
            for index,cite in enumerate(c['citations']):
                for cid,line in findings(cite.get('path','quote.txt'),cite.get('quote','')):
                    d=ctx.defect(cid,'checks/secrets.py',ctx.run['run_path'],
                        evidence_key=['quote',c['id'],index,line]);value['defects'].append(d)
    for path in paths:
        p = Path(path)
        if not p.is_file():
            continue
        text = ctx.read(p).decode('utf-8','replace')
        for cid, line in findings(path,text):
            # Never quote a secret into evidence or a generator report. Cite the
            # owner-input run snapshot and its changed-path identity instead.
            defect=ctx.defect(cid,'checks/secrets.py',ctx.run['run_path'],
                claim_id=str(p), lines=[1,1],evidence_key=[str(p),line])
            defect['location']={'path':str(p),'lines':[line,line]}
            value['defects'].append(defect)


if __name__ == '__main__':
    sys.exit(main_check('secrets', check))
