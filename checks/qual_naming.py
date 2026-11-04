import sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from common import *


def check(ctx, value):
    repo = canonical(ctx.run['repo'])
    for path in ctx.run['changed_paths']:
        p = Path(path)
        if not p.is_file():
            continue
        text = ctx.read(p).decode('utf-8','replace')
        name = p.name
        if p.suffix == '.go':
            functions = re.findall(r'^func\s+(Test\w+)\s*\(',text,re.M)
            qual = re.fullmatch(r'qual_.+_test\.go',name)
            if any(f.startswith('TestQual') for f in functions) and not qual:
                value['defects'].append(ctx.defect('qual.test_name','checks/qual_naming.py',p))
            if name.startswith('qual_') and (not qual or not functions or any(not f.startswith('TestQual') for f in functions)):
                value['defects'].append(ctx.defect('qual.file_name','checks/qual_naming.py',p))
        if below(p.resolve(),repo) and (repo/'go.mod').exists() and name.startswith('qual_') and p.suffix in ('.py','.sh'):
            value['defects'].append(ctx.defect('qual.driver','checks/qual_naming.py',p))


if __name__ == '__main__':
    sys.exit(main_check('qual_naming', check))
