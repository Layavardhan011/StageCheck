import sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from common import *


def approved(ctx):
    manifest = ctx.root / 'RWA/start/START_MANIFEST.md'
    rows = re.findall(r'^\| `([^`]+)` \|.*`([0-9a-f]{64})` \|$', ctx.read(manifest).decode(), re.M)
    return {str((manifest.parent / path).resolve()): sha for path, sha in rows}


def check(ctx, value):
    data = claims(ctx)
    permitted_approved = approved(ctx)
    candidates = [(p, '') for p in ctx.run['changed_paths'] + ctx.run.get('read_paths', [])]
    for c in data['claims']:
        for cite in c['citations']:
            if cite['type'] in ('document', 'file'):
                candidates.append((cite['path'], c['id']))
                if cite.get('approved') and permitted_approved.get(str(Path(cite['path']).resolve())) != cite['sha256']:
                    value['defects'].append(ctx.defect('scope.draft_approved', 'checks/scope_paths.py', ctx.run['claims'], c['id'],evidence_key=cite['path']))
            elif cite['type'] == 'command':
                candidates += [(cite['record'], c['id']), (cite['cwd'], c['id'])]
    for path, claim_id in sorted(set(candidates)):
        if not ctx.permitted(path):
            value['defects'].append(ctx.defect('scope.excluded', 'checks/scope_paths.py', ctx.run['claims'], claim_id,evidence_key=path))
    if ctx.run.get('response'):
        return
    repo = canonical(ctx.run['repo'])
    surfaces = {str(Path(p).parent.relative_to(repo)) for p in ctx.run['changed_paths']
                if below(Path(p).resolve(), repo)}
    if len(surfaces) > 1:
        # Wider boundaries are owner inputs, never claims-file declarations.
        wider = ctx.run.get('wider_scope')
        if not wider:
            value['defects'].append(ctx.defect('scope.package_span', 'checks/scope_paths.py', ctx.run['claims']))
        else:
            from citations import validate_citation
            if wider['type'] != 'document' or not (wider['path'] == ctx.bind['Execution plan']['path'] or
                    wider['path'] == ctx.bind['Owner grant ledger (§9)']['path']):
                raise ToolError('wider scope must cite the bound Plan or grant ledger')
            if validate_citation(ctx, wider) or not all(any(below(Path(p).resolve(), canonical(s)) for s in ctx.run['wider_surfaces']) for p in ctx.run['changed_paths']):
                raise ToolError('wider boundary does not resolve')


if __name__ == '__main__':
    sys.exit(main_check('scope_paths', check))
