import sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from common import *


def validate_citation(ctx, cite):
    kind = cite['type']
    if kind == 'command':
        try:
            record_raw = ctx.read(cite['record'])
            retained = loads(record_raw)
            if digest(record_raw) != cite['record_sha256']:
                return 'citation.command_mismatch'
            expected = {'argv': cite['argv'], 'cwd': cite['cwd'], 'exit': cite['exit_status'],
                        'stdout_sha256': cite['stdout_sha256'], 'stderr_sha256': cite['stderr_sha256']}
            if any(retained.get(k) != v for k, v in expected.items()):
                return 'citation.command_mismatch'
            for stream in ['stdout', 'stderr']:
                if digest(ctx.read(Path(cite['record']).parent / stream)) != cite[stream + '_sha256']:
                    return 'citation.command_mismatch'
            return None
        except (OSError, ValueError, ToolError):
            return 'citation.command_mismatch'
    if kind == 'upstream':
        pinned = ctx.run.get('upstream', {}).get(cite['repository'])
        if not pinned or pinned['commit'] != cite['commit']:
            return 'citation.upstream_identity'
        checkout = canonical(pinned['checkout'])
        path = checkout / cite['path']
        if not below(path.resolve(), checkout) or symlink_component(path):
            return 'citation.upstream_identity'
        execution = ctx.run_command(['git','-C',str(checkout),'rev-parse','HEAD'], checkout)
        if execution['exit_status'] or execution['stdout'].strip() != cite['commit']:
            return 'citation.upstream_identity'
        committed = ctx.run_command(['git','-C',str(checkout),'show',cite['commit'] + ':' + cite['path']], checkout)
        if committed['exit_status'] or committed['stdout_sha256'] != cite['sha256']:
            return 'citation.upstream_identity'
    else:
        path = Path(cite['path'])
    if not path.is_file():
        return 'citation.missing_file'
    raw = ctx.read(path)
    if digest(raw) != cite['sha256']:
        return 'citation.hash_mismatch'
    lines = raw.decode('utf-8').splitlines()
    first, last = cite['lines']
    if first < 1 or last < first or last > len(lines):
        return 'citation.line_range'
    if not cite['quote'] or cite['quote'] not in '\n'.join(lines[first-1:last]):
        return 'citation.quote_not_found'
    return None


def check(ctx, value):
    data = claims(ctx)
    for c in data['claims']:
        for index, cite in enumerate(c['citations']):
            if ctx.run.get('response') and cite['type'] in ('file','document') and not ctx.permitted(cite['path']):
                # Owner's scoped exception: scope_paths retains the refusal;
                # excluded source bytes must never be opened for a quote check.
                value['not_run'].append(c['id']+': citation not checked: excluded source '+cite['path'])
                continue
            defect = validate_citation(ctx, cite)
            if defect:
                value['defects'].append(ctx.defect(defect, 'checks/citations.py', ctx.run['claims'], c['id'],
                    evidence_key=[index, cite.get('path', cite.get('record')), cite.get('lines')]))


if __name__ == '__main__':
    sys.exit(main_check('citations', check))
