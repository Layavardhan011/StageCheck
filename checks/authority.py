import sys
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timezone
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from common import *
from citations import validate_citation


def approved_remote(url, approved):
    if url == 'DISABLED':
        return True
    if url not in approved:
        return False
    if url.startswith('git@github.com:'):
        return url.split(':',1)[1].startswith('xorewa/')
    parsed = urlparse(url)
    return parsed.hostname == 'github.com' and parsed.path.startswith('/xorewa/') and parsed.scheme in ('https','ssh')


def forbidden_endpoint(argv):
    for arg in argv:
        for url in re.findall(r'https?://[^\s"\']+', arg):
            host = (urlparse(url).hostname or '').lower()
            if host in ('multiversx.com','elrond.com') or host.endswith('.multiversx.com') or host.endswith('.elrond.com'):
                return True
    return False


def grant_valid(ctx, grant, argv, cwd):
    if not grant or not isinstance(grant, dict):
        return False
    cite = grant.get('citation')
    if not cite or cite.get('path') != ctx.bind['Owner grant ledger (§9)']['path'] or validate_citation(ctx, cite):
        return False
    expiry = grant.get('expires_utc')
    if expiry:
        if datetime.fromisoformat(expiry.replace('Z','+00:00')) <= datetime.now(timezone.utc):
            return False
        if expiry not in cite['quote']:
            return False
    elif grant.get('expiry_stage') in ('SP1', 'SP2'):
        stage = grant['expiry_stage']
        state = loads(ctx.read(ctx.bind['Current-state pointer']['path']))
        if not state.get('status','').startswith(stage + '_') or 'end of ' + stage not in cite['quote']:
            return False
    else:
        return False
    return any(item.get('argv') == argv and item.get('cwd') == cwd for item in grant.get('commands', []))


SAFE_GIT_CONFIG = {'protocol.allow', 'gc.auto', 'core.quotepath', 'color.ui'}


GIT_GLOBAL_PAIRS = ('-C', '-c')
GIT_GLOBAL_EQ = ('--git-dir=', '--work-tree=')
OUTPUT_FLAGS = ('--ext-diff', '--textconv', '--output', '--open-files-in-pager', '-O')
# Owner 2026-10-22 (evidence/owner_rulings_2026-10-22/stagecheck_noise_and_carry/): read-only text tools.
TEXT_READERS = ('grep', 'head', 'tail', 'wc', 'diff', 'ls', 'uniq', 'jq')
SED_PRINT = re.compile(r'^\s*((\d+|\$)(\s*,\s*(\d+|\$))?)?\s*p\s*$')
FIND_WRITERS = ('-exec', '-execdir', '-ok', '-okdir', '-delete', '-fprint', '-fprint0', '-fprintf', '-fls')
GO_CLASS = ('test', 'vet', 'build', 'list')


def git_consequential(argv):
    words = list(argv[1:])
    # -C <dir>, --git-dir=/--work-tree= and -c <key=value> with a harmless key keep a read command
    # read-only; a -c key that can start a program (core.fsmonitor, diff.external, core.pager, ...) is consequential.
    while words and (words[0] in GIT_GLOBAL_PAIRS and len(words) >= 2 or words[0].startswith(GIT_GLOBAL_EQ)):
        if words[0] == '-c' and words[1].split('=', 1)[0].lower() not in SAFE_GIT_CONFIG:
            return True
        words = words[1:] if words[0].startswith(GIT_GLOBAL_EQ) else words[2:]
    if not words:
        return True
    sub, args = words[0], words[1:]
    writes_output = any(x in OUTPUT_FLAGS or x.startswith('--output=') or x.startswith('--open-files-in-pager=') for x in args)
    if sub == 'branch':
        return args not in ([], ['--show-current'], ['--list'])
    if sub == 'remote':
        if not args or args == ['-v']:
            return False
        if args[0] == 'get-url':
            rest = args[1:]
            return not (rest and not rest[-1].startswith('-') and all(x in ('--push', '--all') for x in rest[:-1]))
        return True
    if sub == 'tag':
        listing = not args or args[0] in ('-l', '--list', '--points-at', '--contains', '--merged', '--no-merged') or args[0].startswith('--points-at=')
        creating = any(x in ('-d', '--delete', '-a', '--annotate', '-s', '--sign', '-u', '-f', '--force', '-m', '-F', '-e', '--edit') for x in args)
        return not listing or creating or writes_output
    if sub == 'cat-file':
        return not (args and args[0] in ('-t', '-s', '-p', '-e')) or writes_output
    if sub in ('status', 'show', 'diff', 'log', 'ls-tree', 'rev-parse', 'ls-files', 'grep', 'for-each-ref', 'rev-list'):
        # Read-looking git commands can write outputs or invoke helpers.
        return writes_output
    return True


def sed_read_only(args):
    """Only sed -n with line-range print scripts is read-only; -i, script files, other options and any
    w/W/e/r command make it consequential. Every -e script is checked, not only the first."""
    quiet, scripts, operands, i = False, [], [], 0
    while i < len(args):
        x = args[i]
        if x in ('-e', '--expression'):
            if i + 1 >= len(args):
                return False
            scripts.append(args[i + 1]); i += 2; continue
        if x.startswith('--expression='):
            scripts.append(x.split('=', 1)[1])
        elif x in ('--quiet', '--silent'):
            quiet = True
        elif x.startswith('--'):
            return False
        elif x.startswith('-') and x != '-':
            if set(x[1:]) - {'n', 'E', 'r', 'u', 'z'}:
                return False
            quiet |= 'n' in x[1:]
        else:
            operands.append(x)
        i += 1
    if not scripts:
        if not operands:
            return False
        scripts = [operands[0]]
    return quiet and all(SED_PRINT.match(s) for s in scripts)


def consequential(argv):
    if not argv:
        return True
    name = Path(argv[0]).name
    args = argv[1:]
    if name == 'git':
        return git_consequential(argv)
    if name == 'rg':
        return any(x == '--pre' or x.startswith('--pre=') for x in args)
    if name in ('cat', 'sha256sum', 'realpath'):
        return False
    if name == 'uniq':
        # uniq [INPUT [OUTPUT]] writes its second operand.
        return len([x for x in args if not x.startswith('-') or x == '-']) > 1
    if name in TEXT_READERS:
        return False
    if name == 'sort':
        return any(x.startswith('--output') or (x.startswith('-') and not x.startswith('--') and 'o' in x[1:]) for x in args)
    if name == 'sed':
        return not sed_read_only(args)
    if name == 'find':
        return any(x in FIND_WRITERS for x in args)
    if name == 'go' and args in [['version'], ['env']]:
        return False
    return True


def go_class(argv):
    return bool(argv) and Path(argv[0]).name == 'go' and len(argv) > 1 and argv[1] in GO_CLASS


def class_grant_valid(ctx, grant, argv):
    """Owner 2026-10-22: local offline Go builds and tests are granted as a class by the cited SP2 grant's
    'Permitted execution' line; the class grant must cite the ledger exactly and be unexpired."""
    if not go_class(argv) or not isinstance(grant, dict) or grant.get('class') != 'go_local':
        return False
    cite = grant.get('citation')
    if not cite or cite.get('path') != ctx.bind['Owner grant ledger (§9)']['path'] or validate_citation(ctx, cite):
        return False
    stage = grant.get('expiry_stage')
    if stage not in ('SP1', 'SP2') or 'end of ' + stage not in cite['quote'] or 'Permitted execution' not in cite['quote']:
        return False
    state = loads(ctx.read(ctx.bind['Current-state pointer']['path']))
    return state.get('status', '').startswith(stage + '_')


def check(ctx, value):
    data = claims(ctx)
    remote_config = loads(ctx.read(ctx.tool / 'config/remotes.json'))
    config = loads(ctx.read(ctx.tool / 'config/commands.json'))
    if not ctx.run.get('response'):
        repo = canonical(ctx.run['repo'])
        names = ctx.run_command(['git','-C',str(repo),'remote'], repo)
        if names['exit_status']:
            raise ToolError('cannot inspect effective git remotes')
        for name in names['stdout'].splitlines():
            urls = ctx.run_command(['git','-C',str(repo),'remote','get-url','--push','--all',name], repo)
            if urls['exit_status']:
                raise ToolError('cannot resolve push URL')
            for url in urls['stdout'].splitlines():
                if not approved_remote(url, remote_config['approved_push_urls']):
                    value['defects'].append(ctx.defect('authority.remote','checks/authority.py',ctx.run['claims'],evidence_key=[name,url]))
    records = set(ctx.run.get('operation_records', []))
    records.update(cite['record'] for c in data['claims'] for cite in c['citations'] if cite['type']=='command')
    for record in sorted(records):
        retained = loads(ctx.read(record))
        argv, cwd = retained['argv'], retained['cwd']
        if forbidden_endpoint(argv):
            value['defects'].append(ctx.defect('authority.upstream_endpoint','checks/authority.py',record))
        # Generator records are subjects, never the source of execution authority.
        grant = config.get('product_grant')
        if consequential(argv) and not grant_valid(ctx, grant, argv, cwd) and not any(class_grant_valid(ctx, g, argv) for g in config.get('class_grants', [])):
            value['defects'].append(ctx.defect('authority.grant','checks/authority.py',record))


if __name__ == '__main__':
    sys.exit(main_check('authority', check))
