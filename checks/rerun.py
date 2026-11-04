import sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from common import *
from authority import grant_valid, forbidden_endpoint, class_grant_valid
import json, os, shutil, tempfile

# Owner 2026-10-22 (lever 2, evidence/owner_rulings_2026-10-22/stagecheck_noise_and_carry/FOLLOWUP_DECISION_VERBATIM.txt item 6):
# a cited `go test`/`go vet` that uses only safe flags is rerun by rule (no per-command listing) in a fresh copy of its
# module, under the go_local class grant, and compared per test from `go test -json`.
SAFE_GO_FLAG = re.compile(r'^-(count=\d+|run=.*|skip=.*|json|race|short|timeout=\w+|v|failfast|p=\d+|cpu=[\d,]+|parallel=\d+|tags=[\w,.-]*|vet=off|shuffle=off|buildvcs=false)$')
# Value flags may also be written as two words (-run X); the value is validated as in the one-word form.
VALUE_FLAGS = {'-run': r'.*', '-skip': r'.*', '-timeout': r'\w+', '-count': r'\d+', '-p': r'\d+', '-parallel': r'\d+', '-cpu': r'[\d,]+', '-tags': r'[\w,.-]*'}


def auto_candidate(ctx, auto, argv, cwd):
    """Returns (module root, cwd relative to it) or a reason string why the command does not qualify."""
    if len(argv) < 3 or Path(argv[0]).name != 'go':
        return 'not a go command'
    # The binary path and hash come from the owner-installed configuration, so its identity is read directly
    # (it may sit outside the evidence roots that ctx.read admits).
    binary = Path(auto['binary'])
    if not binary.is_file() or binary.is_symlink():
        return 'configured go binary is missing or a symlink'
    if not Path(argv[0]).is_file() or canonical(argv[0]) != canonical(binary):
        return 'go binary is not the configured toolchain'
    if digest(binary.read_bytes()) != auto['binary_sha256']:
        return 'configured go binary hash differs from the configuration'
    if argv[1] not in auto['subcommands']:
        return 'go subcommand not rerunnable: ' + argv[1]
    packages = []
    args = list(argv[2:])
    i = 0
    while i < len(args):
        a = args[i]
        if a in VALUE_FLAGS:
            if i + 1 >= len(args) or not re.fullmatch(VALUE_FLAGS[a], args[i + 1]):
                return 'flag value not rerunnable: ' + a
            i += 2
            continue
        i += 1
        if a.startswith('-'):
            if not SAFE_GO_FLAG.match(a):
                return 'flag not rerunnable: ' + a
        elif re.fullmatch(r'\.(/[\w.-]+)*(/\.\.\.)?', a) and '..' not in [x for x in a.split('/') if x != '...']:
            packages.append(a)
        else:
            return 'package pattern not rerunnable: ' + a
    if not packages:
        return 'no package pattern'
    try:
        c = canonical(cwd)
    except Exception:
        return 'cwd does not exist'
    roots = [canonical(ctx.root / r) for r in auto['roots'] if (ctx.root / r).exists()]
    module = next((d for d in [c, *c.parents] if (d / 'go.mod').is_file()), None)
    if module is None or not any(below(module, r) for r in roots):
        return 'cwd not inside a Go module under the configured roots'
    return module, c.relative_to(module)


def test_outcomes(text):
    found = {}
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict) and event.get('Action') in ('pass', 'fail', 'skip'):
            found[(event.get('Package', ''), event.get('Test', ''))] = event['Action']
    return found


def auto_rerun(ctx, value, config, claim_id, cite, done):
    auto = config.get('auto_rerun') or {}
    if not auto.get('enabled'):
        return False
    target = auto_candidate(ctx, auto, cite['argv'], cite['cwd'])
    if isinstance(target, str):
        value['not_run'].append(claim_id + ': not rerun by rule: ' + target)
        return False
    if not any(class_grant_valid(ctx, g, cite['argv']) for g in config.get('class_grants', [])):
        value['not_run'].append(claim_id + ': no valid go_local class grant for an automatic rerun')
        return True
    # Each distinct command runs once; every citation of it is compared against that one execution, so a
    # second (possibly false) record citing the same command is never skipped.
    key = (tuple(cite['argv']), cite['cwd'])
    if key not in done and len(done) >= auto['max_reruns']:
        value['not_run'].append(claim_id + ': automatic rerun cap reached')
        return True
    record = Path(cite['record'])
    cited_stdout = record.parent / 'stdout'
    if not cited_stdout.is_file() or digest(ctx.read(cited_stdout)) != cite['stdout_sha256']:
        value['not_run'].append(claim_id + ': cited stdout is not retained beside its record; outcome not compared')
        cited_text = None
    else:
        cited_text = ctx.read(cited_stdout).decode('utf-8', 'replace')
    module, rel = target
    if key in done:
        execution = done[key]
    else:
        execution = done[key] = execute_copy(ctx, auto, cite, module, rel)
    if execution is None:
        value['not_run'].append(claim_id + ': automatic rerun did not finish')
        return True
    compare(ctx, value, claim_id, cite, execution, cited_text)
    return True


def execute_copy(ctx, auto, cite, module, rel):
    with tempfile.TemporaryDirectory(prefix='stagecheck-rerun-') as tmp:
        tmp = Path(tmp)
        copy = tmp / 'module'
        shutil.copytree(module, copy, symlinks=True, ignore=shutil.ignore_patterns('.git'))
        for d in ('gotmp', 'home'):
            (tmp / d).mkdir()
        env = {k: v for k, v in os.environ.items() if not k.startswith(('LD_', 'ANTHROPIC_')) and not k.startswith('GO') and k not in ['CGO_CFLAGS', 'CGO_CPPFLAGS', 'CGO_CXXFLAGS', 'CGO_LDFLAGS']}
        env.update(auto['environment'])
        # The configured build cache is reused; -count=1 below keeps test results from ever being served from it.
        env.update(GOTOOLCHAIN='local', GOPROXY='off', GOWORK='off', GOENV='off', GOFLAGS='-mod=readonly',
                   GOTMPDIR=str(tmp / 'gotmp'), HOME=str(tmp / 'home'))
        argv = list(cite['argv'])
        if argv[1] == 'test':
            rest, i = [], 2
            while i < len(argv):
                if argv[i] == '-count':
                    i += 2
                    continue
                if not argv[i].startswith('-count='):
                    rest.append(argv[i])
                i += 1
            argv = [argv[0], argv[1], '-count=1'] + rest
        try:
            return ctx.run_command(argv, copy / rel, timeout=auto['timeout_seconds'], env=env)
        except ToolError:
            return None


def compare(ctx, value, claim_id, cite, execution, cited_text):
    if execution['exit_status'] != cite['exit_status']:
        value['defects'].append(ctx.defect('rerun.exit', 'checks/rerun.py', cite['record'], claim_id))
    if cited_text is not None and '-json' in cite['argv']:
        before, after = test_outcomes(cited_text), test_outcomes(execution['stdout'])
        if not before:
            value['not_run'].append(claim_id + ': cited output has no go test events; outcome not compared')
        else:
            changed = sorted(k for k in before if after.get(k) != before[k])
            if changed:
                value['defects'].append(ctx.defect('rerun.outcome', 'checks/rerun.py', cite['record'], claim_id,
                                                   evidence_key=[list(k) + [before[k], after.get(k)] for k in changed[:50]]))


def check(ctx, value):
    data = claims(ctx)
    config = loads(ctx.read(ctx.tool/'config/commands.json'))
    cited = [(c['id'], x) for c in data['claims'] for x in c['citations'] if x['type']=='command']
    if not config['enabled']:
        if cited:
            value['not_run'].append('product reruns disabled: owner command selection and grant confirmation required')
        return
    auto_done = {}
    for claim_id, cite in cited:
        choices = [x for x in config['commands'] if x['argv']==cite['argv'] and x['cwd']==cite['cwd']]
        if not choices and auto_rerun(ctx, value, config, claim_id, cite, auto_done):
            continue
        if not choices:
            value['defects'].append(ctx.defect('rerun.unselected','checks/rerun.py',cite['record'],claim_id))
            value['not_run'].append(claim_id+': cited command has no owner-selected rerun; no execution authorized')
            continue
        if len(choices)!=1:
            raise ToolError('claimed command is not uniquely owner-selected')
        selected = choices[0]
        argv = selected['argv']
        env = selected['environment']
        if forbidden_endpoint(argv):
            raise ToolError('forbidden upstream endpoint')
        if not grant_valid(ctx,config['product_grant'],argv,selected['cwd']):
            raise ToolError('no applicable unexpired product-execution grant')
        if not grant_valid(ctx,config['product_grant'],selected['smoke_argv'],selected['cwd']):
            raise ToolError('smoke command is not covered by the owner execution grant')
        expected_binary = canonical(selected['binary'])
        if argv[0] != str(expected_binary) or digest(ctx.read(expected_binary)) != selected['binary_sha256'] or env.get('GOTOOLCHAIN')!='local':
            value['defects'].append(ctx.defect('rerun.toolchain','checks/rerun.py',ctx.tool/'config/commands.json',claim_id))
            continue
        # Inputs are owner-selected and must match both before and after execution.
        for path, sha in selected['inputs'].items():
            if digest(ctx.read(path)) != sha:
                raise ToolError('rerun input differs: '+path)
        clean_env = {k:v for k,v in os.environ.items() if not k.startswith(('LD_','ANTHROPIC_')) and k not in ['GOROOT','GODEBUG','GOEXPERIMENT','CGO_CFLAGS','CGO_CPPFLAGS','CGO_CXXFLAGS','CGO_LDFLAGS']}
        clean_env.update(env)
        clean_env.update(GOTOOLCHAIN='local',GOPROXY='off',GOWORK='off',GOENV='off')
        smoke = ctx.run_command(selected['smoke_argv'],selected['cwd'],timeout=selected['smoke_timeout_seconds'],env=clean_env)
        if smoke['exit_status']:
            raise ToolError('smoke check failed; full rerun was not executed')
        execution = ctx.run_command(argv,selected['cwd'],timeout=selected['timeout_seconds'],env=clean_env)
        for path, sha in selected['inputs'].items():
            if digest(ctx.read(path)) != sha:
                raise ToolError('rerun changed an input: '+path)
        if execution['exit_status'] != cite['exit_status']:
            value['defects'].append(ctx.defect('rerun.exit','checks/rerun.py',cite['record'],claim_id))
        if execution['stdout_sha256'] != cite['stdout_sha256'] or execution['stderr_sha256'] != cite['stderr_sha256']:
            value['defects'].append(ctx.defect('rerun.output','checks/rerun.py',cite['record'],claim_id))


if __name__ == '__main__':
    sys.exit(main_check('rerun', check))
