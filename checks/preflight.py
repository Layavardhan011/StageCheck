import sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from common import *
from agents import validate_instruction


def manifest_entries(tool):
    entries = {}
    for line in (tool / 'MANIFEST.sha256').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match or match[2] in entries or '\\' in match[2]:
            raise ToolError('ambiguous manifest row')
        entries[match[2]] = match[1]
    return entries


def check(ctx, value):
    source = 'checks/preflight.py'
    def bad(cid, path, escalation=False, key=None):
        value['defects'].append(ctx.defect(cid, source, path, evidence_key=key))
        value['escalate'] |= escalation
    for role, identity in ctx.bind.items():
        if not isinstance(identity, dict):
            continue
        path = Path(identity['path'])
        if symlink_component(path):
            bad('preflight.symlink', ctx.contract, True, role)
            continue
        if not path.is_file():
            raise ToolError('missing control file: ' + str(path))
        actual = digest(ctx.read(path))
        if role != 'Current-state pointer' and actual != identity['sha256']:
            bad('preflight.bound_hash', ctx.contract, True, role)
    contract_hash = digest(ctx.read(ctx.contract))
    for name in ctx.paths['instruction_copies']:
        path = Path(name).expanduser()
        if not path.is_absolute():
            path = ctx.root.parent.parent / path
        if digest(ctx.read(path)) != contract_hash:
            bad('preflight.instructions_differ', ctx.contract, key=name)
    entries = manifest_entries(ctx.tool)
    reused = {'verify_manifest': '../evidence/claude_audits/tools/verify_manifest.py',
              'verify_state_chain': '../evidence/claude_audits/tools/verify_state_chain.py',
              'capture': '../qualification/reviews/capture_sp1_evidence.py'}
    allowed_external = set(reused.values())
    for rel, expected in sorted(entries.items()):
        path = ctx.tool / rel
        if not below(path.resolve(), ctx.tool) and rel not in allowed_external:
            raise ToolError('unapproved manifest tool: ' + rel)
        if symlink_component(path):
            bad('preflight.symlink', ctx.tool / 'MANIFEST.sha256', key=rel)
        elif not path.is_file() or digest(ctx.read(path)) != expected:
            bad('preflight.reused_hash' if rel in allowed_external else 'preflight.bound_hash',
                ctx.tool / 'MANIFEST.sha256', rel not in allowed_external, rel)
    for path in sorted(ctx.tool.rglob('*')):
        if path.is_symlink():
            bad('preflight.symlink', ctx.tool / 'MANIFEST.sha256', key=str(path))
        elif path.is_file() and path.name != 'MANIFEST.sha256' and str(path.relative_to(ctx.tool)) not in entries:
            bad('preflight.unlisted_file', ctx.tool / 'MANIFEST.sha256', key=str(path))
    descriptor = ctx.root / 'controls/STAGECHECK_ROOT.json'
    if descriptor.exists():
        binding = loads(ctx.read(descriptor))
        if set(binding) != {'root', 'manifest_sha256'} or canonical(binding['root']) != ctx.tool:
            raise ToolError('ambiguous STAGECHECK_ROOT descriptor')
        value['unbound'] = binding['manifest_sha256'] != digest(ctx.read(ctx.tool / 'MANIFEST.sha256'))
        if value['unbound']:
            bad('preflight.binding_mismatch', descriptor)
    else:
        value['unbound'] = True
    # Required descriptor target directories, not just descriptor bytes.
    for role in ['Evidence root','Product repositories','Qualification tree (§11)']:
        bound=ctx.bind[role]
        if digest(Path(bound['path']).read_bytes())!=bound['sha256']:
            continue
        for key,target in loads(ctx.read(bound['path'])).items():
            if key=='root' or key.endswith('_root'):
                if not Path(target).is_absolute() or not Path(target).is_dir() or symlink_component(target):
                    raise ToolError('invalid descriptor target: '+str(target))
    agent_config = loads(ctx.read(ctx.tool / 'config/agents.json'))
    declared = [a['instruction'] for a in agent_config['agents']] + [agent_config['orchestrator_instruction']]
    actual = {p.name for p in (ctx.tool / 'agent_instructions').glob('*.md')} - {'00_common.md'}
    if set(declared) != actual or len(declared) != len(set(declared)):
        bad('preflight.agent_mapping', ctx.tool / 'config/agents.json')
    else:
        try:
            validate_instruction(ctx,'common','00_common.md')
            validate_instruction(ctx,'orchestrator',agent_config['orchestrator_instruction'])
            for agent in agent_config['agents']:
                validate_instruction(ctx,agent['id'],agent['instruction'])
        except ToolError:
            bad('preflight.agent_mapping',ctx.tool/'config/agents.json')
    # Never execute a reused tool whose bytes failed the identity check.
    if any(d['check_id'] in ('preflight.reused_hash', 'preflight.symlink', 'preflight.bound_hash') for d in value['defects']):
        value['not_run'].append('reused verifiers: identity/path check failed')
        return
    for rel in reused.values():
        if rel not in entries:
            raise ToolError('reused tool absent from manifest: ' + rel)
    env = os.environ.copy()
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    start = ctx.root / 'RWA/start'
    calls = [
        [sys.executable, str(ctx.tool / reused['verify_manifest']), str(start),
         digest(ctx.read(start / 'START_MANIFEST.md')), ctx.bind['architecture']['path'],
         ctx.bind['architecture']['sha256']],
        [sys.executable, str(ctx.tool / reused['verify_state_chain']), str(ctx.root),
         ctx.bind['protected_sha256'], ctx.bind['Current-state pointer']['sha256']]
    ]
    for i, argv in enumerate(calls):
        execution = ctx.run_command(argv, ctx.tool, env=env)
        if execution['exit_status']:
            bad('preflight.state_history' if i else 'preflight.bound_hash', ctx.contract, True)
    # The reused chain verifier checks linkage/snapshots. Cover its documented
    # gap: protected identity and declared factual changes in EVERY snapshot.
    for record in state_history_findings(ctx.root, ctx.bind['protected_sha256'], lambda p: loads(ctx.read(p))):
        bad('preflight.state_history', record, True)


WRITABLE = {'status','source_lock','current_task','completed_tasks','evidence_references','open_prerequisites'}
PROTECTED = {'schema_version','programme','architecture','execution_plan','authority','evidence_root','qualification_root','note'}


def state_history_findings(root, bound_protected, read_json):
    """Records of evidence/state_updates that break the update rule. Each record is judged against the
    protected identity in force at its own time: a factual update keeps the protected fields unchanged; a
    protected-field change is valid only as an owner installation. The chain must link, and its last
    snapshot must carry today's bound protected identity."""
    def protected_hash(state):
        return digest(json.dumps({k: state[k] for k in sorted(PROTECTED)},
                                 sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode())
    found = []
    previous_after = None
    last = None
    for record in sorted((Path(root) / 'evidence/state_updates').glob('[0-9][0-9][0-9][0-9].json')):
        r = read_json(record)
        seq = record.stem
        before = read_json(record.with_name(seq + '.before.json'))
        after = read_json(record.with_name(seq + '.after.json'))
        changed = {k for k in set(before) | set(after) if before.get(k) != after.get(k)}
        fields = r.get('changed_fields', [])
        declared_fields = {re.split(r'[.\[]', x)[0] for x in fields} if isinstance(fields, list) else set()
        valid = set(before) == set(after) == WRITABLE | PROTECTED and changed == declared_fields
        if changed <= WRITABLE:
            valid &= protected_hash(before) == protected_hash(after)
        else:
            valid &= 'owner' in str(r.get('actor', '')).lower()
        valid &= all(r.get(k) for k in ['actor','reason','supporting_evidence'])
        valid &= previous_after is None or before == previous_after
        previous_after = after
        last = record
        if not valid:
            found.append(record)
    if last is not None and protected_hash(previous_after) != bound_protected and last not in found:
        found.append(last)
    return found


if __name__ == '__main__':
    sys.exit(main_check('preflight', check))
