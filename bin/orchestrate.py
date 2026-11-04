"""One owner-launched iteration. No automatic generator invocation."""
from datetime import datetime, timezone
import fnmatch
from common import *
from render_report import render
from agents import select_agents, call_agent, validate_instruction
from quality import versions as quality_versions, blocking_evidence

CHECKS=['preflight','scope_paths','citations','report_lint','authority','secrets','qual_naming','rerun','carry_forward']
EXIT={'CLEAR':0,'BLOCKED':1,'ESCALATE':2,'TOOL_ERROR':3}


def decide(defects, errors, escalation, history, iteration):
    history=[h for h in history if h['verdict'].get('result')!='TOOL_ERROR']
    if errors:
        return 'TOOL_ERROR', []
    if escalation:
        return 'ESCALATE', ['The control or architecture identity differs. Restore the owner-bound bytes, or have the owner review and install new bindings; which disposition applies?']
    previous=history[-1]['verdict'] if history else None
    previous_ids={d['defect_id'] for d in previous['defects']} if previous else set()
    older_ids={d['defect_id'] for h in history[:-1] for d in h['verdict']['defects']}
    for defect in defects:
        defect['status']='repeated' if defect['defect_id'] in previous_ids else 'new'
        if defect['defect_id'] in older_ids and defect['defect_id'] not in previous_ids:
            defect['status']='reappeared'
    if any(d['status']=='reappeared' for d in defects):
        return 'ESCALATE', ['A previously absent defect reappeared. Resume with a corrected root cause and its evidence, or return the item for owner disposition; which applies?']
    blocking={d['defect_id'] for d in defects if d['mode']=='blocking'}
    previous_blocking={d['defect_id'] for d in previous['defects'] if d['mode']=='blocking'} if previous else set()
    if blocking and blocking==previous_blocking:
        return 'ESCALATE', ['The blocking defect set is unchanged. Provide a repair with evidence, or dispute the findings for owner ruling; which applies?']
    if blocking and iteration>=4:
        return 'ESCALATE', ['The two repair iterations and final resubmission are exhausted. Owner-authorize a new bounded task, or stop this task; which applies?']
    return ('BLOCKED',[]) if blocking else ('CLEAR',[])


def history_read(task_dir,exclude=None):
    history=[]
    if not task_dir.exists():
        return history
    directories=list(task_dir.iterdir())
    if exclude is not None and exclude.parent==task_dir:
        if not exclude.name.isdigit() or int(exclude.name)!=max((int(p.name) for p in directories if p.name.isdigit()),default=0):
            raise ToolError('only the current final attempt may be excluded')
        directories=[p for p in directories if p!=exclude]
    if any(not p.name.isdigit() or not p.is_dir() or p.is_symlink() for p in directories):
        raise ToolError('unexpected task history entry')
    for directory in sorted(directories,key=lambda p:int(p.name)):
        if not directory.is_dir() or directory.is_symlink() or not directory.name.isdigit():
            raise ToolError('unexpected task history entry')
        seal=load(directory/'seal.json')
        for name in ['verdict.json','generator_report.md']:
            path=directory/name
            if symlink_component(path) or digest(path.read_bytes())!=seal[name]:
                raise ToolError('history identity mismatch: '+str(path))
        verdict=load(directory/'verdict.json')
        if verdict['previous'] != (history[-1]['seal'] if history else {}):
            raise ToolError('broken previous-iteration identity link')
        history.append({'verdict':verdict,'seal':seal})
    return history


def depth_for(paths, repo, requested, config):
    ranks={'docs':0,'code':1,'sensitive':2}
    if config.get('approved') is not True:
        return requested or 'docs'
    selected=ranks[requested or 'docs']
    for path in paths:
        rel=str(Path(path).relative_to(repo))
        matches=[ranks[r['depth']] for r in config['rules'] if fnmatch.fnmatch(rel,r['pattern'])]
        selected=max(selected,max(matches) if matches else ranks[config['default']])
    return ['docs','code','sensitive'][selected]


def capture_check(ctx,name,run_path,out):
    directory=out/(name+'.execution')
    directory.mkdir()
    argv=[sys.executable,str(ctx.tool/'checks'/ (name+'.py')),'--run',str(run_path),'--output-dir',str(out)]
    env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1'
    r=subprocess.run(argv,cwd=ctx.tool,env=env,capture_output=True,timeout=120,shell=False)
    (directory/'stdout').write_bytes(r.stdout)
    (directory/'stderr').write_bytes(r.stderr)
    execution={'argv':argv,'cwd':str(ctx.tool),'exit':r.returncode,
               'stdout_sha256':digest(r.stdout),'stderr_sha256':digest(r.stderr)}
    create(directory/'execution.json',execution)
    value=load(out/(name+'.json'))
    schema(value,load(ctx.tool/'schemas/verdict.schema.json'))
    if value.get('type')!='check' or value['id']!=name:
        raise ToolError('wrong check output identity')
    expected=3 if value['errors'] else 1 if value['defects'] else 0
    if r.returncode!=expected:
        raise ToolError('check exit status differs from its output')
    if value['defects']:
        # Each observed finding resolves to the actual checker invocation and
        # retained summary output. Original source evidence stays in the check
        # JSON, avoiding self-referential result hashes and secret quotations.
        cite={'type':'command','record':str(directory/'execution.json'),
              'record_sha256':digest((directory/'execution.json').read_bytes()),'argv':argv,
              'cwd':str(ctx.tool),'exit_status':r.returncode,
              'stdout_sha256':digest(r.stdout),'stderr_sha256':digest(r.stderr)}
        for defect in value['defects']:
            defect['evidence']=[cite]
    return value


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--task',required=True)
    parser.add_argument('--response',action='store_true')
    parser.add_argument('--repo')
    parser.add_argument('--base')
    parser.add_argument('--report',required=True)
    parser.add_argument('--claims',required=True)
    parser.add_argument('--depth',choices=['docs','code','sensitive'])
    parser.add_argument('--allow-dirty',action='store_true',help='explicitly inspect working-tree bytes; retain dirty status and identity')
    parser.add_argument('--root')
    parser.add_argument('--contract')
    parser.add_argument('--output-dir',help='optional task history directory within the bound evidence root')
    parser.add_argument('--record',action='append',default=[])
    parser.add_argument('--wider-scope')
    parser.add_argument('--upstream',nargs=3,action='append',default=[],metavar=('REPOSITORY','CHECKOUT','COMMIT'))
    args=parser.parse_args()
    if args.response:
        if args.repo is not None or args.base is not None or args.allow_dirty or args.upstream or args.wider_scope or args.record:
            parser.error('response mode rejects repository, dirty, upstream, scope and operation inputs')
    elif args.repo is None or args.base is None:
        parser.error('delivery mode requires --repo and --base')
    tool=Path(__file__).resolve().parent.parent
    root=canonical(args.root) if args.root else tool.parent
    contract=canonical(args.contract) if args.contract else canonical(root.parent.parent/'AGENTS.md')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}',args.task) or args.base is not None and args.base.startswith('-'):
        parser.error('task or base is not a valid owner input')
    identities=bindings(contract)
    evidence_descriptor=Path(identities['Evidence root']['path'])
    if digest(evidence_descriptor.read_bytes())!=identities['Evidence root']['sha256']:
        print('NOT DONE: evidence-root binding differs; no output written\nFull Blast Radius Check: evidence descriptor identity compared; all remaining checks unexecuted\nEnforcement Self-Check: Enforcement is manual; evidence binding differs; all checks not run')
        return 2
    evidence_root=canonical(load(evidence_descriptor)['root'])
    evidence=evidence_root/'stagecheck'
    if symlink_component(evidence):
        raise ToolError('symlink output root')
    task_dir=Path(args.output_dir).expanduser().absolute() if args.output_dir else evidence/args.task
    if symlink_component(task_dir) or not task_dir.resolve().is_relative_to(evidence_root):
        raise ToolError('output directory must stay within the bound evidence root without symlinks')
    if task_dir.exists() and not task_dir.is_dir():
        raise ToolError('output directory is not a directory')
    if not task_dir.exists():
        task_dir.mkdir()
    history_error=None
    try:
        history=history_read(task_dir)
    except ToolError as exc:
        history=[];history_error=str(exc)
    dirs=[int(p.name) for p in task_dir.iterdir() if p.is_dir() and p.name.isdigit()]
    attempt=max(dirs,default=0)+1
    if history_error is None and attempt!=len(history)+1:
        raise ToolError('task history changed during admission; concurrent submission refused')
    out=task_dir/str(attempt);out.mkdir()
    checks_out=out/'checks';checks_out.mkdir()
    agents_out=out/'agents';agents_out.mkdir()
    iteration=1+sum(h['verdict']['result']!='TOOL_ERROR' for h in history)
    verdict={'type':'verdict','task_id':args.task,'iteration':iteration,
             'contract_sha256':digest(contract.read_bytes()),'checked_head':'UNKNOWN',
             'manifest_sha256':digest((tool/'MANIFEST.sha256').read_bytes()),'bound':False,
             'depth':args.depth or 'docs','input_hashes':{},'previous':history[-1]['seal'] if history else {},
             'checks':[],'agents':[],'defects':[],'not_run':[],'errors':[],
             'result':'TOOL_ERROR','questions':[],'counts':{'blocking':0,'report_only':0,'not_run':0}}
    ctx=None
    try:
        if args.response:
            repo=None;changed=[];depth=args.depth or 'docs'
            head={'stdout':'response'};base={'stdout':'response'}
            status=None;verdict.update(checked_head='response',dirty=False,status_sha256=digest(b''),response=True)
        else:
            repo=canonical(args.repo)
            git=command(['git','-C',str(repo),'rev-parse','--show-toplevel'],repo)
            if git['exit_status'] or canonical(git['stdout'].strip())!=repo:
                raise ToolError('repo argument must be the exact git repository root')
            head=command(['git','-C',str(repo),'rev-parse','HEAD'],repo)
            base=command(['git','-C',str(repo),'rev-parse','--verify',args.base+'^{commit}'],repo)
            if head['exit_status'] or base['exit_status']:
                raise ToolError('cannot resolve launcher head/base')
            verdict['checked_head']=head['stdout'].strip()
            status=command(['git','-C',str(repo),'status','--porcelain=v1','-uall'],repo)
            create(out/'repository_status.json',status)
            if status['exit_status']:
                raise ToolError('cannot establish repository status')
            verdict.update(dirty=bool(status['stdout']),status_sha256=status['stdout_sha256'])
            if verdict['dirty'] and not args.allow_dirty:
                raise ToolError('dirty repository refused; owner may explicitly select --allow-dirty to inspect working-tree bytes')
            paths=command(['git','-C',str(repo),'diff','--no-ext-diff','--no-textconv','--name-only','-z',base['stdout'].strip(),'--'],repo)
            untracked=command(['git','-C',str(repo),'ls-files','--others','--exclude-standard','-z'],repo)
            if paths['exit_status'] or untracked['exit_status']:
                raise ToolError('cannot enumerate changed paths')
            changed=sorted({str(repo/p) for p in (paths['stdout']+untracked['stdout']).split('\0') if p})
            depth=depth_for(changed,repo,args.depth,load(tool/'config/depth.json'))
        run={'task_id':args.task,'iteration':iteration,'tool_root':str(tool),'programme_root':str(root),
             'contract':str(contract),'repo':None if args.response else str(repo),'base':base['stdout'].strip(),'checked_head':verdict['checked_head'],
             'claims':str(Path(args.claims).expanduser().resolve()),'report':str(Path(args.report).expanduser().resolve()),
             'depth':depth,'changed_paths':changed,'operation_records':[str(canonical(p)) for p in args.record],
             'run_path':str(out/'run.json'),'upstream':{},'read_paths':[],
             'dirty':verdict['dirty'],'status_sha256':verdict['status_sha256']}
        for repository,checkout,commit in args.upstream:
            if repository in run['upstream'] or not re.fullmatch('[0-9a-f]{40}',commit):
                raise ToolError('ambiguous upstream lock')
            run['upstream'][repository]={'checkout':str(canonical(checkout)),'commit':commit}
        # Upstream locks are owner launcher inputs only; absence means UNKNOWN.
        if args.wider_scope:
            packet=load(canonical(args.wider_scope));run.update(wider_scope=packet['citation'],wider_surfaces=packet['surfaces'])
        if args.response:run['response']=True
        create(out/'run.json',run)
        ctx=Context(run)
        check_versions=quality_versions(ctx)
        main_config=loads(ctx.read(tool/'config/agents.json'))
        main_file=main_config['orchestrator_instruction']
        main_raw=validate_instruction(ctx,'orchestrator',main_file)
        verdict['input_hashes'][str(tool/'agent_instructions'/main_file)]=digest(main_raw)
        for path in [contract,tool/'MANIFEST.sha256',Path(args.report),Path(args.claims)]:
            verdict['input_hashes'][str(path.resolve())]=digest(ctx.read(path))
        # Startup metadata is a separate retained record, not generator-defined scope.
        if args.response:
            metadata={'cwd':str(Path.cwd()),'repo':None,'head':'response','base':'response','status':None,
                      'contract_sha256':verdict['contract_sha256'],'response':True}
        else:
            metadata={'cwd':str(Path.cwd()),'repo':str(repo),'head':verdict['checked_head'],'base':run['base'],
                      'status':status,
                      'branch':command(['git','-C',str(repo),'branch','--show-current'],repo),
                      'staged':command(['git','-C',str(repo),'diff','--no-ext-diff','--no-textconv','--cached','--name-only','-z'],repo),
                      'unstaged':command(['git','-C',str(repo),'diff','--no-ext-diff','--no-textconv','--name-only','-z'],repo),
                      'python':command([sys.executable,'--version'],repo),'contract_sha256':verdict['contract_sha256'],
                      'orchestrator_instruction':{'path':str(tool/'agent_instructions'/main_file),'sha256':digest(main_raw),
                                                  'execution':'deterministic Python; no orchestrator model call'}}
        create(out/'startup.json',metadata)
        verdict['depth']=depth
        for name in CHECKS:
            try:
                if args.response and name in ['qual_naming','rerun','carry_forward']:
                    checked=result(name);checked['not_run'].append(name+': response mode: no repository change')
                else:
                    checked=capture_check(ctx,name,out/'run.json',checks_out)
            except Exception as exc:
                checked=result(name);checked['errors'].append(type(exc).__name__+': '+str(exc));checked['not_run'].append(name+': no valid check result')
            verdict['checks'].append(checked)
            checked['version']=check_versions[name]['sha256']
            verdict['errors'] += checked['errors']
            verdict['not_run'] += checked['not_run']
        preflight=verdict['checks'][0]
        verdict['bound']=not preflight['unbound'] and not preflight['errors']
        modes=load(tool/'config/modes.json')
        quality=blocking_evidence(ctx,out,[d for c in verdict['checks'] for d in c['defects']])
        verdict['quality']=quality
        for name,entry in quality['checks'].items():
            entry['requested_mode']=modes['checks'][name]
        quality['blocking_by_measurement']=[name for name,c in quality['checks'].items() if verdict['bound'] and c['requested_mode']=='blocking' and c['source']=='measurement']
        quality['blocking_by_override']=[name for name,c in quality['checks'].items() if verdict['bound'] and c['requested_mode']=='blocking' and c['source']=='override']
        for checked in verdict['checks']:
            for defect in checked['defects']:
                requested=modes['checks'][checked['id']]
                earned=quality['checks'][checked['id']]['source'] in {'override','measurement'}
                defect['mode']=requested if verdict['bound'] and (requested!='blocking' or earned) else 'report_only'
                verdict['defects'].append(defect)
        agent_config=load(tool/'config/agents.json')
        records=[loads(ctx.read(p)) for p in run['operation_records']]
        failure_recorded=any(r.get('exit',0)!=0 or r.get('class') in ['Product defect','product defect','Self-inflicted','self-inflicted','Environment event','environment event','Invocation error','invocation error'] for r in records)
        selected=[] if args.response else select_agents(agent_config,depth,failure_recorded)
        if args.response:verdict['not_run'].append('model agents: response mode; no model calls')
        semantic_unavailable=False
        if not agent_config['enabled']:
            verdict['not_run'] += [a['id']+': model calls disabled; owner configuration required' for a in selected]
            if depth=='sensitive' and not args.response:
                semantic_unavailable=True
        elif verdict['errors'] or any(d['check_id'].startswith('secret.') for d in verdict['defects']) or preflight['defects']:
            verdict['not_run'] += [a['id']+': input or secret/identity check did not admit model inputs' for a in selected]
        elif not args.response:
            data=claims(ctx)
            diff=command(['git','-C',str(repo),'diff','--no-ext-diff','--no-textconv',run['base'],'--'],repo)
            # Agent packet contains facts and diff, never reasoning or peer outputs.
            packet={'claims':data,'changed_paths':changed,'diff':diff['stdout'],
                    'allowed_paths':[str(p) for p in ctx.allowed],'checked_head':run['checked_head'],
                    'dirty':run['dirty'],'status_sha256':run['status_sha256'],
                    'rerun_results':[c for c in verdict['checks'] if c['id']=='rerun'],
                    'failure_records':records if failure_recorded else [],'upstream':run['upstream']}
            for a in selected:
                if a['id']=='independent_rerun' and (any(d['source'].startswith('agent:') for d in verdict['defects']) or
                        any(x['output']['verdict']!='PASS' for x in verdict['agents'])):
                    verdict['not_run'].append('independent_rerun: prior semantic self-checks unresolved')
                    continue
                try:
                    own_packet=dict(packet)
                    if a['id']=='blast_radius':
                        # Remove producer labels before independent enumeration.
                        own_packet['claims']=loads(encode(data))
                        for claim in own_packet['claims']['claims']:
                            claim['blast_radius']=[]
                    measured=call_agent(ctx,a,agent_config,own_packet,agents_out)
                    if a['id']=='blast_radius':
                        own={g['group']:g for g in measured['output']['inventory']}
                        comparisons=[]
                        for c in data['claims']:
                            for g in c['blast_radius']:
                                other=own[g['group']]
                                comparisons.append({'claim_id':c['id'],'group':g['group'],
                                    'producer_label':g['label'],'reviewer_label':other['label'],
                                    'producer_items':g['items'],'reviewer_items':other['items'],
                                    'difference':g['label']!=other['label'] or sorted(g['items'])!=sorted(other['items'])})
                        measured['coverage_comparison']=comparisons
                        measured['coverage_counts']={label:sum(g['label']==label for g in own.values()) for label in ['checked','not_checked','not_applicable']}
                        if any(x['difference'] for x in comparisons):
                            verdict['not_run'].append('blast_radius: producer/self-check inventory differences require reconciliation')
                            verdict['errors'].append('blast-radius inventories disagree; coverage remains unresolved')
                    verdict['agents'].append(measured)
                    if measured['output']['verdict']=='UNKNOWN':
                        verdict['errors'].append(a['id']+': UNKNOWN output')
                        verdict['not_run'].append(a['id']+': load-bearing conclusion UNKNOWN')
                    for f in measured['output']['findings']:
                        d=ctx.defect(f['check_id'],'agent:'+a['id'],f['evidence'][0]['path'],f['claim_id'],f['evidence'],
                                     evidence_key=[a['id'],[(e['path'],e['lines']) for e in f['evidence']]])
                        d['mode']=modes['agents'][a['id']] if verdict['bound'] else 'report_only'
                        verdict['defects'].append(d)
                except Exception as exc:
                    verdict['errors'].append(a['id']+': '+str(exc))
                    verdict['not_run'].append(a['id']+': no valid model result')
        # Recheck all input identities and repository state before a conclusion.
        for checked in verdict['checks']:
            for identity in checked['files']:
                if digest(ctx.read(identity['path']))!=identity['sha256']:
                    raise ToolError('concurrent checked-file change: '+identity['path'])
        observed=dict(ctx.files)
        if any(digest(ctx.read(p))!=sha for p,sha in observed.items()):
            raise ToolError('concurrent orchestration/model evidence change; no conclusion')
        for measured in verdict['agents']:
            identities=dict(measured['instruction_hashes'])
            for finding in measured['output']['findings']:
                identities.update({e['path']:e['sha256'] for e in finding['evidence']})
            if any(digest(ctx.read(p))!=sha for p,sha in identities.items()):
                raise ToolError('model evidence or instruction identity changed after review')
        if any(digest(ctx.read(p))!=sha for p,sha in verdict['input_hashes'].items()) or (not args.response and (metadata['status']!=command(['git','-C',str(repo),'status','--porcelain=v1','-uall'],repo) or verdict['checked_head']!=command(['git','-C',str(repo),'rev-parse','HEAD'],repo)['stdout'].strip())):
            raise ToolError('concurrent input/repository change; no conclusion')
        escalation=any(c['escalate'] for c in verdict['checks'])
        # Identical findings are coalesced, never silently counted twice.
        unique={d['defect_id']:d for d in verdict['defects']}
        verdict['defects']=[unique[k] for k in sorted(unique)]
        verdict['result'],verdict['questions']=decide(verdict['defects'],verdict['errors'],escalation,history,iteration)
        if semantic_unavailable and verdict['result']!='TOOL_ERROR':
            verdict['result']='ESCALATE'
            verdict['questions'].append('Sensitive depth requires semantic checks and rerun review. Configure the required agents or return the task for owner disposition; which applies?')
    except Exception as exc:
        verdict['errors'].append(type(exc).__name__+': '+str(exc))
        verdict['result']='TOOL_ERROR'
        ran={c['id'] for c in verdict['checks']}
        verdict['not_run'] += [c+': setup did not admit execution' for c in CHECKS if c not in ran]
    if history_error and not verdict['errors']:
        verdict['result']='ESCALATE'
        verdict['questions']=[history_error+'. Restore the retained identities or have the owner disposition the altered history; which applies?']
    verdict['not_run']=sorted(set(verdict['not_run']))
    verdict['counts']={'blocking':sum(d['mode']=='blocking' for d in verdict['defects']),
                       'report_only':sum(d['mode']=='report_only' for d in verdict['defects']),
                       'not_run':len(verdict['not_run'])}
    schema(verdict,load(tool/'schemas/verdict.schema.json'))
    create(out/'verdict.json',verdict)
    raw=(out/'verdict.json').read_bytes()
    with (out/'generator_report.md').open('xb') as f:
        f.write(render(verdict,digest(raw)))
    create(out/'seal.json',{name:digest((out/name).read_bytes()) for name in ['verdict.json','generator_report.md']})
    print(json.dumps({'result':verdict['result'],'bound':verdict['bound'],'verdict':str(out/'verdict.json'),
                      'report':str(out/'generator_report.md'),'counts':verdict['counts']}))
    return EXIT[verdict['result']]


if __name__=='__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print('NOT DONE: launcher error: '+str(exc)+'\nFull Blast Radius Check: setup failed; checks not executed\nEnforcement Self-Check: Enforcement is manual; setup failed; all checks not run',file=sys.stderr)
        sys.exit(3)
