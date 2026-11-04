"""Paired tooling fixtures, held-out boundaries and read-only retained-run replay.

No product build/test/model call. Fixture git objects are synthetic test inputs,
not commits to a product repository. Output roots are explicit owner arguments.
"""
import shutil
import zlib
import sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
from common import *
from orchestrate import decide,history_read,depth_for
from render_report import render
from agents import resolve_output,call_agent,validate_instruction
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'checks'))
from citations import validate_citation
from secrets import findings
sys.path.insert(0,str(Path(__file__).resolve().parent))
from improve import compare,resolve_evaluation

CHECK_MODULES=['preflight','scope_paths','citations','report_lint','authority','secrets','qual_naming','rerun','carry_forward']


def manifest(tool):
    paths=sorted(p for p in tool.rglob('*') if p.is_file() and p.name!='MANIFEST.sha256')
    extra=[tool/'../evidence/claude_audits/tools/verify_manifest.py',tool/'../evidence/claude_audits/tools/verify_state_chain.py',tool/'../qualification/reviews/capture_sp1_evidence.py']
    text=''.join(digest(p.read_bytes())+'  '+str(p.relative_to(tool))+'\n' for p in paths)
    for p in extra:
        rel='../qualification/reviews/'+p.name if p.name=='capture_sp1_evidence.py' else '../evidence/claude_audits/tools/'+p.name
        text+=digest(p.read_bytes())+'  '+rel+'\n'
    (tool/'MANIFEST.sha256').write_text(text)


def git_fixture(repo,files):
    repo.mkdir()
    g=repo/'.git';g.mkdir()
    (g/'objects').mkdir();(g/'refs').mkdir();(g/'refs/heads').mkdir()
    (g/'config').write_text('[core]\nrepositoryformatversion = 0\nbare = false\n')
    def object_bytes(kind,data):
        raw=(kind+' '+str(len(data))+'\0').encode()+data
        oid=hashlib.sha1(raw).hexdigest();folder=g/'objects'/oid[:2]
        if not folder.exists():folder.mkdir()
        (folder/oid[2:]).write_bytes(zlib.compress(raw));return oid
    tree=b''
    for name,data in sorted(files.items()):
        (repo/name).write_bytes(data)
        tree+=b'100644 '+name.encode()+b'\0'+bytes.fromhex(object_bytes('blob',data))
    tree_oid=object_bytes('tree',tree)
    commit=object_bytes('commit',f'tree {tree_oid}\nauthor Fixture <fixture@example.invalid> 0 +0000\ncommitter Fixture <fixture@example.invalid> 0 +0000\n\nSynthetic test input\n'.encode())
    (g/'refs/heads/fixture').write_text(commit+'\n');(g/'HEAD').write_text('ref: refs/heads/fixture\n')
    return commit


def fixture(out, tool_source, contract_source, programme_source):
    out=out.resolve(strict=True)
    workspace=out/'workspace';workspace.mkdir()
    (workspace/'NewArc').mkdir();root=workspace/'NewArc/3m';root.mkdir()
    for rel in ['controls','RWA','RWA/start','build','upstream','qualification','qualification/reviews','evidence','evidence/state_updates','evidence/claude_audits','evidence/claude_audits/tools','evidence/stagecheck']:
        (root/rel).mkdir()
    tool=root/'stagecheck';shutil.copytree(tool_source,tool)
    # Installation choices must never enable real product or model execution
    # inside synthetic fixtures. Individual cases supply their own fake grants.
    (tool/'config/commands.json').write_bytes(encode({'enabled':False,'product_grant':None,'commands':[]}))
    fixture_agents=load(tool/'config/agents.json')
    fixture_agents.update(enabled=False,budget_usd=None,timeout_seconds=None)
    for item in fixture_agents['agents']:
        item['model']=None
    (tool/'config/agents.json').write_bytes(encode(fixture_agents))
    for name in ['verify_manifest.py','verify_state_chain.py']:
        shutil.copyfile(programme_source/'evidence/claude_audits/tools'/name,root/'evidence/claude_audits/tools'/name)
    shutil.copyfile(programme_source/'qualification/reviews/capture_sp1_evidence.py',root/'qualification/reviews/capture_sp1_evidence.py')
    state={k:None for k in ['schema_version','programme','architecture','execution_plan','authority','evidence_root','qualification_root','note','source_lock','current_task']}
    state.update(status='SP1_NOT_STARTED',completed_tasks=[],evidence_references=[],open_prerequisites=[])
    protected={k:v for k,v in state.items() if k not in ['status','source_lock','current_task','completed_tasks','evidence_references','open_prerequisites']}
    protected_hash=digest(json.dumps(protected,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode())
    files={
       'controls/DRWA_ACTIVE_STATE.json':encode(state),
       'controls/OWNER_GRANTS.md':b'# Fixture grants\nExpiry: end of SP1\nPermitted execution: selected fixture commands only.\n',
       'controls/FAILURE_PREVENTION.md':b'# Fixture register\n',
       'controls/EVIDENCE_ROOT.json':encode({'root':str(root/'evidence')}),
       'controls/QUALIFICATION_ROOT.json':encode({'root':str(root/'qualification')}),
       'controls/PRODUCT_REPOSITORIES.json':encode({'product_root':str(root/'build'),'untouched_upstream_root':str(root/'upstream')}),
       'RWA/start/RWA_Architecture_v4.2.8.md':b'# Fixture architecture\nSpecification value: accepted\n',
       'RWA/start/DRWA_Development_and_Decision_Plan.md':b'# Fixture plan\n'}
    for rel,data in files.items():
        (root/rel).write_bytes(data)
    start=root/'RWA/start'
    (start/'START_MANIFEST.md').write_text('# Fixture manifest\n'+''.join(f'| `{Path(name).name}` | fixture | `{digest(raw)}` |\n' for name,raw in files.items() if name.startswith('RWA/start/')))
    text=contract_source.read_text()
    original=bindings(contract_source)
    text=text.replace(str(original['root'].parent.parent),str(workspace))
    # Replace each owner identity with an explicitly synthetic fixture identity.
    for role,bound in original.items():
        if isinstance(bound,dict):
            actual=str(bound['path']).replace(str(original['root'].parent.parent),str(workspace))
            text=text.replace(bound['sha256'],digest(Path(actual).read_bytes()))
    text=text.replace(original['protected_sha256'],protected_hash)
    contract=workspace/'contract.txt';contract.write_text(text)
    copy=workspace/'instruction_fixture.txt';copy.write_text(text)
    paths=load(tool/'config/paths.json');paths['instruction_copies']=[str(copy)];(tool/'config/paths.json').write_bytes(encode(paths))
    repo=root/'build/product';head=git_fixture(repo,{'go.mod':b'module fixture\n'})
    # Git index for synthetic fixtures is initialized without creating commits.
    command(['git','-C',str(repo),'read-tree','HEAD'],repo)
    source=repo/'qual_fixture_test.go';source.write_text('package fixture\nfunc TestQualFixture(t *testing.T) {}\n')
    ev=root/'evidence';record=ev/'record.json';record.write_text('{"scope":"fixture only"}\n')
    cite={'type':'document','path':str(start/'RWA_Architecture_v4.2.8.md'),'sha256':digest((start/'RWA_Architecture_v4.2.8.md').read_bytes()),'lines':[2,2],'quote':'Specification value: accepted','approved':True}
    c={'id':'C-001','kind':'observation','text':'Specification value: accepted','scope':'fixture','label':'SOURCE_PROVEN','citations':[cite],'blast_radius':[]}
    data={'task_id':'fixture','iteration':1,'contract_sha256':digest(contract.read_bytes()),'record':str(record),'record_sha256':digest(record.read_bytes()),'claims':[c]}
    claim_path=ev/'claims.json';claim_path.write_bytes(encode(data))
    report=ev/'report.md';report.write_text('NOT DONE: fixture only\nFull Blast Radius Check: fixture source read\nEnforcement Self-Check: Enforcement is manual; fixture only\n\nSpecification value: accepted\n')
    run={'task_id':'fixture','iteration':1,'tool_root':str(tool),'programme_root':str(root),'contract':str(contract),'repo':str(repo),'base':head,'checked_head':head,'claims':str(claim_path),'report':str(report),'depth':'docs','changed_paths':[str(source)],'operation_records':[],'read_paths':[],'upstream':{},'run_path':str(ev/'run.json')}
    (ev/'run.json').write_bytes(encode(run));manifest(tool)
    return run,data,root,tool


def carry_record(root,data,text):
    (root/'RWA/start/DRWA_SP2_Task_Tracker.md').write_text('# Fixture tracker\n| SP2-10 | fixture | b | d | NOT STARTED | — | Carry: bind the epoch before first use |\n')
    record=root/'evidence/RECORD.md';record.write_text(text)
    data['record']=str(record);data['record_sha256']=digest(record.read_bytes())


CARRY_GOOD='NOT DONE: fixture only\nFull Blast Radius Check: fixture\nEnforcement Self-Check: Enforcement is manual; fixture only\n\n## CARRY_FORWARD\n| Source | Obligation | Receiving row |\n|---|---|---|\n| review L22 | bind the epoch | SP2-10 \"Carry: bind the epoch before first use\" |\n- review L21: tests for both flag states -> owner ruling pending\n'


def seed(cid,run,data,root,tool):
    c=data['claims'][0];cite=c['citations'][0];report=Path(run['report']);repo=Path(run['repo'])
    preserve_manifest=False
    if cid=='preflight.bound_hash':
        (root/'controls/OWNER_GRANTS.md').write_text('# Changed fixture grant\n');preserve_manifest=True
    elif cid=='preflight.instructions_differ':
        Path(load(tool/'config/paths.json')['instruction_copies'][0]).write_text('# Changed fixture instruction\n')
    elif cid=='preflight.unlisted_file':
        (tool/'unlisted.txt').write_text('unexpected\n');preserve_manifest=True
    elif cid=='preflight.symlink':
        (tool/'link').symlink_to(tool/'bin/common.py');preserve_manifest=True
    elif cid=='preflight.reused_hash':
        path=root/'evidence/claude_audits/tools/verify_state_chain.py';path.write_bytes(path.read_bytes()+b'\n# changed\n');preserve_manifest=True
    elif cid=='preflight.state_history':
        state=load(root/'controls/DRWA_ACTIVE_STATE.json');state['note']='changed';(root/'controls/DRWA_ACTIVE_STATE.json').write_bytes(encode(state))
    elif cid=='preflight.agent_mapping':
        config=load(tool/'config/agents.json');config['agents']=config['agents'][1:];(tool/'config/agents.json').write_bytes(encode(config))
    elif cid=='preflight.binding_mismatch':
        (root/'controls/STAGECHECK_ROOT.json').write_bytes(encode({'root':str(tool),'manifest_sha256':'0'*64}))
    elif cid=='scope.excluded':
        path=root/'RWA/previous';path.mkdir();f=path/'excluded.md';f.write_text('excluded\n');run['read_paths']=[str(f)]
    elif cid=='scope.draft_approved':
        f=root/'RWA/draft.md';f.write_text('draft\n');cite.update(path=str(f),sha256=digest(f.read_bytes()),lines=[1,1],quote='draft')
    elif cid=='scope.package_span':
        sub=repo/'other';sub.mkdir();f=sub/'x.go';f.write_text('package other\n');run['changed_paths'].append(str(f))
    elif cid=='citation.missing_file':cite['path']=str(root/'RWA/start/missing.md')
    elif cid=='citation.hash_mismatch':cite['sha256']='0'*64
    elif cid=='citation.line_range':cite['lines']=[99,100]
    elif cid=='citation.quote_not_found':cite['quote']='absent text'
    elif cid=='citation.upstream_identity':
        c['citations']=[{'type':'upstream','repository':'fixture upstream','commit':'1'*40,'path':'missing.go','sha256':'0'*64,'lines':[1,1],'quote':'absent'}]
    elif cid=='citation.command_mismatch':
        execution_command(root,run,data);c['citations'][0]['exit_status']=7
    elif cid=='report.headers':report.write_text('NOT DONE: fixture only\nFull Blast Radius Check: fixture source read\n\nSpecification value: accepted\n')
    elif cid=='report.table':report.write_text(report.read_text()+''.join(f'| {i} | checked |\n' for i in range(1,12)))
    elif cid=='report.label':c['text']='SOURCE_PROVEN TEST_PROVEN Specification value: accepted';report.write_text(report.read_text()+'\n'+c['text'])
    elif cid=='report.inference':c.update(label='INFERRED',kind='decision',confidence=0.9)
    elif cid=='report.completion':c.update(kind='completion',blast_radius=[{'group':1,'label':'not_checked','reason':'not exercised','items':[]}])
    elif cid.startswith('report.completion.'):
        c.update(text='Containment is '+cid.rsplit('.',1)[1],blast_radius=[{'group':1,'label':'not_checked','reason':'not exercised','items':[]}])
        report.write_text(report.read_text()+'\n'+c['text']+'\n')
    elif cid=='report.counts':data['counts']={'checked':1,'not_checked':0,'not_applicable':0}
    elif cid=='report.groups':run['depth']='code'
    elif cid=='report.claim_missing':report.write_text('NOT DONE: fixture\nFull Blast Radius Check: source\nEnforcement Self-Check: Enforcement is manual; fixture only\nUnrelated claim\n')
    elif cid.startswith('authority.remote'):
        urls={'authority.remote':'https://github.com/example/fixture.git',
              'authority.remote.multiversx':'https://github.com/multiversx/mx-chain-go.git',
              'authority.remote.other_owner':'git@github.com:other/x'}
        command(['git','-C',str(repo),'config','remote.fixture.url',urls[cid]],repo)
    elif cid in ['authority.upstream_endpoint','authority.grant']:
        path=root/'evidence/operation.json';path.write_bytes(encode({'argv':['curl','https://gateway.multiversx.com/status'] if cid.endswith('upstream_endpoint') else ['go','test','./...'],'cwd':str(repo),'exit':0}));run['operation_records']=[str(path)]
    elif cid=='carry.missing_section':
        carry_record(root,data,CARRY_GOOD.split('## CARRY_FORWARD')[0])
    elif cid=='carry.not_landed':
        carry_record(root,data,CARRY_GOOD+'| review L24 | a hand-off | SP2-10 "an obligation this row does not hold" |\n')
    elif cid=='carry.unrouted':
        carry_record(root,data,CARRY_GOOD+'- review L23: an obligation with no receiving row\n')
    elif cid.startswith('secret.'):
        values={'secret.pem':'-----BEGIN PRIVATE KEY-----\nfixture-only\n','secret.keystore':'{"crypto":{"ciphertext":"fixture-only"}}\n','secret.assignment':'api_key = "fixture-only"\n','secret.filename':'fixture-only\n'}
        path=repo/('.env' if cid=='secret.filename' else 'subject.txt');path.write_text(values[cid]);run['changed_paths']=[str(path)]
    elif cid=='qual.test_name':
        path=repo/'fixture_test.go';path.write_text('package fixture\nfunc TestQualWrong(t *testing.T) {}\n');run['changed_paths']=[str(path)]
    elif cid=='qual.file_name':
        path=repo/'qual_wrong.go';path.write_text('package fixture\nfunc TestOrdinary(t *testing.T) {}\n');run['changed_paths']=[str(path)]
    elif cid=='qual.driver':
        path=repo/'qual_driver.py';path.write_text('# Fixture qualification driver\n');run['changed_paths']=[str(path)]
    elif cid.startswith('rerun.'):
        execution_command(root,run,data,rerun=True)
        config=load(tool/'config/commands.json')
        if cid=='rerun.toolchain':
            config['commands'][0]['argv'][0]='go'
            config['product_grant']['commands'][0]['argv'][0]='go'
            data['claims'][0]['citations'][0]['argv'][0]='go'
        if cid=='rerun.exit':data['claims'][0]['citations'][0]['exit_status']=8
        if cid=='rerun.output':data['claims'][0]['citations'][0]['stdout_sha256']='0'*64
        if cid=='rerun.unselected':config['commands']=[]
        (tool/'config/commands.json').write_bytes(encode(config))
    else:
        raise ToolError('case has no independent seeded mutation: '+cid)
    Path(run['claims']).write_bytes(encode(data));Path(run['run_path']).write_bytes(encode(run))
    if not preserve_manifest:manifest(tool)


def execution_command(root,run,data,rerun=False):
    d=root/'evidence/execution';d.mkdir()
    argv=[str(canonical(sys.executable)),'-c','print("fixture")']
    raw=b'fixture\n';(d/'stdout').write_bytes(raw);(d/'stderr').write_bytes(b'')
    retained={'argv':argv,'cwd':run['repo'],'exit':0,'stdout_sha256':digest(raw),'stderr_sha256':digest(b'')}
    create(d/'execution.json',retained)
    cite={'type':'command','record':str(d/'execution.json'),'record_sha256':digest((d/'execution.json').read_bytes()),'argv':argv,'cwd':run['repo'],'exit_status':0,'stdout_sha256':digest(raw),'stderr_sha256':digest(b'')}
    data['claims'][0]['citations']=[cite]
    if rerun:
        tool=Path(run['tool_root'])
        ledger=root/'controls/OWNER_GRANTS.md'
        grant={'citation':{'type':'document','path':str(ledger),'sha256':digest(ledger.read_bytes()),'lines':[1,3],'quote':ledger.read_text().rstrip()},'expiry_stage':'SP1','commands':[{'argv':argv,'cwd':run['repo']}]}
        grant['commands'].append({'argv':[str(canonical(sys.executable)),'-c','pass'],'cwd':run['repo']})
        config={'enabled':True,'product_grant':grant,'commands':[{'argv':argv,'cwd':run['repo'],'environment':{'GOTOOLCHAIN':'local'},'binary':str(canonical(sys.executable)),'binary_sha256':digest(canonical(sys.executable).read_bytes()),'smoke_argv':[str(canonical(sys.executable)),'-c','pass'],'smoke_timeout_seconds':5,'timeout_seconds':5,'inputs':{}}]}
        (tool/'config/commands.json').write_bytes(encode(config))
        paths=load(tool/'config/paths.json');paths['additional_read_paths']=[str(canonical(sys.executable))];(tool/'config/paths.json').write_bytes(encode(paths))


def execute(run,name,out):
    out.mkdir()
    ctx=Context(run)
    argv=[sys.executable,str(ctx.tool/'checks'/(name+'.py')),'--run',run['run_path'],'--output-dir',str(out)]
    env={k:v for k,v in os.environ.items() if k!='PYTHONPATH'}
    env['PYTHONDONTWRITEBYTECODE']='1'
    executed=command(argv,ctx.tool,timeout=120,env=env)
    create(out/'execution.json',executed)
    value=load(out/(name+'.json'))
    schema(value,load(ctx.tool/'schemas/verdict.schema.json'))
    expected=3 if value['errors'] else 1 if value['defects'] else 0
    if executed['exit_status']!=expected:
        raise ToolError('check exit/output mismatch in fixture')
    create(out/'result.json',value)
    return value


def paired_cases(args,out):
    observed={}
    cases=sorted((args.tool/'evals/cases').glob('*/case.json'))
    for case_file in cases:
        spec=load(case_file);cid=spec['id']
        if spec['target']=='orchestrate':continue
        if args.case and cid not in args.case:continue
        case=out/cid;case.mkdir()
        variants={}
        for twin in ['clean','defective']:
            directory=case/twin;directory.mkdir()
            run,data,root,tool=fixture(directory,args.tool,args.contract,args.root)
            if cid.startswith('authority.remote') and twin=='clean':
                command(['git','-C',run['repo'],'config','remote.fixture.url','DISABLED'],Path(run['repo']))
            if cid.startswith('rerun.') and twin=='clean':
                execution_command(root,run,data,rerun=True);Path(run['claims']).write_bytes(encode(data));manifest(tool)
            if cid.startswith('carry.') and twin=='clean':
                carry_record(root,data,CARRY_GOOD);Path(run['claims']).write_bytes(encode(data))
            if twin=='defective':seed(cid,run,data,root,tool)
            name={'scope':'scope_paths','citation':'citations','report':'report_lint','secret':'secrets','qual':'qual_naming','carry':'carry_forward'}.get(cid.split('.')[0],cid.split('.')[0])
            result1=execute(run,name,directory/'first')
            result2=execute(run,name,directory/'second')
            ids={d['check_id'] for d in result1['defects']}
            correct=(not ids and not result1['errors']) if twin=='clean' else (set(spec['expected'][twin]).issubset(ids) and not result1['errors'])
            deterministic=encode(result1)==encode(result2)
            variants[twin]={'correct':correct,'deterministic':deterministic,'check_ids':sorted(ids),'errors':result1['errors'],'result_sha256':digest(encode(result1))}
        observed[cid]={'ok':all(v['correct'] and v['deterministic'] for v in variants.values()),'variants':variants}
        print(json.dumps({'case':cid,**observed[cid]}),flush=True)
    return observed


def auto_rerun_properties(args,parent,go_class_template):
    """Owner 2026-10-22, lever 2: rule-based reruns of cited go test commands, with a real tiny module and the pinned toolchain."""
    observations={}
    base=parent/'auto_rerun';base.mkdir()
    run,data,root,tool=fixture(base,args.tool,args.contract,args.root)
    go=args.root/'build/.toolchains/go1.26.2/bin/go'
    module=root/'evidence/gomod';module.mkdir()
    (module/'go.mod').write_text('module fixturemod\n\ngo 1.26\n')
    (module/'a_test.go').write_text('package fixturemod\n\nimport "testing"\n\nfunc TestPass(t *testing.T) {}\n\nfunc TestFail(t *testing.T) { t.Fatal("fixture failure") }\n')
    cache=base/'gocache';cache.mkdir();modcache=base/'gomodcache';modcache.mkdir();(base/'home').mkdir()
    env={'GOCACHE':str(cache),'GOMODCACHE':str(modcache),'GOPATH':str(base/'gopath'),'GOTOOLCHAIN':'local','GOFLAGS':'-mod=readonly','GOPROXY':'off','HOME':str(base/'home'),'PATH':os.environ.get('PATH','')}
    def record(name,argv,cwd,stdout=None,exit_status=None):
        d=root/'evidence'/name;d.mkdir()
        executed=command(argv,cwd,timeout=600,env=env)
        out=(stdout if stdout is not None else executed['stdout']).encode()
        (d/'stdout').write_bytes(out);(d/'stderr').write_bytes(executed['stderr'].encode())
        ex=executed['exit_status'] if exit_status is None else exit_status
        create(d/'execution.json',{'argv':argv,'cwd':str(cwd),'exit':ex,'stdout_sha256':digest(out),'stderr_sha256':digest(executed['stderr'].encode())})
        return {'type':'command','record':str(d/'execution.json'),'record_sha256':digest((d/'execution.json').read_bytes()),'argv':argv,'cwd':str(cwd),'exit_status':ex,'stdout_sha256':digest(out),'stderr_sha256':digest(executed['stderr'].encode())},executed
    argv=[str(go),'test','-count=1','-json','./...']
    faithful,executed=record('cited_faithful',argv,module)
    def falsify(line):
        try:event=json.loads(line)
        except ValueError:return line
        if event.get('Action')=='fail' and event.get('Test') in ('TestFail',None):event['Action']='pass'
        return json.dumps(event)
    falsified=''.join(falsify(l)+'\n' for l in executed['stdout'].splitlines())
    observations['auto_rerun_fixture_has_failure']=executed['exit_status']==1 and '"TestFail"' in executed['stdout'] and falsified!=executed['stdout']
    tampered,_=record('cited_tampered',argv,module,stdout=falsified,exit_status=0)
    unsafe,_=record('cited_unsafe',[str(go),'test','-count=1','-json','-coverprofile=cover.out','./...'],module)
    ledger=root/'controls/OWNER_GRANTS.md';ledger_text=ledger.read_text().rstrip()
    go_class={'class':'go_local','citation':{'type':'document','path':str(ledger),'sha256':digest(ledger.read_bytes()),'lines':[1,3],'quote':ledger_text},'expiry_stage':'SP1'}
    auto={'enabled':True,'binary':str(go),'binary_sha256':digest(go.read_bytes()),'subcommands':['test','vet'],'roots':['evidence','build'],'environment':{k:v for k,v in env.items() if k!='PATH'},'timeout_seconds':600,'max_reruns':2}
    def run_with(cites,name,max_reruns=2):
        cfg=load(tool/'config/commands.json');cfg.update(enabled=True,commands=[],class_grants=[go_class],auto_rerun=dict(auto,max_reruns=max_reruns));(tool/'config/commands.json').write_bytes(encode(cfg))
        data['claims'][0]['citations']=cites;Path(run['claims']).write_bytes(encode(data));manifest(tool)
        out=base/('result_'+name);out.mkdir()
        argv2=[sys.executable,str(tool/'checks/rerun.py'),'--run',run['run_path'],'--output-dir',str(out)]
        command(argv2,tool,timeout=900,env={k:v for k,v in os.environ.items() if k!='PYTHONPATH'})
        return load(out/'rerun.json')
    r1=run_with([faithful],'faithful')
    observations['auto_rerun_faithful_clean']=not r1['errors'] and not [d for d in r1['defects'] if d['check_id'].startswith('rerun.')] and any(c['argv'][1]=='test' for c in r1['commands'])
    r2=run_with([tampered],'tampered')
    ids={d['check_id'] for d in r2['defects']}
    observations['auto_rerun_catches_false_pass']=not r2['errors'] and {'rerun.exit','rerun.outcome'}<=ids
    r3=run_with([unsafe],'unsafe')
    observations['auto_rerun_refuses_unsafe_flag']=not r3['commands'] and any('flag not rerunnable: -coverprofile' in x for x in r3['not_run'])
    narrow,_=record('cited_narrow',[str(go),'test','-count=1','-json','-run=^TestPass$','./...'],module)
    r4=run_with([faithful,narrow],'cap',max_reruns=1)
    observations['auto_rerun_cap_enforced']=any('automatic rerun cap reached' in x for x in r4['not_run']) and len([c for c in r4['commands'] if c['argv'][1]=='test'])==1
    r5=run_with([faithful,tampered],'same_command')
    observations['auto_rerun_compares_every_citation']=len([c for c in r5['commands'] if c['argv'][1]=='test'])==1 and {'rerun.exit','rerun.outcome'}<={d['check_id'] for d in r5['defects']}
    from rerun import auto_candidate
    ctx2=Context(run)
    observations['auto_candidate_bounded']=(isinstance(auto_candidate(ctx2,auto,[str(go),'test','-run=X','../other'],str(module)),str)
        and isinstance(auto_candidate(ctx2,auto,[str(go),'build','./...'],str(module)),str)
        and isinstance(auto_candidate(ctx2,auto,['/usr/bin/go','test','./...'],str(module)),str)
        and isinstance(auto_candidate(ctx2,auto,[str(go),'test','-exec=x','./...'],str(module)),str)
        and isinstance(auto_candidate(ctx2,auto,[str(go),'test','-bench','X','./...'],str(module)),str)
        and isinstance(auto_candidate(ctx2,auto,[str(go),'test','-run'],str(module)),str)
        and isinstance(auto_candidate(ctx2,auto,[str(go),'test','-count','x','./...'],str(module)),str)
        and not isinstance(auto_candidate(ctx2,auto,[str(go),'test','-race','-run=^TestPass$','./...'],str(module)),str)
        and not isinstance(auto_candidate(ctx2,auto,[str(go),'test','-buildvcs=false','-count=1','-timeout','60m','-run','^TestPass$','-json','./...'],str(module)),str))
    return observations


def properties(args,out):
    directory=out/'properties';directory.mkdir()
    run,data,root,tool=fixture(directory,args.tool,args.contract,args.root)
    ctx=Context(run)
    observations={}
    observations['installation_execution_isolated']=not load(tool/'config/commands.json')['enabled'] and not load(tool/'config/agents.json')['enabled']
    config_instructions=load(tool/'config/agents.json')
    docs=[('common','00_common.md'),('orchestrator',config_instructions['orchestrator_instruction'])]+[(a['id'],a['instruction']) for a in config_instructions['agents']]
    observations['instruction_structure']=all(validate_instruction(ctx,role,file) for role,file in docs)
    main_doc=tool/'agent_instructions/orchestrator.md';original_doc=main_doc.read_bytes()
    main_doc.write_text('# Purpose\nRole: `orchestrator`.\n')
    try:validate_instruction(ctx,'orchestrator','orchestrator.md');observations['instruction_truncation_rejected']=False
    except ToolError:observations['instruction_truncation_rejected']=True
    main_doc.write_bytes(original_doc)
    skeleton='# Purpose\nRole: `orchestrator`.\n# Inputs\n# Checks\n'+''.join('### ORCHESTRATOR-'+str(i).zfill(3)+' Empty criterion\n' for i in range(1,31))+'# Verdict rules\n# Must not\n# Output\n'+('\n'*1100)
    main_doc.write_text(skeleton)
    try:validate_instruction(ctx,'orchestrator','orchestrator.md');observations['instruction_padding_rejected']=False
    except ToolError:observations['instruction_padding_rejected']=True
    main_doc.write_bytes(original_doc)
    observations['compact_criterion_identity_preserved']=all(len(re.findall(r'^### [A-Z_]+-[0-9]{3} ',ctx.read(tool/'agent_instructions'/file).decode(),re.M))==30 for _,file in docs)
    inventory=[{'group':i,'label':'not_checked','reason':'source not inspected','items':[]} for i in range(1,12)]
    partial={'type':'agent','id':'blast_radius','verdict':'PASS','findings':[],'not_rerun':[],'inventory':inventory}
    try:resolve_output(encode(partial),'blast_radius',ctx);observations['unchecked_blast_pass_rejected']=False
    except ToolError:observations['unchecked_blast_pass_rejected']=True
    partial['verdict']='UNKNOWN';partial['not_rerun']=['applicable sources uninspected']
    observations['partial_blast_unknown_accepted']=resolve_output(encode(partial),'blast_radius',ctx)['verdict']=='UNKNOWN'
    hist=directory/'numeric_history';hist.mkdir();previous={}
    for i in range(1,12):
        entry=hist/str(i);entry.mkdir();create(entry/'verdict.json',{'result':'TOOL_ERROR','previous':previous,'defects':[]})
        (entry/'generator_report.md').write_text('NOT DONE: fixture\nFull Blast Radius Check: synthetic history\nEnforcement Self-Check: Enforcement is manual; fixture history only\n')
        previous={n:digest((entry/n).read_bytes()) for n in ['verdict.json','generator_report.md']};create(entry/'seal.json',previous)
    observations['numeric_attempt_history']=len(history_read(hist))==11
    for name,raw in [('invalid_json',b'{'),('duplicate_json',b'{"x":1,"x":2}'),('nonfinite',b'{"x":NaN}')]:
        try:loads(raw);observations[name]=False
        except Exception:observations[name]=True
    broken=dict(data,unknown=1)
    try:schema(broken,load(tool/'schemas/claims.schema.json'));observations['unknown_field']=False
    except ToolError:observations['unknown_field']=True
    for name,raw in [('agent_invalid_json',b'{}'),('agent_wrong_id',encode({'type':'agent','id':'wrong','verdict':'PASS','findings':[],'not_rerun':[]}))]:
        try:resolve_output(raw,'claim_support',ctx);observations[name]=False
        except Exception:observations[name]=True
    d=ctx.defect('citation.quote_not_found','checks/citations.py',run['claims'],'C-001')
    observations['stable_defect_ids']=d['defect_id']==ctx.defect('citation.quote_not_found','checks/citations.py',run['claims'],'C-001')['defect_id'] and d['defect_id']!=ctx.defect('citation.quote_not_found','checks/citations.py',run['claims'],'C-002')['defect_id']
    observations['distinct_citation_ids']=ctx.defect('citation.quote_not_found','checks/citations.py',run['claims'],'C-001',evidence_key=0)['defect_id']!=ctx.defect('citation.quote_not_found','checks/citations.py',run['claims'],'C-001',evidence_key=1)['defect_id']
    original_role=ctx.defect('report.headers','checks/report_lint.py',run['report'])
    replacement=root/'evidence/report_next.md';replacement.write_bytes(Path(run['report']).read_bytes())
    original_report=run['report'];run['report']=str(replacement)
    observations['id_stable_across_input_locations']=original_role['defect_id']==ctx.defect('report.headers','checks/report_lint.py',str(replacement))['defect_id']
    run['report']=original_report
    d['mode']='blocking'
    old={'defects':[d]};empty={'defects':[]}
    observations['recurrence']=decide([dict(d)],[],False,[{'verdict':old},{'verdict':empty}],3)[0]=='ESCALATE'
    observations['no_progress']=decide([dict(d)],[],False,[{'verdict':old}],2)[0]=='ESCALATE'
    observations['repair_bound']=decide([dict(d)],[],False,[],4)[0]=='ESCALATE'
    observations['tool_error']=decide([],['crash'],False,[],1)[0]=='TOOL_ERROR'
    observations['blocking']=decide([dict(d)],[],False,[],1)[0]=='BLOCKED'
    observations['clear']=decide([],[],False,[],1)[0]=='CLEAR'
    fake={'type':'verdict','task_id':'fixture','iteration':1,'contract_sha256':'1'*64,'checked_head':'fixture','manifest_sha256':'2'*64,'bound':False,'depth':'docs','input_hashes':{},'previous':{},'checks':[],'agents':[],'defects':[d],'not_run':['claim_support: disabled'],'errors':[],'result':'BLOCKED','questions':[],'counts':{'blocking':1,'report_only':0,'not_run':1}}
    rendered=render(fake,digest(encode(fake))).decode()
    observations['renderer']=rendered.startswith('NOT DONE:') and rendered.count('### '+d['defect_id'])==1 and 'Result: UNBOUND advisory' in rendered
    observations['renderer_unresolved_finding_header']=d['check_id'] in rendered.splitlines()[0]
    failed=dict(fake,not_run=[],checks=[dict(result('rerun'),commands=[{'argv':['fixture-command'],'cwd':run['repo'],'exit_status':1,'stdout_sha256':'0'*64,'stderr_sha256':'0'*64}])])
    observations['renderer_failed_command_header']='rerun: command exited 1' in render(failed,digest(encode(failed))).decode().splitlines()[0]
    golden=load(args.tool/'evals/cases/renderer/verdict.json')
    observations['renderer_golden_bytes']=render(golden,'3'*64)==(args.tool/'evals/cases/renderer/golden.md').read_bytes()
    advisory=loads(encode(fake));advisory['defects'][0]['mode']='report_only'
    advisory['not_run']=['claim_support: disabled','blast_radius: disabled']
    third=render(advisory,'3'*64).decode().splitlines()[2]
    observations['renderer_enforcement_inventory']=third==('Enforcement Self-Check: Enforcement is manual; not run: claim_support: disabled; not run: blast_radius: disabled; report-only because unbound: '+d['check_id']+' ('+d['defect_id']+')')
    err=dict(golden,errors=['fixture error'])
    observations['renderer_error_limits']='all applied' not in render(err,'3'*64).decode().splitlines()[2]
    from report_lint import check as lint_report
    original_bytes=Path(run['report']).read_bytes()
    healthy=['NOT DONE: fixture','Full Blast Radius Check: source','Enforcement Self-Check: Enforcement is manual; fixture only']
    header_results=[]
    for lines,want in [(healthy,False),([healthy[0],healthy[2],healthy[1]],True),([healthy[0],healthy[1]],True),(['',healthy[0],'',healthy[1],'',healthy[2]],False)]:
        Path(run['report']).write_text('\n'.join(lines)+'\nSpecification value: accepted\n')
        value=result('report_lint');lint_report(Context(run),value)
        header_results.append(any(x['check_id']=='report.headers' for x in value['defects'])==want)
    Path(run['report']).write_bytes(original_bytes)
    observations['three_header_order_and_blanks']=all(header_results)
    vocabulary=load(tool/'config/controlled_vocabulary.json')
    source_contract=Path(run['contract']).read_text()
    controlled=source_contract.split('The following words are scope-bound',1)[1].split('The following success synonyms',1)[0]
    synonyms=source_contract.split('The following success synonyms',1)[1].split('When evidence is incomplete',1)[0]
    observations['vocabulary_matches_contract']=re.findall(r'`([^`]+)`',controlled)==vocabulary['controlled'] and re.findall(r'`([^`]+)`',synonyms)==vocabulary['synonyms']
    old_claim=loads(encode(data['claims'][0]));terms=vocabulary['controlled']+vocabulary['synonyms'];word_results=[]
    for term in terms:
        data['claims'][0].update(text='Scoped observation: '+term.upper(),blast_radius=[{'group':1,'label':'not_checked','reason':'fixture missing consumer','items':[]}])
        Path(run['claims']).write_bytes(encode(data));Path(run['report']).write_text('\n'.join(healthy)+'\n'+data['claims'][0]['text']+'\n')
        value=result('report_lint');lint_report(Context(run),value)
        word_results.append(any(x['check_id']=='report.completion' for x in value['defects']))
    observations['revision2_all_controlled_terms']=all(word_results)
    data['claims'][0].update(text='prefiximplementedSuffix is an identifier',blast_radius=[{'group':1,'label':'not_checked','reason':'fixture missing consumer','items':[]}])
    Path(run['claims']).write_bytes(encode(data));Path(run['report']).write_text('\n'.join(healthy)+'\n'+data['claims'][0]['text']+'\n')
    value=result('report_lint');lint_report(Context(run),value)
    observations['controlled_word_boundaries']=not any(x['check_id']=='report.completion' for x in value['defects'])
    data['claims'][0]=old_claim;Path(run['claims']).write_bytes(encode(data));Path(run['report']).write_bytes(original_bytes)
    # Held-out source/escape/hash cases; no model ever receives this inventory.
    cite=dict(data['claims'][0]['citations'][0],lines=[1,1])
    observations['heldout.quote_elsewhere']=validate_citation(ctx,cite)=='citation.quote_not_found'
    excluded=root/'RWA/previous';excluded.mkdir();target=excluded/'x.txt';target.write_text('excluded\n');link=root/'RWA/link';link.symlink_to(target)
    observations['heldout.symlink_escape']=not ctx.permitted(link)
    observations['heldout.secret_hash_clean']=not findings('hashes.txt',('f'*64+'\n')*10)
    observations['heldout.unknown_agent']=resolve_output(encode({'type':'agent','id':'claim_support','verdict':'UNKNOWN','findings':[],'not_rerun':['source unavailable']}),'claim_support',ctx)['verdict']=='UNKNOWN'
    # Genuine pinned upstream fixture: clean commit and source, then absent path.
    upstream=root/'upstream/fixture';commit=git_fixture(upstream,{'source.go':b'package fixture\n'})
    run['upstream']={'fixture':{'checkout':str(upstream),'commit':commit}}
    upstream_cite={'type':'upstream','repository':'fixture','commit':commit,'path':'source.go','sha256':digest(b'package fixture\n'),'lines':[1,1],'quote':'package fixture'}
    observations['upstream_clean']=validate_citation(ctx,upstream_cite) is None
    upstream_cite['path']='absent.go'
    observations['upstream_absent']=validate_citation(ctx,upstream_cite)=='citation.upstream_identity'
    # Expiration and generator-controlled grants cannot authorize an operation.
    from authority import grant_valid,consequential,forbidden_endpoint,approved_remote
    observations['remote_literal_disabled']=approved_remote('DISABLED',[]) and all(not approved_remote(v,[]) for v in ['disabled',' DISABLED','DISABLED ','DISABLED/x','https://github.com/multiversx/x','git@github.com:other/x'])
    observations['remote_approval_still_required']=not approved_remote('https://github.com/xorewa/x',[]) and approved_remote('https://github.com/xorewa/x',['https://github.com/xorewa/x']) and not approved_remote('https://github.com/multiversx/x',['https://github.com/multiversx/x'])
    mutations=[['git','branch','-D','fixture'],['git','remote','add','fixture','https://example.invalid/x'],['git','push','origin','branch'],['git','diff','--output=output.txt'],['git','diff','--ext-diff'],['rg','--pre','fixture-helper','pattern']]
    diagnostics=[['git','-C',run['repo'],'status','--porcelain=v1'],['git','branch','--show-current'],['git','remote'],['git','remote','get-url','--push','--all','origin'],['git','diff','--no-ext-diff','--no-textconv','HEAD','--'],['rg','--files']]
    observations['mutating_commands_need_grants']=all(consequential(a) for a in mutations)
    observations['known_read_diagnostics_unblocked']=all(not consequential(a) for a in diagnostics)
    # Owner 2026-10-22: harmless -c keys keep read-only git reads unblocked; program-starting keys do not.
    safe_c=[['git','-c','protocol.allow=never','-C',run['repo'],'log','--oneline','-1'],['git','-c','protocol.allow=never','show','HEAD:go.mod'],['git','-c','gc.auto=0','ls-tree','HEAD']]
    unsafe_c=[['git','-c','core.fsmonitor=fixture-helper','status'],['git','-c','diff.external=fixture-helper','diff'],['git','-c','core.pager=fixture-helper','log'],['git','-c','protocol.allow=never','fetch','origin'],['git','-c','protocol.allow=never','log','--output=out.txt']]
    observations['safe_config_reads_unblocked']=all(not consequential(a) for a in safe_c)
    observations['program_config_or_mutation_needs_grant']=all(consequential(a) for a in unsafe_c)
    # Owner 2026-10-22: state history is judged per record against the identity in force at its time.
    from preflight import state_history_findings,WRITABLE,PROTECTED
    def history_case(records):
        d=directory/('history_'+str(len(list(directory.glob('history_*')))));(d/'evidence/state_updates').mkdir(parents=True)
        for n,(r,b,a) in enumerate(records,1):
            create(d/f'evidence/state_updates/{n:04d}.json',r);create(d/f'evidence/state_updates/{n:04d}.before.json',b);create(d/f'evidence/state_updates/{n:04d}.after.json',a)
        return d
    def ph(s):return digest(json.dumps({k:s[k] for k in sorted(PROTECTED)},sort_keys=True,separators=(',',':'),ensure_ascii=False).encode())
    s0={k:None for k in WRITABLE|PROTECTED};s0['status']='SP1_IN_PROGRESS'
    s1=dict(s0,status='SP1_EVIDENCE_PREPARED');s2=dict(s1,authority='rebound');s3=dict(s2,status='SP2_IN_PROGRESS')
    meta={'reason':'fixture','supporting_evidence':['fixture']}
    good=[(dict(meta,actor='codex',changed_fields=['status']),s0,s1),(dict(meta,actor='owner (installer)',changed_fields=['authority']),s1,s2),(dict(meta,actor='codex',changed_fields=['status']),s2,s3)]
    read=lambda p:json.loads(Path(p).read_text())
    observations['history_owner_rebind_accepted']=state_history_findings(history_case(good),ph(s3),read)==[]
    observations['history_agent_protected_change_rejected']=len(state_history_findings(history_case([good[0],(dict(meta,actor='codex',changed_fields=['authority']),s1,s2),good[2]]),ph(s3),read))==1
    observations['history_broken_link_rejected']=len(state_history_findings(history_case([good[0],(good[1][0],s0,s2),good[2]]),ph(s3),read))==1
    observations['history_undeclared_change_rejected']=len(state_history_findings(history_case([(dict(meta,actor='codex',changed_fields=[]),s0,s1)]+good[1:]),ph(s3),read))==1
    observations['history_stale_tip_rejected']=len(state_history_findings(history_case(good),ph(s1),read))==1
    observations['legacy_apex_endpoint_rejected']=forbidden_endpoint(['curl','https://elrond.com/api'])
    observations['unrelated_endpoint_unblocked']=not forbidden_endpoint(['curl','https://example.invalid/api'])
    agent_path=data['claims'][0]['citations'][0]['path']
    observations['semantic_role_ids_distinct']=ctx.defect('agent.unsupported','agent:claim_support',agent_path,'C-001',evidence_key=['claim_support',[(agent_path,[2,2])]])['defect_id']!=ctx.defect('agent.unsupported','agent:upstream_reuse',agent_path,'C-001',evidence_key=['upstream_reuse',[(agent_path,[2,2])]])['defect_id']
    ledger=root/'controls/OWNER_GRANTS.md'
    expired={'citation':{'type':'document','path':str(ledger),'sha256':digest(ledger.read_bytes()),'lines':[1,3],'quote':ledger.read_text().rstrip()},'expires_utc':'2000-01-01T00:00:00Z','commands':[{'argv':['go','test'],'cwd':run['repo']}]}
    observations['expired_grant']=not grant_valid(ctx,expired,['go','test'],run['repo'])
    # Owner 2026-10-22: wider read-only class; anything that can write or start a program stays consequential.
    from authority import class_grant_valid
    reads=[['git','-c','protocol.allow=never','-C',run['repo'],'tag','--points-at','HEAD'],['git','grep','-n','x'],['git','remote','-v'],['git','for-each-ref','refs/remotes'],['git','rev-list','--count','HEAD'],['git','cat-file','-p','HEAD'],['git','--git-dir=/tmp/x.git','log','-1'],
           ['grep','-rn','x','.'],['sed','-n','1,5p','f'],['sed','-n','-e','3p','f'],['head','-5','f'],['tail','-n','2','f'],['wc','-l','f'],['diff','-u','a','b'],['ls','-la'],['sort','f'],['uniq','f'],['jq','.','f'],['find','.','-name','*.go']]
    writes=[['git','tag','-d','v1'],['git','tag','v2'],['git','merge-tree','--write-tree','a','b'],['git','cat-file','--textconv','HEAD:f'],['git','grep','-O','x'],['git','remote','add','x','y'],
            ['sed','-i','s/a/b/','f'],['sed','-ni','1p','f'],['sed','-n','-e','1p','-e','w out','f'],['sed','-n','1e date','f'],['sed','s/a/b/','f'],['sed','-n','-f','script','f'],['sort','-o','out','f'],['sort','-uo','out','f'],['uniq','in','out'],['find','.','-delete'],['find','.','-exec','rm','{}',';'],['python3','x.py']]
    observations['wider_read_class_unblocked']=all(not consequential(a) for a in reads)
    observations['writers_and_programs_need_grant']=all(consequential(a) for a in writes)
    ledger_text=ledger.read_text().rstrip()
    go_class={'class':'go_local','citation':{'type':'document','path':str(ledger),'sha256':digest(ledger.read_bytes()),'lines':[1,3],'quote':ledger_text},'expiry_stage':'SP1'}
    observations['go_class_grant_accepted']=class_grant_valid(ctx,go_class,['go','test','./...']) and class_grant_valid(ctx,go_class,['go','vet','./...'])
    observations.update(auto_rerun_properties(args,directory,go_class))
    observations['go_class_grant_bounded']=not class_grant_valid(ctx,go_class,['go','run','x.go']) and not class_grant_valid(ctx,go_class,['curl','x']) and not class_grant_valid(ctx,dict(go_class,expiry_stage='SP2'),['go','test']) and not class_grant_valid(ctx,dict(go_class,citation=dict(go_class['citation'],quote='Expiry: end of SP1')),['go','test'])
    installed={'paired':{'escaped':False},'heldout':{'case':True},'replay':{'past':True},'confirmed_defect':True}
    candidate={'paired':{'escaped':True},'heldout':{'case':True},'replay':{'past':True},'owner_label_record':'fixture-only'}
    observations['improvement']=compare(installed,candidate,'escaped')['admissible'] is True
    try:resolve_evaluation(ctx,candidate);observations['improvement_requires_evidence']=False
    except ToolError:observations['improvement_requires_evidence']=True
    candidate['heldout']['case']=False
    try:compare(installed,candidate,'escaped');observations['improvement_regression']=False
    except ToolError:observations['improvement_regression']=True
    # Run the real launcher against fixture bytes, not a product repository.
    # After each alteration, retain a separate task/attempt; never overwrite.
    launcher=[sys.executable,str(tool/'bin/orchestrate.py'),'--task','launcher','--repo',run['repo'],'--base',run['base'],'--report',run['report'],'--claims',run['claims'],'--root',str(root),'--contract',run['contract'],'--allow-dirty']
    data['task_id']='launcher';Path(run['claims']).write_bytes(encode(data));manifest(tool)
    first=command(launcher,tool,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
    create(directory/'launcher_first.json',first)
    observations['full_launcher']=first['exit_status']==0
    first_verdict=load(root/'evidence/stagecheck/launcher/1/verdict.json')
    first_status=load(root/'evidence/stagecheck/launcher/1/repository_status.json')
    first_text=(root/'evidence/stagecheck/launcher/1/generator_report.md').read_text()
    observations['dirty_override_identity']=first_verdict['dirty'] is True and first_verdict['status_sha256']==first_status['stdout_sha256'] and 'working tree dirty (working-tree bytes)' in first_text
    refusal=list(launcher);refusal.remove('--allow-dirty');refusal[refusal.index('--task')+1]='dirty_refusal'
    data['task_id']='dirty_refusal';Path(run['claims']).write_bytes(encode(data))
    refused=command(refusal,tool,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'});create(directory/'dirty_refusal.json',refused)
    refusal_verdict=load(root/'evidence/stagecheck/dirty_refusal/1/verdict.json')
    observations['dirty_default_refused']=refused['exit_status']==3 and refusal_verdict['dirty'] and not refusal_verdict['checks'] and 'dirty repository refused' in '\n'.join(refusal_verdict['errors'])
    Path(run['repo'],'qual_fixture_test.go').unlink()
    data['task_id']='clean_default';Path(run['claims']).write_bytes(encode(data));clean_launch=list(refusal);clean_launch[clean_launch.index('--task')+1]='clean_default'
    clean_run=command(clean_launch,tool,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'});create(directory/'clean_default.json',clean_run)
    clean_verdict=load(root/'evidence/stagecheck/clean_default/1/verdict.json')
    observations['clean_default_admitted']=clean_run['exit_status']==0 and clean_verdict['dirty'] is False and clean_verdict['status_sha256']==digest(b'')
    Path(run['repo'],'qual_fixture_test.go').write_text('package fixture\nfunc TestQualFixture(t *testing.T) {}\n')
    data['task_id']='launcher';Path(run['claims']).write_bytes(encode(data))
    depth_config=load(tool/'config/depth.json');proto=Path(run['repo'])/'fixture.proto'
    observations['unapproved_depth_ignored']=depth_for([str(proto)],Path(run['repo']),None,dict(depth_config,approved=False))=='docs'
    observations['explicit_depth_preserved']=depth_for([str(proto)],Path(run['repo']),'code',dict(depth_config,approved=False))=='code'
    observations['approved_depth_monotonic']=depth_for([str(proto)],Path(run['repo']),'docs',dict(depth_config,approved=True))=='sensitive'
    semantic=list(launcher);semantic[semantic.index('--task')+1]='sensitive_unavailable';semantic+=['--depth','sensitive']
    semantic_results=[]
    for iteration in [1,2]:
        data.update(task_id='sensitive_unavailable',iteration=iteration);Path(run['claims']).write_bytes(encode(data))
        execution=command(semantic,tool,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'});create(directory/('semantic_unavailable_'+str(iteration)+'.json'),execution)
        measured=load(root/'evidence/stagecheck/sensitive_unavailable'/str(iteration)/'verdict.json')
        semantic_results.append(execution['exit_status']==2 and measured['result']=='ESCALATE' and measured['iteration']==iteration and not measured['errors'] and bool(measured['questions']))
    observations['disabled_sensitive_escalates_and_counts']=all(semantic_results)
    unselected_dir=directory/'unselected_launcher';unselected_dir.mkdir()
    ur,ud,uroot,utool=fixture(unselected_dir,args.tool,args.contract,args.root)
    execution_command(uroot,ur,ud,rerun=True);uc=load(utool/'config/commands.json');uc['commands']=[];(utool/'config/commands.json').write_bytes(encode(uc));Path(ur['claims']).write_bytes(encode(ud));manifest(utool)
    ua=[sys.executable,str(utool/'bin/orchestrate.py'),'--task','fixture','--repo',ur['repo'],'--base',ur['base'],'--report',ur['report'],'--claims',ur['claims'],'--root',str(uroot),'--contract',ur['contract'],'--allow-dirty']
    ux=command(ua,utool,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'});create(directory/'unselected_command_launcher.json',ux)
    uv=load(uroot/'evidence/stagecheck/fixture/1/verdict.json');rerun_result=next(x for x in uv['checks'] if x['id']=='rerun')
    observations['unselected_preserves_other_checks']=ux['exit_status']==0 and len(uv['checks'])==len(CHECK_MODULES) and not uv['errors'] and any(x['check_id']=='rerun.unselected' for x in uv['defects']) and not rerun_result['commands'] and bool(rerun_result['not_run'])
    data.update(task_id='launcher',iteration=1);Path(run['claims']).write_bytes(encode(data))
    prior=root/'evidence/stagecheck/launcher/1/verdict.json'
    prior.write_bytes(prior.read_bytes()+b' ')
    data['iteration']=1;Path(run['claims']).write_bytes(encode(data))
    second=command(launcher,tool,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
    create(directory/'launcher_tamper.json',second)
    observations['altered_verdict']=second['exit_status']==2
    # A separately retained task demonstrates report tampering and a crashing
    # script without relying on an abstract mocked decide() outcome.
    data['task_id']='report_tamper';data['iteration']=1;Path(run['claims']).write_bytes(encode(data))
    launch2=list(launcher);launch2[launch2.index('--task')+1]='report_tamper'
    first2=command(launch2,tool,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
    report_path=root/'evidence/stagecheck/report_tamper/1/generator_report.md'
    report_path.write_bytes(report_path.read_bytes()+b'changed')
    second2=command(launch2,tool,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
    create(directory/'launcher_report_tamper.json',second2)
    observations['altered_report']=first2['exit_status']==0 and second2['exit_status']==2
    data['task_id']='check_crash';data['iteration']=1;Path(run['claims']).write_bytes(encode(data))
    (tool/'checks/citations.py').write_text('raise RuntimeError("seeded fixture crash")\n');manifest(tool)
    launch3=list(launcher);launch3[launch3.index('--task')+1]='check_crash'
    crashed=command(launch3,tool,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
    create(directory/'launcher_crash.json',crashed)
    observations['check_crash']=crashed['exit_status']==3
    # Restore fixture source, then exercise malformed claims through the launcher.
    shutil.copyfile(args.tool/'checks/citations.py',tool/'checks/citations.py');manifest(tool)
    data['task_id']='malformed';Path(run['claims']).write_text('{')
    launch4=list(launcher);launch4[launch4.index('--task')+1]='malformed'
    malformed=command(launch4,tool,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
    create(directory/'launcher_malformed.json',malformed)
    observations['malformed_claims']=malformed['exit_status']==3
    data['task_id']='shell_launcher';data['iteration']=1;Path(run['claims']).write_bytes(encode(data))
    shell_launch=[str(tool/'bin/stagecheck.sh'),*launcher[2:]]
    shell_launch[shell_launch.index('--task')+1]='shell_launcher'
    shell_result=command(shell_launch,tool,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
    create(directory/'launcher_shell.json',shell_result)
    observations['shell_launcher']=shell_result['exit_status']==0
    # Same-task concurrency must never overwrite an existing attempt. Both
    # callers supply iteration 1; only one may obtain a successful conclusion.
    data['task_id']='concurrent';data['iteration']=1;Path(run['claims']).write_bytes(encode(data))
    concurrent=list(launcher);concurrent[concurrent.index('--task')+1]='concurrent'
    workers=[subprocess.Popen(concurrent,cwd=tool,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},stdout=subprocess.PIPE,stderr=subprocess.PIPE) for _ in range(2)]
    concurrent_results=[]
    for worker in workers:
        stdout,stderr=worker.communicate(timeout=120)
        concurrent_results.append({'exit':worker.returncode,'stdout_sha256':digest(stdout),'stderr_sha256':digest(stderr),'stdout':stdout.decode(),'stderr':stderr.decode()})
    create(directory/'concurrent.json',concurrent_results)
    observations['concurrent_same_task']=sum(x['exit']==0 for x in concurrent_results)==1 and all(x['exit'] in [0,2,3] for x in concurrent_results)
    # Exercise actual interruption before publication, with no production seam.
    # The isolated fixture is compiled first and its new manifest retained.
    fixture_script=tool/'bin/orchestrate.py'
    normal=fixture_script.read_bytes()
    mutant=normal.replace(b"    create(out/'verdict.json',verdict)",b"    raise SystemExit(9)  # seeded interruption before publication\n    create(out/'verdict.json',verdict)")
    if mutant==normal:raise ToolError('publication crash fixture did not find its exact source boundary')
    compile(mutant,str(fixture_script),'exec');fixture_script.write_bytes(mutant);manifest(tool)
    data['task_id']='publication_crash';Path(run['claims']).write_bytes(encode(data))
    crash_launch=list(launcher);crash_launch[crash_launch.index('--task')+1]='publication_crash'
    crashed_publish=command(crash_launch,tool,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
    create(directory/'publication_crash.json',crashed_publish)
    attempt=root/'evidence/stagecheck/publication_crash/1'
    retained_before={str(p):digest(p.read_bytes()) for p in attempt.rglob('*') if p.is_file()}
    observations['publication_crash']=crashed_publish['exit_status']==9 and not (attempt/'seal.json').exists()
    fixture_script.write_bytes(normal);manifest(tool)
    recovered=command(crash_launch,tool,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
    create(directory/'publication_recovery.json',recovered)
    observations['partial_publication_recovery']=recovered['exit_status'] in [2,3] and all(digest(Path(p).read_bytes())==sha for p,sha in retained_before.items())
    # Owner-directed output overrides retain history semantics and cannot escape
    # the bound evidence root or pass through a symlink, even to an allowed root.
    data['task_id']='override';data['iteration']=1;Path(run['claims']).write_bytes(encode(data))
    override=list(launcher);override[override.index('--task')+1]='override'
    destination=root/'evidence/custom_attempt'
    overridden=command(override+['--output-dir',str(destination)],tool,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
    create(directory/'launcher_override.json',overridden)
    observations['output_override']=overridden['exit_status']==0 and (destination/'1/seal.json').is_file() and not (root/'evidence/stagecheck/override').exists()
    escaped=root.parent/'escaped_attempt'
    escaped_run=command(override+['--output-dir',str(escaped)],tool,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
    create(directory/'launcher_escape.json',escaped_run)
    observations['output_escape_refused']=escaped_run['exit_status']==3 and not escaped.exists()
    linked=root/'evidence/output_link';linked.symlink_to(destination)
    linked_run=command(override+['--output-dir',str(linked/'other')],tool,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
    create(directory/'launcher_symlink.json',linked_run)
    observations['output_symlink_refused']=linked_run['exit_status']==3 and not (destination/'other').exists()
    headers=['NOT DONE:','Full Blast Radius Check:','Enforcement Self-Check:']
    observations['launcher_error_headers']=all(line.startswith(header) for line,header in zip(escaped_run['stderr'].splitlines(),headers)) and len(escaped_run['stderr'].splitlines())==3
    descriptor=root/'controls/EVIDENCE_ROOT.json';original_descriptor=descriptor.read_bytes();descriptor.write_bytes(original_descriptor+b' ')
    binding_run=command(override+['--output-dir',str(root/'evidence/binding_attempt')],tool,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
    descriptor.write_bytes(original_descriptor);create(directory/'launcher_binding.json',binding_run)
    observations['launcher_binding_headers']=binding_run['exit_status']==2 and len(binding_run['stdout'].splitlines())==3 and all(line.startswith(header) for line,header in zip(binding_run['stdout'].splitlines(),headers)) and not (root/'evidence/binding_attempt').exists()
    pipe=root/'evidence/nonregular.pipe';os.mkfifo(pipe)
    try:ctx.read(pipe);observations['nonregular_input']=False
    except ToolError:observations['nonregular_input']=True
    # CLI call-path tests use a deterministic local stub, never a model API.
    response=tool/'bin/stub_response.json'
    response.write_bytes(encode({'type':'agent','id':'claim_support','verdict':'PASS','findings':[],'not_rerun':[]}))
    binary=tool/'bin/stub_claude.py'
    supported_flags='--bare --print --tools --allowedTools --output-format --json-schema --system-prompt-file --settings --model --max-budget-usd --no-session-persistence --disable-slash-commands --strict-mcp-config --mcp-config --setting-sources --permission-mode'
    binary.write_text('#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\nif "--help" in sys.argv:\n print('+repr(supported_flags)+')\nelse:\n print((Path(__file__).parent/"stub_response.json").read_text())\n')
    binary.chmod(0o755)
    settings=load(tool/'settings/claude.settings.json');settings['apiKeyHelper']='fixture-helper-not-executed';(tool/'settings/claude.settings.json').write_bytes(encode(settings))
    config=load(tool/'config/agents.json');config.update(enabled=True,binary=str(binary),budget_usd=0.01,timeout_seconds=5)
    selected=config['agents'][0];selected['model']='fixture-model-not-an-api-id'
    packet={'agent_id':'claim_support','claims':data,'allowed_paths':[str(root)]}
    model_out=directory/'stub_model';model_out.mkdir()
    measured=call_agent(ctx,selected,config,packet,model_out)
    observations['model_call_path']=measured['output']['verdict']=='PASS'
    payload=Path(measured['instruction_payload']['path'])
    observations['instruction_file_transport']=max(len(x.encode()) for x in measured['argv'])<131072 and '--system-prompt-file' in measured['argv'] and '--system-prompt' not in measured['argv'] and payload.read_bytes()==b'\n\n'.join(ctx.read(p) for p in measured['instruction_hashes'])
    observations['three_instruction_sources']=len(measured['instruction_hashes'])==3 and digest(payload.read_bytes())==measured['instruction_payload']['sha256']
    observations['private_instruction_file']=payload.stat().st_mode & 0o777==0o600
    response.write_text('{')
    invalid_out=directory/'stub_invalid';invalid_out.mkdir()
    try:call_agent(ctx,selected,config,packet,invalid_out);observations['model_invalid_json']=False
    except ToolError:observations['model_invalid_json']=True
    bad_cite=dict(cite,quote='nonexistent evidence')
    response.write_bytes(encode({'type':'agent','id':'claim_support','verdict':'FAIL','findings':[{'check_id':'agent.unsupported','claim_id':'C-001','text':'fixture finding','evidence':[bad_cite]}],'not_rerun':[]}))
    discarded_out=directory/'stub_discarded';discarded_out.mkdir()
    discarded=call_agent(ctx,selected,config,packet,discarded_out)
    observations['model_evidence_discarded']=discarded['output']['verdict']=='UNKNOWN' and len(discarded['discarded'])==1
    good_cite=data['claims'][0]['citations'][0]
    response.write_bytes(encode({'type':'agent','id':'claim_support','verdict':'FAIL','findings':[{'check_id':'agent.unsupported','claim_id':'C-NOT-IN-SUBJECT','text':'unsupported fixture claim identity','evidence':[good_cite]}],'not_rerun':[]}))
    foreign_out=directory/'stub_foreign';foreign_out.mkdir()
    foreign=call_agent(ctx,selected,config,packet,foreign_out)
    observations['foreign_claim_discarded']=foreign['output']['verdict']=='UNKNOWN' and foreign['discarded'][0]['reason']=='unknown claim identity'
    missing=directory/'stub_missing_model';missing.mkdir()
    selected['model']=None
    try:call_agent(ctx,selected,config,packet,missing);observations['model_missing_id']=False
    except ToolError:observations['model_missing_id']=True
    create(directory/'observations.json',observations)
    return observations


def replay(args,out):
    replay_out=out/'replay';replay_out.mkdir()
    # Select ten distinct real task families, not ten runs from one task.
    chosen={}
    for path in sorted((args.root/'evidence').glob('sp1_t*/**/execution.json')):
        task=re.match(r'sp1_(t\d+)',path.relative_to(args.root/'evidence').parts[0])
        if task and task[1] not in chosen:chosen[task[1]]=path
        if len(chosen)==10:break
    observations=[]
    for task,path in sorted(chosen.items()):
        raw=path.read_bytes();value=loads(raw);errors=[]
        for stream in ['stdout','stderr']:
            captured=path.parent/stream
            if not captured.is_file() or digest(captured.read_bytes())!=value.get(stream+'_sha256'):
                errors.append('retained '+stream+' identity mismatch')
        observations.append({'task':task,'record':str(path),'record_sha256':digest(raw),'argv':value.get('argv'),'cwd':value.get('cwd'),'exit':value.get('exit'),'findings':errors,
            'not_run':['claims-dependent checks: no claims attachment in selected historical run','product rerun: execution disabled','semantic model calls: owner configuration pending','historical diff/depth/scope: no owner-selected base and exact historical worktree'],
            'label':'SOURCE_PROVEN','owner_label':'PENDING'})
    create(replay_out/'findings.json',observations)
    return observations


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--tool-root',required=True);p.add_argument('--programme-root',required=True)
    p.add_argument('--contract',required=True);p.add_argument('--output-dir',required=True)
    p.add_argument('--smoke',action='store_true');p.add_argument('--replay-only',action='store_true')
    p.add_argument('--case',action='append',default=[])
    p.add_argument('--properties-only',action='store_true')
    a=p.parse_args();a.tool=canonical(a.tool_root);a.root=canonical(a.programme_root);a.contract=canonical(a.contract)
    out=Path(a.output_dir).absolute();out.mkdir()
    before={str(x):digest(x.read_bytes()) for x in sorted(a.tool.rglob('*')) if x.is_file()}
    observations={'paired':{},'properties':{},'replay':[]}
    if a.properties_only:observations['properties']=properties(a,out)
    elif a.replay_only:observations['replay']=replay(a,out)
    elif a.smoke:
        d=out/'smoke';d.mkdir();run,data,root,tool=fixture(d,a.tool,a.contract,a.root)
        checked=execute(run,'citations',d/'result')
        observations['properties']['smoke']=not checked['errors'] and not checked['defects']
    else:
        observations['paired']=paired_cases(a,out)
        if not a.case:
            observations['properties']=properties(a,out)
            observations['replay']=replay(a,out)
    observations['input_sha256']=before
    observations['inputs_unchanged']=all(Path(path).is_file() and digest(Path(path).read_bytes())==sha for path,sha in before.items())
    observations['ok']=observations['inputs_unchanged'] and all(x['ok'] for x in observations['paired'].values()) and all(observations['properties'].values())
    create(out/'results.json',observations)
    print(json.dumps({'ok':observations['ok'],'paired':len(observations['paired']),'properties':observations['properties'],'replay':len(observations['replay']),'output':str(out/'results.json')}),flush=True)
    return 0 if observations['ok'] else 1


if __name__=='__main__':
    try:sys.exit(main())
    except Exception as exc:
        print(type(exc).__name__+': '+str(exc),file=sys.stderr);sys.exit(3)
