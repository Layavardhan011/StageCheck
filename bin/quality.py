"""Owner accuracy prompt §§2–7: versioned evidence, counting and exact bounds.

Tooling requirement is the owner's explicit instruction, contract §0(1)/§5.
No model calls, product execution, grading or acceptance by this module.
"""
import ast
import fcntl
import math
from contextlib import contextmanager
from common import *
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'checks'))

CHECKS=('preflight','scope_paths','citations','report_lint','authority','secrets','qual_naming','rerun','carry_forward')
ADDED={'bin/quality.py','bin/quality_write.py','bin/quality_seeds.py','bin/quality_measure.py','schemas/quality_record.schema.json','evals/test_quality.py','config/quality_targets.json'}
ZERO='0'*64

def policy(ctx):
    raw=ctx.read(ctx.tool/'config/quality_targets.json'); value=loads(raw)
    validate_policy(value)
    return value,digest(raw),raw

def validate_policy(value):
    keys={'confidence','audit_precision','audit_recall','engineering','prompt_development','deciders','scoring_rules','enforced'}
    if set(value)!=keys:
        raise ToolError('quality policy fields differ')
    for k in keys-{'deciders','scoring_rules','enforced'}:
        if type(value[k]) not in (int,float) or not 0<value[k]<1:
            raise ToolError('quality probability must be strictly between zero and one: '+k)
    if not isinstance(value['deciders'],list) or not value['deciders'] or len(set(value['deciders']))!=len(value['deciders']) or not set(value['deciders'])<={'owner','claude'}:
        raise ToolError('invalid deciders')
    if value['scoring_rules']!=['precision_v1','recall_v1','first_submission_v1','prompt_correct_v1'] or value['enforced']!=['audit_precision']:
        raise ToolError('quality scoring/enforcement differs')

def roots(ctx):
    descriptor=ctx.bind['Evidence root']
    raw=ctx.read(descriptor['path'])
    if digest(raw)!=descriptor['sha256']:
        raise ToolError('evidence root binding differs')
    literal=Path(loads(raw)['root'])
    if not literal.is_absolute() or symlink_component(literal) or not literal.is_dir():
        raise ToolError('evidence target must be an absolute directory without symlinks')
    base=canonical(literal)
    output=base/'stagecheck'; records=base/'stagecheck_quality'
    if symlink_component(output) or symlink_component(records):
        raise ToolError('quality root contains symlink')
    return output,records

def versions(ctx):
    """Conservative static dependency closure; inspect AST imports without execution."""
    files={p.relative_to(ctx.tool).as_posix():p for p in ctx.tool.rglob('*') if p.is_file()}
    shared=set()
    for rel in files:
        if rel in ADDED or rel in {'MANIFEST.sha256','config/modes.json'} or '.git' in Path(rel).parts or '__pycache__' in Path(rel).parts or rel.endswith(('.pyc','.md')):
            continue
        if rel.startswith(('config/','schemas/','settings/')) or rel.endswith('.py') and not rel.startswith(('checks/','evals/')):
            shared.add(rel)
    modules={Path(rel).stem:rel for rel in files if rel.endswith('.py') and rel not in ADDED and not rel.startswith('evals/')}
    extras={'../evidence/claude_audits/tools/verify_manifest.py','../evidence/claude_audits/tools/verify_state_chain.py','../qualification/reviews/capture_sp1_evidence.py'}
    result={}
    for name in CHECKS:
        selected=shared|{'checks/'+name+'.py'}; todo=list(selected)
        while todo:
            rel=todo.pop()
            if not rel.endswith('.py'):continue
            for node in ast.walk(ast.parse(files[rel].read_text())):
                imported=[]
                if isinstance(node,ast.Import):imported=[x.name.split('.')[0] for x in node.names]
                if isinstance(node,ast.ImportFrom):imported=[(node.module or '').split('.')[0]]
                for module in imported:
                    dep=modules.get(module)
                    if dep and dep not in selected:
                        selected.add(dep);todo.append(dep)
        pairs=[[rel,digest(ctx.read(ctx.tool/rel))] for rel in sorted(selected|extras)]
        result[name]={'sha256':digest(encode(pairs)),'files':pairs}
    return result

def tail(n,k,p):
    if p<=0:return float(k==0)
    if p>=1:return 1.0
    # Sum the requested tail in log space: no subtraction of nearly equal CDFs.
    terms=[math.lgamma(n+1)-math.lgamma(i+1)-math.lgamma(n-i+1)+i*math.log(p)+(n-i)*math.log1p(-p) for i in range(k,n+1)]
    peak=max(terms)
    return min(1.0,math.exp(peak)*math.fsum(math.exp(t-peak) for t in terms))

def lower(n,k,confidence):
    if type(n)!=int or type(k)!=int or not 0<=k<=n or not 0<confidence<1:raise ToolError('invalid binomial inputs')
    if not n:return None
    if not k:return 0.0
    lo,hi=0.0,1.0
    for _ in range(60):
        mid=(lo+hi)/2
        if tail(n,k,mid)<1-confidence:lo=mid
        else:hi=mid
    return (lo+hi)/2

def figures(n,k,target,confidence):
    bound=lower(n,k,confidence)
    more=0
    if bound is None or bound<target:
        hi=1
        while lower(n+hi,k+hi,confidence)<target:hi*=2
        lo=0
        while lo+1<hi:
            mid=(lo+hi)//2
            if lower(n+mid,k+mid,confidence)>=target:hi=mid
            else:lo=mid
        more=hi
    return {'count':n,'successes':k,'failures':n-k,'point_estimate':k/n if n else None,'lower_bound':bound,'target':target,'status':'insufficient' if not n else 'meets' if bound>=target else 'not_yet','more_successes':more}

VALUES={'finding_label':{'true_defect','false_block','unresolved'},'coverage':{'covered'},'missed_defect':{'missed'},'missed_defect_closure':{'closed'},'prompt_outcome':{'correct','wrong','unresolved'},'delivery_outcome':{'met','not_met','unresolved'},'carryover':{'evidence_carries_over'},'blocking_override':{'blocking_allowed'},'confirmation':{'confirmed'},'policy_snapshot':{'snapshot'},'continuation':{'continued'}}
OWNER_ONLY={'carryover','blocking_override','prompt_outcome','continuation'}

def line_bytes(record):
    return (json.dumps(record,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()

def record_shape(record):
    kind=record.get('kind')
    if kind not in VALUES or record.get('value') not in VALUES[kind]:raise ToolError('unknown record kind/value')
    base={'kind','value','subject','previous'}
    if kind!='policy_snapshot':base|={'actor','type','policy_sha256','evidence'}
    if not base<=set(record) or set(record)-base-{'note','replaces'}:raise ToolError('record fields differ')
    if not isinstance(record['subject'],dict):raise ToolError('subject must be an object')
    if not re.fullmatch('[0-9a-f]{64}',record['previous']):raise ToolError('invalid previous-line hash')
    if kind!='policy_snapshot':
        if record['actor'] not in ['owner','claude'] or record['type'] not in ['proposal','decision']:raise ToolError('invalid actor/record type')
        if not re.fullmatch('[0-9a-f]{64}',record['policy_sha256']) or not isinstance(record['evidence'],list):raise ToolError('invalid policy/evidence shape')
    if 'replaces' in record and not re.fullmatch('[0-9a-f]{64}',record['replaces']):raise ToolError('invalid replacement hash')
    if 'note' in record:
        from secrets import findings
        if not isinstance(record['note'],str) or '\n' in record['note'] or '\r' in record['note'] or findings('quality-note.txt',record['note']):raise ToolError('invalid or credential-shaped note')

def read_chain(folder):
    """Damage is structural; bad individual record semantics are revalidated later."""
    if not folder.exists():return [],{}
    if symlink_component(folder):raise ToolError('symlink records root')
    paths=numbered(folder,'records','jsonl')
    if [p.name for p in paths]!=['records.'+str(i).zfill(4)+'.jsonl' for i in range(1,len(paths)+1)]:raise ToolError('record-file sequence differs')
    records=[];identities={};previous=ZERO
    for index,path in enumerate(paths):
        if symlink_component(path):raise ToolError('symlink record file')
        raw=path.read_bytes();identities[str(path)]=digest(raw);valid=[];broken=False
        for line in raw.splitlines(keepends=True):
            try:
                value=loads(line)
                if not line.endswith(b'\n') or not isinstance(value,dict) or value.get('previous')!=previous:raise ToolError('line chain differs')
            except (ToolError,TypeError):broken=True;break
            previous=digest(line)
            valid.append(dict(record=value,sha256=previous,file=str(path),position=len(records)+len(valid)))
        records.extend(valid)
        if broken:
            if index+1==len(paths):raise ToolError('damaged record file: '+path.name)
            following=paths[index+1].read_bytes().splitlines(keepends=True)
            try:
                c=loads(following[0]);record_shape(c)
                if c['kind']!='continuation' or c['actor']!='owner' or c['type']!='decision' or c['value']!='continued' or c['previous']!=previous or c['subject']!={'file_sha256':digest(raw),'last_valid_sha256':previous}:raise ToolError('unmatched continuation')
            except (IndexError,ToolError,TypeError):raise ToolError('damaged record file lacks owner continuation') from None
        elif index+1<len(paths):
            raise ToolError('continuation may only follow a damaged file')
    return records,identities

def valid_prefix(folder):
    """Owner recovery diagnostic: last valid identity, without modifying damage."""
    paths=numbered(folder,'records','jsonl')
    if not paths:raise ToolError('no damaged file')
    if symlink_component(folder) or any(symlink_component(p) for p in paths):raise ToolError('symlink record file')
    if [p.name for p in paths]!=['records.'+str(i).zfill(4)+'.jsonl' for i in range(1,len(paths)+1)]:raise ToolError('record-file sequence differs')
    previous=ZERO
    # Previous closed files are admitted by read_chain with a dummy-independent prefix;
    # traverse all physical lines, skipping damaged suffixes only when a next owner continuation verifies.
    for i,path in enumerate(paths):
        raw=path.read_bytes();broken=False
        for line in raw.splitlines(keepends=True):
            try:
                v=loads(line)
                if not line.endswith(b'\n') or v.get('previous')!=previous:raise ToolError('broken')
            except (ToolError,AttributeError):broken=True;break
            previous=digest(line)
        if broken and i<len(paths)-1:
            c=loads(paths[i+1].read_bytes().splitlines()[0]);record_shape(c)
            if c['kind']!='continuation' or c['actor']!='owner' or c['type']!='decision' or c['previous']!=previous or c['subject']!={'file_sha256':digest(raw),'last_valid_sha256':previous}:raise ToolError('earlier damage is unclosed')
        elif not broken and i<len(paths)-1:raise ToolError('unexpected record sequence')
        elif not broken:raise ToolError('last file is not damaged')
    return paths[-1],previous

def real_verdicts(ctx,exclude=None):
    from orchestrate import history_read
    output,_=roots(ctx); found={};invalid=[]
    if not output.exists():return found,invalid
    for task in sorted(output.iterdir()):
        if not task.is_dir() or task.is_symlink():continue
        paths=[p for p in task.glob('[0-9]*/verdict.json') if p.parent!=exclude]
        if not paths:continue
        try:
            history=history_read(task,exclude) if exclude is not None else history_read(task)
            for p,h in zip(sorted(paths,key=lambda p:int(p.parent.name)),history):
                raw=ctx.read(p)
                if digest(raw)!=h['seal']['verdict.json']:raise ToolError('sealed verdict changed while loading')
                value=loads(raw)
                schema(value,load(ctx.tool/'schemas/verdict.schema.json'))
                if value.get('type')!='verdict' or value['task_id']!=task.name:raise ToolError('real verdict task identity differs')
                found[digest(raw)]={'path':str(p),'value':value}
        except (ToolError,OSError,KeyError,ValueError) as exc:
            invalid.append({'task':task.name,'reason':str(exc)})
    return found,invalid

def witnesses(ctx,evidence,runs):
    for item in evidence:
        if isinstance(item,str):
            if not any(d['defect_id']==item for r in runs.values() for d in r['value']['defects']):raise ToolError('unknown evidence defect id')
        elif isinstance(item,dict) and set(item)=={'path','sha256'}:
            if digest(ctx.read(item['path']))!=item['sha256']:raise ToolError('evidence identity differs')
        else:raise ToolError('invalid evidence item')

def subject_key(record):
    return record['kind'],line_bytes(record['subject']).decode()

def validate_record(ctx,r,known,runs,current=None,override_only=False):
    schema(r,load(ctx.tool/'schemas/quality_record.schema.json'))
    record_shape(r);kind=r['kind'];s=r['subject']
    if kind=='policy_snapshot':
        if set(s)!={'policy_bytes','sha256'} or digest(s['policy_bytes'].encode())!=s['sha256']:raise ToolError('snapshot identity differs')
        validate_policy(loads(s['policy_bytes']))
        return
    if kind=='continuation':
        if r['actor']!='owner' or r['type']!='decision' or set(s)!={'file_sha256','last_valid_sha256'}:raise ToolError('continuation must be owner decision')
        return
    witnesses(ctx,r['evidence'],runs)
    def verdict(sha):
        if sha not in runs:raise ToolError('verdict is absent, unsealed or not a real run')
        return runs[sha]['value']
    def check(name):
        if name not in CHECKS:raise ToolError('unknown check')
    def version(name,v):
        check(name)
        if not isinstance(v,str) or not re.fullmatch('[0-9a-f]{64}',v):raise ToolError('invalid version identity')
        if current is None:return  # Tree identity was an admission fact, not a later revalidation requirement.
        candidates=[c.get('version') for x in runs.values() for c in x['value']['checks'] if c['id']==name]
        if current is not None:candidates.append(current[name]['sha256'])
        if v not in candidates:raise ToolError('version is neither current nor from a real run')
    if kind=='finding_label':
        if set(s)!={'task','defect_id','check','version'}:raise ToolError('finding subject differs')
        check(s['check']);version(s['check'],s['version']);matches=[]
        for x in runs.values():
            v=x['value'];cs={c['id']:c.get('version') for c in v['checks']}
            if v['task_id']==s['task'] and cs.get(s['check'])==s['version'] and any(d['defect_id']==s['defect_id'] and d['source']=='checks/'+s['check']+'.py' for d in v['defects']):matches.append(x['path'])
        if not matches or not any(isinstance(e,dict) and e.get('path') in matches for e in r['evidence']):raise ToolError('finding/version not witnessed in a cited real verdict')
    elif kind=='coverage':
        if set(s)!={'verdicts'} or not isinstance(s['verdicts'],list) or not s['verdicts']:raise ToolError('coverage subject differs')
        for sha in s['verdicts']:verdict(sha)
    elif kind=='missed_defect':
        if set(s)!={'task','verdict','check','defect_id'}:raise ToolError('missed subject differs')
        if s['check']!='none':check(s['check'])
        if verdict(s['verdict'])['task_id']!=s['task']:raise ToolError('missed task differs')
    elif kind=='missed_defect_closure':
        if set(s)!={'record','seed_id'} or s['record'] not in known or known[s['record']]['record']['kind']!='missed_defect' or not re.fullmatch('[0-9a-f]{64}',s['seed_id']):raise ToolError('closure subject differs')
    elif kind=='delivery_outcome':
        if set(s)!={'task','verdict'}:raise ToolError('delivery subject differs')
        v=verdict(s['verdict'])
        if v['task_id']!=s['task'] or v['iteration']!=1 or any(x['value']['task_id']==s['task'] and int(Path(x['path']).parent.name)<int(Path(runs[s['verdict']]['path']).parent.name) for x in runs.values()):raise ToolError('delivery is not first submitted attempt')
    elif kind=='prompt_outcome':
        if set(s)=={'path','sha256'}:
            if digest(ctx.read(s['path']))!=s['sha256']:raise ToolError('prompt identity differs')
        elif set(s)=={'assembly_digest'}:
            if not any(isinstance(e,dict) and assembler_record_matches(ctx,e['path'],s['assembly_digest']) for e in r['evidence']):raise ToolError('assembler record does not identify prompt')
        else:raise ToolError('prompt subject differs')
    elif kind=='carryover':
        if set(s)!={'check','old','new'} or s['old']==s['new']:raise ToolError('carryover subject differs')
        version(s['check'],s['old']);version(s['check'],s['new'])
    elif kind=='blocking_override':
        if set(s)!={'check','version'}:raise ToolError('override subject differs')
        check(s['check'])
        if s['version']!='all':version(s['check'],s['version'])
    elif kind=='confirmation':
        if set(s)!={'proposals'} or not isinstance(s['proposals'],list) or not s['proposals'] or len(set(s['proposals']))!=len(s['proposals']):raise ToolError('confirmation subject differs')
        for sha in s['proposals']:
            if sha not in known or known[sha]['record'].get('type')!='proposal':raise ToolError('confirmation names missing/non-proposal record')
    if 'replaces' in r:
        old=known.get(r['replaces'])
        if not old or old['record']['kind']!=kind or subject_key(old['record'])!=subject_key(r):raise ToolError('correction subject differs or record is absent')

def effective(ctx,chain,runs,current=None,override_only=False):
    """Validate using the snapshot at each position; confirmations decide at their position."""
    known={};decisions=[];skipped=[];snap=None;replaced=set()
    for item in chain:
        r=item['record'];sha=item['sha256']
        try:
            validate_record(ctx,r,known,runs,current,override_only)
            if r['kind']=='policy_snapshot':
                snap=(r['subject']['sha256'],loads(r['subject']['policy_bytes']));known[sha]=item;continue
            if r['kind']=='continuation':known[sha]=item;continue
            if not override_only:
                if snap is None or r['policy_sha256']!=snap[0]:raise ToolError('record does not identify the policy then in force')
                deciders=snap[1]['deciders']
                if r['type']=='decision' and r['actor'] not in deciders:raise ToolError('actor was not a decider')
                if r['kind'] in {'coverage','confirmation'} and r['actor'] not in deciders:raise ToolError('coverage/confirmation actor was not decider')
            known[sha]=item
            if r['type']!='decision':continue
            expanded=[]
            if r['kind']=='confirmation':
                for proposed in r['subject']['proposals']:
                    if proposed in replaced:raise ToolError('confirmation names replaced proposal')
                    expanded.append((known[proposed],r['actor']))
            else:expanded=[(item,r['actor'])]
            for source,actor in expanded:
                value=source['record']
                if value['kind'] in OWNER_ONLY and actor!='owner':
                    skipped.append({'record':source['sha256'],'reason':'owner-only counting decision'});continue
                if override_only and (value['kind']!='blocking_override' or actor!='owner'):continue
                if value.get('replaces'):
                    replaced.add(value['replaces'])
                decisions.append(dict(source,deciding_actor=actor,decision_position=item['position']))
        except (ToolError,KeyError,TypeError,ValueError,OSError) as exc:
            skipped.append({'record':sha,'reason':str(exc)})
    decisions=[d for d in decisions if d['sha256'] not in replaced]
    latest={}
    for d in decisions:latest[subject_key(d['record'])]=d
    return list(latest.values()),skipped,known

@contextmanager
def locked(folder):
    if symlink_component(folder):raise ToolError('symlink records folder')
    folder.mkdir(exist_ok=True)
    if symlink_component(folder) or not folder.is_dir():raise ToolError('records folder admission differs')
    p=folder/'.quality.lock'
    try:fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW,0o600)
    except FileExistsError:fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX);yield
    finally:fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)

def append_record(ctx,request,recover=False):
    _,folder=roots(ctx)
    with locked(folder):
        if recover:
            bad,previous=valid_prefix(folder)
            if request!={'actor':'owner'}:raise ToolError('recovery requires explicit owner actor')
            r={'kind':'continuation','value':'continued','subject':{'file_sha256':digest(bad.read_bytes()),'last_valid_sha256':previous},'actor':'owner','type':'decision','policy_sha256':ZERO,'evidence':[],'previous':previous}
            dest=folder/('records.'+str(int(bad.name.split('.')[1])+1).zfill(4)+'.jsonl')
            with dest.open('xb') as f:f.write(line_bytes(r));f.flush();os.fsync(f.fileno())
            return digest(line_bytes(r))
        pol,psha,praw=policy(ctx);chain,_=read_chain(folder)
        runs,_=real_verdicts(ctx);current=versions(ctx)
        check_anchors(folder,chain,runs)
        decisions,skipped,known=effective(ctx,chain,runs)
        latest_snapshot=next((x for x in reversed(chain) if x['sha256'] in known and x['record'].get('kind')=='policy_snapshot'),None)
        previous=chain[-1]['sha256'] if chain else ZERO
        if set(request)&{'previous','policy_sha256'}:raise ToolError('writer owns chain/policy fields')
        r=dict(request,policy_sha256=psha,previous=previous)
        if r.get('kind') in {'policy_snapshot','continuation'}:raise ToolError('writer owns snapshot/recovery records')
        schema(r,load(ctx.tool/'schemas/quality_record.schema.json'))
        validate_record(ctx,r,known,runs,current)
        if r['type']=='decision' and r['actor'] not in pol['deciders'] or r['kind'] in {'coverage','confirmation'} and r['actor'] not in pol['deciders']:raise ToolError('actor cannot decide under current policy')
        if r['type']=='decision' and r['kind'] in OWNER_ONLY and r['actor']!='owner':raise ToolError('owner-only decision')
        replaced={x['record'].get('replaces') for x in decisions}
        if r['kind']=='confirmation' and any(p in replaced for p in r['subject']['proposals']):raise ToolError('confirmation names replaced proposal')
        lines=[]
        if latest_snapshot is None or latest_snapshot['record']['subject']['sha256']!=psha:
            snapshot={'kind':'policy_snapshot','value':'snapshot','subject':{'policy_bytes':praw.decode(),'sha256':psha},'previous':previous}
            lines.append(line_bytes(snapshot));r['previous']=digest(lines[-1])
        lines.append(line_bytes(r))
        paths=numbered(folder,'records','jsonl');dest=paths[-1] if paths else folder/'records.0001.jsonl'
        with dest.open('ab' if paths else 'xb') as f:
            for line in lines:f.write(line);f.flush();os.fsync(f.fileno())
        return digest(lines[-1])

def label_decision(ctx,citation):
    """One label mechanism: a counting outcome identified by its complete-line hash."""
    if not isinstance(citation,dict) or set(citation)!={'type','record_sha256'} or citation['type']!='quality_record':raise ToolError('owner label must cite a quality record identity')
    _,folder=roots(ctx);chain,_=read_chain(folder);runs,_=real_verdicts(ctx)
    check_anchors(folder,chain,runs)
    decisions,_,_=effective(ctx,chain,runs)
    selected=[d for d in decisions if d['sha256']==citation['record_sha256'] and d['record']['kind'] in {'finding_label','missed_defect'} and d['record']['value'] in {'true_defect','missed'}]
    if len(selected)!=1:raise ToolError('owner label is absent, replaced, unconfirmed or not a counted defect')
    return selected[0]

def record_anchors(folder):
    """Owner ruling 1: hashes anchor the observed prefix; appends remain permitted."""
    return {str(p):{'sha256':digest(p.read_bytes()),'bytes':p.stat().st_size}
            for p in sorted(folder.glob('records.*.jsonl'))}

def check_anchors(folder,chain,runs):
    anchors=[]
    for v in runs.values():
        anchors.append(v['value'].get('quality',{}).get('record_files',{}))
    for p in numbered(folder,'measurement','json'):
        if symlink_component(p):raise ToolError('symlink measurement')
        anchors.append(load(p).get('record_files',{}))
    closed={x['record']['subject']['file_sha256'] for x in chain if x['record'].get('kind')=='continuation'}
    for inventory in anchors:
        for path,identity in inventory.items():
            p=Path(path)
            if p.parent!=folder or not re.fullmatch(r'records\.\d{4,}\.jsonl',p.name) or symlink_component(p):raise ToolError('record anchor path differs')
            raw=p.read_bytes()
            if digest(raw) in closed:continue  # Explicit owner recovery dispositions the damaged bytes.
            if type(identity.get('bytes'))!=int or identity['bytes']<0 or len(raw)<identity['bytes'] or digest(raw[:identity['bytes']])!=identity['sha256']:
                raise ToolError('recorded prefix hash differs')

def numbered(folder,stem,suffix):
    paths=list(folder.glob(stem+'.*.'+suffix))
    if any(not re.fullmatch(stem+r'\.\d{4,}\.'+suffix,p.name) for p in paths):raise ToolError('numbered output name differs')
    numbers=[int(p.name.split('.')[1]) for p in paths]
    if len(set(numbers))!=len(numbers):raise ToolError('duplicate output sequence')
    return sorted(paths,key=lambda p:int(p.name.split('.')[1]))

def next_output(folder,stem,suffix):
    paths=numbered(folder,stem,suffix)
    return folder/(stem+'.'+str(int(paths[-1].name.split('.')[1])+1 if paths else 1).zfill(4)+'.'+suffix)

def seed_results(folder):
    results=[];skipped=[]
    for p in reversed(numbered(folder,'seed_result','json')):
        try:
            if symlink_component(p):raise ToolError('symlink seed result')
            v=load(p)
            if set(v)!={'seed_set_sha256','versions','seeds','fixture_configuration'} or set(v['versions'])!=set(CHECKS):raise ToolError('seed result fields differ')
            f=v['fixture_configuration'];names={'config/agents.json','config/commands.json','config/paths.json'}
            if (set(f)!={'verified_only_allowed_differences','allowed_differences','file_sha256','copies_checked'} or f['verified_only_allowed_differences'] is not True
                or f['allowed_differences']!=sorted(names|{'MANIFEST.sha256'}) or set(f['file_sha256'])!=names
                or any(not isinstance(x,str) or not re.fullmatch('[0-9a-f]{64}',x) for x in f['file_sha256'].values())
                or type(f['copies_checked'])!=int or f['copies_checked']!=2*len(v['seeds'])):raise ToolError('seed fixture configuration evidence differs')
            if any(not isinstance(x,str) or not re.fullmatch('[0-9a-f]{64}',x) for x in v['versions'].values()):raise ToolError('seed result version differs')
            ids=[]
            for s in v['seeds']:
                if set(s)!={'seed_id','target_rule','check','detected','clean_firings'} or s['check'] not in CHECKS or type(s['detected'])!=bool or not re.fullmatch('[0-9a-f]{64}',s['seed_id']):raise ToolError('seed result subject differs')
                if not isinstance(s['clean_firings'],dict) or any(c not in CHECKS or not isinstance(r,list) or not r or any(not isinstance(x,str) for x in r) for c,r in s['clean_firings'].items()):raise ToolError('seed clean firings differ')
                ids.append(s['seed_id'])
            if ids!=sorted(set(ids)) or digest(encode(ids))!=v['seed_set_sha256']:raise ToolError('seed set identity differs')
            results.append({'path':str(p),'sha256':digest(p.read_bytes()),'value':v})
        except (ToolError,KeyError,TypeError,ValueError,OSError) as exc:skipped.append({'file':p.name,'reason':str(exc)})
    return results,skipped

def precision(ctx,runs,decisions,current):
    labels=[d for d in decisions if d['record']['kind']=='finding_label']
    covered={v for d in decisions if d['record']['kind']=='coverage' for v in d['record']['subject']['verdicts']}
    output={}
    for check in CHECKS:
        accepted={current[check]['sha256']}
        edges=[d['record']['subject'] for d in decisions if d['record']['kind']=='carryover' and d['record']['subject']['check']==check and d['deciding_actor']=='owner']
        while True:
            expanded=accepted|{e['old'] for e in edges if e['new'] in accepted}
            if expanded==accepted:break
            accepted=expanded
        findings={};earlier=False
        for sha,r in runs.items():
            v=r['value'];version=next((c.get('version') for c in v['checks'] if c['id']==check),None)
            for f in v['defects']:
                if f['source']!='checks/'+check+'.py' or not version:continue
                if version not in accepted:earlier=True;continue
                key=(v['task_id'],f['defect_id'])
                item=findings.setdefault(key,{'versions':set(),'covered':False,'rule':f['check_id']})
                item['versions'].add(version);item['covered']|=sha in covered
        counted=[];pending=[];rules={}
        for (task,fid),f in sorted(findings.items()):
            matching=[d for d in labels if d['record']['subject']['check']==check and d['record']['subject']['task']==task and d['record']['subject']['defect_id']==fid and d['record']['subject']['version'] in f['versions']]
            latest=max(matching,key=lambda d:d['decision_position']) if matching else None
            if latest is None and not f['covered']:
                pending.append({'task':task,'defect_id':fid,'rule':f['rule']});continue
            success=latest is not None and latest['record']['value']=='true_defect'
            counted.append(success);rules.setdefault(f['rule'],[]).append(success)
        output[check]={'count':len(counted),'successes':sum(counted),'pending':pending,'version_reset':earlier,'rules':{r:{'count':len(x),'successes':sum(x),'failures':len(x)-sum(x)} for r,x in sorted(rules.items())}}
    return output

def measure_data(ctx,exclude=None):
    pol,psha,_=policy(ctx);_,folder=roots(ctx);chain,_=read_chain(folder)
    runs,bad_runs=real_verdicts(ctx,exclude);check_anchors(folder,chain,runs)
    current=versions(ctx);decisions,skipped,_=effective(ctx,chain,runs)
    audit=precision(ctx,runs,decisions,current);seeds,bad_seeds=seed_results(folder)
    gaps=[];selected={};checks={}
    missed=[d for d in decisions if d['record']['kind']=='missed_defect']
    closures=[d for d in decisions if d['record']['kind']=='missed_defect_closure']
    for check in CHECKS:
        stat=audit[check];pr=figures(stat['count'],stat['successes'],pol['audit_precision'],pol['confidence'])
        sr=next((x for x in seeds if x['value']['versions'][check]==current[check]['sha256']),None)
        pairs=[s for s in sr['value']['seeds'] if s['check']==check] if sr else []
        detected={s['seed_id'] for s in pairs if s['detected'] and check not in s['clean_firings']}
        rc=figures(len(pairs),len(detected),pol['audit_recall'],pol['confidence'])
        open_missed=[]
        for m in missed:
            if m['record']['subject']['check']!=check:continue
            closed=any(c['record']['subject']['record']==m['sha256'] and c['record']['subject']['seed_id'] in detected for c in closures)
            if not closed:open_missed.append(m['sha256'])
        if open_missed and rc['status']=='meets':rc['status']='not_yet'
        if sr:selected[sr['path']]=sr['sha256']
        other_firings=[{'seed_id':s['seed_id'],'rules':s['clean_firings'][check]} for s in sr['value']['seeds'] if check in s['clean_firings'] and s['check']!=check] if sr else []
        checks[check]={'version':current[check]['sha256'],'precision':pr,'recall':rc,'pending_count':len(stat['pending']),'pending':stat['pending'],'version_reset':stat['version_reset'],'by_rule':stat['rules'],'open_missed_defects':open_missed,'other_clean_firings':other_firings}
    gaps=[m['sha256'] for m in missed if m['record']['subject']['check']=='none']
    outcomes={}
    for kind,key,success in [('delivery_outcome','engineering','met'),('prompt_outcome','prompt_development','correct')]:
        ds=[d for d in decisions if d['record']['kind']==kind]
        outcomes[key]=dict(figures(len(ds),sum(d['record']['value']==success for d in ds),pol[key],pol['confidence']),enforced=False)
    scripts=sorted(ctx.tool.glob('bin/*.py'))+[ctx.tool/'checks/secrets.py']
    return {'policy_sha256':psha,'record_files':record_anchors(folder),'seed_results':dict(sorted(selected.items())),
            'computing_scripts':{str(p):digest(p.read_bytes()) for p in scripts},'checks':checks,**outcomes,
            'uncovered_gaps':gaps,'skipped_records':skipped,'invalid_runs':bad_runs,'invalid_seed_results':bad_seeds}

def summary(value):
    lines=['NOT DONE: targets below their lower-bound requirements remain unearned; no product or runtime acceptance.',
           'Full Blast Radius Check: record chains, sealed verdicts, historical policies and current versions revalidated; see paired measurement JSON.',
           'Enforcement Self-Check: enforcement is manual; actors are declared, not authenticated.', '',
           'Check | precision k/n; lower; status; more | pending | recall k/n; lower; status; more | open missed',
           '--- | --- | --- | --- | ---']
    def fmt(f):return str(f['successes'])+'/'+str(f['count'])+'; '+('none' if f['lower_bound'] is None else format(f['lower_bound'],'.6f'))+'; '+f['status']+'; '+str(f['more_successes'])
    for name,c in value['checks'].items():lines.append(name+' | '+fmt(c['precision'])+' | '+str(c['pending_count'])+' | '+fmt(c['recall'])+' | '+str(len(c['open_missed_defects'])))
    for key in ['engineering','prompt_development']:lines.append(key+' (not enforced): '+fmt(value[key]))
    lines.append('Uncovered gaps: '+json.dumps(value['uncovered_gaps']))
    for c in value['checks'].values():
        for p in c['pending']:lines.append('Pending: '+json.dumps(p,sort_keys=True))
    lines.append('Per-rule precision, other-check clean firings, and file identities: paired JSON.')
    for key in ['skipped_records','invalid_runs','invalid_seed_results']:
        for item in value[key]:lines.append(key+': '+json.dumps(item,sort_keys=True))
    return ('\n'.join(lines)+'\n').encode()

def write_measurement(ctx):
    _,folder=roots(ctx)
    with locked(folder):
        value=measure_data(ctx);dest=next_output(folder,'measurement','json');report=dest.with_suffix('.md')
        if report.exists():raise ToolError('measurement summary already exists')
        create(dest,value)
        with report.open('xb') as f:f.write(summary(value));f.flush();os.fsync(f.fileno())
    return dest

def policy_bound(ctx,sha):
    manifest=ctx.tool/'MANIFEST.sha256'
    if not manifest.exists():return True
    entries=[line.split() for line in manifest.read_text().splitlines() if line.split() and line.split()[-1].lstrip('*')=='config/quality_targets.json']
    return len(entries)==1 and entries[0][0]==sha

def blocking_evidence(ctx,exclude,current_defects):
    """Part F: quality failure only withholds authority; it never adds a finding/error."""
    value={'policy_sha256':None,'record_files':{},'checks':{}}
    for name in CHECKS:
        value['checks'][name]={'source':'report_only','reason':'no data','pending_count':None,'earlier_pending_count':None,'current_pending_count':0}
    # Separate Context prevents mutable outcome files entering the launcher's
    # immutable-input barrier. Locked read yields a retained evidence snapshot.
    qctx=Context(ctx.run)
    try:
        current=versions(qctx);_,folder=roots(qctx)
        with locked(folder):
            value['record_files']=record_anchors(folder)
            chain,_=read_chain(folder);runs,_=real_verdicts(qctx,exclude);check_anchors(folder,chain,runs)
            overrides,_,_=effective(qctx,chain,runs,override_only=True)
            try:
                measured=measure_data(qctx,exclude);psha=measured['policy_sha256'];value['policy_sha256']=psha
                matched=policy_bound(qctx,psha);policy_reason=None if matched else 'policy not matching manifest'
            except Exception:
                measured=None;policy_reason='policy or measurement evidence invalid'
                p=qctx.tool/'config/quality_targets.json'
                if p.is_file() and not symlink_component(p):value['policy_sha256']=digest(p.read_bytes())
            # Pending remains observable even when current policy is invalid.
            if measured is None:
                decisions,_,_=effective(qctx,chain,runs)
                stats=precision(qctx,runs,decisions,current)
            for name in CHECKS:
                entry=value['checks'][name]
                c=measured['checks'][name] if measured else None
                earlier=c['pending_count'] if c else len(stats[name]['pending'])
                observed={(r['value']['task_id'],d['defect_id']) for r in runs.values() for d in r['value']['defects'] if d['source']=='checks/'+name+'.py' and any(x['id']==name and x.get('version')==current[name]['sha256'] for x in r['value']['checks'])}
                own={(ctx.run['task_id'],d['defect_id']) for d in current_defects if d['source']=='checks/'+name+'.py'}-observed
                entry.update(earlier_pending_count=earlier,current_pending_count=len(own),pending_count=earlier+len(own))
                override=any(d['record']['kind']=='blocking_override' and d['deciding_actor']=='owner' and d['record']['subject']['check']==name and d['record']['subject']['version'] in {'all',current[name]['sha256']} for d in overrides)
                if override:entry.update(source='override',reason='owner override');continue
                if policy_reason:entry['reason']=policy_reason;continue
                f=c['precision'];entry['precision']=f
                if earlier:entry['reason']='findings from earlier runs still pending';continue
                if f['status']=='meets':entry.update(source='measurement',reason='precision meets');continue
                if c['version_reset'] and f['count']==0:entry['reason']='version changed; earlier evidence not carried over'
                elif f['count']==0:entry['reason']='no data'
                else:entry['reason']='not yet: '+json.dumps(f,sort_keys=True,separators=(',',':'))
    except Exception:
        for entry in value['checks'].values():entry.update(source='report_only',reason='record chain, anchor or evidence unavailable',pending_count=None,earlier_pending_count=None)
    return value

def assembler_record_matches(ctx,path,identity):
    """Existing assembler.py run(): canonical payload and paired output identities.

    Reuses line_bytes canonical encoding (without LF), matching canonical_bytes.
    This validates artifact identity, not authentication of its producer.
    """
    try:
        path=Path(path)
        if path.name!='record.json' or not isinstance(identity,str) or not re.fullmatch('[0-9a-f]{64}',identity):return False
        value=loads(ctx.read(path))
        payload={k:value[k] for k in ['blocks','given','computed','selection','file_hashes']}
        if not isinstance(payload['blocks'],list) or any(not isinstance(payload[k],dict) for k in ['given','computed','file_hashes']) or payload['selection'] is not None:return False
        if 'authored' in value:payload['authored']=value['authored']
        if value['result']!='CLEAR' or value['assembly_digest']!=identity or digest(line_bytes(payload)[:-1])!=identity:return False
        return digest(ctx.read(path.parent/'task_prompt.md'))==value['prompt_sha256'] and digest(ctx.read(path.parent/'claims.json'))==value['claims_sha256']
    except (ToolError,KeyError,TypeError,ValueError,OSError):return False
