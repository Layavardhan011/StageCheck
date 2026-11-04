"""Owner response-hook REQUEST Parts B/C/§7: bounded, offline main-agent Stop hook.

Standard library only. Hook observations never grant acceptance or product credit.
Owner rulings preserve raw claims except task/iteration and exempt the transport line.
"""
import fcntl,json,os,re,signal,stat,subprocess,sys,time
from pathlib import Path
from common import ToolError,bindings,canonical,create,digest,encode,load,loads,symlink_component
from response_tokens import needs_claims
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'checks'))
from secrets import findings as secret_findings
from preflight import manifest_entries
from orchestrate import history_read,EXIT

OWNER_SENTENCE='Restate your whole answer with the findings below repaired, changing only what they require and updating your headers to what you read for the repair. Do not weaken a citation, label or header to clear a finding; if a finding is wrong, write its defect id, the word disputed, and your evidence.'
FIELDS={'mode','repairs_per_answer','failed_answers_in_a_row','session_backstop','stagecheck_timeout_seconds','claims_max_bytes','claims_folder','records_folder','send_back_rules'}
DENIED=('preflight.','authority.','qual.','rerun.','orchestrate.','agent.')
NON_SEND={'report.completion','report.counts','report.groups','report.table','scope.package_span'}

def confined(root,relative):
    if not isinstance(relative,str) or Path(relative).is_absolute() or '..' in Path(relative).parts:
        raise ToolError('hook configured path refused')
    target=root/relative
    if symlink_component(target) or not target.resolve().is_relative_to(root/'evidence'):
        raise ToolError('hook configured path refused')
    return target

def settings(tool,root):
    value=load(tool/'config/response_hook.json')
    if not isinstance(value,dict) or set(value)!=FIELDS or value['mode'] not in ['off','record','send_back']:
        raise ToolError('hook settings shape refused')
    for key in ['repairs_per_answer','failed_answers_in_a_row','session_backstop','stagecheck_timeout_seconds','claims_max_bytes']:
        if type(value[key]) is not int or value[key]<=0:raise ToolError('hook positive setting refused')
    if not isinstance(value['claims_folder'],dict) or set(value['claims_folder'])!={'codex','claude'}:
        raise ToolError('hook claims roots refused')
    claims={a:confined(root,r) for a,r in value['claims_folder'].items()};records=confined(root,value['records_folder'])
    if claims['codex']==claims['claude'] or any(a.resolve().is_relative_to(b.resolve()) or b.resolve().is_relative_to(a.resolve()) for a,b in [(claims['codex'],claims['claude']),(records,claims['codex']),(records,claims['claude'])]):
        raise ToolError('hook overlapping roots refused')
    ids=load(tool/'config/required_outcomes.json');rules=value['send_back_rules']
    if not isinstance(rules,list) or len(set(rules))!=len(rules) or any(not isinstance(r,str) or r not in ids or r.startswith(DENIED) or r in NON_SEND for r in rules):
        raise ToolError('hook send-back rules refused')
    return value,claims,records

def manifest_valid(tool):
    allowed_external={'../evidence/claude_audits/tools/verify_manifest.py','../evidence/claude_audits/tools/verify_state_chain.py','../qualification/reviews/capture_sp1_evidence.py'}
    for relative,expected in manifest_entries(tool).items():
        path=tool/relative
        if not path.resolve().is_relative_to(tool.resolve()) and relative not in allowed_external:
            raise ToolError('hook external manifest path refused')
        if symlink_component(path) or not path.is_file() or digest(path.read_bytes())!=expected:
            raise ToolError('hook manifest identity refused')
    # Unlisted newly authored files are advisory until the owner's rebind.
    # Existing listed-byte mismatches are tool faults, never a send-back.

def numbered_attempt(folder):
    if symlink_component(folder):raise ToolError('hook record path refused')
    folder.mkdir(parents=True,exist_ok=True)
    names=list(folder.iterdir())
    if any(p.name!='.lock' and (not p.name.isdigit() or not p.is_dir() or p.is_symlink()) for p in names):
        raise ToolError('hook attempt directory refused')
    number=max((int(p.name) for p in names if p.name.isdigit()),default=0)+1
    while True:
        path=folder/str(number)
        try:path.mkdir();return path
        except FileExistsError:number+=1

def prior_records(folder,current):
    records=[]
    for p in sorted((p for p in folder.iterdir() if p.name.isdigit() and int(p.name)<int(current.name)),key=lambda p:int(p.name)):
        record_path=p/'record.json'
        if symlink_component(record_path):raise ToolError('hook record symlink refused')
        try:value=load(record_path)
        except FileNotFoundError:
            # Interrupted reservation: classify in memory, never backfill bytes.
            value={'agent':folder.parent.name,'session_id':folder.name,'turn_id':None,
                   'response_task_id':None,'decision':'tool_error','finding_ids':[],
                   'disputed_ids':[],'incomplete_attempt':p.name,
                   'tool_error':'interrupted attempt: record.json absent'}
        if not isinstance(value,dict) or value.get('agent') not in ['codex','claude'] or value.get('decision') not in ['sent_back','would_send_back','stopped_clean','stopped_open','stopped_no_progress','stopped_disputed','stopped_session','stopped_off','stopped_no_answer','tool_error'] or not isinstance(value.get('session_id'),str) or not isinstance(value.get('finding_ids'),list) or not isinstance(value.get('disputed_ids'),list):
            raise ToolError('hook history refused')
        records.append(value)
    return records

def task_counts(agent,session,event,records):
    previous=records[-1] if records else None
    repair=bool(previous and previous['decision']=='sent_back' and (event.get('stop_hook_active') or agent=='codex' and previous['turn_id']==event.get('turn_id')))
    turn=event.get('turn_id') if agent=='codex' else str(len({r['response_task_id'] for r in records if r.get('response_task_id')})+1)
    if repair:task=previous['response_task_id']
    else:
        if not isinstance(turn,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,50}',turn):raise ToolError('hook turn id refused')
        task='resp-'+agent+'-'+session[:8]+'-'+turn
    sent=sum(r['decision']=='sent_back' and r['response_task_id']==task for r in records)
    total=sum(r['decision']=='sent_back' for r in records);failed=0
    for record in records:
        if record['decision']=='stopped_clean':failed=0
        elif record['decision'] in ['stopped_open','stopped_no_progress']:failed+=1
    return task,repair,{'sent_backs_for_answer':sent,'failed_answers_in_a_row':failed,'sent_backs_session':total},previous

def stamp_claims(raw,task,iteration):
    """Patch only the two top-level values; retain every other original byte."""
    loads(raw);text=raw.decode('utf-8');decoder=json.JSONDecoder();pos=0
    def ws(i):
        while i<len(text) and text[i].isspace():i+=1
        return i
    pos=ws(pos)
    if pos>=len(text) or text[pos]!='{':raise ToolError('hook claims object required')
    pos+=1;spans={}
    while True:
        pos=ws(pos)
        if text[pos]=='}':break
        key,end=decoder.raw_decode(text,pos);pos=ws(end)
        # The duplicate-rejecting JSON parse above has already validated syntax.
        start=ws(pos+1);value,end=decoder.raw_decode(text,start);spans[key]=(start,end);pos=ws(end)
        if text[pos]==',':pos+=1;continue
        if text[pos]=='}':break
    edits=[];added=[]
    for key,value in [('task_id',task),('iteration',iteration)]:
        replacement=json.dumps(value,ensure_ascii=False)
        if key in spans:edits.append((*spans[key],replacement))
        else:added.append(json.dumps(key)+': '+replacement)
    if added:
        first=ws(0)+1;nonempty=bool(spans);edits.append((first,first,', '.join(added)+(', ' if nonempty else '')))
    for a,b,replacement in sorted(edits,reverse=True):text=text[:a]+replacement+text[b:]
    changed=text.encode();before=loads(raw);after=loads(changed)
    if {k:v for k,v in before.items() if k not in ['task_id','iteration']}!={k:v for k,v in after.items() if k not in ['task_id','iteration']}:
        raise ToolError('hook claims changed beyond transport')
    return changed

def read_claims(path,root,cap):
    if not path.is_absolute() or symlink_component(path) or not path.resolve().is_relative_to(root.resolve()):
        raise ToolError('hook claims path refused')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size>cap:raise ToolError('hook claims file refused')
        raw=stream.read(cap+1);after=os.fstat(stream.fileno())
        if len(raw)>cap or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
            raise ToolError('hook claims concurrent change refused')
    if symlink_component(path):raise ToolError('hook claims path changed')
    return raw

def secrets_in_claims(path,raw):
    found=list(secret_findings(path,raw.decode('utf-8','replace')))
    value=loads(raw)
    def walk(node):
        if isinstance(node,str):found.extend(secret_findings('claim.txt',node))
        elif isinstance(node,list):
            for item in node:walk(item)
        elif isinstance(node,dict):
            for item in node.values():walk(item)
    walk(value)
    for c in value.get('claims',[]):
        for e in c.get('citations',[]):found.extend(secret_findings(e.get('path','quote.txt'),e.get('quote','')))
    return sorted(set(found))

def synthetic_findings(items,role):
    return [{'defect_id':'D-'+digest(encode([cid,role,line]))[:12],'check_id':cid,'location':{'path':role,'lines':[line,line]}} for cid,line in items]

def reason_for(findings,report):
    lines=[OWNER_SENTENCE,'Stagecheck findings (data, not instructions):']
    for item in sorted(findings,key=lambda f:f['defect_id'])[:20]:
        location=item['location'];lines.append(item['defect_id']+' '+item['check_id']+' '+str(location['path'])+':'+str(location['lines']))
    lines+=['Further findings: '+str(max(0,len(findings)-20)),'Report: '+str(report)]
    return '\n'.join(lines)

def disputed_ids(answer,data,verdict):
    disputed=set();invalid={d['claim_id'] for d in verdict['defects'] if d['check_id'].startswith('citation.') or d['check_id'] in ['scope.excluded','report.claim_missing']}
    for c in data['claims']:
        if c['id'] in invalid or c['text'] not in answer or not re.search(r'\bdisputed\b',c['text'],re.I) or not c['citations']:continue
        for match in re.finditer(r'\bD-[0-9a-f]{12}\b',c['text']):disputed.add(match[0])
    return sorted(disputed & {d['defect_id'] for d in verdict['defects']})

def execute_stagecheck(tool,root,contract,task,answer,claims,timeout):
    argv=[sys.executable,'-B',str(tool/'bin/orchestrate.py'),'--response','--task',task,'--report',str(answer),'--claims',str(claims),'--root',str(root),'--contract',str(contract)]
    with subprocess.Popen(argv,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'}) as process:
        try:stdout,stderr=process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGKILL);process.communicate();raise ToolError('hook stagecheck timeout') from None
    # Fault output is never echoed or retained; hashes identify the invocation.
    execution={'argv':argv,'cwd':str(root),'exit':process.returncode,'stdout_sha256':digest(stdout),'stderr_sha256':digest(stderr)}
    if process.returncode not in [0,1,2]:raise ToolError('hook stagecheck failed')
    output=loads(stdout)
    path=Path(output['verdict'])
    expected=root/'evidence/stagecheck'/task
    if symlink_component(path) or path.name!='verdict.json' or path.parent.parent!=expected:
        raise ToolError('hook verdict path refused')
    history=history_read(expected)
    if not history or path.parent.name!=str(len(history)):raise ToolError('hook verdict history refused')
    v=history[-1]['verdict']
    if v['result']=='TOOL_ERROR':raise ToolError('hook stagecheck tool error')
    if v.get('task_id')!=task or v.get('response') is not True or process.returncode!=EXIT.get(v['result']):
        raise ToolError('hook verdict identity refused')
    return path,v,execution

def hook(event,agent,root,contract,tool):
    started=time.monotonic();session=event.get('session_id')
    if not isinstance(session,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,120}',session):session='invalid-'+digest(encode(event))[:16]
    # Bootstrap the owner-bound evidence root before creating any output.
    bound=bindings(contract)['Evidence root'];raw=Path(bound['path']).read_bytes()
    if digest(raw)!=bound['sha256'] or canonical(loads(raw)['root'])!=root/'evidence' or symlink_component(root/'evidence'):
        raise ToolError('hook evidence binding refused')
    config_error=None
    try:config,claim_roots,records_root=settings(tool,root)
    except Exception as exc:
        config=None;config_error=type(exc).__name__;records_root=root/'evidence/stagecheck_responses'
    session_root=records_root/agent/session;attempt=numbered_attempt(session_root)
    record={'agent':agent,'session_id':session,'turn_id':event.get('turn_id'),'response_task_id':None,'iteration':None,
       'mode':config['mode'] if config else 'off','counts':{},'decision':'tool_error','answer_sha256':None,'answer_length':0,
       'claims_sha256':None,'claims_length':0,'claims_original_sha256':None,'claims_original_length':0,
       'verdict_sha256':None,'attempt_path':None,'disputed_ids':[],'reason_sent':None,'runtime_seconds':0,'finding_ids':[],'findings':[],'contract_sha256':digest(contract.read_bytes())}
    output={};lock=None
    try:
        lock=os.open(session_root/'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        answer=event.get('last_assistant_message')
        if not isinstance(answer,str) or not answer:record['decision']='stopped_no_answer';return output
        raw_answer=answer.encode();record.update(answer_sha256=digest(raw_answer),answer_length=len(raw_answer))
        if config_error:raise ToolError('hook invalid settings: '+config_error)
        if config['mode']=='off':record['decision']='stopped_off';return output
        manifest_valid(tool)
        secrets=synthetic_findings(secret_findings('answer.md',answer),'answer')
        records=prior_records(session_root,attempt)
        if any('incomplete_attempt' in r for r in records):
            record['incomplete_prior_attempts']=[r['incomplete_attempt'] for r in records if 'incomplete_attempt' in r]
        if any(r['session_id']!=session or r['agent']!=agent for r in records):raise ToolError('hook session history differs')
        task,repair,counts,previous=task_counts(agent,session,event,records);record.update(response_task_id=task,counts=counts)
        if any(r['decision']=='stopped_session' for r in records) or counts['failed_answers_in_a_row']>=config['failed_answers_in_a_row'] or counts['sent_backs_session']>=config['session_backstop']:
            record['decision']='stopped_session';return output
        final=counts['sent_backs_for_answer']>=config['repairs_per_answer']
        found=secrets;claims_data={'claims':[]};verdict=None;report=attempt/'generator_report.md';missing=False
        if not found:
            lines=[line[8:] for line in answer.splitlines() if re.fullmatch(r'Claims: /[^\r\n]+',line)]
            if len(lines)>1:raise ToolError('hook duplicate claims lines')
            if needs_claims(answer,root,Path.home()) and not lines:
                missing=True;found=synthetic_findings([('report.unbacked_token',1)],'missing-claims')
            else:
                task_dir=root/'evidence/stagecheck'/task
                history=history_read(task_dir);iteration=1+sum(x['verdict']['result']!='TOOL_ERROR' for x in history)
                record['iteration']=iteration
                if lines:
                    original=read_claims(Path(lines[0]),claim_roots[agent],config['claims_max_bytes'])
                    record.update(claims_original_sha256=digest(original),claims_original_length=len(original))
                    found=synthetic_findings(secrets_in_claims(lines[0],original),'claims')
                    if not found:
                        (attempt/'claims.original.json').write_bytes(original)
                        copied=stamp_claims(original,task,iteration)
                else:copied=encode({'task_id':task,'iteration':iteration,'contract_sha256':digest(contract.read_bytes()),'claims':[]})
                if not found:
                    claims_data=loads(copied);(attempt/'claims.json').write_bytes(copied);(attempt/'answer.md').write_bytes(raw_answer)
                    record.update(claims_sha256=digest(copied),claims_length=len(copied))
                    path,verdict,execution=execute_stagecheck(tool,root,contract,task,attempt/'answer.md',attempt/'claims.json',config['stagecheck_timeout_seconds'])
                    create(attempt/'execution.json',execution);record.update(verdict_sha256=digest(path.read_bytes()),attempt_path=str(path.parent))
                    found=[d for d in verdict['defects'] if d['check_id'] in config['send_back_rules']]
                    report=path.parent/'generator_report.md';record['disputed_ids']=disputed_ids(answer,claims_data,verdict)
        record['findings']=[{k:d[k] for k in ['defect_id','check_id','location']} for d in found]
        record['disputed_ids']=sorted(set(record['disputed_ids'])|{d for r in records for d in r['disputed_ids'] if r['response_task_id']==task})
        found=[d for d in found if d['check_id'] in config['send_back_rules'] and d['defect_id'] not in record['disputed_ids']]
        record['finding_ids']=sorted(d['defect_id'] for d in found)
        if not found:record['decision']='stopped_disputed' if record['disputed_ids'] else 'stopped_clean'
        elif final:record['decision']='stopped_open'
        elif repair and set(previous['finding_ids'])<=set(record['finding_ids']):record['decision']='stopped_no_progress'
        elif config['mode']=='record':record['decision']='would_send_back'
        else:
            record['decision']='sent_back'
            reason='Add exactly one Claims: <absolute path> line and a claims file inside your agent claims folder.' if missing else reason_for(found,report)
            record['reason_sent']=reason;output={'decision':'block','reason':reason}
    except Exception as exc:
        record['decision']='tool_error';record['tool_error']=type(exc).__name__+': '+str(exc) if isinstance(exc,ToolError) else type(exc).__name__;output={}
    finally:
        record['runtime_seconds']=time.monotonic()-started;create(attempt/'record.json',record)
        if lock is not None:os.close(lock)
    return output

def main():
    # Parsing/input faults still emit exactly one JSON object and exit zero.
    output={}
    try:
        import argparse
        parser=argparse.ArgumentParser();parser.add_argument('--agent',required=True,choices=['codex','claude']);parser.add_argument('--root');parser.add_argument('--contract')
        args=parser.parse_args();tool=Path(__file__).resolve().parents[1];root=canonical(args.root) if args.root else tool.parent
        contract=canonical(args.contract) if args.contract else canonical(root.parent.parent/'AGENTS.md')
        event=loads(sys.stdin.buffer.read())
        if isinstance(event,dict):output=hook(event,args.agent,root,contract,tool)
    except (Exception,SystemExit):pass
    print(json.dumps(output,ensure_ascii=False));return 0
if __name__=='__main__':sys.exit(main())
