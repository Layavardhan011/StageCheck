"""Owner response-hook REQUEST §6/§7: isolated fixtures; no live agent hooks."""
import json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
from common import *
from response_tokens import fact_tokens,needs_claims,unbacked_tokens
from run_evals import fixture,manifest,execute,seed,execution_command
from orchestrate import history_read
import response_hook as rh
from unittest.mock import patch

PROGRAMME=Path('/home/magnus/Desktop/Desk/WIP/1. Team/Dir/RWA/NewArc/3m')
CONTRACT=PROGRAMME.parent.parent/'AGENTS.md'
HEADS='NOT DONE: fixture only\nFull Blast Radius Check: nothing was read or run\nEnforcement Self-Check: manual\n'

class Response(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='response-test-');self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name);self.source=Path(__file__).resolve().parents[1]
        self.run,self.data,self.root,self.tool=fixture(self.home,self.source,CONTRACT,PROGRAMME)
        self.run.update(response=True,repo=None,base='response',checked_head='response',changed_paths=[],dirty=False)
        self.data.pop('record');self.data.pop('record_sha256');self.data['claims']=[]
        Path(self.run['report']).write_text(HEADS);self.save()
    def save(self):
        Path(self.run['claims']).write_bytes(encode(self.data));Path(self.run['run_path']).write_bytes(encode(self.run))
    def check(self,name):
        self.save();folder=self.home/('check-'+str(len(list(self.home.glob('check-*')))))
        return execute(self.run,name,folder)
    def launch(self,extra=()):
        self.save();manifest(self.tool)
        argv=[sys.executable,'-B',str(self.tool/'bin/orchestrate.py'),'--response','--task',self.data['task_id'],'--report',self.run['report'],'--claims',self.run['claims'],'--root',str(self.root),'--contract',self.run['contract'],*extra]
        started=time.monotonic();r=subprocess.run(argv,capture_output=True,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},timeout=30)
        self.elapsed=time.monotonic()-started
        return r
    def test_minimal_response_and_history(self):
        for iteration in [1,2]:
            self.data['iteration']=iteration;r=self.launch();self.assertEqual(r.returncode,0,r.stderr+r.stdout)
        history=history_read(self.root/'evidence/stagecheck/fixture');self.assertEqual(len(history),2)
        v=history[-1]['verdict'];self.assertTrue(v['response']);self.assertEqual(v['checked_head'],'response');self.assertFalse(v['dirty'])
        self.assertFalse(v['errors']);self.assertEqual(v['agents'],[])
        self.assertTrue(all(any(name+': response mode: no repository change'==x for x in v['not_run']) for name in ['qual_naming','rerun']))
        run=load(self.root/'evidence/stagecheck/fixture/2/run.json');self.assertIsNone(run['repo']);self.assertEqual(run['changed_paths'],[])
        print(json.dumps({'response_seconds':self.elapsed,'scope':'isolated fixture'}))
    def test_response_arguments_refused(self):
        for flag,values in [('--repo',[str(self.root)]),('--base',['HEAD']),('--allow-dirty',[]),('--upstream',['x','y','0'*40]),('--record',['x']),('--wider-scope',['x'])]:
            r=self.launch([flag,*values]);self.assertEqual(r.returncode,2,(flag,r.stderr));self.assertFalse((self.root/'evidence/stagecheck/fixture').exists())
    def test_response_record_exception_delivery_retained(self):
        ctx=Context(self.run);self.assertEqual(claims(ctx)['claims'],[])
        self.data.update(record=None,record_sha256=None);self.save();claims(ctx)
        self.run.pop('response');self.save()
        with self.assertRaises(ToolError):claims(Context(self.run))
    def test_response_record_hash_requires_attachment(self):
        self.data['record_sha256']='0'*64;self.save()
        with self.assertRaisesRegex(ToolError,'without an attachment'):claims(Context(self.run))
    def test_emphasis_response_only(self):
        Path(self.run['report']).write_text('**NOT DONE:** fixture\n__Full Blast Radius Check:__ nothing was read or run\n**Enforcement Self-Check:** manual\n')
        self.assertEqual(self.check('report_lint')['defects'],[])
        self.run.pop('response');self.data.update(record=str(self.root/'evidence/record.json'),record_sha256=digest((self.root/'evidence/record.json').read_bytes()))
        self.assertIn('report.headers',{d['check_id'] for d in self.check('report_lint')['defects']})
    def test_tokens_and_backed_twins(self):
        path=self.root/'RWA/start/RWA_Architecture_v4.2.8.md'
        cite={'type':'file','path':str(path),'sha256':digest(path.read_bytes()),'lines':[1,2],'quote':'Specification value: accepted'}
        examples=[('path',str(path)),('hex','a'*40),('hex','b'*64),('lines',str(path)+' L2'),('url','https://example.invalid/source'),('label','SOURCE_PROVEN')]
        for kind,text in examples:
            with self.subTest(kind=kind,text=text):
                self.assertTrue(unbacked_tokens(text,{'claims':[]},self.root,Path.home()))
                c={'id':'c','text':text,'label':'SOURCE_PROVEN','citations':[cite]}
                if kind=='hex':c['text']+=' '+text
                self.assertEqual(unbacked_tokens(text,{'claims':[c]},self.root,Path.home()),[])
        self.assertEqual(fact_tokens('a'*39,self.root,Path.home()),[])
        self.assertTrue(needs_claims(HEADS+'\n'+str(path),self.root,Path.home()))
        self.assertFalse(needs_claims(HEADS,self.root,Path.home()))
        self.assertTrue(needs_claims(HEADS.replace('nothing was read or run','a file read'),self.root,Path.home()))
        self.assertEqual(fact_tokens('Claims: '+str(path),self.root,Path.home()),[])
        self.assertTrue(fact_tokens('**Claims:** '+str(path),self.root,Path.home()))
    def test_line_source_intent(self):
        a=str(self.root/'RWA/a.md');b=str(self.root/'RWA/b.md')
        data={'claims':[{'label':'SOURCE_PROVEN','text':'x','citations':[{'path':a,'lines':[1,5]},{'path':b,'lines':[9,12]}]}]}
        self.assertFalse(unbacked_tokens('`'+a+'` L2',data,self.root,Path.home()))
        self.assertTrue(unbacked_tokens('`'+a+'` L10',data,self.root,Path.home()))
        self.assertFalse(unbacked_tokens('`'+a+'`. Then L10 from `'+b+'`.',data,self.root,Path.home()))
        self.assertTrue(unbacked_tokens('`'+b+'`. Then L2.',data,self.root,Path.home()))
    def test_defect_identity_stable(self):
        Path(self.run['report']).write_text(HEADS+'\n'+'a'*64)
        a=self.check('report_lint');b=self.check('report_lint');self.assertEqual(a['defects'],b['defects']);self.assertEqual(a['defects'][0]['check_id'],'report.unbacked_token')
    def test_secret_quotes_and_inputs(self):
        Path(self.run['report']).write_text(HEADS+'\npassword = fixture-canary')
        self.assertIn('secret.assignment',{d['check_id'] for d in self.check('secrets')['defects']})
        Path(self.run['report']).write_text(HEADS)
        path=self.root/'RWA/quote.txt';path.write_text('-----BEGIN PRIVATE KEY-----\nfixture\n')
        self.data['claims']=[{'id':'c','text':'quote inspected','label':'SOURCE_PROVEN','kind':'observation','scope':'fixture','blast_radius':[],
           'citations':[{'type':'file','path':str(path),'sha256':digest(path.read_bytes()),'lines':[1,2],'quote':path.read_text()}]}]
        self.assertIn('secret.pem',{d['check_id'] for d in self.check('secrets')['defects']})
    def test_scope_and_authority_no_repository(self):
        self.assertFalse(self.check('scope_paths')['errors']);self.assertFalse(self.check('authority')['errors'])
        self.assertEqual(self.check('authority')['commands'],[])

class Hook(unittest.TestCase):
    save=Response.save
    def setUp(self):
        Response.setUp(self)
        self.config=load(self.tool/'config/response_hook.json');self.config['mode']='send_back'
        self.record_root=self.root/self.config['records_folder']
        for rel in self.config['claims_folder'].values():(self.root/rel).mkdir(parents=True)
        self.path=self.root/self.config['claims_folder']['codex']/'claims.json'
        self.data['task_id']='agent-placeholder';self.data['iteration']=999
        self.event={'session_id':'session-fixture-01','turn_id':'turn-01','stop_hook_active':False,'last_assistant_message':HEADS}
        self.write_config()
    def write_config(self):
        (self.tool/'config/response_hook.json').write_bytes(encode(self.config));manifest(self.tool)
    def submit(self,answer=None,agent='codex',**event):
        if answer is not None:self.event['last_assistant_message']=answer
        self.event.update(event);return rh.hook(dict(self.event),agent,self.root,Path(self.run['contract']),self.tool)
    def records(self,agent='codex'):
        root=self.record_root/agent/self.event['session_id']
        return [load(p/'record.json') for p in sorted((p for p in root.iterdir() if p.name.isdigit()),key=lambda p:int(p.name))]
    def backed(self,text='SOURCE_PROVEN Specification value: accepted'):
        cite={'type':'file','path':str(self.root/'RWA/start/RWA_Architecture_v4.2.8.md'),'sha256':digest((self.root/'RWA/start/RWA_Architecture_v4.2.8.md').read_bytes()),'lines':[1,2],'quote':'Specification value: accepted'}
        self.data['claims']=[{'id':'c','text':text,'kind':'observation','scope':'fixture','label':'SOURCE_PROVEN','citations':[cite],'blast_radius':[]}]
        self.path.write_bytes(encode(self.data))
        return HEADS+'\n'+text+'\nClaims: '+str(self.path)+'\n'
    def test_both_agent_shapes_and_no_claims(self):
        self.assertEqual(self.submit(),{});self.assertEqual(self.records()[-1]['decision'],'stopped_clean')
        event=dict(self.event);event.pop('turn_id');self.event=event
        self.assertEqual(self.submit(agent='claude'),{});self.assertEqual(self.records('claude')[-1]['decision'],'stopped_clean')
        self.assertTrue(self.records('claude')[-1]['response_task_id'].endswith('-1'))
    def test_claim_transport_and_exact_original(self):
        answer=self.backed();original=self.path.read_bytes()
        self.assertEqual(self.submit(answer),{});r=self.records()[-1];self.assertEqual(r['decision'],'stopped_clean')
        folder=self.root/self.config['records_folder']/'codex'/self.event['session_id']/'1'
        self.assertEqual((folder/'claims.original.json').read_bytes(),original)
        copied=(folder/'claims.json').read_bytes();self.assertEqual(r['claims_original_sha256'],digest(original));self.assertEqual(r['claims_sha256'],digest(copied))
        before=original.split(b'"claims":',1)[1].split(b'"contract_sha256"',1)[0]
        self.assertIn(before,copied);self.assertEqual(load(folder/'claims.json')['iteration'],1)
        self.assertNotEqual(load(folder/'claims.json')['task_id'],'agent-placeholder')
    def test_stamp_missing_and_pretty_fields(self):
        for raw in [b'{ "claims" : [], "contract_sha256":"x" }',b'{"task_id":"wrong", "claims":[{"text":"task_id and iteration"}],"iteration":99}']:
            changed=rh.stamp_claims(raw,'task',2)
            self.assertEqual(loads(changed)['task_id'],'task');self.assertEqual(loads(changed)['iteration'],2)
            for before,after in [(loads(raw).get('claims'),loads(changed).get('claims'))]:self.assertEqual(before,after)
        with self.assertRaises(ToolError):rh.stamp_claims(b'{"claims":[],"claims":[]}','task',2)
    def test_missing_claims_and_no_progress(self):
        answer=HEADS+'\n'+'a'*64
        self.assertEqual(self.submit(answer)['decision'],'block');self.assertIn('Claims:',self.records()[-1]['reason_sent'])
        self.assertEqual(self.submit(answer),{});self.assertEqual(self.records()[-1]['decision'],'stopped_no_progress')
        self.assertEqual(len(self.records()),2)
    def test_rule_admission_and_pairs(self):
        # Cases in the existing suite supply independently stated broken inputs.
        # These run only their target check; hook disposition is tested separately.
        for rule in self.config['send_back_rules']:
            if rule in ['report.unbacked_token'] or rule.startswith('secret.'):continue
            with self.subTest(rule=rule),tempfile.TemporaryDirectory(prefix='response-rule-') as tmp:
                run,data,root,tool=fixture(Path(tmp),self.source,CONTRACT,PROGRAMME)
                run.update(response=True,repo=None,changed_paths=[])
                if rule=='scope.excluded':
                    p=root/'RWA/previous';p.mkdir();f=p/'x.txt';f.write_text('excluded');run['read_paths']=[str(f)]
                else:
                    # Existing seed recipes require the fixture repository while
                    # preparing inputs; no recorded command is executed by response checks.
                    original_repo=str(root/'build/product');run['repo']=original_repo
                    seed(rule,run,data,root,tool);run['repo']=None;run['changed_paths']=[]
                Path(run['run_path']).write_bytes(encode(run))
                name={'citation':'citations','scope':'scope_paths','report':'report_lint'}[rule.split('.')[0]]
                value=execute(run,name,Path(tmp)/'observed')
                self.assertFalse(value['errors']);self.assertIn(rule,{d['check_id'] for d in value['defects']})
    def test_wrong_quote_then_repair(self):
        answer=self.backed();self.data['claims'][0]['citations'][0]['quote']='invented fixture quote';self.path.write_bytes(encode(self.data))
        out=self.submit(answer);self.assertEqual(out['decision'],'block');self.assertIn('citation.quote_not_found',out['reason']);self.assertNotIn('invented fixture quote',out['reason'])
        answer=self.backed();self.assertEqual(self.submit(answer,stop_hook_active=True),{});self.assertEqual(self.records()[-1]['decision'],'stopped_clean')
        self.assertEqual(self.records()[0]['response_task_id'],self.records()[1]['response_task_id'])
    def test_modes_and_manifest_fault(self):
        self.config['mode']='record';self.write_config();self.submit(HEADS+'\n'+'a'*64)
        self.assertEqual(self.records()[-1]['decision'],'would_send_back')
        self.config['mode']='off';self.write_config()
        with patch.object(rh,'manifest_valid',side_effect=AssertionError('off must not check')):self.assertEqual(self.submit(),{})
        self.assertEqual(self.records()[-1]['decision'],'stopped_off')
        self.config['mode']='send_back';self.write_config();p=self.tool/'bin/common.py';p.write_bytes(p.read_bytes()+b'\n')
        self.assertEqual(self.submit(HEADS),{});self.assertEqual(self.records()[-1]['decision'],'tool_error')
    def test_invalid_settings_and_denied_rules(self):
        for key,value in [('mode','bad'),('claims_max_bytes',0),('session_backstop',True),('send_back_rules',['preflight.bound_hash']),('send_back_rules',['authority.grant']),('send_back_rules',['report.completion']),('records_folder','../escape')]:
            original=self.config[key];self.config[key]=value;self.write_config();self.assertEqual(self.submit(HEADS),{});self.assertEqual(self.records()[-1]['decision'],'tool_error');self.config[key]=original
            self.assertIn('invalid settings',self.records()[-1]['tool_error'])
        self.write_config()
        self.event['last_assistant_message']=None;self.submit();self.assertEqual(self.records()[-1]['decision'],'stopped_no_answer')
    def test_claim_path_refusals(self):
        for mode in ['outside','symlink','oversize','fifo']:
            with self.subTest(mode=mode):
                target=self.path
                if target.exists() or target.is_symlink():target.unlink()
                if mode=='outside':target=self.root/'evidence/other.json';target.write_text('{}')
                elif mode=='symlink':target.symlink_to(self.root/'evidence/claims.json')
                elif mode=='oversize':target.write_bytes(b' '*(self.config['claims_max_bytes']+1))
                else:os.mkfifo(target)
                self.assertEqual(self.submit(HEADS+'\nClaims: '+str(target)),{});self.assertEqual(self.records()[-1]['decision'],'tool_error')
                if mode=='fifo':target.unlink()
        self.path.write_text('{}');self.assertEqual(self.submit(HEADS+'\nClaims: '+str(self.path)+'\nClaims: '+str(self.path)),{});self.assertEqual(self.records()[-1]['decision'],'tool_error')
    def test_secrets_never_retained(self):
        for rule,text in [('secret.pem','-----BEGIN PRIVATE KEY-----\nfixture-unique-canary'),('secret.keystore','{"crypto":{"ciphertext":"fixture-unique-canary"}}'),('secret.assignment','password = fixture-unique-canary')]:
            out=self.submit(HEADS+'\n'+text,turn_id=rule.replace('.','-'));self.assertEqual(out['decision'],'block');self.assertIn(rule,out['reason']);self.assertNotIn('fixture-unique-canary',out['reason'])
            self.assertEqual(self.submit(HEADS,stop_hook_active=True),{});self.assertEqual(self.records()[-1]['decision'],'stopped_clean')
        answer=self.backed();self.data['claims'][0]['citations'][0]['quote']='password = fixture-claims-canary';self.path.write_bytes(encode(self.data))
        self.submit(answer,turn_id='claims-secret')
        root=self.root/self.config['records_folder']
        for p in root.rglob('*'):
            if p.is_file():self.assertNotIn(b'fixture-unique-canary',p.read_bytes());self.assertNotIn(b'fixture-claims-canary',p.read_bytes())
    def test_reason_bound_and_no_content(self):
        found=[{'defect_id':'D-'+str(i).zfill(12),'check_id':'citation.quote_not_found','location':{'path':'answer','lines':[i,i]},'evidence':[{'quote':'private-canary'}]} for i in range(30)]
        reason=rh.reason_for(found,'generator_report.md');self.assertTrue(reason.startswith(rh.OWNER_SENTENCE));self.assertIn('Further findings: 10',reason);self.assertEqual(reason.count('citation.quote_not_found'),20);self.assertNotIn('private-canary',reason)
    def test_stdout_one_object(self):
        for agent in ['codex','claude']:
            event=dict(self.event,last_assistant_message=HEADS,session_id='cli-'+agent)
            r=subprocess.run([sys.executable,'-B',str(self.tool/'bin/response_hook.py'),'--agent',agent,'--root',str(self.root),'--contract',self.run['contract']],input=encode(event),capture_output=True,timeout=20)
            self.assertEqual(r.returncode,0);self.assertEqual(r.stdout.strip(),b'{}');self.assertEqual(r.stderr,b'')
    def test_fault_and_timeout(self):
        for failure in [ToolError('hook stagecheck timeout'),ToolError('hook stagecheck failed')]:
            with patch.object(rh,'execute_stagecheck',side_effect=failure):
                self.assertEqual(self.submit(HEADS),{});self.assertEqual(self.records()[-1]['decision'],'tool_error')

    def fake_stage(self,findings):
        # Decision-unit inputs, deliberately independent of checker output.
        # Real checker pairs and sealed integration are separate tests.
        out=self.root/'evidence/fake-verdict.json';out.write_bytes(encode({'defects':findings}))
        return out,{'defects':findings},{'scope':'decision unit only'}
    def finding(self,rule,number=1):
        return {'defect_id':'D-'+format(number,'012x'),'check_id':rule,'claim_id':'c','location':{'path':'answer','lines':[4,4]}}
    def test_each_rule_effect_and_twin(self):
        for i,rule in enumerate(self.config['send_back_rules']):
            with self.subTest(rule=rule):
                with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([self.finding(rule)])):
                    answer=self.backed();out=self.submit(answer,turn_id='rule-'+str(i),stop_hook_active=False)
                    self.assertEqual(out['decision'],'block');self.assertIn(rule,out['reason'])
                    self.assertIn(rule,[d['check_id'] for d in self.records()[-1]['findings']])
                with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([])):
                    self.assertEqual(self.submit(self.backed(),stop_hook_active=True),{})
                    self.assertEqual(self.records()[-1]['decision'],'stopped_clean')
    def test_real_rule_pipeline_pairs(self):
        rules=[r for r in self.config['send_back_rules'] if not r.startswith('secret.') and r not in ['scope.excluded','report.unbacked_token']]
        for i,rule in enumerate(rules):
            with self.subTest(rule=rule):
                answer=self.backed();Path(self.run['report']).write_text(answer)
                self.data['claims'][0]['citations'][0]['approved']=True
                self.run['repo']=str(self.root/'build/product')
                seed(rule,self.run,self.data,self.root,self.tool);self.run['repo']=None
                answer=Path(self.run['report']).read_text();self.path.write_bytes(encode(self.data))
                if 'Claims: ' not in answer:answer+='\nClaims: '+str(self.path)
                output=self.submit(answer,turn_id='actual-'+str(i),stop_hook_active=False)
                self.assertEqual(output['decision'],'block');self.assertIn(rule,output['reason'])
                self.assertEqual(self.submit(self.backed(),stop_hook_active=True),{})
                self.assertEqual(self.records()[-1]['decision'],'stopped_clean')
    def test_real_token_pipeline_pairs(self):
        path=str(self.root/'RWA/start/RWA_Architecture_v4.2.8.md')
        examples=[path,'a'*40,'b'*64,'`'+path+'` L2','https://example.invalid/source','SOURCE_PROVEN','`python3 fixture.py` exit 0']
        for i,text in enumerate(examples):
            with self.subTest(text=text):
                self.data['claims']=[];self.path.write_bytes(encode(self.data))
                answer=HEADS+'\n'+text+'\nClaims: '+str(self.path)
                out=self.submit(answer,turn_id='token-'+str(i),stop_hook_active=False)
                self.assertEqual(out['decision'],'block');self.assertIn('report.unbacked_token',out['reason'])
                answer=self.backed(text)
                if text.startswith('`python3'):
                    folder=self.root/'evidence/token-command';folder.mkdir()
                    for name in ['stdout','stderr']:(folder/name).write_bytes(b'')
                    record={'argv':['python3','fixture.py'],'cwd':str(self.root/'build/product'),'exit':0,'stdout_sha256':digest(b''),'stderr_sha256':digest(b'')}
                    (folder/'execution.json').write_bytes(encode(record))
                    cite={'type':'command','record':str(folder/'execution.json'),'record_sha256':digest((folder/'execution.json').read_bytes()),'argv':record['argv'],'cwd':record['cwd'],'exit_status':0,'stdout_sha256':record['stdout_sha256'],'stderr_sha256':record['stderr_sha256']}
                    self.data['claims'][0]['citations'].append(cite);self.path.write_bytes(encode(self.data))
                self.assertEqual(self.submit(answer,stop_hook_active=True),{});self.assertEqual(self.records()[-1]['decision'],'stopped_clean')
    def test_secret_filename_pipeline_pair(self):
        answer=self.backed();original=self.path;self.path=original.with_name('.env');self.path.write_bytes(original.read_bytes())
        answer=answer.replace(str(original),str(self.path))
        out=self.submit(answer);self.assertEqual(out['decision'],'block');self.assertIn('secret.filename',out['reason'])
        self.assertFalse((self.record_root/'codex'/self.event['session_id']/'1/claims.original.json').exists())
        self.path=original;self.assertEqual(self.submit(self.backed()),{});self.assertEqual(self.records()[-1]['decision'],'stopped_clean')
    def test_excluded_citation_pipeline_pair_and_delivery(self):
        folder=self.root/'RWA/previous';folder.mkdir();file=folder/'excluded.txt';file.write_text('excluded fixture')
        answer=self.backed('excluded fixture inspected');cite=self.data['claims'][0]['citations'][0]
        cite.update(path=str(file),sha256=digest(file.read_bytes()),lines=[1,1],quote='excluded fixture');self.path.write_bytes(encode(self.data))
        out=self.submit(answer);self.assertEqual(out['decision'],'block');self.assertIn('scope.excluded',out['reason'])
        record=self.records()[-1];v=load(Path(record['attempt_path'])/'verdict.json');self.assertFalse(v['errors'])
        citations=next(c for c in v['checks'] if c['id']=='citations');self.assertIn('not checked: excluded source',' '.join(citations['not_run']))
        self.assertNotIn(str(file),[p['path'] for c in v['checks'] for p in c['files']])
        self.assertEqual(self.submit(self.backed(),stop_hook_active=True),{});self.assertEqual(self.records()[-1]['decision'],'stopped_clean')
        self.run.pop('response');self.run['repo']=str(self.root/'build/product');self.data.update(task_id=self.run['task_id'],iteration=self.run['iteration'],record=str(self.root/'evidence/record.json'),record_sha256=digest((self.root/'evidence/record.json').read_bytes()))
        self.data['claims'][0]['citations'][0]=cite;self.save()
        result=execute(self.run,'citations',self.home/'delivery-excluded');self.assertTrue(result['errors']);self.assertFalse(result['not_run'])
    def test_claude_new_answer_while_previous_sent_back(self):
        previous={'decision':'sent_back','turn_id':None,'response_task_id':'resp-claude-session--1','finding_ids':[]}
        task,repair,counts,last=rh.task_counts('claude','session-01',{'stop_hook_active':False},[previous])
        self.assertFalse(repair);self.assertEqual(task,'resp-claude-session--2')
        task,repair,counts,last=rh.task_counts('claude','session-01',{'stop_hook_active':True},[previous])
        self.assertTrue(repair);self.assertEqual(task,previous['response_task_id'])
    def test_repairs_final_and_reset(self):
        for active in [False,True]:
            self.event['session_id']='repairs-'+str(active)
            for n in [1,2,3]:
                with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([self.finding('report.headers',n)])) as call:
                    out=self.submit(HEADS,turn_id='same',stop_hook_active=active)
                    self.assertEqual(call.call_count,1)
                    self.assertEqual(self.records()[-1]['counts']['sent_backs_for_answer'],n-1)
                    self.assertEqual(self.records()[-1]['decision'],'sent_back' if n<3 else 'stopped_open')
                    self.assertEqual(bool(out),n<3)
            with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([self.finding('report.headers',4)])):
                self.assertEqual(self.submit(HEADS,turn_id='new',stop_hook_active=False)['decision'],'block')
                self.assertEqual(self.records()[-1]['counts']['sent_backs_for_answer'],0)
        self.event['session_id']='final-repaired'
        for n in [1,2]:
            with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([self.finding('report.headers',n)])):self.submit(HEADS,turn_id='same',stop_hook_active=True)
        with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([])) as call:
            self.assertEqual(self.submit(HEADS),{});self.assertEqual(call.call_count,1);self.assertEqual(self.records()[-1]['decision'],'stopped_clean')
    def test_claude_round_limits_and_session_reset(self):
        # Claude has no turn id: false starts a task; true identifies a repair.
        self.event.pop('turn_id');agent='claude'
        for n in [1,2,3]:
            with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([self.finding('report.headers',n)])) as call:
                out=self.submit(HEADS,agent=agent,stop_hook_active=n>1)
                self.assertEqual(call.call_count,1);self.assertEqual(bool(out),n<3)
                self.assertEqual(self.records(agent)[-1]['decision'],'sent_back' if n<3 else 'stopped_open')
                self.assertEqual(self.records(agent)[-1]['counts']['sent_backs_for_answer'],n-1)
        with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([])):
            self.submit(HEADS,agent=agent,stop_hook_active=False)
            self.assertEqual(self.records(agent)[-1]['decision'],'stopped_clean')
            self.assertEqual(self.records(agent)[-1]['counts']['sent_backs_for_answer'],0)
        with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([self.finding('report.headers')])):
            for n in range(3):
                self.assertEqual(self.submit(HEADS,agent=agent,stop_hook_active=False)['decision'],'block')
                self.assertEqual(self.submit(HEADS,agent=agent,stop_hook_active=True),{})
                self.assertEqual(self.records(agent)[-1]['decision'],'stopped_no_progress')
            self.assertEqual(self.submit(HEADS,agent=agent,stop_hook_active=False),{})
            self.assertEqual(self.records(agent)[-1]['decision'],'stopped_session')
        self.event['session_id']='claude-backstop'
        for n in range(20):
            with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([self.finding('report.headers')])):
                self.assertEqual(self.submit(HEADS,agent=agent,stop_hook_active=False)['decision'],'block')
            with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([])):
                self.assertEqual(self.submit(HEADS,agent=agent,stop_hook_active=True),{})
        with patch.object(rh,'execute_stagecheck',side_effect=AssertionError('session backstop')):
            self.assertEqual(self.submit(HEADS,agent=agent,stop_hook_active=False),{})
            self.assertEqual(self.records(agent)[-1]['decision'],'stopped_session')
    def test_failed_run_and_clean_reset(self):
        for active in [False,True]:
            self.event['session_id']='failures-'+str(active)
            with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([self.finding('report.headers')])):
                for task in ['one','two','three']:
                    self.assertEqual(self.submit(HEADS,turn_id=task,stop_hook_active=False)['decision'],'block')
                    self.assertEqual(self.submit(HEADS,stop_hook_active=active),{})
                    self.assertEqual(self.records()[-1]['decision'],'stopped_no_progress')
                self.assertEqual(self.submit(HEADS,turn_id='four',stop_hook_active=False),{})
                self.assertEqual(self.records()[-1]['decision'],'stopped_session')
            # Owner may later raise a setting; the already-stopped session must
            # remain stopped independently of the current numerical threshold.
            self.config['failed_answers_in_a_row']=10;self.write_config()
            with patch.object(rh,'execute_stagecheck',side_effect=AssertionError('permanent session stop')):
                self.assertEqual(self.submit(HEADS,turn_id='five'),{})
                self.assertEqual(self.records()[-1]['decision'],'stopped_session')
            self.config['failed_answers_in_a_row']=3;self.write_config()
        self.event['session_id']='reset-failures'
        with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([self.finding('report.headers')])):
            self.submit(HEADS,turn_id='one',stop_hook_active=False);self.submit(HEADS)
        with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([])):self.submit(HEADS,turn_id='two',stop_hook_active=False)
        with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([self.finding('report.headers')])):
            self.submit(HEADS,turn_id='three',stop_hook_active=False);self.assertEqual(self.records()[-1]['counts']['failed_answers_in_a_row'],0)
    def test_twenty_backstop(self):
        for active in [False,True]:
            self.event['session_id']='backstop-'+str(active)
            with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([self.finding('report.headers')])):
                for n in range(20):
                    self.assertEqual(self.submit(HEADS,turn_id='t'+str(n),stop_hook_active=False)['decision'],'block')
                    with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([])):self.submit(HEADS,stop_hook_active=active)
                self.assertEqual(self.submit(HEADS,turn_id='t20',stop_hook_active=False),{})
                self.assertEqual(self.records()[-1]['decision'],'stopped_session');self.assertEqual(self.records()[-1]['counts']['sent_backs_session'],20)
    def test_partial_progress_and_disputes(self):
        a=self.finding('citation.quote_not_found',1);b=self.finding('citation.hash_mismatch',2)
        with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([a,b])):self.submit(self.backed())
        with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([b])):
            out=self.submit(self.backed());self.assertEqual(out['decision'],'block');self.assertNotIn(a['defect_id'],out['reason'])
        self.event['session_id']='disputes'
        with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([self.finding('report.headers')])):
            text=self.finding('report.headers')['defect_id']+' disputed: Specification value: accepted'
            self.assertEqual(self.submit(self.backed(text)),{});self.assertEqual(self.records()[-1]['decision'],'stopped_disputed')
        self.assertEqual(rh.disputed_ids(text,self.data,{'defects':[a]}),[])
        with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([self.finding('report.headers'),b])):
            self.submit(self.backed(text));self.assertEqual(self.records()[-1]['decision'],'sent_back')
            self.assertNotIn(self.finding('report.headers')['defect_id'],self.records()[-1]['finding_ids'])
        with patch.object(rh,'execute_stagecheck',return_value=self.fake_stage([self.finding('report.headers')])):
            self.assertEqual(self.submit(self.backed()),{});self.assertEqual(self.records()[-1]['decision'],'stopped_disputed')
    def test_unbound_advisory_and_unlisted(self):
        (self.tool/'new-unlisted.txt').write_text('fixture')
        (self.root/'controls/STAGECHECK_ROOT.json').write_bytes(encode({'root':str(self.tool),'manifest_sha256':'0'*64}))
        self.assertEqual(self.submit(HEADS),{});r=self.records()[-1];self.assertEqual(r['decision'],'stopped_clean')
        v=load(Path(r['attempt_path'])/'verdict.json');self.assertFalse(v['bound'])
        self.assertTrue({'preflight.binding_mismatch','preflight.unlisted_file'}<={d['check_id'] for d in v['defects']})
    def test_real_timeout_kills_process_group(self):
        # Temporary fake launcher demonstrates the process-group timeout itself.
        launcher=self.tool/'bin/orchestrate.py';pidfile=self.root/'evidence/timeout-child.pid'
        launcher.write_text('import subprocess,sys,time\nfrom pathlib import Path\np=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"])\nPath('+repr(str(pidfile))+').write_text(str(p.pid))\ntime.sleep(30)\n')
        started=time.monotonic()
        with self.assertRaisesRegex(ToolError,'timeout'):rh.execute_stagecheck(self.tool,self.root,Path(self.run['contract']),'timeout',self.path,self.path,1)
        self.assertLess(time.monotonic()-started,5);pid=int(pidfile.read_text())
        state=Path('/proc')/str(pid)/'stat'
        try:state_text=state.read_text()
        except (FileNotFoundError,ProcessLookupError):pass  # Reaped before open or during read.
        else:self.assertEqual(state_text.split()[2],'Z')
    def test_record_lock_and_identity_faults(self):
        self.submit(HEADS);folder=self.record_root/'codex'/self.event['session_id']
        fd=os.open(folder/'.lock',os.O_RDWR)
        import fcntl
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:self.assertEqual(self.submit(HEADS),{})
        finally:os.close(fd)
        self.assertEqual(self.records()[-1]['decision'],'tool_error')
        # A failed concurrent record is retained; no shared record is overwritten.
        self.submit(HEADS,turn_id='after-concurrency');self.assertEqual(self.records()[-1]['decision'],'stopped_clean')
    def test_real_timeout_accepts_reaped_child(self):
        # The child may disappear before open (ENOENT) or during read (ESRCH).
        read=Path.read_text;exists=Path.exists
        def proc_stat(path):return path.name=='stat' and path.parent.parent==Path('/proc')
        for error in [FileNotFoundError,ProcessLookupError]:
            observed=[]
            def disappearing(path,*args,**kwargs):
                if proc_stat(path):observed.append(str(path));raise error(str(path))
                return read(path,*args,**kwargs)
            def previously_present(path):return True if proc_stat(path) else exists(path)
            with self.subTest(error=error.__name__),patch.object(Path,'exists',previously_present),patch.object(Path,'read_text',disappearing):
                self.test_real_timeout_kills_process_group()
            self.assertEqual(len(observed),1)
    def test_missing_prior_record_recovers_without_rewriting(self):
        for agent in ['codex','claude']:
            folder=self.record_root/agent/self.event['session_id'];old=folder/'1';old.mkdir(parents=True)
            marker=old/'answer.md';marker.write_text('interrupted fixture');before=marker.read_bytes()
            self.assertEqual(self.submit(HEADS,agent=agent,stop_hook_active=False),{})
            current=load(folder/'2/record.json');self.assertEqual(current['decision'],'stopped_clean')
            self.assertEqual(current['incomplete_prior_attempts'],['1'])
            history=rh.prior_records(folder,folder/'3')
            self.assertEqual(history[0]['decision'],'tool_error');self.assertIsNone(history[0]['response_task_id'])
            self.assertEqual(history[0]['finding_ids'],[]);self.assertEqual(history[0]['disputed_ids'],[])
            self.assertFalse((old/'record.json').exists());self.assertEqual(marker.read_bytes(),before)
            self.assertEqual(current['counts']['failed_answers_in_a_row'],0)
    def test_timeout_reaping_keeps_live_child_and_io_error_guards(self):
        read=Path.read_text
        for expected,stat_value in [
            (AssertionError,'1 (fixture) S\n'),(AssertionError,'1 (fixture) R\n'),
            (IndexError,''),(PermissionError,PermissionError('fixture permission')),
            (OSError,OSError(5,'fixture I/O error')),
            (IsADirectoryError,IsADirectoryError('fixture directory')),
            (NotADirectoryError,NotADirectoryError('fixture not directory'))]:
            def observed(path,*args,**kwargs):
                if path.name=='stat' and path.parent.parent==Path('/proc'):
                    if isinstance(stat_value,Exception):raise stat_value
                    return stat_value
                return read(path,*args,**kwargs)
            with self.subTest(expected=expected.__name__),patch.object(Path,'read_text',observed),self.assertRaises(expected):
                self.test_real_timeout_kills_process_group()
    def test_command_token(self):
        cmd='python3 -B fixture.py';text='`'+cmd+'` exit 0'
        data={'claims':[{'text':'run','label':'TEST_PROVEN','citations':[{'type':'command','argv':['python3','-B','fixture.py']}]}]}
        self.assertEqual(unbacked_tokens(text,data,self.root,Path.home()),[])
        self.assertEqual(unbacked_tokens(text,{'claims':[]},self.root,Path.home())[0]['kind'],'command')
        self.assertFalse(any(t['kind']=='command' for t in fact_tokens('`'+cmd+'`',self.root,Path.home())))
        self.assertTrue(any(t['kind']=='command' for t in fact_tokens('`/usr/bin/true` exit 0',self.root,Path.home())))
        absolute='`/tmp/fixture-command --arg` exit 0'
        tokens=fact_tokens(absolute,self.root,Path.home())
        self.assertEqual([t['value'] for t in tokens if t['kind']=='path'],['/tmp/fixture-command'])
        nested="`python3 -B '"+str(self.root/'RWA/path with spaces.py')+"'` exit 0"
        self.assertEqual([t['value'] for t in fact_tokens(nested,self.root,Path.home()) if t['kind']=='path'],[str(self.root/'RWA/path with spaces.py')])

if __name__=='__main__':unittest.main()
