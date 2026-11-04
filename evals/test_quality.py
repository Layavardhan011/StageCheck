"""Owner accuracy prompt §6: isolated tests, independent expectations; no real data."""
import sys, unittest, tempfile, shutil, subprocess, os
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
import quality as q
sys.path.insert(0,str(Path(__file__).resolve().parent))
from run_evals import fixture,manifest
from decimal import Decimal, localcontext
from math import comb

TABLE=[(59,59,.950492),(58,58,.949661),(93,92,.950006),(92,91,.949474),(124,122,.950100),(123,121,.949701),(100,95,.897747),(20,19,.783894),(30,30,.904966)]

def independent(n,k):
    """Decimal exact integer-coefficient binomial polynomial; independent of log summation."""
    with localcontext() as c:
        c.prec=60; lo=Decimal(0);hi=Decimal(1);alpha=Decimal('0.05')
        if n==k:return float(alpha**(Decimal(1)/n))
        for _ in range(180):
            p=(lo+hi)/2
            value=sum(Decimal(comb(n,i))*p**i*(1-p)**(n-i) for i in range(k,n+1))
            if value<alpha:lo=p
            else:hi=p
        return float((lo+hi)/2)

class Statistics(unittest.TestCase):
    def test_independent_table(self):
        for n,k,want in TABLE:
            reference=independent(n,k)
            self.assertAlmostEqual(reference,want,delta=1e-6)
            self.assertAlmostEqual(q.lower(n,k,.95),reference,delta=1e-12)
    def test_edges(self):
        self.assertIsNone(q.lower(0,0,.95));self.assertEqual(q.lower(5,0,.95),0)
        self.assertEqual(q.figures(0,0,.95,.95)['status'],'insufficient')
        self.assertEqual(q.figures(30,30,.95,.95)['more_successes'],29)
        self.assertEqual(q.figures(50,49,.95,.95)['more_successes'],43)
    def test_invalid(self):
        for args in [(1,2,.95),(-1,0,.95),(2,1,1)]:
            with self.assertRaises(q.ToolError):q.lower(*args)

class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='quality-test-');self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name)
        self.tool=Path(__file__).resolve().parents[1]
        self.programme=Path('/home/magnus/Desktop/Desk/WIP/1. Team/Dir/RWA/NewArc/3m')
        self.contract=self.programme.parent.parent/'AGENTS.md'
        self.run,self.data,self.root,self.ft=fixture(self.home,self.tool,self.contract,self.programme)
        self.ctx=q.Context(self.run)
        self.records=q.roots(self.ctx)[1]
    def verdict(self,task='fixture',attempt=1,defect_id='D-fixture',check='citations',version=None):
        folder=self.root/'evidence/stagecheck'/task/str(attempt);folder.mkdir(parents=True)
        vers=q.versions(self.ctx);checks=[dict(q.result(c),version=vers[c]['sha256']) for c in q.CHECKS]
        if version:next(c for c in checks if c['id']==check)['version']=version
        defect=self.ctx.defect('citation.hash_mismatch','checks/'+check+'.py',self.run['claims'])
        defect['defect_id']=defect_id
        value={'type':'verdict','task_id':task,'iteration':attempt,'contract_sha256':q.digest(self.contract.read_bytes()),'checked_head':'fixture','manifest_sha256':q.digest((self.ft/'MANIFEST.sha256').read_bytes()),'bound':True,'depth':'docs','input_hashes':{},'previous':q.load(folder.parent/str(attempt-1)/'seal.json') if attempt>1 else {},'checks':checks,'agents':[],'defects':[defect] if defect_id else [],'not_run':[],'errors':[],'result':'CLEAR','questions':[],'counts':{'blocking':0,'report_only':int(bool(defect_id)),'not_run':0}}
        q.create(folder/'verdict.json',value);(folder/'generator_report.md').write_bytes(b'fixture report\n');q.create(folder/'seal.json',{n:q.digest((folder/n).read_bytes()) for n in ['verdict.json','generator_report.md']})
        return folder/'verdict.json',value
    def request(self,kind,subject,value,actor='owner',type='decision',evidence=None,**extra):
        return dict(kind=kind,subject=subject,value=value,actor=actor,type=type,evidence=evidence or [],**extra)
    def label(self,path,value='true_defect',actor='owner',type='decision',**extra):
        v=q.load(path);check=next(c for c in v['checks'] if c['id']=='citations')
        return self.request('finding_label',{'task':v['task_id'],'defect_id':v['defects'][0]['defect_id'],'check':'citations','version':check['version']},value,actor,type,[{'path':str(path),'sha256':q.digest(path.read_bytes())}],**extra)
    def test_policy(self):
        self.assertEqual(q.policy(self.ctx)[0]['audit_precision'],.95)
        p=self.ft/'config/quality_targets.json';value=q.load(p);value['audit_precision']=1;p.write_bytes(q.encode(value))
        with self.assertRaises(q.ToolError):q.policy(self.ctx)
    def test_versions(self):
        before=q.versions(self.ctx)
        for path in ['checks/citations.py','bin/common.py','config/required_outcomes.json','config/commands.json']:
            p=self.ft/path;old=p.read_bytes();p.write_bytes(old+b'\n');after=q.versions(self.ctx)
            self.assertNotEqual(before['citations']['sha256'],after['citations']['sha256']);p.write_bytes(old)
        for path in ['bin/quality.py','config/modes.json','config/quality_targets.json','README.md']:
            p=self.ft/path;old=p.read_bytes();p.write_bytes(old+b'\n');self.assertEqual(before,q.versions(self.ctx));p.write_bytes(old)
        c=self.ft/'bin/__pycache__';c.mkdir();(c/'x.pyc').write_bytes(b'fixture');self.assertEqual(before,q.versions(self.ctx))
    def test_writer_and_snapshot(self):
        path,v=self.verdict();first=q.append_record(self.ctx,self.label(path));chain,_=q.read_chain(self.records)
        self.assertEqual(len(chain),2);self.assertEqual(chain[0]['record']['kind'],'policy_snapshot')
        pol=self.ft/'config/quality_targets.json';value=q.load(pol);value['confidence']=.9;pol.write_bytes(q.encode(value))
        q.append_record(self.ctx,self.label(path,'false_block'));chain,_=q.read_chain(self.records)
        self.assertEqual(len(chain),4);self.assertEqual(chain[2]['record']['kind'],'policy_snapshot')
    def test_writer_refusal_pairs(self):
        path,v=self.verdict();good=self.label(path)
        cases=[]
        for key,val in [('actor','codex'),('value','invented'),('type','invented'),('note','api_key=canary'),('unknown',True)]:
            cases.append(dict(good,**{key:val}))
        cases.append(dict(good,actor='claude'));cases.append(dict(good,subject=dict(good['subject'],version='0'*64)))
        cases.append(dict(good,evidence=[{'path':str(path),'sha256':'0'*64}]))
        for bad in cases:
            with self.subTest(bad=bad):
                with self.assertRaises(q.ToolError):q.append_record(self.ctx,bad)
                q.append_record(self.ctx,good)
        q.append_record(self.ctx,dict(good,actor='claude',type='proposal'))
        p=path.parent/'seal.json';p.write_bytes(p.read_bytes()+b' ')
        # Whitespace in seal changes no verified verdict identity; change the actual sealed verdict.
        path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaises(q.ToolError):q.append_record(self.ctx,good)
    def test_confirmation_and_corrections(self):
        p,v=self.verdict();proposal=q.append_record(self.ctx,self.label(p,actor='claude',type='proposal'))
        confirmation=self.request('confirmation',{'proposals':[proposal]},'confirmed')
        q.append_record(self.ctx,confirmation)
        runs,_=q.real_verdicts(self.ctx);chain,_=q.read_chain(self.records);d,skipped,_=q.effective(self.ctx,chain,runs,q.versions(self.ctx))
        self.assertEqual(len(d),1);self.assertEqual(d[0]['deciding_actor'],'owner')
        q.append_record(self.ctx,self.label(p,'false_block',replaces=proposal))
        with self.assertRaises(q.ToolError):q.append_record(self.ctx,confirmation)
    def test_two_writers(self):
        p,v=self.verdict();request=self.root/'evidence/request.json';q.create(request,self.label(p))
        argv=[sys.executable,'-B',str(self.ft/'bin/quality_write.py'),'--run',self.run['run_path'],'--record',str(request)]
        workers=[subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'}) for _ in range(2)]
        try:
            for w in workers:
                out,err=w.communicate(timeout=30);self.assertEqual(w.returncode,0,err.decode())
        finally:
            for w in workers:
                if w.poll() is None:w.terminate()
                w.communicate(timeout=10)
        chain,_=q.read_chain(self.records);self.assertEqual(len(chain),3)
    def test_policy_history_deciders(self):
        p,v=self.verdict();old=q.append_record(self.ctx,self.label(p,actor='claude',type='proposal'))
        policy=self.ft/'config/quality_targets.json';value=q.load(policy);value['deciders'].append('claude');policy.write_bytes(q.encode(value))
        q.append_record(self.ctx,self.request('coverage',{'verdicts':[q.digest(p.read_bytes())]},'covered'))
        runs,_=q.real_verdicts(self.ctx);chain,_=q.read_chain(self.records);decisions,_,_=q.effective(self.ctx,chain,runs)
        self.assertFalse(any(d['sha256']==old for d in decisions))
        prompt=self.root/'evidence/prompt.txt';prompt.write_text('fixture prompt')
        with self.assertRaises(q.ToolError):q.append_record(self.ctx,self.request('prompt_outcome',{'path':str(prompt),'sha256':q.digest(prompt.read_bytes())},'correct','claude'))
    def test_record_semantics_skip(self):
        p,v=self.verdict();q.append_record(self.ctx,self.label(p));chain,_=q.read_chain(self.records)
        bad=dict(chain[-1]['record'],value='invalid');raw=q.line_bytes(bad);f=self.records/'records.0001.jsonl'
        f.write_bytes(q.line_bytes(chain[0]['record'])+raw)
        chain,_=q.read_chain(self.records);runs,_=q.real_verdicts(self.ctx);decisions,skipped,_=q.effective(self.ctx,chain,runs)
        self.assertEqual(decisions,[]);self.assertEqual(len(skipped),1)
    def test_subject_refusal_pairs(self):
        p,v=self.verdict();sha=q.digest(p.read_bytes());version=next(c['version'] for c in v['checks'] if c['id']=='citations')
        seed='1'*64
        missed=q.append_record(self.ctx,self.request('missed_defect',{'task':'fixture','verdict':sha,'check':'citations','defect_id':'later'},'missed'))
        subjects=[
            ('coverage',{'verdicts':['0'*64]},{'verdicts':[sha]},'covered'),
            ('missed_defect',{'task':'wrong','verdict':sha,'check':'citations','defect_id':'later'},{'task':'fixture','verdict':sha,'check':'none','defect_id':'later'},'missed'),
            ('missed_defect_closure',{'record':'0'*64,'seed_id':seed},{'record':missed,'seed_id':seed},'closed'),
            ('delivery_outcome',{'task':'wrong','verdict':sha},{'task':'fixture','verdict':sha},'met'),
            ('blocking_override',{'check':'citations','version':'0'*64},{'check':'citations','version':version},'blocking_allowed')]
        for kind,bad,good,value in subjects:
            with self.subTest(kind=kind):
                with self.assertRaises(q.ToolError):q.append_record(self.ctx,self.request(kind,bad,value))
                q.append_record(self.ctx,self.request(kind,good,value))
        q.append_record(self.ctx,self.request('blocking_override',{'check':'citations','version':'all'},'blocking_allowed'))
        p2,v2=self.verdict(attempt=2)
        with self.assertRaises(q.ToolError):q.append_record(self.ctx,self.request('delivery_outcome',{'task':'fixture','verdict':q.digest(p2.read_bytes())},'met'))
        prompt=self.root/'evidence/prompt.txt';prompt.write_text('fixture prompt')
        for sha0 in ['0'*64,q.digest(prompt.read_bytes())]:
            req=self.request('prompt_outcome',{'path':str(prompt),'sha256':sha0},'correct')
            if sha0=='0'*64:
                with self.assertRaises(q.ToolError):q.append_record(self.ctx,req)
            else:q.append_record(self.ctx,req)
        for actor in ['claude','owner']:
            req=self.request('carryover',{'check':'citations','old':'0'*64,'new':version},'evidence_carries_over',actor)
            with self.assertRaises(q.ToolError):q.append_record(self.ctx,req)
    def test_improvement_counting_label(self):
        p,v=self.verdict();proposal=q.append_record(self.ctx,self.label(p,actor='claude',type='proposal'))
        cite={'type':'quality_record','record_sha256':proposal}
        with self.assertRaises(q.ToolError):q.label_decision(self.ctx,cite)
        q.append_record(self.ctx,self.request('confirmation',{'proposals':[proposal]},'confirmed'))
        self.assertEqual(q.label_decision(self.ctx,cite)['deciding_actor'],'owner')
        direct=q.append_record(self.ctx,self.label(p));self.assertEqual(q.label_decision(self.ctx,{'type':'quality_record','record_sha256':direct})['sha256'],direct)
        with self.assertRaises(q.ToolError):q.label_decision(self.ctx,{'type':'quality_record','record_sha256':'0'*64})
    def test_chain_damage_and_recovery(self):
        p,v=self.verdict();q.append_record(self.ctx,self.label(p));f=self.records/'records.0001.jsonl';original=f.read_bytes()
        for raw in [original.replace(b'snapshot',b'snapshoX',1),b''.join(original.splitlines(keepends=True)[1:]),b''.join(reversed(original.splitlines(keepends=True))),original+b'{']:
            f.write_bytes(raw)
            with self.assertRaises(q.ToolError):q.read_chain(self.records)
            with self.assertRaises(q.ToolError):q.append_record(self.ctx,self.label(p))
            f.write_bytes(original)
        f.write_bytes(original+b'{')
        with self.assertRaises(q.ToolError):q.append_record(self.ctx,{'actor':'claude'},True)
        q.append_record(self.ctx,{'actor':'owner'},True)
        q.append_record(self.ctx,self.label(p,'false_block'))
        chain,_=q.read_chain(self.records);self.assertEqual(len(chain),4);self.assertEqual(f.read_bytes(),original+b'{')

    def seed_case(self):
        return {'id':'PRIVATE-NAME-CANARY','target':'report.headers','pair':{'clean':{},'defective':{'edits':[{'path':'NewArc/3m/evidence/report.md','text':'NOT DONE: CONTENT-CANARY\n'}]}}}

    def seed_metadata(self,count):
        names=['config/agents.json','config/commands.json','config/paths.json']
        return {'verified_only_allowed_differences':True,'allowed_differences':sorted(names+['MANIFEST.sha256']),
                'file_sha256':{name:q.digest((self.ft/name).read_bytes()) for name in names},'copies_checked':2*count}

    def test_declarative_seeds(self):
        from quality_seeds import run_seeds
        from unittest.mock import patch
        seeds=self.home/'private';seeds.mkdir();p=seeds/'NAME-CANARY.json';q.create(p,self.seed_case())
        owned=[];constructor=tempfile.TemporaryDirectory
        def capture(*args,**kwargs):
            value=constructor(*args,**kwargs);owned.append(Path(value.name));return value
        with patch('quality_seeds.tempfile.TemporaryDirectory',capture):
            first=run_seeds(self.ctx,seeds,8192);second=run_seeds(self.ctx,seeds,8192)
        self.assertEqual(first.read_bytes(),second.read_bytes())
        value=q.load(first);self.assertTrue(value['seeds'][0]['detected'])
        for p in self.records.iterdir():
            self.assertNotIn(b'CANARY',p.read_bytes())
        self.assertTrue(owned);self.assertTrue(all(not p.exists() for p in owned))

    def test_seed_refusals(self):
        from quality_seeds import seed_path,apply_side,run_seeds
        workspace=self.root.parent.parent
        for path in ['/tmp/out','../out','NewArc/3m/stagecheck/bin/common.py','NewArc/3m/build/product/.git/config']:
            with self.assertRaises(q.ToolError):seed_path(workspace,self.ft,path)
        link=workspace/'link';link.symlink_to(self.root)
        with self.assertRaises(q.ToolError):seed_path(workspace,self.ft,'link/evidence/x')
        good={'edits':[{'path':'NewArc/3m/evidence/new.txt','text':'fixture'}]}
        apply_side(good,self.run,self.data,self.root,self.ft,32)
        for bad in [{'edits':[{'path':'NewArc/3m/evidence/x.py','text':'print(1)'}]},dict(good,run={'tool_root':'outside'}),dict(good,execute='code')]:
            with self.assertRaises(q.ToolError):apply_side(bad,self.run,self.data,self.root,self.ft,32)
        with self.assertRaises(q.ToolError):apply_side(good,self.run,self.data,self.root,self.ft,1)
        seeds=self.home/'private';seeds.mkdir();q.create(seeds/'seed.json',self.seed_case())
        for cap in [0,1]:
            with self.assertRaises(q.ToolError):run_seeds(self.ctx,seeds,cap)
        (seeds/'link.json').symlink_to(seeds/'seed.json')
        with self.assertRaises(q.ToolError):run_seeds(self.ctx,seeds,8192)

    def test_measure_counting(self):
        p,v=self.verdict();q.append_record(self.ctx,self.label(p,'unresolved'))
        p2,_=self.verdict(attempt=2);self.verdict(attempt=3)
        latest=q.append_record(self.ctx,self.label(p2))
        other,_=self.verdict(task='second');q.append_record(self.ctx,self.label(other,'false_block'))
        pending,_=self.verdict(task='pending',defect_id='D-pending')
        covered,_=self.verdict(task='covered',defect_id='D-covered')
        q.append_record(self.ctx,self.request('coverage',{'verdicts':[q.digest(covered.read_bytes())]},'covered'))
        c=q.measure_data(self.ctx)['checks']['citations']
        self.assertEqual((c['precision']['count'],c['precision']['successes'],c['pending_count']),(3,1,1))
        q.append_record(self.ctx,self.label(p2,'false_block',actor='claude',type='proposal',replaces=latest))
        self.assertEqual(q.measure_data(self.ctx)['checks']['citations']['precision']['successes'],1)
        q.append_record(self.ctx,self.label(p2,'false_block',replaces=latest))
        self.assertEqual(q.measure_data(self.ctx)['checks']['citations']['precision']['successes'],0)
        first=q.write_measurement(self.ctx);second=q.write_measurement(self.ctx)
        self.assertEqual(first.read_bytes(),second.read_bytes());self.assertIn('D-pending',first.with_suffix('.md').read_text())

    def test_carryover_chain(self):
        p,v=self.verdict();q.append_record(self.ctx,self.label(p));old=q.versions(self.ctx)['citations']['sha256']
        file=self.ft/'checks/citations.py';file.write_bytes(file.read_bytes()+b'\n# version two\n');middle=q.versions(self.ctx)['citations']['sha256']
        self.assertEqual(q.measure_data(self.ctx)['checks']['citations']['precision']['count'],0)
        q.append_record(self.ctx,self.request('carryover',{'check':'citations','old':old,'new':middle},'evidence_carries_over'))
        self.assertEqual(q.measure_data(self.ctx)['checks']['citations']['precision']['count'],1)
        p2,_=self.verdict(attempt=2);q.append_record(self.ctx,self.label(p2,'false_block'))
        self.assertEqual(q.measure_data(self.ctx)['checks']['citations']['precision']['count'],1)
        self.assertEqual(q.measure_data(self.ctx)['checks']['citations']['precision']['successes'],0)
        file.write_bytes(file.read_bytes()+b'\n# version three\n');new=q.versions(self.ctx)['citations']['sha256']
        self.assertEqual(q.measure_data(self.ctx)['checks']['citations']['precision']['count'],0)
        pol=self.ft/'config/quality_targets.json';value=q.load(pol);value['deciders'].append('claude');pol.write_bytes(q.encode(value))
        req=self.request('carryover',{'check':'citations','old':middle,'new':new},'evidence_carries_over','claude')
        with self.assertRaises(q.ToolError):q.append_record(self.ctx,req)
        q.append_record(self.ctx,dict(req,type='proposal'))
        self.assertEqual(q.measure_data(self.ctx)['checks']['citations']['precision']['count'],0)
        q.append_record(self.ctx,dict(req,actor='owner'))
        self.assertEqual(q.measure_data(self.ctx)['checks']['citations']['precision']['count'],1)

    def test_recall_and_open_missed(self):
        p,v=self.verdict();miss=q.append_record(self.ctx,self.request('missed_defect',{'task':'fixture','verdict':q.digest(p.read_bytes()),'check':'citations','defect_id':'missed'},'missed'))
        gap=q.append_record(self.ctx,self.request('missed_defect',{'task':'fixture','verdict':q.digest(p.read_bytes()),'check':'none','defect_id':'gap'},'missed'))
        ids=[q.digest(str(i).encode()) for i in range(59)]
        seeds={'seed_set_sha256':q.digest(q.encode(sorted(ids))),'versions':{c:v['sha256'] for c,v in q.versions(self.ctx).items()},'seeds':[{'seed_id':i,'target_rule':'citation.hash_mismatch','check':'citations','detected':True,'clean_firings':{}} for i in sorted(ids)],'fixture_configuration':self.seed_metadata(len(ids))}
        self.records.mkdir(exist_ok=True);q.create(self.records/'seed_result.0001.json',seeds)
        measured=q.measure_data(self.ctx);self.assertEqual(measured['checks']['citations']['recall']['status'],'not_yet');self.assertEqual(measured['uncovered_gaps'],[gap])
        q.append_record(self.ctx,self.request('missed_defect_closure',{'record':miss,'seed_id':ids[0]},'closed'))
        self.assertEqual(q.measure_data(self.ctx)['checks']['citations']['recall']['status'],'meets')
        seeds['seeds'][0]['clean_firings']={'citations':['citation.hash_mismatch']};q.create(self.records/'seed_result.0002.json',seeds)
        self.assertEqual(q.measure_data(self.ctx)['checks']['citations']['recall']['successes'],58)
        file=self.ft/'checks/citations.py';file.write_bytes(file.read_bytes()+b'\n# reset\n')
        c=q.measure_data(self.ctx)['checks']['citations'];self.assertEqual(c['open_missed_defects'],[miss]);self.assertEqual(c['recall']['count'],0)

    def test_final_line_anchor_and_append(self):
        p,v=self.verdict();q.append_record(self.ctx,self.label(p));q.write_measurement(self.ctx)
        q.append_record(self.ctx,self.label(p,'unresolved'))  # Appending does not invalidate the older prefix.
        q.measure_data(self.ctx)
        path=self.records/'records.0001.jsonl';raw=path.read_bytes()
        q.write_measurement(self.ctx)
        path.write_bytes(raw.replace(b'unresolved',b'false_block'))
        q.read_chain(self.records)  # Accepted format limitation before an external anchor.
        with self.assertRaises(q.ToolError):q.measure_data(self.ctx)
        with self.assertRaises(q.ToolError):q.append_record(self.ctx,self.label(p))

    def test_recovery_measure_and_outcomes(self):
        p,v=self.verdict();q.append_record(self.ctx,self.label(p));q.append_record(self.ctx,self.request('delivery_outcome',{'task':'fixture','verdict':q.digest(p.read_bytes())},'met'))
        prompt=self.root/'evidence/prompt.txt';prompt.write_text('fixture prompt')
        q.append_record(self.ctx,self.request('prompt_outcome',{'path':str(prompt),'sha256':q.digest(prompt.read_bytes())},'unresolved'))
        f=self.records/'records.0001.jsonl';f.write_bytes(f.read_bytes()+b'{')
        with self.assertRaises(q.ToolError):q.write_measurement(self.ctx)
        q.append_record(self.ctx,{'actor':'owner'},True);q.append_record(self.ctx,self.label(p,'false_block'))
        measured=q.load(q.write_measurement(self.ctx));self.assertEqual(measured['checks']['citations']['precision']['failures'],1)
        self.assertEqual(measured['engineering']['successes'],1);self.assertEqual(measured['prompt_development']['failures'],1)

    def launch(self,task):
        # Existing fixture contains an untracked qualification file. Explicit dirty
        # inspection retains its identity; product execution stays disabled.
        data=q.load(self.run['claims']);data['task_id']=task;Path(self.run['claims']).write_bytes(q.encode(data))
        manifest(self.ft)
        (self.root/'controls/STAGECHECK_ROOT.json').write_bytes(q.encode({'root':str(self.ft),'manifest_sha256':q.digest((self.ft/'MANIFEST.sha256').read_bytes())}))
        args=[sys.executable,'-B',str(self.ft/'bin/orchestrate.py'),'--task',task,'--repo',self.run['repo'],'--base',self.run['base'],'--report',self.run['report'],'--claims',self.run['claims'],'--root',str(self.root),'--contract',str(self.ctx.contract),'--allow-dirty']
        r=subprocess.run(args,capture_output=True,timeout=45,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
        path=self.root/'evidence/stagecheck'/task/'1/verdict.json'
        self.assertTrue(path.exists(),r.stderr.decode())
        value=q.load(path)
        self.assertNotEqual(value['result'],'TOOL_ERROR',value['errors'])
        return r,path,value

    def configure_blocking(self):
        file=self.ft/'config/modes.json';v=q.load(file);v['checks']['citations']='blocking';file.write_bytes(q.encode(v))
        data=q.load(self.run['claims']);data['claims'][0]['citations'][0]['sha256']='0'*64;Path(self.run['claims']).write_bytes(q.encode(data))

    def test_launch_no_data_and_overrides(self):
        self.configure_blocking();r,p,v=self.launch('no-data')
        self.assertEqual((r.returncode,v['result'],v['counts']['blocking']),(0,'CLEAR',0))
        self.assertEqual(v['quality']['checks']['citations']['current_pending_count'],1)
        self.assertIn('no data',p.with_name('generator_report.md').read_text())
        self.assertTrue(all('version' in c for c in v['checks']))
        current=q.versions(self.ctx)['citations']['sha256']
        q.append_record(self.ctx,self.request('blocking_override',{'check':'citations','version':current},'blocking_allowed'))
        r,p,v=self.launch('override-version');self.assertEqual((r.returncode,v['result']),(1,'BLOCKED'))
        self.assertEqual(v['quality']['checks']['citations']['source'],'override')
        self.assertEqual(v['quality']['blocking_by_override'],['citations'])
        q.append_record(self.ctx,self.request('blocking_override',{'check':'citations','version':'all'},'blocking_allowed'))
        pol=self.ft/'config/quality_targets.json';pol.write_text('{"invalid":true}')
        r,p,v=self.launch('override-invalid');self.assertEqual(v['counts']['blocking'],1)
        f=self.records/'records.0001.jsonl';f.write_bytes(f.read_bytes()+b'{')
        r,p,v=self.launch('damaged');self.assertEqual((r.returncode,v['result'],v['counts']['blocking']),(0,'CLEAR',0))
        self.assertIn('record chain',v['quality']['checks']['citations']['reason'])

    def test_launch_measured_pending_and_reset(self):
        self.configure_blocking();self.launch('bootstrap')  # Install final fixture paths/config before labels.
        p=q.load(self.root/'evidence/stagecheck/bootstrap/1/verdict.json')
        q.append_record(self.ctx,self.request('coverage',{'verdicts':[q.digest((self.root/'evidence/stagecheck/bootstrap/1/verdict.json').read_bytes())]},'covered'))
        for i in range(93):
            path,_=self.verdict(task='count-'+str(i),defect_id='D-'+str(i));q.append_record(self.ctx,self.label(path))
        r,path,v=self.launch('earned');self.assertEqual((r.returncode,v['result']),(1,'BLOCKED'))
        self.assertEqual(v['quality']['checks']['citations']['source'],'measurement')
        self.assertEqual(v['quality']['checks']['citations']['earlier_pending_count'],0)
        self.assertEqual(v['quality']['checks']['citations']['current_pending_count'],1)
        r,path,v=self.launch('prior-pending');self.assertEqual((r.returncode,v['result']),(0,'CLEAR'))
        self.assertIn('earlier runs still pending',v['quality']['checks']['citations']['reason'])
        file=self.ft/'checks/citations.py';file.write_bytes(file.read_bytes()+b'\n# new version\n')
        r,path,v=self.launch('reset');self.assertEqual((r.returncode,v['result']),(0,'CLEAR'))
        self.assertIn('version changed',v['quality']['checks']['citations']['reason'])

    def test_final_line_edit_after_sealed_run(self):
        self.configure_blocking();self.launch('bootstrap')
        q.append_record(self.ctx,self.request('blocking_override',{'check':'citations','version':'all'},'blocking_allowed'))
        r,p,v=self.launch('anchored');self.assertEqual(v['counts']['blocking'],1)
        f=self.records/'records.0001.jsonl';original=f.read_bytes()
        # A same-length, valid final-line note edit leaves the previous-line chain valid.
        line=q.loads(original.splitlines()[-1]);line['note']='edited';f.write_bytes(b''.join(original.splitlines(keepends=True)[:-1])+q.line_bytes(line))
        q.read_chain(self.records)
        with self.assertRaises(q.ToolError):q.measure_data(self.ctx)
        r,p,v=self.launch('after-edit');self.assertEqual((r.returncode,v['result'],v['counts']['blocking']),(0,'CLEAR',0))
        self.assertIn('anchor',v['quality']['checks']['citations']['reason'])

    def populate_precision(self,n=59):
        path,value=self.verdict(task='sample')
        original=value['defects'][0]
        value['defects']=[dict(original,defect_id='D-'+str(i)) for i in range(n)]
        path.write_bytes(q.encode(value));seal=path.with_name('seal.json');s=q.load(seal);s['verdict.json']=q.digest(path.read_bytes());seal.write_bytes(q.encode(s))
        first=q.append_record(self.ctx,self.label(path));chain,_=q.read_chain(self.records);previous=first
        # Synthetic, structurally valid history is a fixture input, not a real grade.
        with (self.records/'records.0001.jsonl').open('ab') as output:
            for d in value['defects'][1:]:
                r=self.label(path);r['subject']['defect_id']=d['defect_id'];r.update(previous=previous,policy_sha256=chain[0]['record']['subject']['sha256'])
                raw=q.line_bytes(r);output.write(raw);previous=q.digest(raw)
        return path

    def test_gate_conditions(self):
        from quality import blocking_evidence
        path=self.populate_precision();manifest(self.ft)
        current=q.versions(self.ctx)['citations']['sha256']
        def gate():return blocking_evidence(self.ctx,None,[])['checks']['citations']
        self.assertEqual(gate()['source'],'measurement')
        q.append_record(self.ctx,self.label(path,'false_block'))
        self.assertIn('not yet',gate()['reason'])
        q.append_record(self.ctx,self.label(path))
        pending,_=self.verdict(task='pending');self.assertIn('pending',gate()['reason'])
        q.append_record(self.ctx,self.request('coverage',{'verdicts':[q.digest(pending.read_bytes())]},'covered'))
        pol=self.ft/'config/quality_targets.json';original=pol.read_bytes();pol.write_bytes(original+b' ')
        self.assertIn('not matching',gate()['reason'])
        q.append_record(self.ctx,self.request('blocking_override',{'check':'citations','version':current},'blocking_allowed'))
        self.assertEqual(gate()['source'],'override')
        pol.write_text('{}');self.assertEqual(gate()['source'],'override')
        f=self.records/'records.0001.jsonl';f.write_bytes(f.read_bytes()+b'{');self.assertEqual(gate()['source'],'report_only')
        q.append_record(self.ctx,{'actor':'owner'},True)
        pol.write_bytes(original);q.append_record(self.ctx,self.request('blocking_override',{'check':'citations','version':'all'},'blocking_allowed'))
        self.assertEqual(gate()['source'],'override')

    def test_claude_cannot_override_and_invalid_policy(self):
        def gate():return q.blocking_evidence(self.ctx,None,[])['checks']['citations']
        self.assertEqual(gate()['source'],'report_only')
        pol=self.ft/'config/quality_targets.json';v=q.load(pol);v['deciders'].append('claude');pol.write_bytes(q.encode(v));manifest(self.ft)
        req=self.request('blocking_override',{'check':'citations','version':'all'},'blocking_allowed','claude','proposal')
        with self.assertRaises(q.ToolError):q.append_record(self.ctx,dict(req,type='decision'))
        proposal=q.append_record(self.ctx,req)
        q.append_record(self.ctx,self.request('confirmation',{'proposals':[proposal]},'confirmed','claude'))
        self.assertEqual(gate()['source'],'report_only')
        pol.write_text('{}');self.assertEqual(gate()['source'],'report_only')

    def test_gate_reset_and_no_data_reasons(self):
        # fixture() already generates a manifest containing the copied policy.
        self.assertEqual(q.blocking_evidence(self.ctx,None,[])['checks']['citations']['reason'],'no data')
        manifest(self.ft)
        self.assertEqual(q.blocking_evidence(self.ctx,None,[])['checks']['citations']['reason'],'no data')
        self.populate_precision();file=self.ft/'checks/citations.py';file.write_bytes(file.read_bytes()+b'\n# version reset\n');manifest(self.ft)
        self.assertIn('version changed',q.blocking_evidence(self.ctx,None,[])['checks']['citations']['reason'])

    def test_more_refusal_twins(self):
        path,v=self.verdict();good=self.label(path)
        for bad in [dict(good,subject={}),dict(good,subject=dict(good['subject'],check='unknown')),dict(good,subject=dict(good['subject'],task='wrong')),dict(good,subject=dict(good['subject'],defect_id='missing')),dict(good,note='two\nlines'),dict(good,evidence=['unknown']),dict(good,evidence=[3]),dict(good,replaces='0'*64),dict(good,previous='0'*64),dict(good,policy_sha256='0'*64)]:
            with self.assertRaises(q.ToolError):q.append_record(self.ctx,bad)
            q.append_record(self.ctx,good)
        for kind,subject,value in [('coverage',{'verdicts':[]},'covered'),('confirmation',{'proposals':[]},'confirmed'),('confirmation',{'proposals':['0'*64]},'confirmed'),('prompt_outcome',{'assembly_digest':'0'*64},'correct'),('carryover',{'check':'citations','old':'all','new':'all'},'evidence_carries_over')]:
            with self.assertRaises(q.ToolError):q.append_record(self.ctx,self.request(kind,subject,value))
        pol=self.ft/'config/quality_targets.json';original=pol.read_bytes()
        for key,val in [('confidence',0),('deciders',[]),('deciders',['codex']),('deciders',['owner','owner']),('scoring_rules',[]),('enforced',[]),('extra',1)]:
            value=q.loads(original);value[key]=val;pol.write_bytes(q.encode(value))
            with self.assertRaises(q.ToolError):q.policy(self.ctx)
        pol.write_bytes(original);q.append_record(self.ctx,good)

    def test_structural_recovery_refusals(self):
        p,v=self.verdict();q.append_record(self.ctx,self.label(p));f=self.records/'records.0001.jsonl';original=f.read_bytes()
        with self.assertRaises(q.ToolError):q.append_record(self.ctx,{'actor':'owner'},True)
        extra=self.records/'records.0002.jsonl';extra.write_bytes(original)
        with self.assertRaises(q.ToolError):q.read_chain(self.records)
        extra.unlink();gap=self.records/'records.0003.jsonl';gap.write_bytes(original)
        with self.assertRaises(q.ToolError):q.read_chain(self.records)
        with self.assertRaises(q.ToolError):q.valid_prefix(self.records)
        gap.unlink();f.write_bytes(original+b'{');q.append_record(self.ctx,{'actor':'owner'},True)
        continuation=extra.read_bytes();c=q.loads(continuation);c['actor']='claude';extra.write_bytes(q.line_bytes(c))
        with self.assertRaises(q.ToolError):q.read_chain(self.records)
        extra.write_bytes(continuation);q.read_chain(self.records)
        f.write_bytes(original);with_cont=extra.read_bytes()
        with self.assertRaises(q.ToolError):q.read_chain(self.records)
        f.write_bytes(original+b'{');extra.write_bytes(with_cont+b'{')
        q.append_record(self.ctx,{'actor':'owner'},True);q.read_chain(self.records)

    def test_roots_and_output_refusals(self):
        p,v=self.verdict();q.append_record(self.ctx,self.label(p));q.write_measurement(self.ctx)
        raw=q.roots(self.ctx)[0];link=self.root/'evidence/stagecheck_quality.link';link.symlink_to(self.records)
        with self.assertRaises(q.ToolError):q.read_chain(link)
        linked=self.records/'records.0002.jsonl';linked.symlink_to(self.records/'records.0001.jsonl')
        with self.assertRaises(q.ToolError):q.read_chain(self.records)
        linked.unlink()
        identity=q.record_anchors(self.records)
        wrong={str(self.root/'evidence/outside.jsonl'):next(iter(identity.values()))}
        measure=self.records/'measurement.0001.json';original=measure.read_bytes();value=q.loads(original);value['record_files']=wrong;measure.write_bytes(q.encode(value))
        with self.assertRaises(q.ToolError):q.measure_data(self.ctx)
        measure.write_bytes(original)
        bad=self.records/'measurement.bad.json';bad.write_text('{}')
        with self.assertRaises(q.ToolError):q.numbered(self.records,'measurement','json')
        bad.unlink();(self.records/'measurement.0002.md').write_text('existing output')
        with self.assertRaises(q.ToolError):q.write_measurement(self.ctx)
        descriptor=Path(self.ctx.bind['Evidence root']['path']);before=descriptor.read_bytes();descriptor.write_bytes(before+b' ')
        with self.assertRaises(q.ToolError):q.roots(self.ctx)
        descriptor.write_bytes(before)

    def test_seed_result_refusals(self):
        self.records.mkdir(exist_ok=True);p=self.records/'seed_result.0001.json'
        sid='1'*64;good={'seed_set_sha256':q.digest(q.encode([sid])),'versions':{c:v['sha256'] for c,v in q.versions(self.ctx).items()},'seeds':[{'seed_id':sid,'check':'citations','target_rule':'citation.hash_mismatch','detected':True,'clean_firings':{}}],'fixture_configuration':self.seed_metadata(1)}
        bads=[{},dict(good,seed_set_sha256='0'*64),dict(good,versions={c:'invalid' for c in q.CHECKS})]
        for key,value in [('detected','yes'),('check','unknown'),('seed_id','invalid'),('clean_firings',{'unknown':['rule']})]:
            entry=dict(good['seeds'][0],**{key:value});bads.append(dict(good,seeds=[entry]))
        for bad in bads:
            p.write_bytes(q.encode(bad));valid,skipped=q.seed_results(self.records);self.assertEqual(valid,[]);self.assertEqual(len(skipped),1)
            p.write_bytes(q.encode(good));valid,skipped=q.seed_results(self.records);self.assertEqual(len(valid),1);self.assertEqual(skipped,[])

    def test_unversioned_verdict_refusal(self):
        p,v=self.verdict();req=self.label(p)
        for c in v['checks']:c.pop('version')
        p.write_bytes(q.encode(v));s=q.load(p.with_name('seal.json'));s['verdict.json']=q.digest(p.read_bytes());p.with_name('seal.json').write_bytes(q.encode(s))
        req['subject']['version']=None;req['evidence']=[{'path':str(p),'sha256':q.digest(p.read_bytes())}]
        with self.assertRaises(q.ToolError):q.append_record(self.ctx,req)

    def test_record_envelope_api(self):
        p,v=self.verdict();q.append_record(self.ctx,self.label(p));chain,_=q.read_chain(self.records);valid=chain[-1]['record']
        for key,bad in [('subject',[]),('previous','bad'),('actor','codex'),('type','invalid'),('policy_sha256','bad'),('evidence','bad'),('replaces','bad'),('unexpected',True)]:
            with self.assertRaises(q.ToolError):q.record_shape(dict(valid,**{key:bad}))
            q.record_shape(valid)

    def test_revalidation_policy_and_actor(self):
        p,v=self.verdict();q.append_record(self.ctx,self.label(p));f=self.records/'records.0001.jsonl';original=f.read_bytes();chain,_=q.read_chain(self.records)
        for override in [{'actor':'claude','value':'false_block'},{'policy_sha256':'0'*64,'value':'false_block'}]:
            bad=dict(chain[-1]['record'],previous=chain[-1]['sha256'],**override);f.write_bytes(original+q.line_bytes(bad))
            measured=q.measure_data(self.ctx);self.assertEqual(measured['checks']['citations']['precision']['successes'],1);self.assertEqual(len(measured['skipped_records']),1)
        f.write_bytes(original)

    def test_recovery_empty_and_symlink_roots(self):
        self.records.mkdir()
        with self.assertRaises(q.ToolError):q.valid_prefix(self.records)
        output=q.roots(self.ctx)[0];backup=output.with_name('stagecheck.saved');output.rename(backup);output.symlink_to(backup)
        with self.assertRaises(q.ToolError):q.roots(self.ctx)
        output.unlink();backup.rename(output);q.roots(self.ctx)

    def test_descriptor_root_symlink_refusal(self):
        descriptor=Path(self.ctx.bind['Evidence root']['path']);value=q.load(descriptor)
        link=self.home/'evidence-alias';link.symlink_to(Path(value['root']),target_is_directory=True)
        value['root']=str(link);descriptor.write_bytes(q.encode(value))
        self.ctx.bind['Evidence root']['sha256']=q.digest(descriptor.read_bytes())
        with self.assertRaises(q.ToolError):q.roots(self.ctx)

    def test_assembler_record_identity(self):
        folder=self.root/'evidence/assembly';folder.mkdir();record=folder/'record.json'
        q.create(record,{'assembly_digest':'0'*64})
        def request():return self.request('prompt_outcome',{'assembly_digest':q.load(record)['assembly_digest']},'correct',evidence=[{'path':str(record),'sha256':q.digest(record.read_bytes())}])
        with self.assertRaises(q.ToolError):q.append_record(self.ctx,request())
        payload={'blocks':[],'given':{},'computed':{},'selection':None,'file_hashes':{}}
        prompt=b'fixture prompt\n';claims=b'{}\n';(folder/'task_prompt.md').write_bytes(prompt);(folder/'claims.json').write_bytes(claims)
        value={'result':'CLEAR',**payload,'assembly_digest':q.digest(q.line_bytes(payload)[:-1]),'prompt_sha256':q.digest(prompt),'claims_sha256':q.digest(claims)}
        record.write_bytes(q.encode(value));q.append_record(self.ctx,request())
        value['given']={'task':'changed'};record.write_bytes(q.encode(value))
        with self.assertRaises(q.ToolError):q.append_record(self.ctx,request())

    def test_record_sequence_above_four_digits(self):
        self.records.mkdir();body=b'{';previous='0'*64
        for number in range(1,10001):
            (self.records/('records.'+str(number).zfill(4)+'.jsonl')).write_bytes(body)
            record={'kind':'continuation','value':'continued','subject':{'file_sha256':q.hashlib.sha256(body).hexdigest(),'last_valid_sha256':previous},'actor':'owner','type':'decision','policy_sha256':'0'*64,'evidence':[],'previous':previous}
            raw=(q.json.dumps(record,sort_keys=True,separators=(',',':'))+'\n').encode()
            previous=q.hashlib.sha256(raw).hexdigest();body=raw+(b'{' if number<9999 else b'')
        chain,_=q.read_chain(self.records);self.assertEqual(len(chain),9999)

    def test_invalid_snapshot_does_not_poison_new_record(self):
        path,v=self.verdict();pol,sha,raw=q.policy(self.ctx);self.records.mkdir()
        bad={'kind':'policy_snapshot','value':'snapshot','subject':{'policy_bytes':raw.decode(),'sha256':sha},'previous':'0'*64,'actor':'owner'}
        (self.records/'records.0001.jsonl').write_bytes((q.json.dumps(bad,sort_keys=True,separators=(',',':'))+'\n').encode())
        q.append_record(self.ctx,self.label(path))
        value=q.measure_data(self.ctx)
        self.assertEqual(len(value['skipped_records']),1)
        self.assertEqual(value['checks']['citations']['precision']['successes'],1)

    def test_verdict_changes_between_seal_and_read(self):
        path,v=self.verdict();original=path.read_bytes();read=self.ctx.read
        def changed(p):
            if Path(p)==path:path.write_bytes(original+b' ')
            return read(p)
        self.ctx.read=changed
        runs,invalid=q.real_verdicts(self.ctx)
        self.assertEqual(runs,{})
        self.assertEqual(len(invalid),1)

    def test_seed_shape_refusal_twins(self):
        from quality_seeds import run_seeds,apply_side,merge
        seeds=self.home/'seeds';seeds.mkdir();p=seeds/'seed.json';good=self.seed_case()
        for bad in [{},dict(good,extra=True),dict(good,target='unknown.rule'),dict(good,pair={}),dict(good,pair={'clean':[], 'defective':{}}),dict(good,pair={'clean':{'claims':{'record_sha256':'0'*64}},'defective':{}})]:
            p.write_bytes(q.encode(bad))
            with self.assertRaises(q.ToolError):run_seeds(self.ctx,seeds,8192)
        p.write_bytes(q.encode(good));self.assertTrue(q.load(run_seeds(self.ctx,seeds,8192))['seeds'][0]['detected'])
        duplicate=seeds/'duplicate.json';duplicate.write_bytes(p.read_bytes())
        with self.assertRaises(q.ToolError):run_seeds(self.ctx,seeds,8192)
        duplicate.unlink();extra=seeds/'not-json.txt';extra.write_text('input')
        with self.assertRaises(q.ToolError):run_seeds(self.ctx,seeds,8192)
        extra.unlink()
        with self.assertRaises(q.ToolError):run_seeds(self.ctx,self.ft,8192)
        with self.assertRaises(q.ToolError):run_seeds(self.ctx,self.home/'absent',8192)
        for bad in [{'edits':[{}]},{'run':{'depth':'unknown'}},{'run':{'changed_paths':'bad'}}]:
            with self.assertRaises(q.ToolError):apply_side(bad,self.run,self.data,self.root,self.ft,8192)
        with self.assertRaises(q.ToolError):merge({},[])

class Guards(unittest.TestCase):
    """Owner Ruling 3: isolated hostile cases for previously surviving refusals.

    These use public helper boundaries where later validation would otherwise
    mask a disabled guard. Early-admission cases also assert no seed-data access.
    """
    setUp=Fixture.setUp
    verdict=Fixture.verdict
    request=Fixture.request
    label=Fixture.label
    seed_case=Fixture.seed_case
    seed_metadata=Fixture.seed_metadata

    def snapshot(self):
        pol,sha,raw=q.policy(self.ctx)
        return {'kind':'policy_snapshot','value':'snapshot','subject':{'policy_bytes':raw.decode(),'sha256':sha},'previous':q.ZERO}

    def test_read_chain_admission(self):
        self.records.mkdir();target=self.home/'record-target';raw=q.line_bytes(self.snapshot());target.write_bytes(raw)
        path=self.records/'records.0001.jsonl';path.symlink_to(target)
        with self.assertRaises(q.ToolError):q.read_chain(self.records)
        path.unlink();path.write_bytes(raw);self.assertEqual(len(q.read_chain(self.records)[0]),1)
        path.rename(self.records/'records.0002.jsonl')
        with self.assertRaises(q.ToolError):q.read_chain(self.records)
        (self.records/'records.0002.jsonl').rename(path)
        path.write_bytes(raw[:-1])
        with self.assertRaises(q.ToolError):q.read_chain(self.records)
        path.unlink();link=self.home/'records-alias';link.symlink_to(self.records)
        with self.assertRaises(q.ToolError):q.read_chain(link)
        self.assertEqual(q.read_chain(self.records),([] ,{}))

    def test_valid_prefix_admission(self):
        self.records.mkdir();one=self.records/'records.0001.jsonl';two=self.records/'records.0002.jsonl'
        one.write_bytes(b'{');link=self.home/'records-alias';link.symlink_to(self.records)
        with self.assertRaises(q.ToolError):q.valid_prefix(link)
        self.assertEqual(q.valid_prefix(self.records),(one,q.ZERO))
        one.rename(two)
        with self.assertRaises(q.ToolError):q.valid_prefix(self.records)
        two.rename(one)
        raw=q.line_bytes(self.snapshot());one.write_bytes(raw[:-1])
        self.assertEqual(q.valid_prefix(self.records),(one,q.ZERO))
        one.write_bytes(raw);two.write_bytes(b'{')
        with self.assertRaises(q.ToolError):q.valid_prefix(self.records)
        one.write_bytes(b'{')
        c={'kind':'continuation','value':'continued','subject':{'file_sha256':'1'*64,'last_valid_sha256':q.ZERO},'previous':q.ZERO,'actor':'owner','type':'decision','policy_sha256':q.ZERO,'evidence':[]}
        two.write_bytes(q.line_bytes(c)+b'{')
        with self.assertRaises(q.ToolError):q.valid_prefix(self.records)
        c['subject']['file_sha256']=q.digest(b'{');two.write_bytes(q.line_bytes(c)+b'{')
        self.assertEqual(q.valid_prefix(self.records),(two,q.digest(q.line_bytes(c))))

    def test_real_verdict_task(self):
        p,v=self.verdict();self.assertEqual(len(q.real_verdicts(self.ctx)[0]),1)
        v['task_id']='other';p.write_bytes(q.encode(v));seal=q.load(p.with_name('seal.json'));seal['verdict.json']=q.digest(p.read_bytes());p.with_name('seal.json').write_bytes(q.encode(seal))
        runs,bad=q.real_verdicts(self.ctx);self.assertEqual(runs,{});self.assertEqual(len(bad),1)

    def test_witness_admission(self):
        p,v=self.verdict();runs,_=q.real_verdicts(self.ctx)
        q.witnesses(self.ctx,[v['defects'][0]['defect_id']],runs)
        for bad in [['absent'],[3]]:
            with self.assertRaises(q.ToolError):q.witnesses(self.ctx,bad,runs)

    def test_record_subject_admission(self):
        p,v=self.verdict();q.append_record(self.ctx,self.label(p));chain,_=q.read_chain(self.records);runs,_=q.real_verdicts(self.ctx)
        known={x['sha256']:x for x in chain};current=q.versions(self.ctx);sha=q.digest(p.read_bytes());version=current['citations']['sha256'];pol=q.policy(self.ctx)[1]
        def full(kind,subject,value):return dict(self.request(kind,subject,value),previous=q.ZERO,policy_sha256=pol)
        pairs=[
            (dict(self.snapshot(),subject=dict(self.snapshot()['subject'],sha256='1'*64)),self.snapshot()),
            (full('continuation',{'file_sha256':q.ZERO,'last_valid_sha256':q.ZERO},'continued')|{'actor':'claude'},full('continuation',{'file_sha256':q.ZERO,'last_valid_sha256':q.ZERO},'continued')),
            (full('missed_defect',{'task':'fixture','verdict':sha,'check':'none','defect_id':'later','extra':1},'missed'),full('missed_defect',{'task':'fixture','verdict':sha,'check':'none','defect_id':'later'},'missed')),
            (full('delivery_outcome',{'task':'fixture','verdict':sha,'extra':1},'met'),full('delivery_outcome',{'task':'fixture','verdict':sha},'met')),
            (full('prompt_outcome',{},'correct'),full('prompt_outcome',{'path':str(p),'sha256':sha},'correct')),
            (full('blocking_override',{'check':'citations','version':'all','extra':1},'blocking_allowed'),full('blocking_override',{'check':'citations','version':'all'},'blocking_allowed'))]
        old=dict(current);old['citations']={'sha256':'1'*64};other=self.verdict(task='old',version='1'*64);runs,_=q.real_verdicts(self.ctx)
        pairs.append((full('carryover',{'check':'citations','old':version,'new':version},'evidence_carries_over'),full('carryover',{'check':'citations','old':'1'*64,'new':version},'evidence_carries_over')))
        for bad,good in pairs:
            with self.subTest(kind=bad['kind']):
                with self.assertRaises(q.ToolError):q.validate_record(self.ctx,bad,known,runs,current)
                q.validate_record(self.ctx,good,known,runs,current)

    def test_effective_admission(self):
        p,v=self.verdict();proposal=q.append_record(self.ctx,self.label(p,actor='claude',type='proposal'))
        q.append_record(self.ctx,self.request('confirmation',{'proposals':[proposal]},'confirmed'))
        q.append_record(self.ctx,self.label(p,'false_block',replaces=proposal))
        f=self.records/'records.0001.jsonl';chain,_=q.read_chain(self.records);raw=f.read_bytes()
        late=dict(self.request('confirmation',{'proposals':[proposal]},'confirmed'),previous=chain[-1]['sha256'],policy_sha256=q.policy(self.ctx)[1])
        f.write_bytes(raw+q.line_bytes(late));runs,_=q.real_verdicts(self.ctx);decisions,bad,_=q.effective(self.ctx,q.read_chain(self.records)[0],runs)
        self.assertEqual([d['record']['value'] for d in decisions],['false_block']);self.assertEqual(len(bad),1)
        f.write_bytes(raw)
        chain,_=q.read_chain(self.records)
        forged=dict(self.request('coverage',{'verdicts':[q.digest(p.read_bytes())]},'covered',actor='claude',type='proposal'),previous=chain[-1]['sha256'],policy_sha256=q.policy(self.ctx)[1])
        proof=q.digest(q.line_bytes(forged));f.write_bytes(raw+q.line_bytes(forged))
        confirmed=dict(self.request('confirmation',{'proposals':[proof]},'confirmed'),previous=proof,policy_sha256=q.policy(self.ctx)[1]);f.write_bytes(f.read_bytes()+q.line_bytes(confirmed))
        decisions,bad,known=q.effective(self.ctx,q.read_chain(self.records)[0],runs)
        self.assertNotIn(proof,known);self.assertFalse(any(d['record']['kind']=='coverage' for d in decisions));self.assertEqual(len(bad),2)

    def test_lock_admission(self):
        from unittest.mock import patch
        dangling=self.home/'dangling';dangling.symlink_to(self.home/'absent')
        with self.assertRaises(q.ToolError):
            with q.locked(dangling):pass
        target=self.home/'lock-target';target.mkdir();folder=self.home/'lock-folder';mkdir=Path.mkdir
        def swap(path,*args,**kwargs):
            result=mkdir(path,*args,**kwargs)
            if path==folder:path.rmdir();path.symlink_to(target)
            return result
        with patch.object(Path,'mkdir',swap):
            with self.assertRaises(q.ToolError):
                with q.locked(folder):pass
        self.assertFalse((target/'.quality.lock').exists())
        folder.unlink()
        with q.locked(folder):self.assertTrue((folder/'.quality.lock').is_file())

    def test_append_owned_records(self):
        request=self.request('continuation',{'file_sha256':q.ZERO,'last_valid_sha256':q.ZERO},'continued')
        with self.assertRaises(q.ToolError):q.append_record(self.ctx,request)
        p,_=self.verdict();q.append_record(self.ctx,self.label(p))

    def test_label_shape(self):
        p,_=self.verdict();sha=q.append_record(self.ctx,self.label(p));good={'type':'quality_record','record_sha256':sha}
        self.assertEqual(q.label_decision(self.ctx,good)['sha256'],sha)
        with self.assertRaises(q.ToolError):q.label_decision(self.ctx,dict(good,extra=1))

    def test_anchor_and_sequence_admission(self):
        self.records.mkdir();other=self.home/'measure.json';other.write_bytes(q.encode({'record_files':{}}));p=self.records/'measurement.0001.json';p.symlink_to(other)
        with self.assertRaises(q.ToolError):q.check_anchors(self.records,[],{})
        p.unlink();p.write_bytes(other.read_bytes());q.check_anchors(self.records,[],{})
        (self.records/'measurement.00001.json').write_bytes(p.read_bytes())
        with self.assertRaises(q.ToolError):q.numbered(self.records,'measurement','json')

    def good_seed_result(self):
        sid='1'*64
        return {'seed_set_sha256':q.digest(q.encode([sid])),'versions':{c:v['sha256'] for c,v in q.versions(self.ctx).items()},
                'seeds':[{'seed_id':sid,'check':'citations','target_rule':'citation.hash_mismatch','detected':True,'clean_firings':{}}], 'fixture_configuration':self.seed_metadata(1)}

    def test_seed_result_admission(self):
        self.records.mkdir();other=self.home/'result.json';good=self.good_seed_result();other.write_bytes(q.encode(good));p=self.records/'seed_result.0001.json';p.symlink_to(other)
        valid,bad=q.seed_results(self.records);self.assertEqual(valid,[]);self.assertEqual(len(bad),1)
        p.unlink();p.write_bytes(q.encode(dict(good,extra=1)));valid,bad=q.seed_results(self.records);self.assertEqual(valid,[]);self.assertEqual(len(bad),1)
        for key,value in [('verified_only_allowed_differences',False),('allowed_differences',[]),('file_sha256',{}),('copies_checked',1)]:
            p.write_bytes(q.encode(dict(good,fixture_configuration=dict(good['fixture_configuration'],**{key:value}))))
            valid,bad=q.seed_results(self.records);self.assertEqual(valid,[]);self.assertEqual(len(bad),1)
        p.write_bytes(q.encode(good));self.assertEqual(len(q.seed_results(self.records)[0]),1)

    def test_seed_path_list_admission(self):
        from quality_seeds import apply_side
        path='NewArc/3m/evidence/report.md'
        with self.assertRaises(q.ToolError):apply_side({'run':{'read_paths':(path,)}},self.run,self.data,self.root,self.ft,8192)
        for overrides in [{'tool_root':[path]},[]]:
            with self.subTest(overrides=overrides):
                with self.assertRaises(q.ToolError):apply_side({'run':overrides},self.run,self.data,self.root,self.ft,8192)
        apply_side({'run':{'read_paths':[path]}},self.run,self.data,self.root,self.ft,8192)

    def test_seed_early_admission(self):
        from quality_seeds import run_seeds
        from unittest.mock import patch
        seeds=self.home/'seeds';seeds.mkdir()
        with self.assertRaises(q.ToolError):run_seeds(self.ctx,seeds,8192)
        p=seeds/'seed.json';raw=q.encode(self.seed_case());p.write_bytes(raw)
        opened=Path.open;rglob=Path.rglob
        def denied_open(path,*args,**kwargs):
            if path==p:raise AssertionError('oversize seed was opened before refusal')
            return opened(path,*args,**kwargs)
        with patch.object(Path,'open',denied_open):
            with self.assertRaises(q.ToolError):run_seeds(self.ctx,seeds,1)
        def denied_inventory(path,*args,**kwargs):
            if path==seeds:raise AssertionError('seed folder inventoried before cap admission')
            return rglob(path,*args,**kwargs)
        with patch.object(Path,'rglob',denied_inventory):
            for cap in [0,True]:
                with self.assertRaises(q.ToolError):run_seeds(self.ctx,seeds,cap)
        link=self.home/'seed-alias';link.symlink_to(seeds)
        def denied_alias(path,*args,**kwargs):
            if path==link:raise AssertionError('symlink seed folder was inspected')
            return rglob(path,*args,**kwargs)
        with patch.object(Path,'rglob',denied_alias):
            with self.assertRaises(q.ToolError):run_seeds(self.ctx,link,8192)
        p.unlink();outside=self.home/'seed-input.json';outside.write_bytes(raw);p.symlink_to(outside)
        with self.assertRaises(q.ToolError):run_seeds(self.ctx,seeds,8192)
        p.unlink();p.write_bytes(raw)
        stat=Path.stat
        def stale_size(path,*args,**kwargs):
            value=stat(path,*args,**kwargs)
            if path==p:
                fields=list(value);fields[6]=len(raw)-1;return os.stat_result(fields)
            return value
        with patch.object(Path,'stat',stale_size):
            with self.assertRaises(q.ToolError):run_seeds(self.ctx,seeds,len(raw)-1)
        self.assertTrue(q.load(run_seeds(self.ctx,seeds,8192))['seeds'][0]['detected'])

    def test_seed_source_barrier(self):
        import quality_seeds as runner
        from unittest.mock import patch
        seeds=self.home/'seeds';seeds.mkdir();q.create(seeds/'seed.json',self.seed_case());execute=runner.execute
        def changed(run,name,out):
            value=execute(run,name,out)
            if name=='report_lint' and b'CONTENT-CANARY' in Path(run['report']).read_bytes():
                p=self.ft/'README.md';p.write_bytes(p.read_bytes()+b'\n')
            return value
        with patch.object(runner,'execute',changed):
            with self.assertRaises(q.ToolError):runner.run_seeds(self.ctx,seeds,8192)
        self.assertEqual(list(self.records.glob('seed_result.*.json')),[])

    def test_fixture_exception(self):
        import quality_seeds as runner
        from unittest.mock import patch
        source=runner.tool_inventory(self.ft)
        self.assertEqual(set(runner.verify_fixture(source,self.ft)),set(runner.FIXTURE_FILES))
        file=self.ft/'checks/citations.py';raw=file.read_bytes();file.write_bytes(raw+b'\n')
        with self.assertRaises(q.ToolError):runner.verify_fixture(source,self.ft)
        file.write_bytes(raw);added=self.ft/'empty-dir';added.mkdir()
        with self.assertRaises(q.ToolError):runner.verify_fixture(source,self.ft)
        added.rmdir();file.unlink();file.symlink_to(self.tool/'checks/citations.py')
        with self.assertRaises(q.ToolError):runner.tool_inventory(self.ft)
        file.unlink();file.write_bytes(raw)
        seeds=self.home/'seeds';seeds.mkdir();q.create(seeds/'seed.json',self.seed_case())
        observed=[];verify=runner.verify_fixture
        def retain(source,tool):
            value=verify(source,tool);observed.append({name:q.hashlib.sha256((tool/name).read_bytes()).hexdigest() for name in runner.FIXTURE_FILES});return value
        with patch.object(runner,'verify_fixture',retain):result=q.load(runner.run_seeds(self.ctx,seeds,8192))
        self.assertEqual(len(observed),4);self.assertTrue(all(value==result['fixture_configuration']['file_sha256'] for value in observed))
        self.assertEqual(result['fixture_configuration']['copies_checked'],2)
        self.assertEqual(result['versions'],{c:v['sha256'] for c,v in q.versions(self.ctx).items()})

    def test_fixture_inventory_admission(self):
        import quality_seeds as runner
        alias=self.home/'tool-alias';alias.symlink_to(self.ft)
        with self.assertRaises(q.ToolError):runner.tool_inventory(alias)
        fifo=self.ft/'fixture-fifo';os.mkfifo(fifo)
        with self.assertRaises(q.ToolError):runner.tool_inventory(self.ft)
        fifo.unlink()
        file=self.ft/'config/commands.json';raw=file.read_bytes();file.unlink();source=runner.tool_inventory(self.ft)
        with self.assertRaises(q.ToolError):runner.verify_fixture(source,self.ft)
        file.write_bytes(raw);source=runner.tool_inventory(self.ft);runner.verify_fixture(source,self.ft)

    def test_fixture_configuration_barriers(self):
        import quality_seeds as runner
        from unittest.mock import patch
        seeds=self.home/'seeds';seeds.mkdir();q.create(seeds/'seed.json',self.seed_case())
        factory=runner.fixture;execute=runner.execute;calls=0
        def altered_factory(*args):
            nonlocal calls
            value=factory(*args);calls+=1
            if calls==2:
                file=value[3]/'config/commands.json';file.write_bytes(file.read_bytes()+b'\n');manifest(value[3])
            return value
        with patch.object(runner,'fixture',altered_factory):
            with self.assertRaises(q.ToolError):runner.run_seeds(self.ctx,seeds,8192)
        def altered_execution(run,name,out):
            value=execute(run,name,out)
            if name=='report_lint' and b'CONTENT-CANARY' in Path(run['report']).read_bytes():
                tool=Path(run['tool_root']);file=tool/'config/commands.json';file.write_bytes(file.read_bytes()+b'\n');manifest(tool)
            return value
        with patch.object(runner,'execute',altered_execution):
            with self.assertRaises(q.ToolError):runner.run_seeds(self.ctx,seeds,8192)
        self.assertEqual(list(self.records.glob('seed_result.*.json')),[])

if __name__=='__main__':unittest.main()
