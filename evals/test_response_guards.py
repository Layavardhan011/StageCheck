"""Owner response-hook REQUEST §6/§7: refusal probes from specified invariants."""
import unittest,tempfile,os,json,copy
from pathlib import Path
from unittest.mock import patch,MagicMock
from test_response import Hook,HEADS,rh,ToolError,encode,digest,load

class Refusals(Hook):
    # Only this class's own tests run; inherited decision tests are exercised
    # by test_response.py, independently of these focused refusal probes.
    def test_refusals(self):
        def refused(message,call):
            with self.subTest(refusal=message),self.assertRaisesRegex(ToolError,message):call()
        # These resolve inside evidence if the lexical guard is removed,
        # so a later containment guard cannot mask its loss.
        for rel in ['../x','/tmp/x',str(self.root/'evidence/a'),'evidence/../evidence/a']:
            refused('configured path refused',lambda:rh.confined(self.root,rel))
        link=self.root/'evidence/link';link.symlink_to(self.root/'evidence')
        refused('configured path refused',lambda:rh.confined(self.root,'evidence/link/a'))
        link.unlink()
        refused('configured path refused',lambda:rh.confined(self.root,'build/a'))
        for key,value,message in [('mode','bad','settings shape'),('claims_max_bytes',0,'positive setting'),('claims_folder',{},'claims roots'),('send_back_rules',['authority.grant'],'send-back rules')]:
            before=self.config[key];self.config[key]=value;self.write_config()
            refused(message,lambda:rh.settings(self.tool,self.root));self.config[key]=before
        self.config['records_folder']=self.config['claims_folder']['codex'];self.write_config()
        refused('overlapping roots',lambda:rh.settings(self.tool,self.root))
        self.config['records_folder']='evidence/stagecheck_responses';self.write_config()
        external=self.root/'evidence/external.txt';external.write_text('fixture')
        m=self.tool/'MANIFEST.sha256';before=m.read_bytes()
        m.write_bytes(before+(digest(external.read_bytes())+'  ../evidence/external.txt\n').encode())
        refused('external manifest',lambda:rh.manifest_valid(self.tool));m.write_bytes(before)
        p=self.tool/'bin/common.py';raw=p.read_bytes();p.write_bytes(raw+b'\n')
        refused('manifest identity',lambda:rh.manifest_valid(self.tool));p.write_bytes(raw)
        folder=self.root/'evidence/numbering';folder.mkdir();folderlink=folder/'alias';folderlink.symlink_to(folder)
        refused('record path',lambda:rh.numbered_attempt(folderlink));folderlink.unlink()
        (folder/'other.txt').write_text('fixture');refused('attempt directory',lambda:rh.numbered_attempt(folder));(folder/'other.txt').unlink()
        prior=folder/'1';prior.mkdir();now=folder/'2';now.mkdir();record=prior/'record.json';record.symlink_to(external)
        refused('record symlink',lambda:rh.prior_records(folder,now));record.unlink();record.write_text('{}')
        refused('history refused',lambda:rh.prior_records(folder,now))
        refused('turn id',lambda:rh.task_counts('codex','session',{'turn_id':'../escape'},[]))
        refused('claims object',lambda:rh.stamp_claims(b'[]','task',1))
        with patch.object(rh,'loads',side_effect=[{}, {'claims':[]},{'claims':['changed']} ]):
            refused('changed beyond transport',lambda:rh.stamp_claims(b'{"claims":[]}','task',1))
        external.write_bytes(b'{}')
        refused('claims path refused',lambda:rh.read_claims(external,self.root/'evidence/allowed',100))
        refused('claims file refused',lambda:rh.read_claims(external,self.root/'evidence',1))
        # A changed metadata observation and post-read symlink guard independently.
        info=os.stat(external);altered=MagicMock(st_dev=info.st_dev,st_ino=info.st_ino,st_size=info.st_size,st_mtime_ns=info.st_mtime_ns+1)
        with patch.object(rh.os,'fstat',side_effect=[info,altered]):
            refused('concurrent change',lambda:rh.read_claims(external,self.root/'evidence',100))
        with patch.object(rh,'symlink_component',side_effect=[False,True]):
            refused('path changed',lambda:rh.read_claims(external,self.root/'evidence',100))

    def test_verdict_refusals(self):
        expected=self.root/'evidence/stagecheck/task';out=expected/'1';out.mkdir(parents=True);path=out/'verdict.json';path.write_text('{}')
        good={'task_id':'task','response':True,'result':'CLEAR','defects':[]}
        def invoke():return rh.execute_stagecheck(self.tool,self.root,Path(self.run['contract']),'task',self.path,self.path,1)
        def probe(message,code=0,verdict=good,history=None,output=path):
            process=MagicMock();process.__enter__.return_value=process;process.returncode=code
            process.communicate.return_value=(encode({'verdict':str(output)}),b'')
            with self.subTest(refusal=message),patch.object(rh.subprocess,'Popen',return_value=process),patch.object(rh,'history_read',return_value=history if history is not None else [{'verdict':verdict}]),self.assertRaisesRegex(ToolError,message):invoke()
        probe('stagecheck failed',code=3)
        probe('verdict path',output=self.root/'evidence/wrong/verdict.json')
        probe('verdict history',history=[])
        probe('stagecheck tool error',verdict=dict(good,result='TOOL_ERROR'))
        probe('verdict identity',verdict=dict(good,task_id='other'))
        probe('verdict identity',verdict=dict(good,response=False))
        probe('verdict identity',verdict=dict(good,result='BLOCKED'))

    def test_hook_refusals(self):
        # Invalid settings are deliberately caught into off/tool_error records.
        self.config['mode']='invalid';self.write_config();self.submit(HEADS)
        self.assertEqual(self.records()[-1]['decision'],'tool_error')
        self.config['mode']='send_back';self.write_config()
        self.submit(HEADS);p=self.record_root/'codex'/self.event['session_id']/'2/record.json'
        data=load(p);data['session_id']='other';p.write_bytes(encode(data))
        self.assertEqual(self.submit(HEADS),{});self.assertEqual(self.records()[-1]['decision'],'tool_error')
        self.assertIn('session history differs',self.records()[-1]['tool_error'])
        self.event['session_id']='duplicates';self.path.write_text('{}')
        self.submit(HEADS+'\nClaims: '+str(self.path)+'\nClaims: '+str(self.path))
        self.assertEqual(self.records()[-1]['decision'],'tool_error')
        self.assertIn('duplicate claims lines',self.records()[-1]['tool_error'])
        descriptor=self.root/'controls/EVIDENCE_ROOT.json';descriptor.write_text('{}')
        with self.assertRaisesRegex(ToolError,'evidence binding'):self.submit(HEADS)

if __name__=='__main__':
    suite=unittest.TestSuite(Refusals(name) for name in ['test_refusals','test_verdict_refusals','test_hook_refusals'])
    result=unittest.TextTestRunner().run(suite);raise SystemExit(not result.wasSuccessful())
