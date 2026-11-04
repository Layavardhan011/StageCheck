"""Owner response-hook REQUEST §6/§7: compile-valid guard/rule mutations in temporary copies.
No executable seeds or real records. Test failures are intentional mutation oracles.
"""
import argparse,ast,json,os,shutil,signal,subprocess,sys,tempfile,time
from pathlib import Path
sys.dont_write_bytecode=True

def main():
    p=argparse.ArgumentParser();p.add_argument('--smoke',action='store_true');a=p.parse_args()
    source=Path(__file__).resolve().parents[1];hook=source/'bin/response_hook.py';raw=hook.read_text();tree=ast.parse(raw)
    jobs=[]
    for node in ast.walk(tree):
        if isinstance(node,ast.Raise) and isinstance(node.exc,ast.Call) and isinstance(node.exc.func,ast.Name) and node.exc.func.id=='ToolError':
            message=ast.unparse(node.exc.args[0]);tests=['test_response_guards.py']
            if 'timeout' in message:tests=['test_response.py','Hook.test_real_timeout_kills_process_group']
            if 'invalid settings' in message:tests=['test_response.py','Hook.test_invalid_settings_and_denied_rules']
            jobs.append({'id':'refusal:'+message+':'+str(node.lineno),'path':'bin/response_hook.py','line':node.lineno,'replacement':'pass','tests':tests,'ast':True})
    common=(source/'bin/common.py').read_text()
    node=next(n for n in ast.walk(ast.parse(common)) if isinstance(n,ast.Raise) and 'response record hash without' in ast.unparse(n))
    jobs.append({'id':'refusal:response-record','path':'bin/common.py','line':node.lineno,'replacement':'pass','tests':['test_response.py','Response.test_response_record_hash_requires_attachment'],'ast':True})
    for rule in json.loads((source/'config/response_hook.json').read_text())['send_back_rules']:
        jobs.append({'id':'rule:'+rule,'path':'bin/response_hook.py','old':"d['check_id'] in config['send_back_rules']","new":"d['check_id'] in config['send_back_rules'] and d['check_id'] != "+repr(rule),'tests':['test_response.py','Hook.test_each_rule_effect_and_twin']})
    for name,old,new,tests in [
      ('repairs',"final=counts['sent_backs_for_answer']>=config['repairs_per_answer']",'final=False',['Hook.test_repairs_final_and_reset']),
      ('failure-limit',"counts['failed_answers_in_a_row']>=config['failed_answers_in_a_row']",'False',['Hook.test_failed_run_and_clean_reset']),
      ('backstop',"counts['sent_backs_session']>=config['session_backstop']",'False',['Hook.test_twenty_backstop']),
      ('permanent-stop',"any(r['decision']=='stopped_session' for r in records)",'False',['Hook.test_failed_run_and_clean_reset']),
      ('no-progress',"repair and set(previous['finding_ids'])<=set(record['finding_ids'])",'False',['Hook.test_missing_claims_and_no_progress']),
      ('disputed',"and d['defect_id'] not in record['disputed_ids']",'',['Hook.test_partial_progress_and_disputes']),
      ('reason-cap',"[:20]",'[:30]',['Hook.test_reason_bound_and_no_content'])]:
        jobs.append({'id':'limit:'+name,'path':'bin/response_hook.py','old':old,'new':new,'tests':['test_response.py',*tests]})
    jobs.append({'id':'emphasis','path':'bin/response_tokens.py','old':"line.strip().strip('*_').strip() if emphasis else line",'new':'line','tests':['test_response.py','Response.test_emphasis_response_only']})
    jobs.append({'id':'response-arguments','path':'bin/orchestrate.py','old':"args.repo is not None or args.base is not None or args.allow_dirty or args.upstream or args.wider_scope or args.record",'new':'False','tests':['test_response.py','Response.test_response_arguments_refused']})
    jobs.append({'id':'claude-new-turn','path':'bin/response_hook.py','old':"event.get('stop_hook_active') or agent=='codex'",'new':"agent=='claude' or event.get('stop_hook_active') or agent=='codex'",'tests':['test_response.py','Hook.test_claude_new_answer_while_previous_sent_back']})
    jobs.append({'id':'excluded-citation-skip','path':'checks/citations.py','old':"ctx.run.get('response') and cite['type'] in ('file','document') and not ctx.permitted(cite['path'])",'new':'False','tests':['test_response.py','Hook.test_excluded_citation_pipeline_pair_and_delivery']})
    jobs.append({'id':'excluded-citation-not-checked','path':'checks/citations.py','old':"value['not_run'].append(c['id']+': citation not checked: excluded source '+cite['path'])",'new':'pass','tests':['test_response.py','Hook.test_excluded_citation_pipeline_pair_and_delivery']})
    jobs.append({'id': 'reaped-child-enoent', 'path': 'evals/test_response.py', 'old': 'except (FileNotFoundError,ProcessLookupError):pass  # Reaped before open or during read.', 'new': 'except ProcessLookupError:pass', 'tests': ['test_response.py', 'Hook.test_real_timeout_accepts_reaped_child']})
    jobs.append({'id': 'reaped-child-esrch', 'path': 'evals/test_response.py', 'old': 'except (FileNotFoundError,ProcessLookupError):pass  # Reaped before open or during read.', 'new': 'except FileNotFoundError:pass', 'tests': ['test_response.py', 'Hook.test_real_timeout_accepts_reaped_child']})
    jobs.append({'id': 'other-proc-io-error', 'path': 'evals/test_response.py', 'old': 'except (FileNotFoundError,ProcessLookupError):pass  # Reaped before open or during read.', 'new': 'except OSError:pass', 'tests': ['test_response.py', 'Hook.test_timeout_reaping_keeps_live_child_and_io_error_guards']})
    jobs.append({'id':'incomplete-attempt-recovery','path':'bin/response_hook.py','old':'except FileNotFoundError:','new':'except PermissionError:','tests':['test_response.py','Hook.test_missing_prior_record_recovers_without_rewriting']})
    jobs.append({'id':'live-child-state-guard','path':'evals/test_response.py','old':"else:self.assertEqual(state_text.split()[2],'Z')",'new':'else:pass','tests':['test_response.py','Hook.test_timeout_reaping_keeps_live_child_and_io_error_guards']})
    if a.smoke:jobs=jobs[:1]
    results=[]
    with tempfile.TemporaryDirectory(prefix='response-mutations-') as temp:
        tool=Path(temp)/'stagecheck';shutil.copytree(source,tool)
        for job in jobs:
            path=tool/job['path'];before=path.read_text()
            if job.get('ast'):
                parsed=ast.parse(before)
                class Change(ast.NodeTransformer):
                    def visit_Raise(self,node):return ast.copy_location(ast.Pass(),node) if node.lineno==job['line'] else node
                changed=ast.unparse(Change().visit(parsed))+'\n'
            else:
                assert job['old'] in before,job['id'];changed=before.replace(job['old'],job['new'])
            compile(changed,str(path),'exec');path.write_text(changed)
            argv=[sys.executable,'-B',str(tool/'evals'/job['tests'][0]),*job['tests'][1:]]
            started=time.monotonic()
            with subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'}) as process:
                try:stdout,stderr=process.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid,signal.SIGKILL);stdout,stderr=process.communicate()
            # Count only executed unittest failures/errors, never syntax/import/invocation errors.
            observed=stderr.decode('utf-8','replace')
            killed=process.returncode!=0 and 'Ran ' in observed and ('FAILED (' in observed)
            results.append({'id':job['id'],'compiled':True,'killed':killed,'exit':process.returncode,'seconds':time.monotonic()-started,'stderr':observed,'stdout':stdout.decode('utf-8','replace')})
            path.write_text(before)
            print(json.dumps({'probe':job['id'],'killed':killed}),flush=True)
    print(json.dumps({'results':results,'total':len(results),'killed':sum(r['killed'] for r in results),'surviving':[r['id'] for r in results if not r['killed']]}))
    return 0 if all(r['killed'] for r in results) else 1
if __name__=='__main__':sys.exit(main())
