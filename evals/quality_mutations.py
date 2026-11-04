"""Owner accuracy prompt §6/§7: compile-first, isolated disabled-guard probes.

All edits and child tests stay in task-owned temporary copies. No live records.
"""
import ast,copy,shutil,tempfile,subprocess,json,sys,os,hashlib
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
sys.dont_write_bytecode=True

GROUPS={
 'validate_policy':['test_policy','test_more_refusal_twins'],
 'roots':['test_roots_and_output_refusals','test_recovery_empty_and_symlink_roots','test_descriptor_root_symlink_refusal'],
 'record_shape':['test_record_envelope_api','test_writer_refusal_pairs','test_more_refusal_twins','test_confirmation_and_corrections'],
 'read_chain':['test_chain_damage_and_recovery','test_structural_recovery_refusals'],
 'valid_prefix':['test_chain_damage_and_recovery','test_structural_recovery_refusals','test_recovery_empty_and_symlink_roots'],
 'real_verdicts':['test_subject_refusal_pairs','test_writer_refusal_pairs','test_verdict_changes_between_seal_and_read'],
 'witnesses':['test_writer_refusal_pairs','test_more_refusal_twins'],
 'validate_record':['test_subject_refusal_pairs','test_more_refusal_twins','test_confirmation_and_corrections','test_unversioned_verdict_refusal','test_assembler_record_identity'],
 'effective':['test_confirmation_and_corrections','test_policy_history_deciders','test_record_semantics_skip','test_claude_cannot_override_and_invalid_policy','test_revalidation_policy_and_actor'],
 'append_record':['test_writer_refusal_pairs','test_more_refusal_twins','test_confirmation_and_corrections','test_subject_refusal_pairs','test_chain_damage_and_recovery','test_claude_cannot_override_and_invalid_policy','test_invalid_snapshot_does_not_poison_new_record'],
 'locked':['test_two_writers','test_roots_and_output_refusals'],
 'label_decision':['test_improvement_counting_label'],
 'check_anchors':['test_final_line_anchor_and_append','test_roots_and_output_refusals'],
 'numbered':['test_roots_and_output_refusals'],
 'write_measurement':['test_roots_and_output_refusals'],
 'seed_results':['test_seed_result_refusals'],
}
EXTRA={
 'read_chain':['Guards.test_read_chain_admission'],
 'valid_prefix':['Guards.test_valid_prefix_admission'],
 'real_verdicts':['Guards.test_real_verdict_task'],
 'witnesses':['Guards.test_witness_admission'],
 'validate_record':['Guards.test_record_subject_admission'],
 'effective':['Guards.test_effective_admission'],
 'locked':['Guards.test_lock_admission'],
 'append_record':['Guards.test_append_owned_records'],
 'label_decision':['Guards.test_label_shape'],
 'check_anchors':['Guards.test_anchor_and_sequence_admission'],
 'numbered':['Guards.test_anchor_and_sequence_admission'],
 'seed_results':['Guards.test_seed_result_admission'],
 'tool_inventory':['Guards.test_fixture_exception','Guards.test_fixture_inventory_admission'],
 'verify_fixture':['Guards.test_fixture_exception','Guards.test_fixture_inventory_admission'],
 'apply_side':['Guards.test_seed_path_list_admission'],
 'run_seeds':['Guards.test_seed_early_admission','Guards.test_seed_source_barrier','Guards.test_fixture_exception','Guards.test_fixture_configuration_barriers'],
}

def probes(tool):
    result=[]
    for rel in ['bin/quality.py','bin/quality_seeds.py']:
        tree=ast.parse((tool/rel).read_text())
        for fn in [x for x in tree.body if isinstance(x,ast.FunctionDef)]:
            for node in ast.walk(fn):
                if isinstance(node,ast.Raise) and isinstance(node.exc,ast.Call) and getattr(node.exc.func,'id',None)=='ToolError':
                    tests=GROUPS.get(fn.name,['test_seed_refusals','test_declarative_seeds','test_seed_shape_refusal_twins'] if rel.endswith('quality_seeds.py') else None)
                    if tests:tests=tests+EXTRA.get(fn.name,[])
                    if tests:result.append((rel,fn.name,node.lineno,node.col_offset,'raise',tests))
            if fn.name=='blocking_evidence':
                for node in ast.walk(fn):
                    if isinstance(node,ast.If) and (isinstance(node.test,ast.Name) and node.test.id=='policy_reason' or any(isinstance(x,ast.Constant) and x.value in {'override','measurement','version changed; earlier evidence not carried over','no data','findings from earlier runs still pending'} for s in node.body for x in ast.walk(s))):
                        for direction in [False,True]:result.append((rel,fn.name,node.lineno,node.col_offset,str(direction),['test_gate_conditions','test_claude_cannot_override_and_invalid_policy','test_gate_reset_and_no_data_reasons']))
    # This condition applies the computed authority to actual launcher findings.
    result.append(('bin/orchestrate.py','mode_application',0,0,'disable',['test_launch_no_data_and_overrides']))
    result.append(('bin/quality.py','policy_bound',0,0,'disable',['test_gate_conditions']))
    return result

def run_probe(tool,probe):
    rel,fn,line,col,kind,tests=probe
    with tempfile.TemporaryDirectory(prefix='quality-mutant-') as scratch:
        target=Path(scratch)/'stagecheck';shutil.copytree(tool,target)
        file=target/rel;source=file.read_text()
        if fn=='mode_application':source=source.replace("(requested!='blocking' or earned)",'True')
        elif fn=='policy_bound':source=source.replace("return len(entries)==1 and entries[0][0]==sha",'return True')
        else:
            tree=ast.parse(source)
            class Disable(ast.NodeTransformer):
                def visit_Raise(self,node):
                    if kind=='raise' and node.lineno==line and node.col_offset==col:return ast.copy_location(ast.Pass(),node)
                    return self.generic_visit(node)
                def visit_If(self,node):
                    if kind!='raise' and node.lineno==line and node.col_offset==col:node.test=ast.Constant(value=kind=='True')
                    return self.generic_visit(node)
            source=ast.unparse(ast.fix_missing_locations(Disable().visit(tree)))+'\n'
        identity=hashlib.sha256(source.encode()).hexdigest()
        try:compile(source,str(file),'exec')
        except SyntaxError as exc:return {'probe':probe[:-1],'compiled':False,'killed':False,'reason':str(exc)}
        file.write_text(source)
        argv=[sys.executable,'-B',str(target/'evals/test_quality.py')]+[t if '.' in t else 'Fixture.'+t for t in tests]
        r=subprocess.run(argv,capture_output=True,timeout=100,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
        return {'probe':probe[:-1],'source_sha256':identity,'compiled':True,'killed':r.returncode!=0,'argv':argv,'exit':r.returncode,'stdout':r.stdout.decode(),'stderr':r.stderr.decode()}

def main():
    p=__import__('argparse').ArgumentParser();p.add_argument('--smoke',action='store_true');p.add_argument('--function');p.add_argument('--line',type=int);a=p.parse_args()
    tool=Path(__file__).resolve().parents[1];items=probes(tool)
    if a.smoke:items=items[:1]
    if a.function:items=[x for x in items if x[1]==a.function]
    if a.line is not None:items=[x for x in items if x[2]==a.line]
    with ThreadPoolExecutor(max_workers=3) as pool:
        values=list(pool.map(lambda item:run_probe(tool,item),items))
    for value in values:print(json.dumps(value,sort_keys=True))
    print(json.dumps({'total':len(values),'compiled':sum(v['compiled'] for v in values),'killed':sum(v['killed'] for v in values),'unkilled':[v['probe'] for v in values if not v['killed']]},sort_keys=True))
    return 0 if all(v['compiled'] for v in values) else 1

if __name__=='__main__':sys.exit(main())
