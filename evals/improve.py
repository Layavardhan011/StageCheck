"""Compare an owner-supplied candidate with installed checks; never install it.

Prompt Phase E requires all paired, held-out and replay outcomes. This command
only admits a proposal when those explicit outcome records justify it.
"""
import sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
from common import *


def compare(installed,candidate,target):
    for key in ['paired','heldout','replay']:
        if key not in installed or key not in candidate or set(installed[key])!=set(candidate[key]) or not installed[key]:
            raise ToolError('comparison needs identical, nonempty '+key+' inventories')
    if installed['paired'].get(target) is not False or candidate['paired'].get(target) is not True:
        raise ToolError('target must fail on installed checks and be caught by candidate')
    regressions=[key+'/'+case for key in ['paired','heldout','replay'] for case in installed[key]
                 if candidate[key][case] is not True]
    if regressions:
        raise ToolError('candidate has unresolved failures: '+str(regressions))
    if not installed.get('confirmed_defect') or not candidate.get('owner_label_record'):
        raise ToolError('owner-labelled escaped finding required')
    return {'target':target,'admissible':True,'classification':'RELAXATION' if candidate.get('relaxes_check') else 'candidate; owner installation and rebind required'}


def resolve_evaluation(ctx,packet):
    sys.path.insert(0,str(ctx.tool/'checks'))
    from citations import validate_citation
    proof=packet.get('evaluation')
    if not isinstance(proof,dict) or validate_citation(ctx,proof['execution']):
        raise ToolError('proposal needs resolvable retained evaluation command evidence')
    raw=ctx.read(proof['result_record'])
    if digest(raw)!=proof['result_sha256']:
        raise ToolError('evaluation result identity differs')
    observed=loads(raw)
    if not observed.get('inputs_unchanged') or not observed.get('input_sha256'):
        raise ToolError('evaluation does not establish exact unchanged source inputs')
    for path,sha in observed['input_sha256'].items():
        if digest(ctx.read(path))!=sha:
            raise ToolError('proposal source has changed since evaluation')
    outcomes={'paired':{k:v['ok'] for k,v in observed['paired'].items()},
              'heldout':{k:v for k,v in observed['properties'].items() if k.startswith('heldout.')},
              'replay':{r['task']:not r['findings'] and not r['not_run'] for r in observed['replay']}}
    if any(packet.get(k)!=v for k,v in outcomes.items()):
        raise ToolError('typed proposal counts do not equal the retained evaluation results')
    return outcomes


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--installed',required=True);p.add_argument('--candidate',required=True)
    p.add_argument('--target',required=True);p.add_argument('--output-dir',required=True)
    p.add_argument('--run',required=True)
    a=p.parse_args()
    ctx=Context(load(canonical(a.run)))
    installed=loads(ctx.read(canonical(a.installed)));candidate=loads(ctx.read(canonical(a.candidate)))
    resolve_evaluation(ctx,installed);resolve_evaluation(ctx,candidate)
    sys.path.insert(0,str(ctx.tool/'checks'))
    from citations import validate_citation
    from quality import label_decision
    label_decision(ctx,candidate.get('owner_label_record'))
    result=compare(installed,candidate,a.target)
    out=Path(a.output_dir).absolute()
    evidence=canonical(load(ctx.bind['Evidence root']['path'])['root'])
    if not below(out.resolve(),evidence/'stagecheck/proposals') or symlink_component(out):
        raise ToolError('proposal output must remain under the bound proposals root')
    out.mkdir()
    for name,path in [('installed',a.installed),('candidate',a.candidate)]:
        raw=canonical(path).read_bytes()
        result[name+'_sha256']=digest(raw)
        (out/(name+'.json')).write_bytes(raw)
    create(out/'proposal.json',result)


if __name__=='__main__':
    try:
        main()
    except Exception as exc:
        print('NOT DONE: proposal not admitted: '+str(exc)+'\nFull Blast Radius Check: explicit comparison inputs only; no installation',file=sys.stderr)
        sys.exit(3)
