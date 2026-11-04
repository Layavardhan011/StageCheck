"""Three-repeat semantic measurements, only after owner model configuration.

Fixture results are observations; no model reliability or independent credit.
Held-out cases are never included in this tuning/measurement input set.
"""
import sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import *
from agents import call_agent
from run_evals import fixture,manifest


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--tool-root',required=True);p.add_argument('--programme-root',required=True)
    p.add_argument('--contract',required=True);p.add_argument('--output-dir',required=True)
    a=p.parse_args()
    tool=canonical(a.tool_root);root=canonical(a.programme_root);contract=canonical(a.contract)
    config=load(tool/'config/agents.json')
    if not config['enabled']:
        raise ToolError('owner model configuration is disabled; no live measurement ran')
    cases=load(tool/'evals/cases/model_semantics/cases.json')
    out=Path(a.output_dir).absolute();out.mkdir()
    measured={}
    for spec in cases:
        selected=[x for x in config['agents'] if x['id']==spec['agent']]
        if len(selected)!=1:
            raise ToolError('case agent mapping is ambiguous')
        observations=[]
        for twin in ['clean','defective']:
            variant=out/(spec['id']+'.'+twin);variant.mkdir()
            run,data,fr,ft=fixture(variant,tool,contract,root)
            subject=fr/'RWA/subject.md';subject.write_text(spec['source']+'\n')
            cite={'type':'file','path':str(subject),'sha256':digest(subject.read_bytes()),'lines':[1,len(subject.read_text().splitlines())],'quote':spec['source']}
            claim=data['claims'][0]
            claim.update(text=spec[twin],citations=[cite])
            ctx=Context(run)
            for repeat in range(1,4):
                repeat_dir=variant/str(repeat);repeat_dir.mkdir()
                packet={'agent_id':spec['agent'],'claims':data,'changed_paths':[str(subject)],'diff':spec[twin],
                        'allowed_paths':[str(x) for x in ctx.allowed],'case_id':spec['id']}
                if spec['agent']=='blast_radius':
                    for c in packet['claims']['claims']:c['blast_radius']=[]
                r=call_agent(ctx,selected[0],config,packet,repeat_dir)
                observations.append({'twin':twin,'repeat':repeat,'verdict':r['output']['verdict'],
                                     'findings':len(r['output']['findings']),'discarded':len(r['discarded']),
                                     'signature':digest(encode(r['output']))})
        measured[spec['id']]={'agent':spec['agent'],'observations':observations,
            'seeded_defects_caught':sum(x['twin']=='defective' and x['verdict']=='FAIL' for x in observations),
            'clean_cases_wrongly_flagged':sum(x['twin']=='clean' and x['verdict']=='FAIL' for x in observations),
            'unknown':sum(x['verdict']=='UNKNOWN' for x in observations),
            'discarded':sum(x['discarded'] for x in observations),
            'repeat_disagreement':{t:len({x['signature'] for x in observations if x['twin']==t})>1 for t in ['clean','defective']}}
    create(out/'measurements.json',{'classification':'observed self-check measurements; no semantic reliability verdict','cases':measured})


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print('NOT DONE: '+str(exc)+'\nFull Blast Radius Check: model input admission only; live measurements incomplete',file=sys.stderr)
        sys.exit(3)
