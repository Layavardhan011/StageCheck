"""Owner-invoked offline semantic case proposal (prompt Phase E).

This invokes only the configured eval_curator. It writes no rule change, patch,
installed case, model setting, control or acceptance record.
"""
import sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bin'))
from common import *
from agents import call_agent


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--run',required=True);p.add_argument('--finding',required=True)
    p.add_argument('--output-dir',required=True)
    a=p.parse_args();ctx=Context(load(canonical(a.run)))
    config=loads(ctx.read(ctx.tool/'config/agents.json'))
    if not config['enabled']:
        raise ToolError('offline curator requires owner-selected model configuration')
    selected=[x for x in config['agents'] if x['id']=='eval_curator']
    if len(selected)!=1:
        raise ToolError('eval_curator mapping is ambiguous')
    finding_raw=ctx.read(canonical(a.finding))
    finding=loads(finding_raw)
    sys.path.insert(0,str(ctx.tool/'checks'))
    from secrets import findings
    if findings('curator-input.json',finding_raw.decode()):
        raise ToolError('credential-shaped curator input was not sent')
    out=Path(a.output_dir).absolute()
    evidence=canonical(load(ctx.bind['Evidence root']['path'])['root'])
    if not below(out.resolve(),evidence/'stagecheck/proposals') or symlink_component(out):
        raise ToolError('curator output must be under the bound stagecheck proposals root')
    out.mkdir()
    packet={'agent_id':'eval_curator','confirmed_finding':finding,
            'finding_sha256':digest(finding_raw),'allowed_paths':[str(x) for x in ctx.allowed],
            'not_inputs':'heldout cases and generator reasoning are excluded'}
    call_agent(ctx,selected[0],config,packet,out)


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print('NOT DONE: curator did not produce an admitted proposal: '+str(exc)+'\nFull Blast Radius Check: supplied run and finding only; no rule installation',file=sys.stderr)
        sys.exit(3)
