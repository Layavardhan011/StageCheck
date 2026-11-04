"""Owner accuracy prompt Part D/§7 and declarative-seed ruling: private offline twins.

Only owner/Claude invokes this on real seeds. No model or product execution.
Errors are deliberately content-free; all seed-derived files live in TemporaryDirectory.
"""
import tempfile
from quality import *
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'evals'))
from run_evals import fixture,execute,manifest

PREFIX={'preflight':'preflight','scope':'scope_paths','citation':'citations','report':'report_lint','authority':'authority','secret':'secrets','qual':'qual_naming','rerun':'rerun','carry':'carry_forward'}
FIXTURE_FILES=('config/agents.json','config/commands.json','config/paths.json')
FIXTURE_ALLOWED=(*FIXTURE_FILES,'MANIFEST.sha256')

def tool_inventory(tool):
    """Ruling 3: all entries, including empty directories; no symlink exclusions."""
    if symlink_component(tool):raise ToolError('fixture tool symlink refused')
    entries={}
    for p in tool.rglob('*'):
        if p.is_symlink():raise ToolError('fixture tool symlink refused')
        if not p.is_file() and not p.is_dir():raise ToolError('fixture tool entry refused')
        entries[p.relative_to(tool).as_posix()]=digest(p.read_bytes()) if p.is_file() else None
    return entries

def verify_fixture(source,tool):
    actual=tool_inventory(tool)
    differences={name for name in set(source)|set(actual) if source.get(name)!=actual.get(name) or (name in source)!=(name in actual)}
    if set(source)!=set(actual) or not differences<=set(FIXTURE_ALLOWED):raise ToolError('fixture tool difference refused')
    if any(not isinstance(actual.get(name),str) for name in FIXTURE_ALLOWED):raise ToolError('fixture configuration file refused')
    return {name:actual[name] for name in FIXTURE_FILES}

def seed_path(workspace,tool,value):
    if not isinstance(value,str) or not value or Path(value).is_absolute() or '..' in Path(value).parts or '.git' in Path(value).parts:
        raise ToolError('seed path refused')
    p=workspace/value
    if symlink_component(p) or not p.resolve().is_relative_to(workspace) or p.resolve().is_relative_to(tool):raise ToolError('seed path refused')
    return p

def merge(original,overrides):
    if not isinstance(overrides,dict):raise ToolError('seed override refused')
    result=loads(encode(original))
    for key,value in overrides.items():
        result[key]=merge(result[key],value) if isinstance(result.get(key),dict) and isinstance(value,dict) else value
    return result

def expand_paths(value,workspace,tool):
    if isinstance(value,list):return [expand_paths(v,workspace,tool) for v in value]
    if isinstance(value,dict):
        result={}
        for key,v in value.items():
            if key in {'path','record'} and isinstance(v,str):result[key]=str(seed_path(workspace,tool,v))
            else:result[key]=expand_paths(v,workspace,tool)
        return result
    return value

def apply_side(side,run,data,root,tool,max_bytes):
    workspace=root.parent.parent
    if not isinstance(side,dict) or set(side)-{'edits','claims','run'}:raise ToolError('seed side refused')
    total=0
    for edit in side.get('edits',[]):
        if not isinstance(edit,dict) or set(edit)!={'path','text'} or not isinstance(edit['text'],str):raise ToolError('seed edit refused')
        p=seed_path(workspace,tool,edit['path'])
        if p.suffix.lower() in {'.py','.sh','.bash','.exe','.so','.dll','.bat','.ps1'}:raise ToolError('executable seed edit refused')
        raw=edit['text'].encode();total+=len(raw)
        if total>max_bytes:raise ToolError('seed expanded size refused')
        p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
    data=merge(data,expand_paths(side.get('claims',{}),workspace,tool))
    overrides=side.get('run',{})
    if not isinstance(overrides,dict) or set(overrides)-{'depth','changed_paths','read_paths'}:raise ToolError('seed run override refused')
    for key,value in overrides.items():
        if key=='depth':
            if value not in {'docs','code','sensitive'}:raise ToolError('seed depth refused')
            run[key]=value
        else:
            if not isinstance(value,list):raise ToolError('seed paths refused')
            run[key]=[str(seed_path(workspace,tool,p)) for p in value]
    Path(run['claims']).write_bytes(encode(data));Path(run['run_path']).write_bytes(encode(run))

def run_seeds(ctx,folder,max_bytes):
    if type(max_bytes)!=int or max_bytes<=0:raise ToolError('positive seed cap required')
    policy(ctx);_,records=roots(ctx)
    # Admission precedes any seed access. Rechecked under the publication lock.
    chain,_=read_chain(records);runs,_=real_verdicts(ctx);check_anchors(records,chain,runs)
    folder=Path(folder).absolute()
    if symlink_component(folder) or not folder.is_dir() or folder.resolve().is_relative_to(ctx.tool):raise ToolError('seed folder refused')
    paths=sorted(folder.rglob('*'))
    if any(symlink_component(p) for p in paths):raise ToolError('seed symlink refused')
    files=[p for p in paths if p.is_file()]
    if not files or any(p.suffix!='.json' for p in files):raise ToolError('seed files refused')
    version_map={c:v['sha256'] for c,v in versions(ctx).items()};source_inventory=tool_inventory(ctx.tool);results=[];ids=set();configuration=None
    for path in files:
        if path.stat().st_size>max_bytes:raise ToolError('seed size refused')
        with path.open('rb') as seed_handle:raw=seed_handle.read(max_bytes+1)
        if len(raw)>max_bytes:raise ToolError('seed size refused')
        sid=digest(raw)
        if sid in ids:raise ToolError('duplicate seed identity')
        ids.add(sid);case=loads(raw)
        if not isinstance(case,dict) or set(case)-{'id','target','pair','expected'} or not {'target','pair'}<=set(case):raise ToolError('seed shape refused')
        target=case['target'];check=PREFIX.get(target.split('.')[0]) if isinstance(target,str) else None
        if not check or target not in ctx.outcomes:raise ToolError('seed target refused')
        if not isinstance(case['pair'],dict) or set(case['pair'])!={'clean','defective'}:raise ToolError('seed twins refused')
        fired={};defective=[]
        for side in ['clean','defective']:
            with tempfile.TemporaryDirectory(prefix='stagecheck-private-seed-') as scratch:
                run,data,root,tool=fixture(Path(scratch),ctx.tool,ctx.contract,ctx.root)
                # Context resolves relative instruction paths from the fixture workspace.
                # This avoids temporary names in the recorded configuration hashes.
                paths=load(tool/'config/paths.json');paths['instruction_copies']=['instruction_fixture.txt']
                (tool/'config/paths.json').write_bytes(encode(paths));manifest(tool)
                hashes=verify_fixture(source_inventory,tool)
                if configuration is not None and hashes!=configuration:raise ToolError('fixture configuration changed between twins')
                configuration=hashes
                apply_side(case['pair'][side],run,data,root,tool,max_bytes)
                names=CHECKS if side=='clean' else [check]
                for name in names:
                    value=execute(run,name,Path(scratch)/(name+'.output'))
                    if value['errors']:raise ToolError('seed execution refused')
                    rules=sorted({d['check_id'] for d in value['defects']})
                    if side=='clean' and rules:fired[name]=rules
                    if side=='defective':defective=rules
                if verify_fixture(source_inventory,tool)!=hashes:raise ToolError('fixture configuration changed during execution')
        results.append({'seed_id':sid,'target_rule':target,'check':check,'detected':target in defective and check not in fired,'clean_firings':fired})
    value={'seed_set_sha256':digest(encode(sorted(ids))),'versions':version_map,'seeds':sorted(results,key=lambda r:r['seed_id']),
           'fixture_configuration':{'verified_only_allowed_differences':True,'allowed_differences':sorted(FIXTURE_ALLOWED),'file_sha256':configuration,'copies_checked':2*len(results)}}
    with locked(records):
        policy(ctx);chain,_=read_chain(records);runs,_=real_verdicts(ctx);check_anchors(records,chain,runs)
        if version_map!={c:v['sha256'] for c,v in versions(ctx).items()} or tool_inventory(ctx.tool)!=source_inventory:raise ToolError('seed versions changed')
        dest=next_output(records,'seed_result','json');create(dest,value)
    return dest

def main():
    p=argparse.ArgumentParser();p.add_argument('--run',required=True);p.add_argument('--seeds',required=True);p.add_argument('--max-seed-bytes',required=True,type=int);a=p.parse_args()
    try:
        dest=run_seeds(Context(load(a.run)),a.seeds,a.max_seed_bytes)
        print(json.dumps({'result':str(dest),'sha256':digest(dest.read_bytes())}));return 0
    except Exception:
        print('NOT DONE: seed run refused; no seed name or content retained',file=sys.stderr);return 3

if __name__=='__main__':sys.exit(main())
