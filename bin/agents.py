"""Read-only Claude call path. Output is always a producer self-check."""
from common import *


def validate_instruction(ctx, role, filename):
    """Check the owner's requested instruction structure; no semantic proof."""
    raw = ctx.read(ctx.tool / 'agent_instructions' / filename)
    text = raw.decode('utf-8')
    headings = re.findall(r'^# (.+)$', text, re.M)
    if headings != ['Purpose', 'Inputs', 'Checks', 'Verdict rules', 'Must not', 'Output']:
        raise ToolError('instruction sections differ: ' + filename)
    if text.count('Role: `' + role + '`.') != 1:
        raise ToolError('instruction role identity differs: ' + filename)
    ids = re.findall(r'^### ([A-Z_]+-[0-9]{3}) ', text, re.M)
    if len(ids) < 30 or len(ids) != len(set(ids)):
        raise ToolError('instruction criterion identities are absent or duplicate: ' + filename)
    sections = re.split(r'^### [A-Z_]+-[0-9]{3} .+$', text, flags=re.M)[1:]
    for section in sections:
        section = section.split('\n# ', 1)[0]
        if any(len(re.findall(r'^'+field+r': \S.*$', section, re.M)) != 1
               for field in ['Question', 'Primary witness', 'Counterexample']):
            raise ToolError('instruction criterion fields are absent or duplicate: ' + filename)
    return raw


def select_agents(config, depth, failure=False):
    return [a for a in config['agents'] if depth in a['depths'] or failure and 'failure' in a['depths']]


def resolve_output(raw, agent_id, ctx):
    # --output-format json wraps structured output in structured_output.
    outer=loads(raw)
    value=outer.get('structured_output',outer)
    schema(value,load(ctx.tool/'schemas/verdict.schema.json'))
    if value.get('type')!='agent' or value['id']!=agent_id:
        raise ToolError('agent output identity/schema differs')
    if value['verdict']=='PASS' and (value['findings'] or value['not_rerun']):
        raise ToolError('agent claimed PASS with open findings or unexecuted work')
    if value['verdict']=='FAIL' and not value['findings']:
        raise ToolError('FAIL without evidence')
    if agent_id=='blast_radius':
        inventory=value.get('inventory',[])
        if sorted(g['group'] for g in inventory)!=list(range(1,12)) or any(g['label']=='checked' and not g['items'] for g in inventory):
            raise ToolError('blast-radius self-check did not enumerate the entire eleven-group surface')
        if value['verdict']=='PASS' and any(g['label']=='not_checked' for g in inventory):
            raise ToolError('blast-radius PASS contradicts unchecked coverage')
    return value


def call_agent(ctx, agent, config, input_packet, out):
    setting_path=ctx.tool/'settings/claude.settings.json'
    settings=loads(ctx.read(setting_path))
    sys.path.insert(0,str(ctx.tool/'checks'))
    from secrets import findings as input_secrets
    if input_secrets('agent-input.json',encode(input_packet).decode()):
        raise ToolError('credential-shaped model input was not sent')
    if not config.get('binary') or not agent.get('model') or not settings.get('apiKeyHelper'):
        raise ToolError('owner-selected Claude binary, apiKeyHelper and pinned model ID are required')
    if not isinstance(config.get('budget_usd'),(int,float)) or config['budget_usd']<=0 or not isinstance(config.get('timeout_seconds'),int) or config['timeout_seconds']<=0:
        raise ToolError('owner-selected positive call budget and timeout are required')
    if agent['tools']!=['Read','Grep','Glob']:
        raise ToolError('agent tools differ from the read-only tool set')
    binary=canonical(config['binary'])
    help_result=command([str(binary),'--help'],ctx.tool)
    flags=['--bare','--print','--tools','--allowedTools','--output-format','--json-schema','--system-prompt-file','--settings','--model','--max-budget-usd','--no-session-persistence','--disable-slash-commands','--strict-mcp-config','--mcp-config','--setting-sources','--permission-mode']
    # Installed 2.1.170 advertises the file form as --system-prompt[-file].
    supported_help=help_result['stdout'].replace('--system-prompt[-file]','--system-prompt --system-prompt-file')
    if help_result['exit_status'] or any(flag not in supported_help for flag in flags):
        raise ToolError('installed Claude help does not establish every selected flag')
    instruction_paths=[ctx.contract,ctx.tool/'agent_instructions/00_common.md',ctx.tool/'agent_instructions'/agent['instruction']]
    instruction_bytes=[ctx.read(ctx.contract), validate_instruction(ctx,'common','00_common.md'),
                       validate_instruction(ctx,agent['id'],agent['instruction'])]
    prompt='\n\n'.join(x.decode() for x in instruction_bytes)
    prompt_path=out/(agent['id']+'.instructions.md')
    # Large manuals exceed Linux's per-argument limit. This file contains only
    # the same three hashed sources, never an additional instruction source.
    descriptor=os.open(prompt_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,'wb') as stream:
        stream.write(prompt.encode('utf-8'))
    # Tool availability, not just permission allow rules, excludes shell/edit/MCP.
    # Inputs remain untrusted subject bytes; they cannot alter tool configuration.
    argv=[str(binary),'--bare','-p','--tools','Read,Grep,Glob','--allowedTools','Read,Grep,Glob',
          '--permission-mode','dontAsk','--setting-sources','',
          '--strict-mcp-config','--mcp-config','{"mcpServers":{}}',
          '--disable-slash-commands','--no-session-persistence',
          '--output-format','json','--json-schema',json.dumps(load(ctx.tool/'schemas/verdict.schema.json')),
          '--system-prompt-file',str(prompt_path),'--settings',str(setting_path),
          '--model',agent['model'],'--max-budget-usd',str(config['budget_usd'])]
    env={k:v for k,v in os.environ.items() if not k.startswith(('ANTHROPIC_','CLAUDE_'))}
    try:
        execution=subprocess.run(argv,cwd=ctx.tool,env=env,input=encode(input_packet),capture_output=True,
                                 timeout=config['timeout_seconds'],shell=False)
    except subprocess.TimeoutExpired as exc:
        create(out/(agent['id']+'.fault.json'),{'id':agent['id'],'fault':'timeout',
            'stdout_sha256':digest(exc.stdout or b''),'stderr_sha256':digest(exc.stderr or b''),
            'input_sha256':digest(encode(input_packet))})
        raise ToolError('agent timeout; no CLEAR result') from exc
    # Do not retain raw model stdout/stderr: invalid output might contain secrets.
    identity={'id':agent['id'],'exit_status':execution.returncode,
              'stdout_sha256':digest(execution.stdout),'stderr_sha256':digest(execution.stderr),
              'instruction_hashes':{str(p):digest(b) for p,b in zip(instruction_paths,instruction_bytes)},
              'input_sha256':digest(encode(input_packet)),'model':agent['model'],
              'instruction_payload':{'path':str(prompt_path),'sha256':digest(prompt.encode('utf-8'))},
              'argv':argv,'cwd':str(ctx.tool)}
    if digest(prompt_path.read_bytes())!=identity['instruction_payload']['sha256']:
        create(out/(agent['id']+'.fault.json'),dict(identity,fault='instruction payload changed during call'))
        raise ToolError('instruction payload changed during model execution')
    if execution.returncode:
        create(out/(agent['id']+'.fault.json'),dict(identity,fault='nonzero exit'))
        raise ToolError('agent command failed; stdout/stderr retained by hash only')
    try:
        value=resolve_output(execution.stdout,agent['id'],ctx)
    except Exception:
        create(out/(agent['id']+'.fault.json'),dict(identity,fault='schema-invalid output'))
        raise ToolError('schema-invalid model output; raw output not retained') from None
    sys.path.insert(0,str(ctx.tool/'checks'))
    from citations import validate_citation
    findings=[]; discarded=[]
    known_claims={c['id'] for c in input_packet.get('claims',{}).get('claims',[])}
    for f in value['findings']:
        if 'claims' in input_packet and f['claim_id'] and f['claim_id'] not in known_claims:
            discarded.append({'claim_id':f['claim_id'],'reason':'unknown claim identity'})
        elif any(below(Path(c['path']).resolve(),ctx.tool/'evals/heldout') or validate_citation(ctx,c) for c in f['evidence']):
            discarded.append({'claim_id':f['claim_id'],'reason':'unresolvable evidence'})
        else:
            findings.append(f)
    value['findings']=findings
    if discarded:
        value['verdict']='UNKNOWN'
        value['not_rerun'].append('agent findings discarded for unresolvable evidence')
    # Revalidate and never retain model-produced patches or credential text.
    sys.path.insert(0,str(ctx.tool/'checks'))
    from secrets import findings as secret_findings
    if secret_findings('agent-output.txt',encode(value).decode()):
        create(out/(agent['id']+'.fault.json'),dict(identity,fault='credential-shaped output suppressed'))
        raise ToolError('model output contained credential-shaped data; raw output was not retained')
    identity.update(output=value,discarded=discarded,classification='self-check; not independent acceptance')
    create(out/(agent['id']+'.json'),identity)
    return identity
