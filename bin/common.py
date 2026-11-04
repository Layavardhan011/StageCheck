"""Shared I/O and evidence primitives required by prompt sections 7 and 8.

No product writes. Paths and identities are supplied by the run and contract.
Only the JSON Schema vocabulary used in the shipped schemas is supported.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True


class ToolError(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def nodup(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ToolError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def loads(data):
    try:
        return json.loads(data, object_pairs_hook=nodup,
                          parse_constant=lambda x: (_ for _ in ()).throw(ToolError('nonfinite JSON: ' + x)))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ToolError('malformed JSON: '+str(exc)) from exc


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                       allow_nan=False) + '\n').encode()


def load(path):
    return loads(Path(path).read_bytes())


def create(path, value):
    with Path(path).open('xb') as stream:
        stream.write(encode(value))


def schema(value, rule, location='$'):
    supported = {'oneOf', 'type', 'properties', 'required', 'additionalProperties',
                 'items', 'minItems', 'maxItems', 'minLength', 'pattern', 'enum',
                 'const', 'minimum', 'maximum'}
    if set(rule) - supported:
        raise ToolError('unsupported schema vocabulary: ' + str(set(rule) - supported))
    if 'oneOf' in rule:
        matches = 0
        for choice in rule['oneOf']:
            try:
                schema(value, choice, location)
                matches += 1
            except ToolError:
                pass
        if matches != 1:
            raise ToolError(location + ': exactly one schema alternative required')
    types = {'object': dict, 'array': list, 'string': str, 'integer': int,
             'number': (int, float), 'boolean': bool}
    kind = rule.get('type')
    if kind and (not isinstance(value, types[kind]) or
                 kind in ('integer', 'number') and isinstance(value, bool)):
        raise ToolError(location + ': wrong type ' + kind)
    if 'enum' in rule and value not in rule['enum']:
        raise ToolError(location + ': unexpected enum value')
    if 'const' in rule and value != rule['const']:
        raise ToolError(location + ': unexpected constant')
    if isinstance(value, dict):
        if set(rule.get('required', [])) - set(value):
            raise ToolError(location + ': missing required fields')
        props = rule.get('properties', {})
        if rule.get('additionalProperties') is False and set(value) - set(props):
            raise ToolError(location + ': unknown fields ' + str(sorted(set(value) - set(props))))
        for key in sorted(set(value) & set(props)):
            schema(value[key], props[key], location + '.' + key)
    if isinstance(value, list):
        if len(value) < rule.get('minItems', 0) or len(value) > rule.get('maxItems', float('inf')):
            raise ToolError(location + ': wrong array length')
        for item in value:
            schema(item, rule.get('items', {}), location + '[]')
    if isinstance(value, str):
        if len(value) < rule.get('minLength', 0):
            raise ToolError(location + ': empty string')
        if 'pattern' in rule and not re.search(rule['pattern'], value):
            raise ToolError(location + ': pattern mismatch')
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < rule.get('minimum', -float('inf')) or value > rule.get('maximum', float('inf')):
            raise ToolError(location + ': value out of range')


def canonical(path):
    return Path(path).expanduser().resolve(strict=True)


def symlink_component(path):
    p = Path(os.path.abspath(Path(path).expanduser()))
    return any(x.is_symlink() for x in [p, *p.parents])


def below(path, root):
    return path == root or path.is_relative_to(root)


def command(argv, cwd, timeout=30, env=None):
    try:
        r = subprocess.run(argv, cwd=cwd, input=None, capture_output=True,
                           timeout=timeout, env=env, shell=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolError('command did not finish: ' + str(exc)) from exc
    return {'argv': list(argv), 'cwd': str(cwd), 'exit_status': r.returncode,
            'stdout_sha256': digest(r.stdout), 'stderr_sha256': digest(r.stderr),
            'stdout': r.stdout.decode('utf-8', 'replace'),
            'stderr': r.stderr.decode('utf-8', 'replace')}


def bindings(contract):
    if not Path(contract).is_file():
        raise ToolError('contract input is not a regular file')
    text = Path(contract).read_text()
    rows = re.findall(r'^\| ([^|]+) \| `([^`]+)` \| `([0-9a-f]{64})` \|$', text, re.M)
    if len(rows) != 7 or len({r[0] for r in rows}) != 7:
        raise ToolError('contract control table is ambiguous')
    result = {role.strip(): {'path': path, 'sha256': sha} for role, path, sha in rows}
    roots = re.findall(r'\*\*Active programme root:\*\* `([^`]+)`', text)
    arch = re.findall(r'\*\*Controlling architecture:\*\* `([^`]+)`, SHA-256 `([0-9a-f]{64})`', text)
    protected = re.findall(r'protected and must reproduce SHA-256 `([0-9a-f]{64})`', text)
    if len(roots) != 1 or len(arch) != 1 or len(protected) != 1:
        raise ToolError('contract architecture/root/state identity is ambiguous')
    root = canonical(roots[0])
    result['architecture'] = {'path': str(root.parent.parent / arch[0][0]), 'sha256': arch[0][1]}
    result['root'] = root
    result['protected_sha256'] = protected[0]
    excluded_section = text.split('Known excluded locations include:', 1)[1].split('Historical citations', 1)[0]
    result['excluded'] = [root.parent.parent / x.rstrip('/') for x in re.findall(r'`([^`]+)`', excluded_section)]
    return result


class Context:
    def __init__(self, run):
        self.run = run
        self.tool = canonical(run['tool_root'])
        self.contract = canonical(run['contract'])
        self.bind = bindings(self.contract)
        self.root = self.bind['root']
        if canonical(run['programme_root']) != self.root:
            raise ToolError('run root disagrees with contract')
        self.files = {}
        self.commands = []
        self.outcomes = load(self.tool / 'config/required_outcomes.json')
        self.paths = load(self.tool / 'config/paths.json')
        self.allowed = [self.root / 'RWA', self.root / 'controls', self.tool]
        self.exact = [self.contract]
        for name in self.paths['instruction_copies']:
            candidate = Path(name).expanduser()
            if not candidate.is_absolute():
                candidate = self.root.parent.parent / candidate
            self.exact.append(candidate.resolve())
        for role in ['Evidence root', 'Product repositories', 'Qualification tree (§11)']:
            descriptor = Path(self.bind[role]['path'])
            if not descriptor.is_file():
                raise ToolError('descriptor is not a regular file')
            # Do not trust a descriptor's target paths before its bound identity matches.
            if digest(descriptor.read_bytes()) != self.bind[role]['sha256']:
                continue
            values = load(descriptor)
            for k, v in values.items():
                if k == 'root' or k.endswith('_root'):
                    self.allowed.append(Path(v).resolve())
        self.allowed.extend(canonical(x) for x in self.paths['additional_read_paths'])

    def permitted(self, path):
        raw = Path(path).expanduser()
        resolved = raw.resolve()
        if symlink_component(raw):
            # Contract's CLAUDE.md symlink is the sole allowed instruction exception.
            if not (raw.name == 'CLAUDE.md' and resolved == self.contract):
                return False
        if any(below(resolved, x.resolve()) for x in self.bind['excluded']):
            return False
        return resolved in self.exact or any(below(resolved, x) for x in self.allowed)

    def read(self, path):
        if not self.permitted(path):
            raise ToolError('excluded or unlisted path: ' + str(path))
        p = canonical(path)
        if not p.is_file():
            raise ToolError('evidence input is not a regular file: '+str(p))
        data = p.read_bytes()
        self.files[str(p)] = digest(data)
        return data

    def run_command(self, argv, cwd, **kw):
        result = command(argv, cwd, **kw)
        self.commands.append(result)
        return result

    def file_evidence(self, path, lines=None, quote=None):
        data = self.read(path)
        text = data.decode('utf-8')
        all_lines = text.splitlines()
        if not all_lines:
            raise ToolError('empty file cannot provide a quoted defect: ' + str(path))
        selected = lines or [1, 1]
        return {'type': 'file', 'path': str(canonical(path)), 'sha256': digest(data),
                'lines': selected, 'quote': quote or '\n'.join(all_lines[selected[0]-1:selected[1]])}

    def defect(self, check_id, source, path, claim_id='', evidence=None, lines=None, evidence_key=None):
        rule = self.outcomes[check_id]
        if evidence is None:
            evidence = [self.file_evidence(path, lines)]
        # Hash identity keys, not mutable quotes/whole-file hashes.
        normalized=str(Path(path).resolve())
        for field in ['report','claims','run_path']:
            if field in self.run and normalized==str(Path(self.run[field]).resolve()):
                normalized='owner-input:'+field
        evidence_identity=evidence_key if evidence_key is not None else [
            (e.get('type'), e.get('lines', []), e.get('argv', [])) for e in evidence]
        key = [check_id, normalized, claim_id, evidence_identity]
        return {'defect_id': 'D-' + digest(encode(key))[:12], 'check_id': check_id,
                'source': source, 'mode': 'report_only', 'clause': rule['clause'],
                'claim_id': claim_id, 'location': {'path': str(path), 'lines': lines or [1, 1]},
                'evidence': evidence, 'required_outcome': rule['required_outcome'], 'status': 'new'}


def result(check_id):
    return {'type': 'check', 'id': check_id, 'defects': [], 'errors': [], 'not_run': [],
            'files': [], 'commands': [], 'unbound': False, 'escalate': False}


def claims(ctx):
    data = loads(ctx.read(ctx.run['claims']))
    rule = load(ctx.tool / 'schemas/claims.schema.json')
    if ctx.run.get('response'):
        # Derive only the response transport exception from the delivery schema.
        # Delivery mode retains every original requirement and field type.
        rule['required'] = [k for k in rule['required'] if k not in ('record','record_sha256')]
        for key in ['record','record_sha256']:
            rule['properties'][key] = {'oneOf':[rule['properties'][key],{'const':None}]}
    schema(data, rule)
    if data['contract_sha256'] != digest(ctx.read(ctx.contract)):
        raise ToolError('claims cite a different contract identity')
    if data['task_id'] != ctx.run['task_id'] or data['iteration'] != ctx.run['iteration']:
        raise ToolError('claims task/iteration differs from launcher identity')
    if ctx.run.get('response') and data.get('record') is None:
        if data.get('record_sha256') is not None:
            raise ToolError('response record hash without an attachment')
    elif digest(ctx.read(data['record'])) != data['record_sha256']:
        raise ToolError('existing record attachment identity differs')
    ids = [c['id'] for c in data['claims']]
    if len(ids) != len(set(ids)):
        raise ToolError('duplicate claim IDs')
    return data


def main_check(name, fn):
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', required=True)
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()
    value = result(name)
    ctx = None
    try:
        ctx = Context(load(args.run))
        fn(ctx, value)
    except Exception as exc:
        value['errors'].append(type(exc).__name__ + ': ' + str(exc))
    if ctx:
        value['files'] = [{'path': k, 'sha256': v} for k, v in sorted(ctx.files.items())]
        value['commands'] = ctx.commands
        schema(value, load(ctx.tool / 'schemas/verdict.schema.json'))
    create(Path(args.output_dir) / (name + '.json'), value)
    print(json.dumps({'check':name,'defects':[d['check_id'] for d in value['defects']],
                      'errors':value['errors'],'not_run':value['not_run']},sort_keys=True))
    return 3 if value['errors'] else 1 if value['defects'] else 0
