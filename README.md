# STAGECHECK — DRWA-defined checking tooling

The main coordinating role is documented in
[`agent_instructions/orchestrator.md`](agent_instructions/orchestrator.md).
The owner explicitly selected deterministic orchestration: `bin/orchestrate.py`
controls execution order and result precedence; no additional orchestrator model
is invoked. `config/agents.json` identifies the main manual separately from the
seven specialist model mappings. Startup retains its identity and preflight
checks the main, common and specialist instruction structures.

Each manual retains 30 numbered questions with a primary witness and a specific
counterexample. The common manual contains the shared review procedure once;
specialists reference it instead of repeating boilerplate for every criterion.
Structure admission checks role identity, headings, distinct criterion ids and
nonempty question/witness/counterexample fields. There is no line-count floor.
These are review specifications, not 270 executed semantic cases. The current
evaluation inventory is the sole source of executed coverage. Detailed manuals
do not establish model reliability; live repeated measurements and independent
review remain required. Exactly three instruction sources still enter each
specialist call: contract, common manual, and that specialist's manual.
Their combined contents are retained in a mode-600 payload file and supplied
with `--system-prompt-file`, avoiding dependence on per-argument size limits.
The payload is a composition artifact, not a fourth instruction source.

The seven specialist manuals are [claim support](agent_instructions/claim_support.md),
[upstream reuse](agent_instructions/upstream_reuse.md),
[blast radius](agent_instructions/blast_radius.md),
[test adequacy](agent_instructions/test_adequacy.md),
[rerun evidence](agent_instructions/independent_rerun.md),
[failure classification](agent_instructions/failure_class.md), and
[evaluation curation](agent_instructions/eval_curator.md).
The [common manual](agent_instructions/00_common.md) defines shared discipline.

This revision uses primary-source guidance on
[simple orchestration](https://www.anthropic.com/engineering/building-effective-agents)
and [agent evaluation](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents).
The [Lost in the Middle paper](https://arxiv.org/abs/2307.03172) motivates measuring
behavior under the actual long context rather than treating length as assurance.
These references inform review methodology; the installed contract and owner's
requirements remain the controlling programme inputs.

NOT DONE: Live model measurements, product reruns, owner depth approval,
promotion, binding and independent review are pending. This is tooling work;
it earns no product, qualification, runtime or acceptance credit.

Full Blast Radius Check: The retained build record and eval results under
`../evidence/stagecheck/build/development/` contain the concrete source,
fixture, command and coverage inventory. Historical replay identifies checks
that cannot run without a claims attachment and historical checkout.

Enforcement Self-Check: Enforcement is manual; the live model measurements,
owner approval, promotion, binding and independent review listed above remain
outside the retained fixture and source evidence.

The latest owner chat authorized developing this system in Codex. It superseded
the earlier session exclusion and phase stops. All writes remain inside this
tool tree and `evidence/stagecheck/`; protected files and product source are not
changed. The original attachment is retained as
`../evidence/stagecheck/build/development/request.txt`. Its observed SHA-256 is
`3338230dda04a20825fc2e1331e85380a243fd02e3f214f33e30999b5112b1ff`.

## Run one iteration

From the programme root, the owner invokes:

```sh
stagecheck/bin/stagecheck.sh --task TASK_ID --repo ABSOLUTE_REPOSITORY_ROOT \
  --base BASE_REF --report ABSOLUTE_REPORT_PATH --claims ABSOLUTE_CLAIMS_PATH
```

Task inputs are owner-typed arguments. The launcher derives HEAD, changed paths,
staged/unstaged/untracked status and effective remotes from git. It never runs
the generator. Dirty repositories are refused by default. An explicit owner
`--allow-dirty` argument admits working-tree bytes; verdict, run and model packet
carry `dirty` and `status_sha256`. `repository_status.json` retains the raw git
status command and output, including for refused attempts. Reports distinguish
HEAD from working-tree state; older records without status fields display UNKNOWN.
A claims attachment references the existing engineering record
by path and hash. `schemas/claims.schema.json` defines the attachment, including
file/upstream citations and command citations against retained `execution.json`,
`stdout` and `stderr` files. Arrays of two integers represent inclusive line
ranges. Commands use the existing record's `exit`, `stdout_sha256` and
`stderr_sha256`, rather than an invented combined-output field.

Optional owner inputs: `--depth docs|code|sensitive` selects explicit depth;
`--record PATH` includes an operation record; `--upstream REPOSITORY CHECKOUT
COMMIT` supplies a pinned source identity; `--wider-scope PATH` supplies a packet
with an exact Plan/ledger `citation` and explicit `surfaces`. `--root` and
`--contract` are for fixture trees. Neither claims nor generator-written records
define the check boundary, allowed commands, source locks or execution grant.

`--output-dir ABSOLUTE_DIRECTORY` optionally selects a task history directory
inside the bound evidence root, without symlink components. Each attempt still
gets its own numbered subdirectory and the usual immutable history links.
The default remains `evidence/stagecheck/TASK_ID/`.

Results are retained under `evidence/stagecheck/TASK_ID/ATTEMPT/`:
`run.json`, `startup.json`, check/agent outputs, `verdict.json`, the deterministically
rendered `generator_report.md` and a seal linking verdict/report hashes.
TOOL_ERROR attempts do not consume a repair iteration. The initial iteration,
two repair iterations and one final resubmission give a maximum of four.

Exit statuses are 0 CLEAR, 1 BLOCKED, 2 ESCALATE, 3 TOOL_ERROR. CLEAR means only
that no blocking defect was found by checks that ran. Reports always begin with
the contract's three required headers, in order: `NOT DONE:`,
`Full Blast Radius Check:`, `Enforcement Self-Check:`. Enforcement is manual;
the third line lists every not-run check and every report-only finding caused
by an unbound tool. UNBOUND appears on the Result line. Missing
or mismatching tool bindings force all findings to report-only. Control and
architecture identity mismatches require owner disposition. Sensitive depth
with required agents disabled returns ESCALATE with an owner question, preserves
the unrun checks and consumes an iteration. Genuine script/schema/input faults
remain TOOL_ERROR. No automatic retry follows an ESCALATE result.

## Owner configuration

No `controls/STAGECHECK_ROOT.json` is created or modified by this build. Its
proposed exact shape is an object with `root` (the absolute tool directory) and
`manifest_sha256` (the hash of MANIFEST.sha256). The owner reviews and installs
it. The manifest uses standard `sha256sum` syntax, lists every tool file and the
two reused verifiers, and excludes itself because a file cannot contain its own
SHA-256. Verify it from the tool directory with `sha256sum -c MANIFEST.sha256`.

Everything starts report-only, with promotion count unset. Only the owner edits
`config/modes.json`. A deterministic check requested as blocking must earn that
authority for its current version or have an owner override, as described below.
Model-agent modes retain their existing behavior. Configuration changes require a
new manifest identity and owner rebind. `config/depth.json` is a proposal awaiting
owner approval. While `approved` is not literal true, no proposed path rule or
default is applied: explicit `--depth` controls depth, otherwise it is docs.
With approved rules, effective depth is the maximum of path and requested depth.

For model calls the owner selects the Claude binary, exact model IDs, per-call
budget and timeout in `config/agents.json`, and the `apiKeyHelper` command in
`settings/claude.settings.json`. Never put a key in a file, environment manifest,
prompt or log. Calls use confirmed local CLI flags, bare mode, no hooks, no
session persistence, no MCP servers, no skills, and only Read/Grep/Glob tools.
Each call has exactly three instruction sources: contract, common instructions,
and its own instruction file. Findings are re-resolved by the citation code.
Invalid output is UNKNOWN/TOOL_ERROR. These producer-launched model calls remain
self-checks under ledger L43 and are never independent acceptance.

For product reruns the owner must confirm the applicable ledger grant and select
exact commands from retained execution records. `config/commands.json` stays
disabled until then. Command-citation byte validation is separate from rerun
selection: a valid citation whose argv/cwd has no selected rerun yields
`rerun.unselected`, an explicit not-run reason and no execution. Other checks
retain their results. The finding follows the rerun check's configured mode;
it is report-only when unbound. Duplicate owner selections remain a tool fault.
Each entry supplies exact argv/cwd/environment, binary and
hash, input hashes, timeouts and smoke argv. The grant packet supplies a current
ledger citation, expiry, and exact command selectors. An SP1 expiry can be
represented as `expiry_stage: SP1` only if its quoted ledger section states
`end of SP1` and the current protected state remains in SP1. Go commands require
the locked path and `GOTOOLCHAIN=local`. The owner-confirmed scope and grant must
cover the smoke command as well as the full command. Output hash differences
are reported literally: Go `-json` timestamps and durations can differ between
runs; no undocumented normalization masks those differences.

The current installation selects the retained `^TestQualDRWAAdminCarrier`
command and its compile smoke under the owner-confirmed
`SP1-LOCAL-FOUNDATION-001` grant. Selection and current input identities are in
`../evidence/stagecheck/build/instruction_revision/product_selection.json`.
This is development evidence only. It does not reproduce the historical source
scope or provide independently accepted qualification. Synthetic evaluations
reset installation execution settings before supplying fixture-only commands.

## Evaluate the tooling

```sh
PYTHONDONTWRITEBYTECODE=1 python3 stagecheck/evals/run_evals.py \
  --tool-root stagecheck --programme-root . --contract ../../AGENTS.md \
  --output-dir evidence/stagecheck/build/NEW_RUN_ID --smoke
```

After the smoke command, omit `--smoke` for paired fixtures, fail-closed/history
properties, held-out boundaries and ten distinct historical task-family records.
Outputs are retained with input/output hashes. `--case CHECK_ID` selects a
bounded paired reproduction; `--properties-only` selects launcher properties;
`--replay-only` selects historical retention checks. The runner never executes
product tests. Repeated checks against the same fixture must emit identical
bytes. Fixtures contain only synthetic keys and synthetic git objects and
never touch live controls or a product repository.

`evals/measure_agents.py` performs the separately configured three-repeat model
measurements. Its output reports observations, UNKNOWN counts, discarded
findings and repeat disagreement, never semantic reliability as a pass.

`evals/improve.py` compares an explicitly owner-labelled escaped defect and
candidate outcome records across paired, held-out and replay inventories. It
rejects missing inventories or new failures and marks any relaxed criterion
RELAXATION. A proposal does not install or rebind anything.
Its `--run` selects the bound roots. Each outcome packet must carry `evaluation`
with `execution` (a command citation), `result_record` and `result_sha256`.
Typed outcomes must equal those retained results, all source identities must
still match, and the candidate's `owner_label_record` must identify a counting
quality record: `{"type":"quality_record","record_sha256":"…"}`. An owner-confirmed
proposal uses its proposal line hash. Missing, superseded, unconfirmed or non-defect
records are refused. Replay entries with omitted checks cannot establish clean coverage
for proposal admission. The current historical replay therefore does not admit
an improvement proposal by itself.
`evals/curate.py --run RUN_JSON --finding FINDING_JSON --output-dir PROPOSAL_DIR`
invokes the separately configured offline eval_curator and retains its sourced
case proposal. It receives no held-out cases and changes no installed rules.

## Accuracy evidence and earned blocking

Requirement: the owner's accuracy-measurement instruction, Parts A–F and §7,
plus the two subsequent rulings on final-line anchors and declarative seeds.
This is tooling under contract §0(1)/§5, with no DRWA product or runtime credit.
The producer builds these tools and never supplies real grades or private seeds.

The owner controls `config/quality_targets.json`: confidence and all targets
start at 0.95, `deciders` at `["owner"]`, and only audit precision is enforced.
All probabilities must lie strictly between zero and one. Fixed scoring rules
are `precision_v1`, `recall_v1`, `first_submission_v1`, `prompt_correct_v1`.
Unresolved outcomes count as failures. Neither the policy nor outcome evidence
changes whether a delivery meets its specification; precision decides only
whether a deterministic check may block. `promotion_count` is redundant for
this mechanism and remains untouched; no code reads it.

The bound is the one-sided exact binomial lower bound, computed by bisection
on the probability of at least k successes in n trials, at alpha = 1-confidence.
No observations gives `insufficient`; otherwise the status is `meets` when
the lower bound reaches target, or `not_yet`. At these targets, 59/59, 92/93
and 122/124 reach it. The point estimate alone never earns blocking.
The reported additional successes are the smallest number needed without
another failure. These are historical measurements, not future guarantees.

Each verdict check carries a version hash of sorted path/hash pairs: its own
check, transitive imports, shared non-check/non-eval Python, configuration,
schemas, settings and three pinned external helper files. Documentation,
bytecode, .git, MANIFEST.sha256, modes.json, quality_targets.json and all newly
added quality files are excluded. Inspected documents and deliveries are inputs,
not version dependencies. Shared changes conservatively reset every check.
Old verdicts without versions do not count. Owner carryovers are directed
edges between versions, followed one step at a time, and apply to precision only.

Owner/Claude commands below take a retained `run.json` for bound root selection.
Never point tests at real records. The records folder is derived from the bound
Evidence root descriptor: `stagecheck_quality/`, beside `stagecheck/` outputs.

```sh
python3 -B stagecheck/bin/quality_write.py --run RUN_JSON --record REQUEST_JSON
python3 -B stagecheck/bin/quality_write.py --run RUN_JSON --recover-owner
python3 -B stagecheck/bin/quality_seeds.py --run RUN_JSON --seeds PRIVATE_FOLDER --max-seed-bytes OWNER_SELECTED_POSITIVE_CAP
python3 -B stagecheck/bin/quality_measure.py --run RUN_JSON
python3 -B stagecheck/evals/test_quality.py
```

A writer request has `kind`, `subject`, `value`, `actor` (owner or claude),
`type` (proposal or decision), `evidence` (path/hash pairs or existing defect ids),
and optional one-line secret-screened `note` or `replaces` record hash. The writer
adds policy/previous hashes. The schema and validator define exact subjects.
Finding subjects are task, defect_id, check and version; witnessing sealed
verdicts go in evidence. Only sealed outputs under the configured default
stagecheck task/attempt root qualify as real runs. Alternate output locations
do not qualify. Every snapshot retains the exact policy bytes and their hash.
Historical deciders apply at each record's position. Later adding a decider
does not confirm prior proposals. A confirmation uses the confirmer's authority
and position. A counting correction replaces its target; proposals do not.
The latest counting decision per subject wins. Carryover, blocking_override,
prompt_outcome and continuation count only with owner as deciding actor.
Actor fields are declarative and provide no identity authentication.

The writer locks, appends complete JSON lines and fsyncs before unlocking.
First-line previous is zero; later hashes cover the entire previous line,
including LF. Owner ruling: **there is no payload_sha256**. A final complete
line can be edited or removed undetected by the previous-line chain alone
until a later append or an external anchor exists. Measurement files and sealed
verdicts record record-file SHA-256 and byte length, anchoring that exact prefix.
Later appends are allowed; edits/truncations inside an anchored prefix are refused.
This is local tamper detection, not protection against rewriting every anchor.
Owner recovery starts the next-numbered file with a continuation naming the
damaged file's full hash and last valid line hash. The damaged bytes stay in
place. Readers use its valid prefix and then continue. An owner continuation
also dispositions older anchors for those explicitly named damaged bytes.
Unclosed damage withholds overrides and earned blocking. Never repair records
by rewriting them. Missing/invalid individual records are skipped with reasons.

Precision counts each task/defect id once across iterations and carried versions.
Latest true_defect is a success; false_block, unresolved and a covered finding
without a decision are failures. Undecided findings in uncovered runs remain
listed as pending. Per-rule breakdowns are informational. Earlier pending
findings prevent earned blocking; the current unsealed run is excluded from
that computation. Verdict/report pending counts include newly observed current
findings, separately from earlier pending counts. If evidence is unreadable,
counts are UNKNOWN (JSON null), never falsely reported as zero.

Recall uses the highest-numbered external seed result compatible with the
check's current version. Editable `evals/heldout/` cases never count. A target
rule must fire on the defective twin while its check fires nothing on the clean
twin. Other-check clean firings are listed. Missed defects stay open across
versions until a counting closure identifies a detected seed in that newest
compatible result. Open misses prevent `meets`; `none` stays an uncovered gap.
Invalid seed results are skipped and listed in the measurement.

Declarative seeds extend the existing case shape: optional `id`/`expected`,
`target` rule, and `pair.clean`/`pair.defective` objects. Each side permits
`edits` containing `{path,text}`, `claims` overrides, and `run` overrides limited
to depth/changed_paths/read_paths. Paths are relative to the fixture workspace;
absolute paths, parent traversal, .git paths, tool-copy paths, symlinks and
executable file edits are refused. Claims path/record fields are also confined.
Each invocation requires a positive maximum seed-file byte size; expanded edit
bytes are capped too. No default cap is chosen. Fixtures disable product/model
execution; seed data is never executed as code. All twins and intermediate
outputs are temporary and removed. Permanent output retains only seed hashes,
target rules/checks, versions and detection/clean-firing data. CLI refusals never
print seed names or content. A seed id hashes its exact JSON file; the seed-set
identity hashes the sorted ids. Results and measurements are numbered, with
exclusive creation; numbering, not timestamps, selects the newest.

Owner Ruling 3 attributes seed results to the source tree's check versions.
Before and after executing each twin, the runner compares every entry in the
fixture tool copy with the source inventory, rejecting symlinks, added/removed
entries and differences outside `config/commands.json`, `config/agents.json`,
`config/paths.json` and `MANIFEST.sha256`. Each result records this verification,
the number of copies checked and SHA-256 of the three fixture configuration
files. All twins must have the same configuration hashes. Relative instruction
paths keep those bytes independent of temporary directory names. Rules depending
on those files are measured under fixture configuration: product/model execution
is disabled and instruction copies point to the fixture. This does not measure
their behavior under the installed production command/agent/path configuration.

`first_submission_v1`: a delivery is met when its first submitted iteration has
no confirmed true defect from stagecheck or Claude's audit. `prompt_correct_v1`:
a prompt is correct when nothing in it was later found wrong, missing or narrowed.
These judgments are supplied as real delivery/prompt outcome decisions; the
measurement counts them and enforces neither target. Prompt decisions are owner
only. Existing assembler record assembly digests may identify prompts, or an
exact prompt path/hash may do so. No assembler change is required.

For a deterministic mode requested as blocking, the orchestrator revalidates
chain/anchors and checks owner overrides first, independent of policy validity
or manifest entry. Without override, it requires valid manifest-matching policy,
precision meets and zero earlier pending findings. It computes from records,
never trusts a measurement's figures. Failure only downgrades to report-only;
reasons under NOT DONE do not affect result/exit precedence. Separate control
identity escalation, tool binding, model modes and runtime errors retain their
existing behavior. An override cannot bypass those controls. Verdicts retain
policy and record-prefix identities, authority sources and pending counts;
the report identity line mirrors them.

Maintenance belongs to the owner/Claude: after each run, propose/decide finding
labels and coverage; after escaped defects, record misses and write private twins;
after each task, decide delivery and prompt outcomes; after labels or version
changes, run seeds then measurement. The owner can override a version/all versions
or carry evidence across reviewed changes. The producer repairs tools only on
instruction, reports version resets, and never grades or feeds real measurements.
No background service or automatic owner decision is installed.

## Limits that remain visible

Report lint reads `config/controlled_vocabulary.json`, a literal mirror of
revision-2 contract §4's controlled words and success synonyms. Matching is
case-insensitive with word boundaries and includes multiword phrases. Such
wording requires scope, citations, a proving label and no not_checked group.
Byte-valid citations still need semantic review of their actual proving scope.
The eval suite checks the vocabulary against the supplied current contract.
Five outcome ids have property/observation coverage rather than paired cases:
`agent.unsupported`, `orchestrate.history`, `orchestrate.recurrence`,
`orchestrate.no_progress` and `orchestrate.repair_bound`. Model effectiveness
and independent review are separate from this deterministic fixture coverage.

The instruction contract and hash links are manually applied controls, not an OS
sandbox or external tamper-proof store. The current Codex permissions include
the workspace root, so this build does not claim the generator is technically
unable to edit the tool tree. A party able to rewrite the whole evidence chain
can also rewrite its hashes. Owner-controlled retention outside that authority
would require a separate owner decision.

The secret check is the requested small filename/regex check, not a proof that
all secret encodings are detectable. It suppresses credential quotes and uses
the retained detector command as evidence. Semantic entailment, upstream reuse,
test adequacy and full consumer enumeration need the configured model checks
and human disposition. A read-only model cannot personally execute a rerun:
the rerun script supplies execution evidence, and the model must disclose what
it did not execute. No independent credit is assigned here.

The existing capture driver was read, but it requires output directly under the
evidence root and cwd under build. Those constraints do not admit this tool's
one-JSON-per-check interface. Rerun execution is therefore retained inside that
check's JSON result; the existing driver is not changed or invoked with an
unsupported output layout. The existing manifest and state verifiers are reused
unchanged and pinned. Additional snapshot checks cover the chain verifier's
protected-history and declared-change gap.

## Per-response Stop checking (owner response-hook REQUEST Parts A–E)

This addition is an owner-review draft until its separate diff approval and
installation. Agent configuration, hook trust and instruction installation are
owner operations. See the retained response_hook_2026-10-12_01 owner_install
material for exact entries, protected surfaces, ledger entries and live tests.

`bin/orchestrate.py --response --task ID --report ABSOLUTE_COPY --claims
ABSOLUTE_COPY` uses the ordinary check outputs, seals, histories and default
evidence/stagecheck task root. It rejects --repo, --base, --allow-dirty,
--upstream, --wider-scope and --record. The run has no repository, response
base/HEAD markers, empty changed paths, dirty=false and docs depth by default.
Explicit depth is retained. Qualification naming and product reruns are listed
under NOT DONE as `response mode: no repository change`. Model calls are always
skipped, even if configured. Command citations are byte-validated, never rerun.
Delivery behavior and its schema requirements stay unchanged.
The owner's later scoped exception lets the response citation loop defer
excluded file/document sources to scope_paths, which still emits scope.excluded.
The citations result explicitly lists each skipped source as not checked and
never reads its bytes. Delivery's excluded-citation TOOL_ERROR remains a
separate later-repair finding; validate_citation itself is unchanged.

Response claims use the existing claims schema, with only record/record_sha256
allowed absent or null in the loader's response branch. A hash without its
record is refused. The hook preserves the agent's original bytes and hash and
patches only the top-level task_id and iteration values in its copied input;
all other bytes, including claims, citations and labels, stay unchanged. An
original may omit those transport values. It must supply the current contract
hash and every required claim/citation field. Read-only observations may cite
the first line; claims about content require exact ranges and quotes.
TEST_PROVEN and RUNTIME_PROVEN claims require command citations.

Only in response mode, Markdown emphasis is stripped at the edges of the
first three non-empty header lines. `report.unbacked_token` uses the single
fact_tokens detector for paths under the programme root/home/tmp, 40/64 hex
strings, line references, URLs, evidence labels and backticked commands on a
line stating an exit status or result. This command heuristic is mechanical;
record-mode observations are needed to assess false send-backs. Delimit paths
containing spaces with backticks or Markdown link syntax. Each token needs the
backing specified in the owner request. Line locators use a same-sentence file
or the nearest preceding path; ranges are inclusive. The exact unindented,
unemphasized `Claims: <absolute path>` transport line alone is excluded from
token backing: the hook verifies, copies and hashes that file. Substantive
paths and modified versions of the line receive ordinary token checking.

`bin/response_hook.py --agent codex|claude` accepts documented Stop JSON on
stdin and emits exactly one JSON object and exit 0. It uses
last_assistant_message directly, never transcript_path. Codex uses turn_id;
Claude uses the count of prior response tasks. Repairs share the task history.
One exclusive numbered hook folder is reserved before answer processing and
records are created exclusively. Counts derive from earlier session records;
no mutable counter is rewritten. Existing protected records, identity errors,
malformed history, invalid settings and checker faults stop without blocking.
An earlier reserved attempt folder with no record.json is an interrupted
attempt: prior_records classifies it in memory as tool_error, with unknown
task/turn and no findings, disputes, success credit or failure-round increment.
The next record lists incomplete_prior_attempts. No earlier folder is backfilled
or rewritten; existing malformed records and symlinks remain refusals.
If an evidence binding or output path is unsafe before reservation, no trusted
record destination exists: stdout is {} and no record can be guaranteed. This
security limitation overrides the literal every-Stop-record promise. The owner
must check bindings/protection before launch and monitor hook launch failures.

The initial owner settings in config/response_hook.json are mode=record,
repairs_per_answer=2, failed_answers_in_a_row=3, session_backstop=20,
stagecheck_timeout_seconds=60 and claims_max_bytes=65536. The claims folders
are evidence/responses/codex and claude; records are under
evidence/stagecheck_responses. Paths are fixture/root-relative, confined to the
bound evidence directory, nonoverlapping and without symlink components.
Changing a listed settings file requires manifest regeneration and owner rebind.
Unlisted additions and a stale descriptor alone remain advisory; changed bytes
already listed in the manifest cause hook tool_error until regeneration.

The default send-back ids are citation.missing_file, citation.hash_mismatch,
citation.line_range, citation.quote_not_found, citation.upstream_identity,
citation.command_mismatch, report.unbacked_token, report.headers, report.label,
report.inference, report.claim_missing, scope.excluded, scope.draft_approved,
secret.pem, secret.keystore, secret.assignment and secret.filename.
Every preflight.*, authority.*, qual.*, rerun.*, orchestrate.* and agent.* id,
scope.package_span, report.completion, report.counts, report.groups and
report.table is forbidden in the send-back settings. stopped_clean means no
remaining eligible finding, not that owner-binding matters were accepted.

No separate required_outcomes id covers settings shape/path validation,
missing/invalid/oversized/nonregular claims, hook-record admission, counters,
session/task naming, process timeout, checker faults, no-progress/dispute
decisions, output JSON shape or the 20-finding reason cap. These are hook
admission/decision guards and use tool_error or bounded disposition records,
not invented checker rules. Missing claims uses report.unbacked_token with a
single instruction to add the file and exact transport line.

off records without checking; record runs checks and records would_send_back;
send_back emits the fixed owner sentence followed by a data heading, up to 20
sorted safe finding ids/rules/locations, a further count and report path. No
quoted content is echoed. Secret matches are detected before answer/claims
retention; only hashes, lengths and sanitized findings are retained. The small
existing secret detector cannot recognize every encoding. A backed disputed
defect id is retained for the owner and not resent on that task. Unchanged
findings on a repair stop_no_progress without another block. The final allowed
submission still runs and ends stopped_clean/open. Three failed answers or 20
send-backs permanently stop sending back for that session, even if the owner
later raises a limit. A clean answer before session stop resets the failure run.
The child checker has a process-group kill timeout. These limits cap rounds,
not tokens. Record time measures hook runtime; stagecheck timing is reported in
the retained fixture command outputs. Leave the 60-second setting pending the
owner's timing review; hook entries use 61 seconds to allow that child timeout.

The hook stops fabrication, not misreading: this describes mechanical tokens,
identity/quote/header/label checks, not a guarantee against every fabricated
statement. A byte-correct quotation can still be misapplied. Semantic claim
support remains a disabled model/owner responsibility. Main-agent answers are
checked; subagent turns enter only through the final answer using their claims.
No 95% semantic accuracy claim follows from fixture coverage. Effective write
protection, live-agent whole-message behavior, trust and a non-producer review
remain owner checks. The generator maintains its own checker under this grant;
manifest binding and Claude review are guards, not independence by themselves.

Response tests: python3 -B stagecheck/evals/test_response.py and
test_response_guards.py. response_regression.py runs the unchanged delivery
suite on synthetic roots; response_mutations.py disables new refusal guards,
each send-back effect, limits and emphasis in disposable compile-valid copies.
They read only permitted construction inputs, execute no product/model code,
write only temporary fixtures and remove those fixtures when finished.
