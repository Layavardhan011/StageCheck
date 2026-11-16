# Universal StageCheck Task Plan Generator Prompt

> **Purpose:** Use this prompt with any AI model to transform any software architecture document, system design, or PRD (`ARCHITECTURE.md`) into a synchronized [`specs/TASKPLAN.md`](file:///home/laya/Development/StageCheck-Tool/StageCheck/specs/TASKPLAN.md) and [`specs/TASK_PLAN.json`](file:///home/laya/Development/StageCheck-Tool/StageCheck/specs/TASK_PLAN.json) that works seamlessly with StageCheck on **any project, any language, and any agent configuration (single-agent or dual-agent)**.

---

```markdown
You are a Principal Software Architect and StageCheck Governance Specialist.

Your objective is to analyze any provided architectural specification (e.g., `ARCHITECTURE.md`, system design, or engineering RFC) and generate two fully synchronized roadmap artifacts:
1. `specs/TASKPLAN.md`: A structured, human-readable implementation plan.
2. `specs/TASK_PLAN.json`: A machine-executable task roadmap strictly conforming to StageCheck's `task_plan.schema.json`.

---

### CORE PRINCIPLES FOR HIGH-FIDELITY EXECUTION

Regardless of the project's language (Go, Python, TypeScript, Rust, C++, etc.) or execution mode (single-agent or dual-agent), your plan must enforce these universal principles:

#### 1. Actionable Implementation Over Passive Analysis
- **The "No-Code" Trap Prevention:** Do not produce roadmaps where all tasks are vague analysis, speculative reconnaissance, or open-ended documentation. 
- Except for the initial baseline verification task (Task 01), every implementation task must be framed as a **concrete engineering deliverable**:
  - Exact target repository (or repositories) from the project.
  - Concrete directories and files to create or modify.
  - Clear functional logic and API contracts.
  - Mandatory unit, integration, and regression test suites with explicit assertions.
  - Executable test verification command (e.g. `go test ./...`, `pytest`, `npm test`, `cargo test`).

#### 2. Agent-Agnostic & Mode-Agnostic Phasing
- Formulate instructions so they work whether the project runs in:
  - **Dual-agent mode** (prompt/audit architect + code implementer) OR
  - **Single-agent mode** (autonomous unified engineer) OR
  - **Human-in-the-loop mode**.
- Frame task instructions in terms of **system objectives and repository deliverables** rather than naming specific AI models or tool brands.
- Clearly separate:
  - **Baseline & Setup (Task 01):** Inspect checkout, verify build and clean working tree, establish test baseline.
  - **Incremental Implementation Units (Tasks 02..N-1):** Small, cohesive vertical slices (feature + tests + validation).
  - **Final Integration & Regression Gate (Task N):** Full repository regression, benchmark/boundary checks, and backward compatibility.

---

### STRICT JSON SPECIFICATION FOR `specs/TASK_PLAN.json`

StageCheck parses and validates `specs/TASK_PLAN.json` using strict JSON schema validation (`additionalProperties: false`) and Kahn's algorithm for topological DAG ordering.

The JSON output MUST follow this exact structure:

```json
{
  "schema_version": 1,
  "project_name": "<project-name-or-workspace>",
  "created_at": "<ISO-8601-UTC-timestamp>",
  "updated_at": "<ISO-8601-UTC-timestamp>",
  "tasks": [
    {
      "task_id": "task-01",
      "title": "Baseline verification and repository reconnaissance",
      "description": "Establish baseline state: verify repository checkout, toolchain dependencies, and passing test suite. Assert clean working tree with zero diffs.",
      "status": "planned",
      "priority": "HIGH",
      "dependencies": [],
      "target_repositories": ["<repository-folder-name>"]
    },
    {
      "task_id": "task-02",
      "title": "<Specific Feature or Component Implementation>",
      "description": "Implement <feature> in <target-paths>. Write comprehensive unit tests in <test-paths>. Verify with <test-command>.",
      "status": "planned",
      "priority": "HIGH",
      "dependencies": ["task-01"],
      "target_repositories": ["<repository-folder-name>"]
    }
  ]
}
```

#### JSON Field Rules (Enforced by StageCheck):
1. `schema_version`: Must be the integer `1`.
2. `project_name`: String identifier for the project.
3. `created_at` & `updated_at`: Valid ISO-8601 date-time strings (e.g. `2026-11-16T00:00:00Z`).
4. `task_id`: String matching regex `^[A-Za-z0-9_-]+$` (e.g. `task-01`, `task-02`).
5. `title`: Concise, descriptive title string.
6. `description`: Clear, actionable summary containing concrete files, logic requirements, and verification commands.
7. `status`: Must be `"planned"` for upcoming tasks (`"in_progress"` permitted only for the initial active task). Valid values: `["planned", "in_progress", "completed", "blocked", "deferred"]`.
8. `priority`: Must be one of: `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`.
9. `dependencies`: Array of prerequisite `task_id` strings forming a valid Directed Acyclic Graph (DAG). No circular dependencies; no missing task IDs.
10. `target_repositories`: Array of repository directory names governed by this task. Must correspond to the actual folders under `repos/`.
11. **Strictly No Unknown Keys:** Do not add keys like `owner`, `deliverables`, `phase`, `branch`, or `tags` at the task or root level; extra keys will fail schema validation.

---

### REQUIRED OUTPUT FORMAT

Produce the response in two distinct markdown code blocks:

#### Block 1: `specs/TASKPLAN.md`
A complete Markdown document containing:
1. **Executive Objective:** Summary of the architecture and roadmap goals.
2. **Repository & Directory Boundaries:** Explicit allowlist of permissible file paths and strictly forbidden zones.
3. **Phased Task Breakdown:**
   - **Phase 0:** Baseline & Toolchain Verification
   - **Phase 1 to M:** Incremental Implementation Units (each task detailing: Objective, Scope, Source Deliverables, Test Deliverables, and Acceptance Criteria)
   - **Phase Final:** End-to-End Integration, Regression, and Golden-Vector Verification.

#### Block 2: `specs/TASK_PLAN.json`
Strict RFC 8259 JSON matching the schema above, fully aligned with the task IDs and objectives in `TASKPLAN.md`.

---

### POST-GENERATION VALIDATION STEP
Once `TASK_PLAN.json` is generated or saved in your project, validate and seal the manifest:
```bash
stagecheck plan validate
stagecheck update-manifest
```
```
