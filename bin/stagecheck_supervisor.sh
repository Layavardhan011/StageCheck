#!/usr/bin/env bash
# ==============================================================================
# StageCheck Autonomous Live Supervisor (Shell Terminal Layer)
# Division of labor: Shell handles colors and UX; Python handles logic and checks.
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

WORKSPACE_ROOT="$(pwd)"
TASK_ID="${1:-task-101}"

echo -e "${CYAN}${BOLD}================================================================================${NC}"
echo -e "${CYAN}${BOLD}                     STAGECHECK v2.0 AUTONOMOUS SUPERVISOR                      ${NC}"
echo -e "${CYAN}${BOLD}================================================================================${NC}"
echo -e "Workspace:    ${WORKSPACE_ROOT}"
echo -e "Active Task:  ${BOLD}${TASK_ID}${NC}"
echo -e "--------------------------------------------------------------------------------"

# Preflight: Verify mandatory Bubblewrap kernel namespace & filesystem isolation (GAP-03)
echo -e "${BLUE}[PREFLIGHT] Verifying Bubblewrap OS namespace isolation...${NC}"
stagecheck supervisor preflight --workspace "${WORKSPACE_ROOT}"

# Step 1: Wait for prompt.md and check stability (30s quiet or 300s hard ceiling)
echo -e "${BLUE}[STEP 1/4] Waiting for Agent 1 to draft Phase-1/prompt.md...${NC}"
echo -e "${YELLOW}>> Developer: Please ask Agent 1 to write the architectural prompt.${NC}"

PROMPT_FILE="${WORKSPACE_ROOT}/evidence/tasks/${TASK_ID}/attempt_1/Phase-1/prompt.md"

while true; do
    if stagecheck supervisor check-stability --file "${PROMPT_FILE}" --seconds 30 --ceiling 300; then
        echo -e "${GREEN}[OK] prompt.md is stable! Triggering automatic prompt verification...${NC}"
        stagecheck verify-prompt --task "${TASK_ID}"
        echo -e "${GREEN}[SUCCESS] prompt_verified.json generated & locked! Advancing Gate 1...${NC}"
        stagecheck gate advance Gate-1 --task "${TASK_ID}"
        echo -e "${BOLD}${CYAN}>>> DEVELOPER ACTION REQUIRED:${NC}"
        echo -e "${BOLD}    Please give '${PROMPT_FILE}' to Agent 2 (Coding Implementer).${NC}"
        break
    fi
    sleep 2
done

# Step 2: Wait for pre_commit_status.json
echo -e "\n${BLUE}[STEP 2/4] Waiting for Agent 2 to implement code & submit pre-commit review...${NC}"
STATUS_FILE="${WORKSPACE_ROOT}/evidence/tasks/${TASK_ID}/attempt_1/Phase-2A/pre_commit_status.json"

while true; do
    if [ -f "${STATUS_FILE}" ]; then
        echo -e "${GREEN}[DETECTED] Agent 2 submitted pre_commit_status.json!${NC}"
        echo -e "${BLUE}[AUDIT] Running automated 270-rule rubric scan...${NC}"
        stagecheck check-rubric --task "${TASK_ID}" --update-json
        
        echo -e "${YELLOW}>> Waiting for Agent 1 to review and approve 'pre_commit_review.json'...${NC}"
        REVIEW_FILE="${WORKSPACE_ROOT}/evidence/tasks/${TASK_ID}/attempt_1/Phase-2A/pre_commit_review.json"
        while true; do
            if [ -f "${REVIEW_FILE}" ] && grep -q '"APPROVED"' "${REVIEW_FILE}"; then
                echo -e "${GREEN}[APPROVED] Agent 1 approved the changes! Advancing Gate 2A...${NC}"
                stagecheck gate advance Gate-2A --task "${TASK_ID}"
                break
            fi
            sleep 2
        done
        break
    fi
    sleep 2
done

# Step 3: Wait for delivery report
echo -e "\n${BLUE}[STEP 3/4] Waiting for Agent 2 delivery (Phase-2B/report.md)...${NC}"
REPORT_FILE="${WORKSPACE_ROOT}/evidence/tasks/${TASK_ID}/attempt_1/Phase-2B/report.md"

while true; do
    if [ -f "${REPORT_FILE}" ]; then
        echo -e "${GREEN}[DETECTED] Delivery report detected! Advancing Gate 2B...${NC}"
        stagecheck gate advance Gate-2B --task "${TASK_ID}"
        break
    fi
    sleep 2
done

# Step 4: Run 9-stage verification audit
echo -e "\n${BLUE}[STEP 4/4] Starting Phase 3 9-Stage Verification Audit...${NC}"
if stagecheck audit --task "${TASK_ID}"; then
    echo -e "${GREEN}[SUCCESS] Audit PASSED! Advancing Gate 3...${NC}"
    stagecheck gate advance Gate-3 --task "${TASK_ID}"
    echo -e "${GREEN}[SEALING] Sealing attempt evidence via Gate 4...${NC}"
    stagecheck gate advance Gate-4 --task "${TASK_ID}"
    echo -e "${GREEN}${BOLD}================================================================================${NC}"
    echo -e "${GREEN}${BOLD}[SUCCESS] TASK COMPLETED AND CRYPTOGRAPHICALLY SEALED!${NC}"
    echo -e "${GREEN}${BOLD}================================================================================${NC}"
else
    echo -e "${RED}${BOLD}[FAIL] Phase 3 audit detected blocking defects.${NC}"
    exit 1
fi

