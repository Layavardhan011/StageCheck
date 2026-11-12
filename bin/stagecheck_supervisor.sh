#!/usr/bin/env bash
# ==============================================================================
# StageCheck Autonomous Live Supervisor (Shell Terminal Layer)
# Division of labor: Shell handles CLI/UX; Python handles state, gates & checks.
# ==============================================================================
set -euo pipefail

CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

WORKSPACE_ROOT=""
TASK_ID=""
ATTEMPT=""
TIMEOUT="1800"
WATCH_MODE="--watch"
JSON_FLAG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        start|watch)
            shift
            ;;
        --task|--task-id)
            TASK_ID="${2:?Missing value for $1}"
            shift 2
            ;;
        --workspace)
            WORKSPACE_ROOT="${2:?Missing value for --workspace}"
            shift 2
            ;;
        --attempt)
            ATTEMPT="${2:?Missing value for --attempt}"
            shift 2
            ;;
        --timeout)
            TIMEOUT="${2:?Missing value for --timeout}"
            shift 2
            ;;
        --once)
            WATCH_MODE="--once"
            shift
            ;;
        --watch)
            WATCH_MODE="--watch"
            shift
            ;;
        --json)
            JSON_FLAG="--json"
            shift
            ;;
        -h|--help)
            echo "Usage: stagecheck_supervisor.sh [--task <id>] [--workspace <path>] [--attempt <N>] [--timeout <sec>] [--once] [--json]"
            exit 0
            ;;
        -*)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
        *)
            if [[ -z "${TASK_ID}" ]]; then
                TASK_ID="$1"
                shift
            else
                echo "Unexpected positional argument: $1" >&2
                exit 1
            fi
            ;;
    esac
done

if [[ -z "${WORKSPACE_ROOT}" ]]; then
    SEARCH_DIR="$(pwd)"
    while [[ "${SEARCH_DIR}" != "/" ]]; do
        if [[ -f "${SEARCH_DIR}/controls/ACTIVE_STATE.json" ]]; then
            WORKSPACE_ROOT="${SEARCH_DIR}"
            break
        fi
        SEARCH_DIR="$(dirname "${SEARCH_DIR}")"
    done
    if [[ -z "${WORKSPACE_ROOT}" ]]; then
        WORKSPACE_ROOT="$(pwd)"
    fi
fi

echo -e "${CYAN}${BOLD}================================================================================${NC}"
echo -e "${CYAN}${BOLD}                     STAGECHECK v2.0 AUTONOMOUS SUPERVISOR                      ${NC}"
echo -e "${CYAN}${BOLD}================================================================================${NC}"
echo -e "Workspace:    ${WORKSPACE_ROOT}"
if [[ -n "${TASK_ID}" ]]; then
    echo -e "Active Task:  ${BOLD}${TASK_ID}${NC}"
fi
echo -e "--------------------------------------------------------------------------------"

echo -e "${BLUE}[PREFLIGHT] Verifying Bubblewrap OS namespace isolation...${NC}"
stagecheck supervisor preflight --workspace "${WORKSPACE_ROOT}"

CMD=(stagecheck supervisor "${WATCH_MODE}" --workspace "${WORKSPACE_ROOT}" --timeout "${TIMEOUT}")
if [[ -n "${TASK_ID}" ]]; then
    CMD+=(--task "${TASK_ID}")
fi
if [[ -n "${ATTEMPT}" ]]; then
    CMD+=(--attempt "${ATTEMPT}")
fi
if [[ -n "${JSON_FLAG}" ]]; then
    CMD+=("${JSON_FLAG}")
fi

exec "${CMD[@]}"
