#!/usr/bin/env bash
# The demo's stand-in for a human approver: signs an approval receipt for
# the exact call the gate held (tool + arguments), valid for 15 minutes.
# In production this is a person clicking Approve in Slack; the receipt the
# gate checks is the same.   usage: approve.sh TOOL ARGS.json
set -euo pipefail
cd "$(dirname "$0")"
: "${APPROVER_KEY:?set APPROVER_KEY to the approver's key file (cloakpipe release keygen)}"
: "${APPROVALS_DIR:?set APPROVALS_DIR to the gate's --approvals directory}"
"${CLOAKPIPE:-cloakpipe}" approve --manifest "${MANIFEST:-cloakpipe.manifest.yaml}" \
  --tool "$1" --args "$2" --task-context "${TASK_CONTEXT:-../support-agent/task-context.json}" \
  --key "$APPROVER_KEY" --expires 15m --out "$APPROVALS_DIR" >/dev/null
