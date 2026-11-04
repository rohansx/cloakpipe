#!/usr/bin/env bash
# Cloud mode's approver: the gate has filed the held call with CloakPipe
# Cloud (--approvals-url). A person approves it on the dashboard's Approvals
# page (or in Slack); the gate's poller verifies the signed receipt and writes
# <fingerprint hex>.approval.json into --approvals. This waits for that file.
# With CLOUD_AUTO_APPROVE=1 (unattended runs), it presses Approve itself,
# through the same api call the dashboard button makes.
#   usage: cloud_approve.sh TOOL ARGS.json FINGERPRINT
set -euo pipefail
cd "$(dirname "$0")"
: "${APPROVALS_DIR:?set APPROVALS_DIR to the --approvals directory of the gate}"
: "${CLOUD_STATE:?set CLOUD_STATE to the directory written by cloud.py setup}"
fp=${3#sha256:}
receipt="$APPROVALS_DIR/$fp.approval.json"
if [ "${CLOUD_AUTO_APPROVE:-}" = 1 ]; then
  python3 cloud.py approve --state "$CLOUD_STATE" "$3" >&2
else
  echo "          approve it on the dashboard: Approvals, $1 (fingerprint ${fp:0:12})" >&2
fi
deadline=$((SECONDS + ${APPROVAL_WAIT_SECS:-600}))
until [ -f "$receipt" ]; do
  [ "$SECONDS" -lt "$deadline" ] || { echo "no approval within ${APPROVAL_WAIT_SECS:-600}s" >&2; exit 1; }
  sleep 1
done
