#!/usr/bin/env bash
# The whole demo, end to end, with every beat checked. Fails loudly.
#
#   ./demo.sh            replay the recorded model replies in fixtures/ (no API key)
#   ./demo.sh live       call the model now (MODEL_PROVIDER / MODEL, see README.md)
#   ./demo.sh record     call the model now and save its replies to fixtures/
#
# Replay replays only the model's replies: the gate, the tools, the approval
# and the verifier all run for real every time.
set -euo pipefail
cd "$(dirname "$0")"

MODE=${1:-replay}
case $MODE in live|record|replay) ;; *) echo "usage: $0 [live|record|replay]" >&2; exit 64 ;; esac
export CLOAKPIPE=${CLOAKPIPE:-cloakpipe}
command -v "$CLOAKPIPE" >/dev/null || { echo "cloakpipe not found: cargo install --locked cloakpipe-cli, or set CLOAKPIPE" >&2; exit 1; }

RUN=$(mktemp -d "${TMPDIR:-/tmp}/cloakpipe-meta-demo.XXXXXX")
export CLOAKPIPE_HOME=$RUN/home          # one gate key and one ledger for the whole demo
mkdir -p .run && ln -sfn "$RUN" .run/last          # .run/last/demo.log: what this run printed
SUPPORT=../support-agent
mkdir -p fixtures
# Keep a copy of everything this run prints (the video is rendered from it).
[ -t 1 ] && export CLOAKPIPE_COLOR=1
exec > >(tee "$RUN/demo.log") 2>&1

beat() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
model_args() { [ "$MODE" = live ] || echo "--fixture fixtures/$1.json --model-mode $MODE"; }
# Each gate gets its own approvals folder: a receipt is for one exact call under one contract.
gate_env() { MOCK_UPSTREAM_LOG=$RUN/$1/upstream.jsonl APPROVALS_DIR=$RUN/$1/approvals; export MOCK_UPSTREAM_LOG APPROVALS_DIR; mkdir -p "$APPROVALS_DIR"; }

"$CLOAKPIPE" release keygen --out "$RUN/approver.json" >/dev/null 2>&1
export APPROVER_KEY=$RUN/approver.json

# Cloud mode (CLOUD_STATE = the directory `cloud.py setup` wrote): every gate
# reports its events to CloakPipe Cloud, and a held call is approved there,
# on the dashboard, instead of by approve.sh. See README.md.
# Each contract (release) reports as its own Cloud gate: `cloud.py setup
# --gate support-desk --gate support-desk-proposed`. A missing name falls
# back to the first gate set up.
APPROVE=(--approver-key "$APPROVER_KEY" --approve-cmd ./approve.sh)
CLOUD_ARGS=()
cloud_gate() {
  [ -n "${CLOUD_STATE:-}" ] || return 0
  eval "$(python3 -c 'import json, os, shlex, sys
s = json.load(open(os.path.join(sys.argv[1], "cloud.json")))["gates"]
g = s.get(sys.argv[2]) or next(iter(s.values()))
print("EVENTS=" + shlex.quote(g["events_url"]), "GATE_URL=" + shlex.quote(g["gate_url"]), "SECRET=" + shlex.quote(g["secret_file"]))
print("KEYS=(" + " ".join(shlex.quote(k) for k in g["approver_keys"]) + ")")' "$CLOUD_STATE" "$1")"
  CLOUD_ARGS=(--gate-arg=--webhook="$EVENTS" --gate-arg=--webhook-secret-file="$SECRET")
  APPROVE=(--approve-cmd ./cloud_approve.sh --gate-arg=--approvals-url="$GATE_URL"
           --gate-arg=--approvals-secret-file="$SECRET" --gate-arg=--approvals-poll-interval=1s)
  for k in "${KEYS[@]}"; do APPROVE+=(--approver-key "$k"); done
  export CLOUD_STATE
}
cloud_gate support-desk

beat "1/4  A Meta model works a support ticket that carries a prompt injection"
gate_env attack
# shellcheck disable=SC2046
python3 agent.py --state-dir "$RUN/attack" --calls-out "$RUN/attack/calls.jsonl" \
  --approvals "$APPROVALS_DIR" "${APPROVE[@]}" "${CLOUD_ARGS[@]}" $(model_args attack) \
  --screen-fixture fixtures/screen.json   # Llama Prompt Guard 2 on the ticket: GROQ_API_KEY, or its recording
python3 check.py "$RUN/attack" --approval-gated

beat "2/4  Shadow mode: the gate records an ordinary ticket without blocking anything"
gate_env shadow
# shellcheck disable=SC2046
python3 agent.py --mode shadow --ticket tickets/T-1042-clean.txt \
  --state-dir "$RUN/shadow" --calls-out "$RUN/shadow/calls.jsonl" "${CLOUD_ARGS[@]}" $(model_args shadow)

beat "3/4  The model drafts the contract from what it saw; CloakPipe validates and enforces it"
# shellcheck disable=SC2046
python3 propose_contract.py --calls "$RUN/shadow/calls.jsonl" --tools "$RUN/shadow/tools.json" \
  --task-context "$SUPPORT/task-context.json" --out "$RUN/proposed.manifest.yaml" $(model_args propose)
sed 's/^/    /' "$RUN/proposed.manifest.yaml"
cp "$SUPPORT/task-context.json" "$RUN/task-context.json"
gate_env attack-proposed
cloud_gate support-desk-proposed
# shellcheck disable=SC2046
MANIFEST=$RUN/proposed.manifest.yaml python3 agent.py --manifest "$RUN/proposed.manifest.yaml" \
  --state-dir "$RUN/attack-proposed" --calls-out "$RUN/attack-proposed/calls.jsonl" \
  --approvals "$APPROVALS_DIR" "${APPROVE[@]}" "${CLOUD_ARGS[@]}" $(model_args attack-proposed)
python3 check.py "$RUN/attack-proposed"

beat "4/4  Prove it: export the signed, hash-chained ledger and verify it offline"
"$CLOAKPIPE" ledger public-key > "$RUN/gate.pub.json"
"$CLOAKPIPE" ledger export --out "$RUN/audit-pack.tar" >/dev/null
"$CLOAKPIPE" verify "$RUN/audit-pack.tar" --key "$RUN/gate.pub.json"

printf "\n\033[1;32mdemo passed\033[0m  (run directory: %s)\n" "$RUN"
