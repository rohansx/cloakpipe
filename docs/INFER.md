# Drafting a contract: `cloakpipe infer`

Writing the first manifest is the hardest part of adopting the gate.
`cloakpipe infer` drafts it from what your agent actually does: run the gate
in shadow mode with capture on, use the agent as usual, and infer a draft in
which every rule cites its evidence. The draft is never activated for you.

```bash
# 1. Capture: shadow mode (or no manifest at all), local files only
cloakpipe mcp-proxy --upstream "<server command>" --task-context task.json \
    --capture ./captures/

# 2. Use the agent normally, or run your test suite through it

# 3. Draft
cloakpipe infer ./captures/ --release my-agent --out cloakpipe.manifest.draft.yaml

# 4. Later, in CI: does new traffic still fit the active contract?
cloakpipe infer ./captures/ --diff cloakpipe.manifest.yaml     # exit 1 on drift
```

## Capture

The decision ledger never stores argument values, so it cannot be used to
draft rules. `--capture <dir>` writes a separate file per proxy run,
`capture-<time>-<pid>-<rand>.jsonl`, recording:

- the trusted task context (from `--task-context`, as the gate sees it);
- every `tools/list` reply (which tools the server offered);
- every `tools/call` with its raw arguments, before the gate decides and
  before any PII transform.

| Property | How |
|---|---|
| Opt-in | Off unless `--capture` is given. |
| Shadow only | Refused with an enforcing gate (`--manifest` without `--mode shadow`). Works without a manifest. |
| Local | Directory `0700`, files `0600`. Never sent anywhere, never in an audit pack. |
| Short-lived | `--capture-max-age DAYS` deletes older capture files at start-up; `infer --delete-after` deletes what it read. |
| Reducible | `--capture-shapes` stores each string as its shape only: length, pattern class (`email`, `url`, `uuid`, `digits`, `id` with its prefix, `text`, `token`) and a salted hash. |

With `--capture-shapes`, equal strings still hash equal under the capture
directory's salt (`.capture-salt`), so **task binding still works**: a
recipient that equals the task's customer email is found without either value
being stored. What is lost: enums, email domains (no `or_pattern`) and URL
hosts. The draft says so.

Shapes reduce what a capture holds; they are not encryption. Know the limits:

- numbers and booleans are kept as they are, and object keys stay raw (a map
  keyed by email address keeps the addresses);
- the salt sits in the capture directory, so whoever can read the captures
  can test guesses for low-entropy strings (short ids, digit runs) against
  the hashes. Protect the directory as you would the raw values, and delete
  it after inferring.

A capture records what the agent sent. An argument that poses as a shape in
a capture of raw values (only an agent could send one) is excluded from the
draft and counted in the review list.

### From OpenTelemetry traces

If the agent is already instrumented, pass its trace export instead:
`cloakpipe infer traces.json`. `infer` reads OTLP/JSON (one document, or the
collector's file exporter, one per line). Each trace is a session. Each span
with `gen_ai.tool.name` is a call, and `gen_ai.tool.call.arguments` (the
GenAI semantic conventions) holds its arguments. Most instrumentations only
record the arguments when told to. For task binding, set a span attribute
`cloakpipe.task` to the task context as JSON. Without it, the draft has
types, ranges and patterns but no `one_of_context`.

Traces carry raw values. Treat the export like a raw capture.

## What gets drafted

| Rule | From |
|---|---|
| Declared tools | Tools that were called. Tools offered but never called stay undeclared (refused) and are listed. |
| `type`, `required` | Every observed value; required when present in every kept call. Whole numbers are `integer`. |
| `min` / `max` | Observed range ×1.25, rounded up to two significant figures (`0` when nothing was negative). |
| `max_len` | Longest string ×1.15, rounded up to one significant figure (3,410 → 4000). Arrays: item count. |
| `enum` | At most six distinct values, each seen about three times or more (not free text). |
| `pattern` | One shared class: `T-[0-9]{4,}` for ids, UUIDs, digit runs, up to three email domains or HTTPS hosts. |
| `one_of_context` | The task-context path the value equals in at least `--bind-threshold` (0.9) of calls, after leftover addresses that recur in one domain are covered by an `or_pattern`. |
| `properties`, `items` | Objects and arrays, recursively (closed objects). |
| `side_effect: true` | Guessed from the tool name (`send`, `refund`, `delete`, …). |
| `approval` | **Suggested only**, commented out: a money-moving tool with an amount-like argument gets `when: "<arg> > <top of observed values>"`. |

Each rule carries a comment: how many calls support it, a confidence level
(`low` below `--min-support`, `medium`, `high` at four times it) and a
redacted example (`d***@customer.example`, `T-1***`, `<text, 57 chars>`).

## Safety rules

- **Observed is not legitimate.** If the agent was tricked during capture,
  the draft could encode the attack. A call is an *outlier* when one of its
  values breaks the pattern the rest follow: a string that is neither the
  bound task value nor a recurring domain, a number or a length more than ten
  times the median. An outlier call is excluded from every rule of its tool
  and listed for review, never widened into the rule.
- **Minimum support.** Below `--min-support` calls (default 5) an argument
  gets only its type and the exact observed bounds, and is flagged.
- **Tight by default.** When unsure, the narrower rule. A refused legitimate
  call in shadow mode is cheap to fix; a loose rule is invisible.
- **A person activates it.** The output is a file. Before writing it, `infer`
  loads it with the gate's own parser and checks every captured call against
  it (`Self-check: 40/41 captured calls pass this draft`).

The review list at the top names every low-support rule, excluded outlier,
`or_pattern` (confirm those addresses are yours), suggested approval and
undeclared tool.

## `--diff`: drift in CI

`infer --diff <manifest>` checks captured traffic against the active
contract instead of drafting:

- **NEW TOOLS**: called but not declared (refused in enforce mode);
- **DRIFT**: calls the contract refuses, by tool, reason and path, with a
  redacted example;
- **COULD BE TIGHTENED**: bounds more than twice what traffic needs, and
  arguments that always equal a task field or take a few values;
- **UNUSED**: declared tools never called, arguments never sent.

New tools or drift exit 1. `--json` prints the report for a CI step.

## Flags

| Flag | Default | |
|---|---|---|
| `--out FILE` | stdout | Refuses to overwrite without `--force`. |
| `--release NAME` | `draft-agent` | The draft's `release`. |
| `--min-support N` | 5 | |
| `--bind-threshold X` | 0.9 | Between 0.5 and 1. |
| `--delete-after` | off | Delete the capture files once the draft is written. |
| `--diff MANIFEST`, `--json` | | Diff mode. |

Exit codes: 0 drafted or no drift, 1 drift or a malformed capture, 2 usage
or I/O error.
