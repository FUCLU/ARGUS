# Vulhihi Stage 2 and Stage 3

## Stage 3 compact: Attack Analyst → Security Auditor

The implemented `--protocol compact` follows `STAGE3_REVISED_PLAN.md` using
two role calls, strict application-side JSON Schema/reference validation,
one repair per role, and at most one bounded expansion to available function
source. Missing external callers/contracts remain unresolved; the runner never
invents them or converts missing evidence into BENIGN. ABP remains the default
baseline; select compact explicitly. `--rounds` applies only to ABP.

Install dependencies with `python -m pip install -r requirements.txt`.
The matching dataset pair is `data/stage2.jsonl` (160 samples, 472 candidates)
and `data/ground_true/sven_test.jsonl` (all 160 sample identities matched).
The 33-row `sven_reconstructed_dedup.json` is a direct-source dataset, not the
Stage 2 input for compact. Use the separate `sven-code-only` protocol below to
send its raw `input` code strings without joining Stage 2.

Validate all input packets without model calls:

```powershell
python run_triage.py --protocol compact --stage2 data/stage2.jsonl --data data/ground_true/sven_test.jsonl --dry-run --output outputs/compact_validation/stage3.jsonl
```

Run a small pilot using the provider/model configured in `.env`:

```powershell
python run_triage.py --protocol compact --stage2 data/stage2.jsonl --data data/ground_true/sven_test.jsonl --limit 5 --workers 1
```

Run the full dataset:

```powershell
python run_triage.py --protocol compact --stage2 data/stage2.jsonl --data data/ground_true/sven_test.jsonl --workers 4
```

Outputs go to a new timestamped `outputs/runs/<timestamp>/` directory. It contains
`stage3.jsonl`, `summary.json`, `manifest.json`, `requests.jsonl`, and immutable
`packets/<sha256>.json` snapshots. Preserve/export the packet directory with the
results. To resume, use `--output` with the exact previous `stage3.jsonl` path.
Resume checks protocol, prompts/schema/model/endpoint/settings, implementation,
input fingerprints, and packet hashes. Unresolved/error candidates are retried.

`--no-few-shot` disables the three synthetic examples. `--no-context-expansion`
disables local-source recovery; `--compact-max-lines 400` controls the source
budget. Evaluation reports resolution coverage and recall over all positive
samples as well as resolved-only metrics. Labels and CWE metadata are joined
for reporting, never sent in the model packet. Source comments remain source
data and may still contain dataset-specific information.

The compact agent prompts are `prompts/attack_analyst.txt` and
`prompts/security_auditor.txt`. For the supplied Qwen-compatible endpoint,
the client sends JSON-object, non-streaming requests with `enable_thinking=false`,
temperature 0, and a 4096-token output allowance. The larger allowance keeps
audit reports from being truncated; application-side validation checks every result.

## Sven reconstructed code-only experiment

This separate protocol runs the two agents directly on each record's `input`
code string. The Analyst receives raw code only; dataset instruction, output
label, CWE, and filename are excluded. The Auditor receives the same code and
the Analyst report as a separate untrusted claim to verify; the code remains
the only evidence for its final verdict. The Analyst reports at most two compact,
recall-oriented scenarios without a class label; the Auditor verifies them and
checks for missed issues.
No Stage 2 join or few-shot examples are used.
Each role is limited to 1024 output tokens at temperature 0. Predictions are
binary (`VULNERABLE`/`BENIGN`); when the snippet does not establish a concrete
vulnerability, the code-only policy classifies it as `BENIGN` and notes the
scope limitation in the explanation.

```powershell
python run_triage.py --protocol sven-code-only --data data/sven_reconstructed_dedup.json --limit 1 --workers 1
```

Omit `--limit 1` to run all 33 records. Results go to a timestamped
`outputs/runs/` directory with `stage3.jsonl`, `stage3.pretty.json`, request logs,
and a `summary.json`. The terminal prints per-sample status and a final metrics table,
not the JSON summary. This experiment is not directly equivalent to compact Stage 3:
it analyzes each reconstructed code input as one sample, without per-sink
Stage 2 candidates or evidence-reference validation.

Validation: `python -m pytest -q`. Tests use scripted model responses; they
check contracts, error handling, recovery, serialization and resume, not model
detection accuracy. The full-dataset preflight currently accepts 461 candidates;
11 lack source-backed `compact_code` and become `INVALID_INPUT` with null label.

This workspace keeps the context extraction and ABP triage stages.

Stage 3 prompt text is kept outside the Python code in `prompts/prosecutor.txt`
and `prompts/defender.txt`; `sinkkb/triage/protocol.py` loads those files.
Pass `--prosecutor-prompt` or `--defender-prompt` to Stage 3 to use alternate
external prompt files.

- **Stage 2** uses CodeBadger/Joern to build context packets from source code
  and the Stage 1 sink results in `data/sven_100pairs_stage1.jsonl`.
- **Stage 3** evaluates candidates embedded in the Stage 2 context packets and
  the Prosecutor–Defender–Prosecutor protocol.

The Stage 1 and Stage 2 artifacts are stored in `data/`. Stage 3 can run from
the Stage 2 artifact alone: it reads sink snapshots and reconstructs source
lines from the context packets. The prompts assess the visible mechanism from
source evidence without a CWE hint. Stage 3 joins samples with
`data/ground_true/sven_test.jsonl` by default to display ground truth and
calculate metrics. Stage 1 can optionally be supplied with `--stage1` for
candidate metadata; its CWE field is not sent to either prompt.

## Requirements

Install Python dependencies with `python -m pip install -r requirements.txt`.
Stage 2 requires CodeBadger/Joern at `http://localhost:4242/mcp` by default.
Stage 3 requires an API key for the selected provider. OpenRouter is the
default; set `OPENROUTER_API_KEY`, or select DeepSeek and set
`TRIAGE_API_KEY`/`DEEPSEEK_API_KEY`. Generic OpenAI-compatible endpoints use
`TRIAGE_PROVIDER=openai-compatible`, `TRIAGE_BASE_URL`, `TRIAGE_API_KEY`, and
`TRIAGE_MODEL`; set the base URL through `/v1` (the runner appends
`/chat/completions`). This provider uses JSON-object response mode and does not
require OpenRouter-specific key/model preflight endpoints.

## Run Stage 2

```powershell
python run_context.py `
  --data <path-to-re-downloaded-sven-source.jsonl> `
  --results data/sven_100pairs_stage1.jsonl
```

By default the result is written to
`outputs/runs/<timestamp>/stage2.jsonl`. The timestamp uses local time and
includes microseconds so separate runs get separate directories. You can pass
`--output` to choose a specific path.

## Run Stage 3

```powershell
python run_triage.py
```

This uses `data/sven_100pairs_stage2.jsonl` and
`data/ground_true/sven_test.jsonl` by default; only identities present in Stage
2 are selected. Stage 1 is optional because Stage 2 packets carry the sink
snapshots. Use `--dry-run` to check artifact coverage without calling the
model API. Pass another labeled source/oracle dataset with `--data` if needed.
Stage 1 can optionally be supplied with `--stage1`.

By default the result and `summary.json` are written to
`outputs/runs/<timestamp>/`. The terminal shows a progress bar and colored
prediction, ground truth, CWE, and status fields. Summary metrics are computed
over rows with known ground truth.
