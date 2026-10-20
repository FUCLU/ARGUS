from pathlib import Path

from argus.stage3 import protocol, runner

ROOT = Path(__file__).resolve().parents[1]
STAGE2 = ROOT / "data" / "fixtures" / "stage2.jsonl"
ORACLE = ROOT / "data" / "fixtures" / "sven_test_oracle.jsonl"


def _candidates():
    stage2 = runner.latest_by_identity(runner.read_jsonl(STAGE2), "Stage 2")
    oracle = runner.unique_index(runner.read_json_document(ORACLE), "oracle")
    for key, row in stage2.items():
        by_rank = {c.get("sink_rank"): c for c in row.get("contexts") or []}
        for rank, cand in enumerate(runner._stage1_from_stage2(row)["sink_candidates"], 1):
            yield runner.prepare_candidate(oracle[key], cand, by_rank.get(rank), rank)


def test_fixture_candidate_counts():
    results = list(_candidates())
    ready = [prepared for prepared, failure in results if failure is None]
    assert len(results) == 472
    assert len(ready) == 461


def test_no_label_or_cwe_in_prompt():
    prepared, _ = next(r for r in _candidates() if r[1] is None)
    for prompt in (protocol.prosecutor_prompt(prepared), protocol.defender_prompt(prepared)):
        for leaked in ("ground_truth", "VULNERABLE_LABEL", "sven_test_pair"):
            assert leaked not in prompt


def test_raw_source_is_not_sent_when_context_missing():
    failures = [f for _, f in _candidates() if f is not None]
    assert failures and all(f["status"] == "invalid_candidate_or_context" for f in failures)
