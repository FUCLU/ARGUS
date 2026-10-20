import json
from pathlib import Path

from argus.stage3 import protocol, runner

ROOT = Path(__file__).resolve().parents[1]
STAGE2 = ROOT / "data" / "fixtures" / "stage2.jsonl"
ORACLE = ROOT / "data" / "fixtures" / "sven_test_oracle.jsonl"


def _first_ready():
    stage2 = runner.latest_by_identity(runner.read_jsonl(STAGE2), "Stage 2")
    oracle = runner.unique_index(runner.read_json_document(ORACLE), "oracle")
    for key, row in stage2.items():
        by_rank = {c.get("sink_rank"): c for c in row.get("contexts") or []}
        for rank, cand in enumerate(runner._stage1_from_stage2(row)["sink_candidates"], 1):
            prepared, failure = runner.prepare_candidate(oracle[key], cand, by_rank.get(rank), rank)
            if failure is None:
                return prepared
    raise AssertionError("no ready candidate in fixture")


class ScriptedAPI:
    """Answers by role (first prompt line) and records every prompt."""

    def __init__(self, adjudicator_verdict="VULNERABLE", sink_line=1):
        self.prompts = []
        self.adjudicator_verdict = adjudicator_verdict
        self.sink_line = sink_line

    def completion(self, messages, schema):
        prompt = messages[0]["content"]
        self.prompts.append(prompt)
        if prompt.startswith("You are the Prosecutor"):
            body = {
                "claim_status": "INSUFFICIENT_EVIDENCE",
                "hypothesis_condition": "The context does not establish the unsafe value.",
                "trigger_path": [], "accused_unguarded_positions": [], "assumptions": [],
                "not_applicable_evidence_lines": [], "actual_sink_line": self.sink_line,
                "candidate_status": "VALID",
            }
        elif prompt.startswith("You are the Defender"):
            body = {"full_slice_reviewed": True, "counter_evidence": [{
                "kind": "BOUNDS_CHECK", "explanation": "a bound",
                "evidence": [{"line": self.sink_line}]}]}
        else:
            body = {"prosecutor_claim_supported": False, "defender_evidence_effective": False,
                    "verdict": self.adjudicator_verdict, "reason": "decided from the context",
                    "evidence_lines": [self.sink_line]}
        return {"choices": [{"message": {"content": json.dumps(body)}}]}


def test_independent_analyses_then_single_adjudication():
    row = _first_ready()
    api = ScriptedAPI(sink_line=row["sink_line"])
    result = protocol.ValidationEngine(api).process(row)
    roles = [p.split(" in an")[0] for p in api.prompts]
    assert roles == ["You are the Prosecutor", "You are the Defender", "You are the Adjudicator"]
    prosecutor_prompt, defender_prompt, adjudicator_prompt = api.prompts
    assert "INSUFFICIENT_EVIDENCE" not in defender_prompt.split("Sink expression:")[1]
    assert "counter_evidence" not in prosecutor_prompt.split("Sink expression:")[1]
    assert "Prosecutor analysis (P_i):" in adjudicator_prompt and "BOUNDS_CHECK" in adjudicator_prompt
    assert result["prediction"] == "VULNERABLE" and result["run_status"] == "completed"
    assert result["prosecutor"] and result["defender"] and result["adjudicator"]


def test_verdict_is_the_adjudicators_not_forced_by_the_analyses():
    row = _first_ready()
    result = protocol.ValidationEngine(ScriptedAPI("BENIGN", row["sink_line"])).process(row)
    assert result["prediction"] == "BENIGN" and result["triage_status"] == "CONFIRMED_BENIGN"


def test_citation_outside_context_is_invalid():
    row = _first_ready()
    result = protocol.ValidationEngine(ScriptedAPI(sink_line=row["sink_line"])).process(
        dict(row, input="x"))
    assert result["prediction"] is None and result["run_status"] == "error"


def test_insufficient_claim_with_stray_fields_is_normalized_not_rejected():
    row = _first_ready()

    class StrayAPI(ScriptedAPI):
        def completion(self, messages, schema):
            response = super().completion(messages, schema)
            if messages[0]["content"].startswith("You are the Prosecutor"):
                body = json.loads(response["choices"][0]["message"]["content"])
                body["trigger_path"] = [{"line": self.sink_line, "claim": "stray"}]
                body["assumptions"] = [{"assumption": "stray", "path_critical": True}]
                body["candidate_status"] = "MISLOCATED"
                response = {"choices": [{"message": {"content": json.dumps(body)}}]}
            return response

    result = protocol.ValidationEngine(StrayAPI(sink_line=row["sink_line"])).process(row)
    assert result["prediction"] in {"VULNERABLE", "BENIGN"}
    assert result["prosecutor"]["trigger_path"] == []
    assert result["protocol_status"] == "REPAIRED"
