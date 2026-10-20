from __future__ import annotations

import json
import hashlib
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from ..io import append_jsonl, timestamped_run_output
from .client import DeepSeek, FatalAPIError, OpenAICompatible, OpenRouter, STAGE_SETTINGS
from .protocol import (
    ABPEngine,
    PROTOCOL,
    candidate_status,
    configure_prompt_templates,
    sanitize_sink,
)


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(source)
    rows = []
    for line_number, line in enumerate(source.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError(f"{source}:{line_number}: expected one JSON object")
        rows.append(row)
    return rows


def read_json_document(path: str | Path) -> list[dict[str, Any]]:
    """Read either a JSON array/object or JSONL source dataset."""
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(source)
    text = source.read_text(encoding="utf-8-sig")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return read_jsonl(source)
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list) or any(not isinstance(row, dict) for row in payload):
        raise ValueError(f"{source}: expected a JSON array of objects or JSONL objects")
    return payload


def identity(row: dict[str, Any], origin: str) -> tuple[str, Any]:
    sample_id = row.get("sample_id")
    if not isinstance(sample_id, str) or not sample_id.strip():
        raise ValueError(f"{origin}: sample_id must be a non-empty string")
    if row.get("idx") is None:
        raise ValueError(f"{origin} {sample_id}: idx is required for artifact joins")
    return sample_id, row["idx"]


def unique_index(rows: list[dict[str, Any]], origin: str) -> dict[tuple[str, Any], dict[str, Any]]:
    indexed: dict[tuple[str, Any], dict[str, Any]] = {}
    for row in rows:
        key = identity(row, origin)
        if key in indexed:
            raise ValueError(f"{origin}: duplicate identity {key!r}")
        indexed[key] = row
    return indexed


def latest_results(
    rows: list[dict[str, Any]],
    origin: str,
    successful_statuses: set[str],
) -> dict[tuple[str, Any], dict[str, Any]]:
    latest: dict[tuple[str, Any], dict[str, Any]] = {}
    successful: dict[tuple[str, Any], dict[str, Any]] = {}
    for row in rows:
        key = identity(row, origin)
        latest[key] = row
        if row.get("status") in successful_statuses:
            successful[key] = row
    for key, row in latest.items():
        if key not in successful:
            successful[key] = row
    return successful


def latest_by_identity(rows: list[dict[str, Any]], origin: str) -> dict[tuple[str, Any], dict[str, Any]]:
    """Keep the last artifact row per sample without interpreting its status field."""
    latest: dict[tuple[str, Any], dict[str, Any]] = {}
    for row in rows:
        latest[identity(row, origin)] = row
    return latest


def _ground_truth(row: dict[str, Any]) -> str | None:
    for key in ("ground_truth", "groundtrue", "oracle", "label", "target", "is_vulnerable", "vulnerable"):
        if key not in row:
            continue
        value = row[key]
        if isinstance(value, bool):
            return "VULNERABLE" if value else "BENIGN"
        if isinstance(value, (int, float)) and value in (0, 1):
            return "VULNERABLE" if value == 1 else "BENIGN"
        text = str(value).strip().lower()
        if text in {"1", "vul", "vulnerable", "positive", "true", "yes"}:
            return "VULNERABLE"
        if text in {"0", "benign", "safe", "negative", "false", "no"}:
            return "BENIGN"
    return None


def normalize_direct_source_rows(rows: list[dict[str, Any]], origin: str) -> list[dict[str, Any]]:
    """Map raw code/label records into the Stage 3 direct-source contract."""
    normalized = []
    for idx, row in enumerate(rows):
        code = row.get("input")
        if not isinstance(code, str) or not code.strip():
            raise ValueError(f"{origin} row {idx}: input must contain source code")
        label = _ground_truth({"label": row.get("output")})
        if label is None:
            raise ValueError(f"{origin} row {idx}: output must be BENIGN or VULNERABLE")
        file_name = str(row.get("file_name") or f"sample_{idx:06d}")
        dataset = str(row.get("dataset") or "direct-source")
        normalized.append({
            "sample_id": f"{dataset}:{file_name}:{idx}",
            "idx": idx,
            "pair_id": row.get("pair_id"),
            "dataset": dataset,
            "file_name": file_name,
            "func": code,
            "ground_truth": label,
            "ground_truth_cwe": _ground_truth_cwe(row),
            "_direct_source_mode": True,
        })
    unique_index(normalized, f"{origin} normalized direct-source dataset")
    return normalized


def _ground_truth_cwe(row: dict[str, Any]) -> str | None:
    for key in ("cwe", "CWE", "ground_truth_cwe"):
        value = row.get(key)
        if value is None or value == "":
            continue
        if isinstance(value, (list, tuple, set)):
            values = sorted({str(item).strip() for item in value if str(item).strip()})
            return ", ".join(values) if values else None
        return str(value).strip()
    return None


def _source_from_contexts(sample_id: str, idx: Any, stage2: dict[str, Any] | None) -> dict[str, Any]:
    """Rebuild the source lines present in Stage 2 packets when raw input is absent."""
    mapped: dict[int, str] = {}
    location = re.compile(r"\[([^\]\r\n]+):([1-9][0-9]*)\] (.*)")
    for context in (stage2 or {}).get("contexts") or []:
        if not isinstance(context, dict) or not isinstance(context.get("anchor"), dict):
            continue
        anchor = context["anchor"]
        file_name, anchor_line, input_line = anchor.get("file_name"), anchor.get("line"), anchor.get("input_line")
        if not isinstance(file_name, str) or type(anchor_line) is not int or type(input_line) is not int:
            continue
        for line in str(context.get("compact_code") or "").splitlines():
            match = location.fullmatch(line)
            if match and match.group(1) == file_name:
                source_line = input_line + int(match.group(2)) - anchor_line
                if source_line > 0:
                    mapped[source_line] = match.group(3)
    if not mapped:
        return {"sample_id": sample_id, "idx": idx, "func": "", "ground_truth": None}
    source_lines = [""] * max(mapped)
    for line, code in mapped.items():
        source_lines[line - 1] = code
    return {"sample_id": sample_id, "idx": idx, "func": "\n".join(source_lines), "ground_truth": None}


def _stage1_from_stage2(stage2: dict[str, Any]) -> dict[str, Any]:
    """Recover Stage 1 candidate snapshots embedded in Stage 2 context packets."""
    contexts = [row for row in stage2.get("contexts", []) if isinstance(row, dict)]
    contexts.sort(key=lambda row: row.get("sink_rank") if type(row.get("sink_rank")) is int else 10**9)
    stats = stage2.get("stats") if isinstance(stage2.get("stats"), dict) else {}
    expected_count = stats.get("candidate_count")
    candidates = []
    for context in contexts:
        sink = context.get("sink")
        if not isinstance(sink, dict):
            continue
        candidate = dict(sink)
        if context.get("cwe") is not None:
            candidate.setdefault("cwe", context.get("cwe"))
        candidates.append(candidate)
    if type(expected_count) is int and expected_count > len(candidates):
        candidates.extend({} for _ in range(expected_count - len(candidates)))
    no_candidates = expected_count == 0
    return {
        "sample_id": stage2["sample_id"],
        "idx": stage2["idx"],
        "status": "ok" if no_candidates or candidates else "missing_candidates",
        "sink_candidates": candidates,
    }


def _candidate_signature(candidate: dict[str, Any]) -> tuple[Any, ...]:
    start = candidate.get("line_start")
    end = candidate.get("line_end", start)
    return (
        start,
        end,
        " ".join(str(candidate.get("expression", "")).split()),
        " ".join(str(candidate.get("operation_type", "")).split()),
    )


def _call_entry_label(entry: dict[str, Any]) -> str | None:
    relation = str(entry.get("relation", ""))
    if relation not in {"caller", "callee"}:
        return None
    name = str(entry.get("name", "")).strip() or "unknown"
    hop = max(1, int(entry.get("hop", 1) or 1))
    suffix = f" (hop {hop})" if hop > 1 else ""
    return f"{relation} {name}{suffix}:"


def _augment_legacy_call_context(compact_code: str, context: dict[str, Any]) -> str:
    """Insert structured caller/callee bodies omitted by older compact renderers."""
    source_location = re.compile(r"\[([^\]\r\n]+):([1-9][0-9]*)\] (.*)")
    lines = compact_code.splitlines()
    existing = {
        (match.group(1), int(match.group(2)), match.group(3))
        for line in lines
        if (match := source_location.fullmatch(line)) is not None
    }
    budget = context.get("context_line_budget", 120)
    budget = budget if type(budget) is int and budget > 0 else 120
    remaining = max(0, budget - len(existing))
    additions: dict[str, list[str]] = {}
    for entry in context.get("call_context") or []:
        if not isinstance(entry, dict):
            continue
        label = _call_entry_label(entry)
        if label is None:
            continue
        for statement in entry.get("statements") or []:
            if remaining <= 0 or not isinstance(statement, dict):
                break
            file_name = str(statement.get("file_name", ""))
            line = statement.get("line")
            code = str(statement.get("code", ""))
            key = (file_name, line, code)
            if not file_name or type(line) is not int or line < 1 or key in existing:
                continue
            additions.setdefault(label, []).append(f"[{file_name}:{line}] {code}")
            existing.add(key)
            remaining -= 1
    if not additions:
        return compact_code

    rendered: list[str] = []
    inserted: set[str] = set()
    for line in lines:
        rendered.append(line)
        if line in additions and line not in inserted:
            rendered.extend(additions[line])
            inserted.add(line)
    pending = [label for label in additions if label not in inserted]
    if pending:
        if rendered and rendered[-1] != "":
            rendered.append("")
        rendered.append("[CALL CONTEXT]")
        for label in pending:
            rendered.append(label)
            rendered.extend(additions[label])
    return "\n".join(rendered)


def context_prompt_code(
    source_code: str,
    candidate: dict[str, Any],
    context: dict[str, Any],
) -> str:
    """Validate Stage 2 compact_code and add original-input citations."""
    source_lines = source_code.splitlines()
    if not 1 <= candidate["line_start"] <= candidate["line_end"] <= len(source_lines):
        raise ValueError("sink span is outside the processed source")
    compact_code = context.get("compact_code")
    anchor = context.get("anchor")
    if not isinstance(compact_code, str) or not compact_code.strip():
        # Recover unresolved Stage 2 anchors from the original function text.
        # This remains source-grounded and keeps the sink plus related operand
        # lines inside the packet's normal line budget.
        budget = context.get("context_line_budget", 120)
        budget = budget if type(budget) is int and budget > 0 else 120
        sink_lines = set(range(candidate["line_start"], candidate["line_end"] + 1))
        if len(sink_lines) > budget:
            raise ValueError("sink span exceeds the source fallback context budget")
        identifiers = set(re.findall(
            r"[A-Za-z_][A-Za-z0-9_]*", candidate.get("expression", "")
        ))
        center = (candidate["line_start"] + candidate["line_end"]) // 2
        other_lines = [line for line in range(1, len(source_lines) + 1) if line not in sink_lines]
        other_lines.sort(key=lambda line: (
            0 if identifiers.intersection(re.findall(
                r"[A-Za-z_][A-Za-z0-9_]*", source_lines[line - 1]
            )) else 1,
            abs(line - center),
            line,
        ))
        selected = sink_lines | set(other_lines[:max(0, budget - len(sink_lines))])
        file_name = (
            anchor.get("file_name") if isinstance(anchor, dict) else None
        ) or "processed_function"
        rendered = ["[SINK]"]
        for line in sorted(sink_lines):
            rendered.append(f"L{line}: [{file_name}:{line}] {source_lines[line - 1]}")
        rendered.append("[FUNCTION SOURCE FALLBACK]")
        for line in sorted(selected - sink_lines):
            rendered.append(f"L{line}: [{file_name}:{line}] {source_lines[line - 1]}")
        return "\n".join(rendered)
    compact_code = _augment_legacy_call_context(compact_code, context)
    if not isinstance(anchor, dict) or not isinstance(anchor.get("file_name"), str):
        raise ValueError("Stage 2 packet has no source anchor for compact_code")
    if type(anchor.get("line")) is not int or type(anchor.get("input_line")) is not int:
        raise ValueError("Stage 2 anchor has no valid line mapping")

    section_headers = {
        "[SINK]",
        "[CONTROL GUARDS]",
        "[BACKWARD DATA FLOW]",
        "[SYMBOL CONTEXT]",
        "[CALL CONTEXT]",
        "[FORWARD DATA FLOW]",
    }
    call_label = re.compile(r"(?:call site|caller .+|callee .+|unresolved call .+):")
    source_location = re.compile(r"\[([^\]\r\n]+):([1-9][0-9]*)\] (.*)")
    call_evidence = {
        (
            str(statement.get("file_name", "")),
            int(statement.get("line", -1)),
            str(statement.get("code", "")),
        )
        for entry in context.get("call_context") or []
        if isinstance(entry, dict)
        for statement in entry.get("statements") or []
        if isinstance(statement, dict)
    }
    selected: set[int] = set()
    selected_locations: set[tuple[str, int]] = set()
    sink_lines: set[int] = set()
    next_virtual_line = len(source_lines) + 1
    current_section: str | None = None
    saw_sink_section = False
    rendered = []
    for compact_line in compact_code.splitlines():
        if compact_line in section_headers:
            current_section = compact_line
            saw_sink_section = saw_sink_section or compact_line == "[SINK]"
            rendered.append(compact_line)
            continue
        if compact_line == "":
            rendered.append(compact_line)
            continue
        if current_section == "[CALL CONTEXT]" and call_label.fullmatch(compact_line):
            rendered.append(compact_line)
            continue
        match = source_location.fullmatch(compact_line)
        if match is None or current_section is None:
            raise ValueError("Stage 2 compact_code has an invalid source location or metadata line")
        file_name = match.group(1)
        local_line = int(match.group(2))
        code = match.group(3)
        location = (file_name, local_line)
        if location in selected_locations:
            raise ValueError("Stage 2 compact_code repeats a source line")
        selected_locations.add(location)

        input_line = anchor["input_line"] + local_line - anchor["line"]
        is_target_statement = (
            file_name == anchor["file_name"]
            and 1 <= input_line <= len(source_lines)
            and source_lines[input_line - 1] == code
        )
        if is_target_statement:
            citation_line = input_line
        else:
            if current_section != "[CALL CONTEXT]" or (file_name, local_line, code) not in call_evidence:
                if file_name == anchor["file_name"]:
                    raise ValueError("Stage 2 compact_code does not match the processed source")
                raise ValueError("Stage 2 compact_code statement is not backed by Stage 2 call_context")
            citation_line = next_virtual_line
            next_virtual_line += 1
        if citation_line in selected:
            raise ValueError("Stage 2 compact_code repeats a citation line")
        selected.add(citation_line)
        if current_section == "[SINK]":
            if not is_target_statement:
                raise ValueError("Stage 2 SINK section must map to the processed source")
            sink_lines.add(citation_line)
        rendered.append(f"L{citation_line}: {compact_line}")
    if not saw_sink_section:
        raise ValueError("Stage 2 compact_code has no SINK section")
    if not set(range(candidate["line_start"], candidate["line_end"] + 1)) <= sink_lines:
        raise ValueError("Stage 2 compact_code does not contain the candidate sink in its SINK section")
    return "\n".join(rendered)


def source_view_for_context(source_code: str, prompt_code: str) -> str:
    """Build the ABP citation view, including virtual call-evidence lines."""
    source_lines = source_code.splitlines()
    evidence_line = re.compile(r"(?m)^L([1-9][0-9]*): \[[^\]\r\n]+:[1-9][0-9]*\] (.*)$")
    evidence = {int(match.group(1)): match.group(2) for match in evidence_line.finditer(prompt_code)}
    if not evidence:
        raise ValueError("Stage 2 context has no valid original input line mapping")
    lines = [""] * max(len(source_lines), max(evidence))
    for line, code in evidence.items():
        if line <= len(source_lines):
            if source_lines[line - 1] != code:
                raise ValueError("Stage 2 target citation differs from the processed source")
            lines[line - 1] = source_lines[line - 1]
        else:
            lines[line - 1] = code
    return "\n".join(lines)


def prepare_candidate(
    source: dict[str, Any],
    candidate: dict[str, Any],
    context: dict[str, Any] | None,
    rank: int,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    snapshot = {
        "line_start": candidate.get("line_start"),
        "line_end": candidate.get("line_end", candidate.get("line_start")),
        "expression": candidate.get("expression", ""),
        "operation_type": candidate.get("operation_type", ""),
    }
    if context is None:
        return None, {
            "sink_rank": rank,
            "sink": snapshot,
            "status": "context_missing",
            "error": "Stage 2 has no context packet for this sink_rank",
        }
    context_sink = context.get("sink")
    if not isinstance(context_sink, dict) or _candidate_signature(snapshot) != _candidate_signature(context_sink):
        return None, {
            "sink_rank": rank,
            "sink": snapshot,
            "status": "join_mismatch",
            "error": "Stage 1 candidate does not match Stage 2 sink snapshot",
        }
    try:
        code = source.get("func")
        if not isinstance(code, str) or not code.strip():
            raise ValueError("processed source row is missing func")
        model_sink = sanitize_sink(candidate)
        cwe_candidate = candidate.get("cwe")
        rendered_context = context_prompt_code(code, model_sink, context)
        validation_view = source_view_for_context(code, rendered_context)
        assessment_input = {
            "dataset": source.get("dataset") or "benchmark",
            "id": source["sample_id"],
            "input": validation_view,
            "prompt_code": rendered_context,
            "model_sink": model_sink,
            "sink_line": model_sink["line_start"],
            "candidate_status": candidate_status(code, model_sink),
            "cwe_candidate": cwe_candidate,
        }
    except (TypeError, ValueError) as exc:
        return None, {
            "sink_rank": rank,
            "sink": snapshot,
            "status": "invalid_candidate_or_context",
            "error": str(exc),
        }
    return assessment_input, None


def assess_candidate(engine: ABPEngine, assessment_input: dict[str, Any], rank: int, sink: dict[str, Any]) -> dict[str, Any]:
    result = engine.process(assessment_input)
    return {
        "sink_rank": rank,
        "sink": sink,
        "cwe_candidate": assessment_input["cwe_candidate"],
        "status": result.get("run_status"),
        "prediction": result.get("prediction"),
        "triage_status": result.get("triage_status"),
        "protocol_status": result.get("protocol_status"),
        "round_count": result.get("round_count"),
        "completed_rounds": result.get("completed_rounds"),
        "vulnerable_votes": result.get("vulnerable_votes"),
        "benign_votes": result.get("benign_votes"),
        "confidence": result.get("confidence"),
        "rounds": result.get("rounds", []),
        "error": result.get("error"),
    }


def _aggregate(candidate_results: list[dict[str, Any]], expected_count: int) -> tuple[str | None, str, str]:
    vulnerable = [row for row in candidate_results if row.get("prediction") == "VULNERABLE"]
    if vulnerable:
        prediction = "VULNERABLE"
        all_assessed = (
            len(candidate_results) == expected_count
            and all(row.get("prediction") in {"VULNERABLE", "BENIGN"} for row in candidate_results)
        )
        return (
            prediction,
            "CONFIRMED_VULNERABLE" if all_assessed else "INCOMPLETE",
            "completed" if all_assessed else "partial",
        )

    benign = [row for row in candidate_results if row.get("prediction") == "BENIGN"]
    all_benign = (
        expected_count > 0
        and len(benign) == expected_count
        and len(candidate_results) == expected_count
    )
    if all_benign:
        return "BENIGN", "CONFIRMED_BENIGN", "completed"

    if not candidate_results:
        return None, "UNAVAILABLE", "error"
    if any(row.get("status") == "error" for row in candidate_results):
        return None, "OPERATIONAL_ERROR", "error"
    return None, "INCOMPLETE", "partial" if benign else "error"


def _process_direct_source(source: dict[str, Any], engine: ABPEngine | None) -> dict[str, Any]:
    """Run the Stage 3 protocol over a complete function without Stage 1/2 artifacts."""
    sample_id, idx = source["sample_id"], source["idx"]
    code = source["func"]
    lines = code.splitlines()
    file_name = source.get("file_name") or sample_id
    base = {
        "sample_id": sample_id,
        "idx": idx,
        "pair_id": source.get("pair_id"),
        "ground_truth": _ground_truth(source),
        "ground_truth_cwe": _ground_truth_cwe(source),
        "analysis_mode": "direct_source",
    }
    marker_sink = {
        "line_start": 1,
        "line_end": max(1, len(lines)),
        "expression": "full-function review; identify a concrete operation to audit",
        "operation_type": "whole_function_review",
    }
    prompt_code = "[FULL FUNCTION SOURCE]\n" + "\n".join(
        f"L{line}: [{file_name}:{line}] {text}"
        for line, text in enumerate(lines, 1)
    )
    if engine is None:
        return {
            **base, "status": "error", "run_status": "error", "prediction": None,
            "triage_status": "UNAVAILABLE", "candidate_count": 1,
            "assessed_candidate_count": 0, "candidate_results": [],
            "errors": ["ABP client is not configured"],
        }
    assessment_input = {
        "dataset": source.get("dataset") or "direct-source",
        "id": sample_id,
        "input": code,
        "prompt_code": prompt_code,
        "model_sink": marker_sink,
        "sink_line": None,
        "candidate_status": "VALID",
        "cwe_candidate": None,
        "direct_source_mode": True,
    }
    result = engine.process(assessment_input)
    prediction = result.get("prediction")
    candidate_result = {
        "sink_rank": 1,
        "sink": marker_sink,
        "analysis_scope": "full function; model selects the operation to audit",
        "status": result.get("run_status"),
        "prediction": prediction,
        "triage_status": result.get("triage_status"),
        "protocol_status": result.get("protocol_status"),
        "round_count": result.get("round_count"),
        "completed_rounds": result.get("completed_rounds"),
        "vulnerable_votes": result.get("vulnerable_votes"),
        "benign_votes": result.get("benign_votes"),
        "confidence": result.get("confidence"),
        "rounds": result.get("rounds", []),
        "error": result.get("error"),
    }
    completed = prediction in {"VULNERABLE", "BENIGN"}
    return {
        **base,
        "protocol": PROTOCOL,
        "status": "ok" if completed else "error",
        "run_status": result.get("run_status"),
        "prediction": prediction,
        "binary_prediction": prediction,
        "triage_status": result.get("triage_status"),
        "candidate_count": 1,
        "assessed_candidate_count": int(completed),
        "candidate_results": [candidate_result],
        "errors": [result["error"]] if result.get("error") else [],
    }


def pair_consistency_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Evaluate complete vulnerable/fixed pairs by pair_id (or sample_id suffix)."""
    pairs: dict[str, dict[str, dict[str, Any]]] = {}
    for row in rows:
        pair_id = row.get("pair_id")
        if not pair_id:
            sample_id = str(row.get("sample_id") or "")
            if sample_id.endswith("_vul") or sample_id.endswith("_fix"):
                pair_id = sample_id[:-4]
        if not pair_id:
            continue
        side = "vul" if row.get("ground_truth") == "VULNERABLE" else (
            "fix" if row.get("ground_truth") == "BENIGN" else None
        )
        if side:
            pairs.setdefault(str(pair_id), {})[side] = row

    complete_pairs = [pair for pair in pairs.values() if "vul" in pair and "fix" in pair]
    total = len(complete_pairs)
    both_correct = sum(
        pair["vul"].get("prediction") == "VULNERABLE"
        and pair["fix"].get("prediction") == "BENIGN"
        for pair in complete_pairs
    )
    vulnerable_detected = sum(
        pair["vul"].get("prediction") == "VULNERABLE"
        for pair in complete_pairs
    )
    fixes_false_alarm = sum(
        pair["fix"].get("prediction") == "VULNERABLE"
        for pair in complete_pairs
    )
    ratio = lambda numerator, denominator: numerator / denominator if denominator else None
    return {
        "complete_pairs": total,
        "both_correct": both_correct,
        "pair_accuracy": ratio(both_correct, total),
        "vulnerable_recall": ratio(vulnerable_detected, total),
        "fix_false_alarm_rate": ratio(fixes_false_alarm, total),
        "incomplete_pairs": len(pairs) - total,
    }


def process_sample(
    source: dict[str, Any],
    stage1: dict[str, Any] | None,
    stage2: dict[str, Any] | None,
    engine: ABPEngine | None,
) -> dict[str, Any]:
    sample_id, idx = source["sample_id"], source["idx"]
    base = {
        "sample_id": sample_id,
        "idx": idx,
        "pair_id": source.get("pair_id"),
        "ground_truth": _ground_truth(source),
        "ground_truth_cwe": _ground_truth_cwe(source),
    }
    if source.get("_direct_source_mode"):
        return _process_direct_source(source, engine)
    if stage1 is None:
        return {**base, "status": "error", "run_status": "error", "prediction": None,
                "triage_status": "UNAVAILABLE", "candidate_results": [],
                "errors": ["missing Stage 1 result"]}
    if stage1.get("status") != "ok":
        return {**base, "status": "error", "run_status": "error", "prediction": None,
                "triage_status": "UNAVAILABLE", "candidate_results": [],
                "errors": [f"Stage 1 status={stage1.get('status')}"]}

    candidates = stage1.get("sink_candidates") or []
    if not candidates:
        return {**base, "status": "no_candidates", "run_status": "no_candidates",
                "prediction": "BENIGN", "binary_prediction": "BENIGN",
                "triage_status": "NO_CANDIDATES",
                "candidate_results": [], "candidate_count": 0,
                "assessed_candidate_count": 0, "errors": []}

    if stage2 is None:
        candidate_results = [{
            "sink_rank": rank,
            "sink": {key: candidate.get(key) for key in (
                "line_start", "line_end", "expression", "operation_type")},
            "status": "context_missing",
            "error": "missing Stage 2 result",
        } for rank, candidate in enumerate(candidates, 1)]
    elif stage2.get("idx") != idx:
        candidate_results = [{
            "sink_rank": rank,
            "sink": {key: candidate.get(key) for key in (
                "line_start", "line_end", "expression", "operation_type")},
            "status": "join_mismatch",
            "error": f"source/Stage 2 idx mismatch: source={idx!r}, stage2={stage2.get('idx')!r}",
        } for rank, candidate in enumerate(candidates, 1)]
    else:
        contexts = stage2.get("contexts") or []
        contexts_by_rank: dict[int, dict[str, Any]] = {}
        duplicate_ranks: set[int] = set()
        malformed_context_count = 0
        for context in contexts:
            rank = context.get("sink_rank") if isinstance(context, dict) else None
            if type(rank) is not int or rank < 1:
                malformed_context_count += 1
                continue
            if rank in contexts_by_rank:
                duplicate_ranks.add(rank)
            contexts_by_rank[rank] = context

        extra_context_ranks = sorted(rank for rank in contexts_by_rank if rank > len(candidates))

        candidate_results = []
        for rank, candidate in enumerate(candidates, 1):
            snapshot = {key: candidate.get(key) for key in (
                "line_start", "line_end", "expression", "operation_type")}
            if rank in duplicate_ranks:
                candidate_results.append({
                    "sink_rank": rank, "sink": snapshot,
                    "status": "join_mismatch", "error": "Stage 2 contains duplicate sink_rank",
                })
                continue
            prepared, failure = prepare_candidate(
                source, candidate, contexts_by_rank.get(rank), rank
            )
            if failure is not None:
                candidate_results.append(failure)
                continue
            if engine is None:
                candidate_results.append({
                    "sink_rank": rank, "sink": snapshot,
                    "status": "not_run", "error": "ABP client is not configured",
                })
                continue
            candidate_results.append(assess_candidate(engine, prepared, rank, snapshot))

        if extra_context_ranks:
            for extra_rank in extra_context_ranks:
                candidate_results.append({
                    "sink_rank": extra_rank,
                    "status": "join_mismatch",
                    "error": "Stage 2 rank has no matching Stage 1 candidate",
                })
        if malformed_context_count:
            candidate_results.append({
                "status": "join_mismatch",
                "error": f"Stage 2 contains {malformed_context_count} packet(s) with invalid sink_rank",
            })

    prediction, triage_status, run_status = _aggregate(candidate_results, len(candidates))
    completed = sum(row.get("prediction") in {"VULNERABLE", "BENIGN"} for row in candidate_results)
    errors = [
        f"candidate[{row.get('sink_rank')}]: {row['error']}"
        for row in candidate_results if row.get("error")
    ]
    return {
        **base,
        "protocol": PROTOCOL,
        "status": "ok" if run_status == "completed" else "partial" if completed else "error",
        "run_status": run_status,
        "prediction": prediction,
        "binary_prediction": prediction,
        "triage_status": triage_status,
        "candidate_count": len(candidates),
        "assessed_candidate_count": completed,
        "candidate_results": candidate_results,
        "errors": errors,
    }


def build_parser():
    import argparse

    prompt_root = Path(__file__).resolve().parents[2] / "prompts"
    parser = argparse.ArgumentParser(
        description="Run Stage 3 ABP triage over Stage 2 sink-context packets."
    )
    parser.add_argument(
        "--data", default="data/ground_true/sven_test.jsonl",
        help="Source/oracle JSON or JSONL (default: data/ground_true/sven_test.jsonl)",
    )
    parser.add_argument("--stage1", default=None, help="Optional Stage 1 sink-localization JSONL; candidates are read from Stage 2 when omitted")
    parser.add_argument("--stage2", default="data/sven_100pairs_stage2.jsonl", help="Stage 2 context JSONL")
    parser.add_argument("--protocol", choices=("abp", "compact", "sven-code-only"), default="abp",
                        help="Stage 3 protocol; compact audits Stage 2 evidence, sven-code-only analyzes reconstructed code strings")
    parser.add_argument("--code-only-mode", choices=("two-agent", "auditor-only"), default="two-agent",
                        help="Code-only comparison: Analyst plus Auditor, or Auditor with code only")
    parser.add_argument("--no-few-shot", action="store_true", help="Compact: omit the three synthetic prompt examples")
    parser.add_argument("--no-context-expansion", action="store_true", help="Compact: disable bounded local-source recovery")
    parser.add_argument("--compact-max-lines", type=int, default=400, help="Compact: maximum source lines in initial/expanded packet")
    parser.add_argument(
        "--direct-source", action="store_true",
        help="Read a JSON/JSONL dataset with input code and output ground-truth labels; bypass Stage 1/2",
    )
    parser.add_argument(
        "--output", default=None,
        help="Output JSONL (default: outputs/runs/<timestamp>/stage3.jsonl)",
    )
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--limit", type=int, default=0, help="0 = all remaining samples")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--provider",
        choices=("openrouter", "deepseek", "openai-compatible"),
        default=None,
        help="Model API provider (default: TRIAGE_PROVIDER or openrouter)",
    )
    parser.add_argument("--model", default=None, help="Override the provider's default model")
    parser.add_argument(
        "--prosecutor-prompt", default=str(prompt_root / "prosecutor.txt"),
        help="External Prosecutor prompt file",
    )
    parser.add_argument(
        "--defender-prompt", default=str(prompt_root / "defender.txt"),
        help="External Defender prompt file",
    )
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="Validate joins and report coverage without API calls")
    return parser


def run(args) -> None:
    if getattr(args, "protocol", "abp") == "sven-code-only":
        from .code_only_runner import run as run_code_only
        return run_code_only(args)
    if getattr(args, "protocol", "abp") == "compact":
        from .compact_runner import run as run_compact
        return run_compact(args)
    if args.start < 0 or args.limit < 0 or args.rounds < 1 or args.workers < 1:
        raise ValueError("start/limit must be non-negative; rounds/workers must be positive")
    provider = (
        getattr(args, "provider", None)
        or os.getenv("TRIAGE_PROVIDER", "openrouter")
    ).strip().lower()
    if provider not in {"openrouter", "deepseek", "openai-compatible"}:
        raise ValueError(f"unsupported triage provider: {provider}")
    model = getattr(args, "model", None)
    if model is None:
        if provider == "deepseek":
            model = (
                os.getenv("DEEPSEEK_TRIAGE_MODEL", "").strip()
                or os.getenv("SINK_MODEL", "").strip()
                or "deepseek-chat"
            )
        elif provider == "openai-compatible":
            model = os.getenv("TRIAGE_MODEL", "qwen3-32b").strip()
        else:
            model = os.getenv("TRIAGE_MODEL", "qwen/qwen3-32b").strip()
    model = model.strip()
    if not model:
        raise ValueError("model must be a non-empty string")
    prompt_files = configure_prompt_templates(
        getattr(args, "prosecutor_prompt", None),
        getattr(args, "defender_prompt", None),
    )
    prompt_digest = hashlib.sha256()
    for role in ("prosecutor", "defender"):
        prompt_digest.update(role.encode("utf-8"))
        prompt_digest.update(Path(prompt_files[role]).read_bytes())
    prompt_signature = prompt_digest.hexdigest()
    run_signature = hashlib.sha256(json.dumps({
        "protocol": PROTOCOL,
        "prompt_signature": prompt_signature,
        "provider": provider,
        "model": model,
        "rounds": args.rounds,
        "direct_source_mode": args.direct_source,
    }, sort_keys=True).encode("utf-8")).hexdigest()
    for settings in STAGE_SETTINGS.values():
        settings["model"] = model

    if args.direct_source:
        if not args.data:
            raise ValueError("--direct-source requires --data")
        raw_source_rows = read_json_document(args.data)
        source_rows = normalize_direct_source_rows(raw_source_rows, args.data)
        sources = {identity(row, "direct-source dataset"): row for row in source_rows}
        stage1_rows = {}
        stage2_rows = {}
    else:
        stage2_rows = latest_by_identity(read_jsonl(args.stage2), "Stage 2")
        stage1_rows = (
            latest_results(read_jsonl(args.stage1), "Stage 1", {"ok"})
            if args.stage1
            else {key: _stage1_from_stage2(row) for key, row in stage2_rows.items()}
        )
        if args.data:
            raw_source_rows = read_json_document(args.data)
            source_index = unique_index(raw_source_rows, "source/oracle dataset")
            sources = {
                key: source_index.get(key) or _source_from_contexts(key[0], key[1], row)
                for key, row in stage2_rows.items()
            }
        else:
            sources = {
                key: _source_from_contexts(key[0], key[1], row)
                for key, row in stage2_rows.items()
            }
            for key, source in sources.items():
                if key in stage1_rows:
                    source["ground_truth"] = _ground_truth(stage1_rows[key])

        source_rows = list(sources.values())
    selected_rows = source_rows[args.start:]
    if args.limit:
        selected_rows = selected_rows[:args.limit]

    output = Path(args.output) if args.output else timestamped_run_output("stage3")
    completed_keys: set[tuple[str, Any]] = set()
    if output.is_file() and not args.no_resume:
        for row in read_jsonl(output):
            key = identity(row, "Stage 3 output")
            if (
                row.get("protocol") == PROTOCOL
                and row.get("run_signature") == run_signature
                and row.get("run_status") in {"completed", "no_candidates"}
            ):
                completed_keys.add(key)

    work = []
    for source in selected_rows:
        key = identity(source, "processed dataset")
        if key in completed_keys:
            continue
        work.append((source, stage1_rows.get(key), stage2_rows.get(key)))

    if args.direct_source:
        processable = len(work)
    else:
        processable = 0
        for source, stage1, stage2 in work:
            if stage1 is None or stage2 is None:
                continue
            candidates = stage1.get("sink_candidates") or []
            by_rank = {
                context.get("sink_rank"): context
                for context in (stage2.get("contexts") or [])
                if isinstance(context, dict)
            }
            for rank, candidate in enumerate(candidates, 1):
                context = by_rank.get(rank)
                if context:
                    _, failure = prepare_candidate(source, candidate, context, rank)
                    if failure is None:
                        processable += 1

    print(json.dumps({
        "provider": provider,
        "model": model,
        "protocol": PROTOCOL,
        "prompt_signature": prompt_signature,
        "run_signature": run_signature,
        "prompt_files": prompt_files,
        "selected": len(selected_rows),
        "pending": len(work),
        "analysis_mode": "direct_source" if args.direct_source else "stage2_context",
        "candidate_artifact_rows_available": sum(stage1 is not None for _, stage1, _ in work),
        "stage2_rows_available": sum(stage2 is not None for _, _, stage2 in work),
        "candidate_contexts_ready": processable,
        "ground_truth_available": sum(_ground_truth(row) is not None for row in selected_rows),
        "model_input": ([
            "full function source from input",
            "single Prosecutor-selected operation per function",
        ] if args.direct_source else [
            "sink candidate snapshot copied from Stage 2",
            "Stage 2 compact_code",
            "source-backed Stage 2 call_context selected under the context budget",
        ]),
        "excluded_from_prompt": ["dataset label", "dataset CWE", "oracle", "patch metadata"],
        "dry_run": args.dry_run,
    }, indent=2))

    if args.dry_run:
        return

    api = None
    engine = None
    try:
        if processable:
            request_log = output.with_name("requests.jsonl")
            if provider == "openrouter":
                key = os.getenv("OPENROUTER_API_KEY", "").strip()
                if not key:
                    raise FatalAPIError("Set OPENROUTER_API_KEY")
                api = OpenRouter(key, request_log)
                api.auth_check()
                api.preflight()
            elif provider == "deepseek":
                key = (
                    os.getenv("TRIAGE_API_KEY", "").strip()
                    or os.getenv("DEEPSEEK_API_KEY", "").strip()
                    or os.getenv("SINK_API_KEY", "").strip()
                )
                if not key:
                    raise FatalAPIError(
                        "Set TRIAGE_API_KEY, DEEPSEEK_API_KEY, or SINK_API_KEY"
                    )
                base_url = (
                    os.getenv("DEEPSEEK_BASE_URL", "").strip()
                    or os.getenv("SINK_BASE_URL", "").strip()
                    or "https://api.deepseek.com"
                )
                api = DeepSeek(key, request_log, base_url=base_url)
            elif provider == "openai-compatible":
                key = os.getenv("TRIAGE_API_KEY", "").strip()
                if not key:
                    raise FatalAPIError("Set TRIAGE_API_KEY for the OpenAI-compatible endpoint")
                base_url = os.getenv("TRIAGE_BASE_URL", "").strip().rstrip("/")
                if not base_url:
                    raise FatalAPIError("Set TRIAGE_BASE_URL to the endpoint base, ending in /v1")
                api = OpenAICompatible(key, request_log, base_url=base_url)
            else:
                raise ValueError(f"unsupported triage provider: {provider}")
            append_jsonl(request_log, {
                "event": "run_config",
                "provider": provider,
                "model": model,
                "protocol": PROTOCOL,
                "prompt_signature": prompt_signature,
                "run_signature": run_signature,
                "rounds": args.rounds,
                "workers": args.workers,
                "prompt_files": prompt_files,
            })
            engine = ABPEngine(api, args.rounds)
        from tqdm.auto import tqdm
        results_by_key = {}
        pool = ThreadPoolExecutor(max_workers=args.workers)
        futures = {}
        progress = None
        try:
            for source, stage1, stage2 in work:
                future = pool.submit(process_sample, source, stage1, stage2, engine)
                futures[future] = source
            progress = tqdm(
                as_completed(futures), total=len(futures), desc="Stage 3",
                unit="sample", dynamic_ncols=True,
            )
            for future in progress:
                row = future.result()
                row["protocol"] = PROTOCOL
                row["prompt_signature"] = prompt_signature
                row["run_signature"] = run_signature
                append_jsonl(output, row)
                results_by_key[(row["sample_id"], row["idx"])] = row
                color = (lambda code, label: f"\033[{code}m{label}\033[0m") if sys.stdout.isatty() else (lambda code, label: label)
                fields = (
                    f"{color('35;1', 'PRED')}: {row.get('prediction') or 'N/A'}  "
                    f"{color('36;1', 'GT')}: {row.get('ground_truth') or 'N/A'}  "
                    f"{color('33;1', 'CWE')}: {row.get('ground_truth_cwe') or 'N/A'}  "
                    f"{color('32;1', 'STATUS')}: {row.get('run_status', 'N/A')}"
                )
                if row.get("errors"):
                    fields += f"  {color('31;1', 'ERROR')}: {'; '.join(row['errors'])}"
                tqdm.write(f"{row['sample_id']}  idx={row['idx']}\n  {fields}\n", file=sys.stdout)
        except KeyboardInterrupt:
            print("\nCtrl+C received. Cancelling queued samples and aborting active API requests...", flush=True)
            for future in futures:
                future.cancel()
            if api is not None:
                api.cancel()
            if progress is not None:
                progress.close()
            pool.shutdown(wait=False, cancel_futures=True)
            raise SystemExit(130)
        except BaseException:
            for future in futures:
                future.cancel()
            if api is not None:
                api.cancel()
            if progress is not None:
                progress.close()
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            if progress is not None:
                progress.close()
            pool.shutdown(wait=True)

        selected_keys = {identity(source, "selected dataset") for source in selected_rows}
        all_rows = {}
        if output.is_file():
            for row in read_jsonl(output):
                key = identity(row, "Stage 3 output")
                if (
                    key in selected_keys
                    and row.get("protocol") == PROTOCOL
                    and row.get("run_signature") == run_signature
                ):
                    all_rows[key] = row
        all_rows.update(results_by_key)
        counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
        categories = {
            ("VULNERABLE", "VULNERABLE"): "tp",
            ("BENIGN", "VULNERABLE"): "fp",
            ("VULNERABLE", "BENIGN"): "fn",
            ("BENIGN", "BENIGN"): "tn",
        }
        for row in all_rows.values():
            category = categories.get((row.get("ground_truth"), row.get("prediction")))
            if category:
                counts[category] += 1
        tp, fp, fn, tn = counts["tp"], counts["fp"], counts["fn"], counts["tn"]
        ratio = lambda numerator, denominator: numerator / denominator if denominator else None
        summary = {
            "samples": len(all_rows), "ground_truth_available": tp + fp + fn + tn,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
            "f1": ratio(2 * tp, 2 * tp + fp + fn),
            "fpr": ratio(fp, fp + tn), "accuracy": ratio(tp + tn, tp + fp + fn + tn),
        }
        summary_path = output.with_name("summary.json")
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print("\nStage 3 metrics")
        print(f"{'Metric':<12} {'Value':>10}")
        for name in ("precision", "recall", "f1", "fpr", "accuracy"):
            value = summary[name]
            print(f"{name.upper():<12} {'N/A' if value is None else f'{value:.4f}':>10}")
        print(f"{'GT samples':<12} {summary['ground_truth_available']:>10}")

        pair_metrics = pair_consistency_metrics(list(all_rows.values()))
        format_metric = lambda value: "N/A" if value is None else f"{value:.4f}"
        print("\nVulnerable–Fixed pair evaluation")
        print(f"{'Measure':<28} {'Value':>12}")
        print(f"{'Complete pairs':<28} {pair_metrics['complete_pairs']:>12}")
        print(f"{'Both labels correct':<28} {pair_metrics['both_correct']:>12}")
        print(f"{'Pair accuracy':<28} {format_metric(pair_metrics['pair_accuracy']):>12}")
        print(f"{'Vulnerable recall (pairs)':<28} {format_metric(pair_metrics['vulnerable_recall']):>12}")
        print(f"{'Fix false alarm rate':<28} {format_metric(pair_metrics['fix_false_alarm_rate']):>12}")
        print(f"{'Incomplete pairs':<28} {pair_metrics['incomplete_pairs']:>12}")
        print(f"Summary saved: {summary_path}")
    finally:
        if api is not None:
            api.close()


def main() -> None:
    from dotenv import load_dotenv

    load_dotenv()
    run(build_parser().parse_args())
