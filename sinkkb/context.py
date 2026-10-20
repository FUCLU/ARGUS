from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Iterable


_FILE_MARKER = re.compile(r"^File number\s+(\d+):\s*$")
_LOCATION = re.compile(r"\[([^\]\r\n]+):(\d+)\]")
_FACT = re.compile(r"^\s*\[([^\]\r\n]+):(\d+)\]\s+(.*?)\s+\(([a-zA-Z_]+)\)\s*$")

_OPERATOR_HINTS = {
    "division": {"<operator>.division"},
    "divide": {"<operator>.division"},
    "modulo": {"<operator>.modulo"},
    "remainder": {"<operator>.modulo"},
    "dereference": {"<operator>.indirection", "<operator>.indirectMemberAccess"},
    "member access": {"<operator>.indirectMemberAccess", "<operator>.fieldAccess"},
    "array access": {"<operator>.indexAccess", "<operator>.indirectIndexAccess"},
    "index": {"<operator>.indexAccess", "<operator>.indirectIndexAccess"},
    "addition": {"<operator>.addition"},
    "subtraction": {"<operator>.subtraction"},
    "multiplication": {"<operator>.multiplication"},
    "shift": {"<operator>.shiftLeft", "<operator>.arithmeticShiftRight", "<operator>.logicalShiftRight"},
    "assignment": {"<operator>.assignment"},
}


@dataclass(frozen=True)
class SourceUnit:
    index: int
    filename: str
    code: str
    start_global_line: int
    end_global_line: int
    language: str

    def contains(self, start: int, end: int | None = None) -> bool:
        actual_end = start if end is None else end
        return self.start_global_line <= start <= actual_end <= self.end_global_line

    def to_local_line(self, global_line: int) -> int:
        return global_line - self.start_global_line + 1

    def to_global_line(self, local_line: int) -> int:
        return self.start_global_line + local_line - 1


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return cleaned[:60] or "sample"


def _function_cpg_identity(unit: SourceUnit) -> tuple[tuple[str, str], str]:
    digest = hashlib.sha256(unit.code.encode("utf-8")).hexdigest()
    extension = ".c" if unit.language == "c" else ".cpp"
    return (unit.language, digest), f"sink_function_{digest[:20]}{extension}"


def split_source_units(
    code: str,
    sample_id: str,
    *,
    language: str = "c",
    filename: str | None = None,
) -> list[SourceUnit]:
    lines = code.splitlines()
    markers = [(i, int(match.group(1))) for i, line in enumerate(lines, 1) if (match := _FILE_MARKER.match(line))]
    extension = ".c" if language == "c" else ".cpp"
    base = _safe_name(sample_id)
    if not markers:
        chosen = filename if filename and filename.lower().endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")) else f"{base}{extension}"
        return [SourceUnit(1, chosen, code, 1, max(1, len(lines)), language)]

    units: list[SourceUnit] = []
    for position, (marker_line, number) in enumerate(markers):
        next_marker = markers[position + 1][0] if position + 1 < len(markers) else len(lines) + 1
        start = marker_line + 1
        end = next_marker - 1
        unit_code = "\n".join(lines[start - 1:end])
        units.append(SourceUnit(number, f"{base}__file_{number}{extension}", unit_code, start, end, language))
    return units


def _normalize(value: Any) -> str:
    return re.sub(r"\s+", "", str(value or "")).rstrip(";")


def _expected_operators(operation_type: str) -> set[str]:
    lowered = operation_type.lower()
    result: set[str] = set()
    for hint, names in _OPERATOR_HINTS.items():
        if hint in lowered:
            result.update(names)
    return result


def select_anchor(candidate: dict[str, Any], nodes: list[dict[str, Any]]) -> dict[str, Any]:
    if not nodes:
        return {"status": "not_found", "alternatives": []}
    expression = _normalize(candidate.get("expression"))
    expected = _expected_operators(str(candidate.get("operation_type", "")))
    ranked: list[tuple[tuple[int, int, int], dict[str, Any]]] = []
    for node in nodes:
        code = _normalize(node.get("code"))
        exact = int(bool(expression) and code == expression)
        contained = int(bool(expression and code) and (code in expression or expression in code))
        operator_match = int(str(node.get("name", "")) in expected) if expected else 0
        ranked.append(((operator_match, exact, contained), node))
    ranked.sort(key=lambda item: item[0], reverse=True)
    best_score = ranked[0][0]
    best = [node for score, node in ranked if score == best_score]
    if best_score == (0, 0, 0):
        return {"status": "not_found", "alternatives": nodes}
    if len(best) != 1:
        return {"status": "ambiguous", "alternatives": best}
    node = best[0]
    identifiers = []
    for name in node.get("identifiers") or []:
        text = str(name).strip()
        if text and text not in identifiers:
            identifiers.append(text)
    return {
        "status": "resolved",
        "node_id": int(node["node_id"]),
        "node_name": str(node.get("name", "")),
        "code": str(node.get("code", "")),
        "filename": node.get("filename"),
        "line": int(node.get("line", candidate.get("line_start", -1))),
        "identifiers": identifiers,
        "alternatives": [],
    }


def _summary(raw: Any) -> str:
    if isinstance(raw, str):
        return raw
    if isinstance(raw, dict):
        for key in ("summary", "_content_text", "data"):
            value = raw.get(key)
            if isinstance(value, str):
                return value
    return ""


def parse_report(raw: Any, filename: str) -> dict[str, Any]:
    text = _summary(raw)
    lines: set[int] = set()
    guard_lines: set[int] = set()
    facts = {"declarations": [], "definitions": [], "usages": []}
    in_control = False
    for row in text.splitlines():
        stripped = row.strip()
        if "Control Dependencies" in stripped or "Control Flow Affected" in stripped:
            in_control = True
            continue
        if stripped.endswith(":") and "Control" not in stripped and not stripped.startswith("["):
            in_control = False
        for found_file, number in _LOCATION.findall(row):
            if found_file.replace("\\", "/").endswith(filename.replace("\\", "/")) or filename.replace("\\", "/").endswith(found_file.replace("\\", "/")):
                line = int(number)
                lines.add(line)
                if in_control:
                    guard_lines.add(line)
        match = _FACT.match(row)
        if not match:
            continue
        found_file, number, code, kind = match.groups()
        if not (found_file.replace("\\", "/").endswith(filename.replace("\\", "/")) or filename.replace("\\", "/").endswith(found_file.replace("\\", "/"))):
            continue
        fact = {"line": int(number), "code": code, "kind": kind}
        if kind in {"declaration", "parameter"}:
            facts["declarations"].append(fact)
        elif kind in {"assignment", "modification", "call_site_arg", "propagation"}:
            facts["definitions"].append(fact)
        elif kind in {"usage", "use_in_call"}:
            facts["usages"].append(fact)
    return {
        "lines": sorted(lines),
        "guard_lines": sorted(guard_lines),
        "facts": facts,
        "raw": text,
    }


def _sink_snapshot(candidate: dict[str, Any]) -> dict[str, Any]:
    start = int(candidate.get("line_start", -1))
    return {
        "line_start": start,
        "line_end": int(candidate.get("line_end", start)),
        "expression": str(candidate.get("expression", "")),
        "operation_type": str(candidate.get("operation_type", "")),
    }


def _source_statements(unit: SourceUnit, local_lines: Iterable[int]) -> list[dict[str, Any]]:
    source = unit.code.splitlines()
    statements = []
    for local_line in sorted(set(local_lines)):
        if not 1 <= local_line <= len(source):
            continue
        statements.append({
            "file_name": unit.filename,
            "line": local_line,
            "input_line": unit.to_global_line(local_line),
            "code": source[local_line - 1],
        })
    return statements


def _source_facts(unit: SourceUnit, facts: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    source = unit.code.splitlines()
    result = []
    seen: set[tuple[int, str, str]] = set()
    for fact in facts:
        local_line = int(fact.get("line", -1))
        code = str(fact.get("code", ""))
        kind = str(fact.get("kind", ""))
        key = (local_line, code, kind)
        if not 1 <= local_line <= len(source) or key in seen:
            continue
        seen.add(key)
        result.append({
            "file_name": unit.filename,
            "line": local_line,
            "input_line": unit.to_global_line(local_line),
            "code": source[local_line - 1],
            "kind": kind,
        })
    return sorted(result, key=lambda item: (item["line"], item["code"], item["kind"]))


def select_call_evidence_lines(
    *,
    anchor_line: int,
    sink_lines: Iterable[int],
    variable_lines: Iterable[int],
    guard_lines: Iterable[int],
    backward_lines: Iterable[int],
    forward_lines: Iterable[int],
    max_lines: int = 32,
) -> tuple[list[int], bool]:
    """Select graph-evidence lines that may seed call-context expansion.

    The order encodes evidence strength rather than source order.  Calls on the
    sink and operand definition/use lines are retained first, followed by
    control guards, the backward slice, and finally the forward slice.  Source
    order is restored before querying Joern.
    """
    groups = (
        sink_lines,
        variable_lines,
        guard_lines,
        backward_lines,
        forward_lines,
    )
    ranked: list[int] = []
    seen: set[int] = set()
    available: set[int] = set()
    for group in groups:
        values = {int(line) for line in group if int(line) > 0}
        available.update(values)
        for line in sorted(values, key=lambda item: (abs(item - anchor_line), item)):
            if line not in seen:
                seen.add(line)
                ranked.append(line)
    limit = max(1, int(max_lines))
    return sorted(ranked[:limit]), len(available) > limit


def _same_file(left: Any, right: Any) -> bool:
    first = str(left or "").replace("\\", "/")
    second = str(right or "").replace("\\", "/")
    return bool(first and second) and (
        first == second
        or first.endswith("/" + second)
        or second.endswith("/" + first)
    )


def _method_context_lines(
    unit: SourceUnit,
    *,
    start: int,
    end: int,
    relation: str,
    call_site_line: int,
    relevant_identifiers: Iterable[str],
    max_body_lines: int,
) -> tuple[list[int], bool]:
    """Choose a bounded method excerpt around sink operands and the call edge."""
    source = unit.code.splitlines()
    first = max(1, start)
    last = min(len(source), end)
    if last < first:
        return [], False
    span = list(range(first, last + 1))
    limit = max(1, int(max_body_lines))
    if len(span) <= limit:
        return span, False

    identifiers = sorted({str(name).strip() for name in relevant_identifiers if str(name).strip()}, key=lambda name: (-len(name), name))
    token_patterns = [re.compile(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])") for name in identifiers]
    symbol_lines = [
        line for line in span
        if any(pattern.search(source[line - 1]) for pattern in token_patterns)
    ]
    primary = call_site_line if relation == "caller" and first <= call_site_line <= last else first
    ranked: list[int] = []

    def add(line: int) -> None:
        if first <= line <= last and line not in ranked:
            ranked.append(line)

    # Preserve the method signature and call edge before expanding by symbols.
    add(first)
    if relation == "caller":
        add(call_site_line)
    for line in sorted(symbol_lines, key=lambda item: (abs(item - primary), item)):
        add(line)
    neighbor_lines = {
        neighbor
        for line in symbol_lines
        for neighbor in (line - 1, line + 1)
        if first <= neighbor <= last
    }
    for line in sorted(neighbor_lines, key=lambda item: (abs(item - primary), item)):
        add(line)
    for line in sorted(span, key=lambda item: (abs(item - primary), item)):
        add(line)
    return sorted(ranked[:limit]), True


def normalize_call_context(
    unit: SourceUnit,
    rows: Iterable[dict[str, Any]],
    *,
    max_body_lines: int = 40,
    relevant_identifiers: Iterable[str] = (),
) -> tuple[list[dict[str, Any]], list[str]]:
    """Convert call-graph rows to source-backed context entries."""
    entries = []
    warnings: list[str] = []
    seen: set[tuple[str, str, tuple[int, ...]]] = set()
    allowed = {"call_site", "caller", "callee", "external_call", "unresolved_call"}
    for row in rows:
        relation = str(row.get("relation", ""))
        if relation not in allowed or not _same_file(row.get("file_name"), unit.filename):
            if "call_context_row_unmapped" not in warnings:
                warnings.append("call_context_row_unmapped")
            continue
        body_span: dict[str, Any] = {}
        if relation in {"caller", "callee"}:
            start = int(row.get("method_line_start", -1))
            end = int(row.get("method_line_end", -1))
            call_site_line = int(row.get("line", -1))
            body_span = {
                "method_line_start": start,
                "method_line_end": end,
            }
            if start < 1 or end < start:
                local_lines = []
            else:
                local_lines, body_truncated = _method_context_lines(
                    unit,
                    start=start,
                    end=end,
                    relation=relation,
                    call_site_line=call_site_line,
                    relevant_identifiers=relevant_identifiers,
                    max_body_lines=max_body_lines,
                )
                body_span["body_truncated"] = body_truncated
                if body_truncated and "call_body_line_limit_reached" not in warnings:
                    warnings.append("call_body_line_limit_reached")
            if relation == "caller" and call_site_line > 0:
                local_lines.append(call_site_line)
        else:
            local_lines = [int(row.get("line", -1))]
        statements = _source_statements(unit, local_lines)
        if not statements:
            if "call_context_row_unmapped" not in warnings:
                warnings.append("call_context_row_unmapped")
            continue
        name = str(row.get("name", "")).strip() or "unknown"
        key = (relation, name, tuple(item["line"] for item in statements))
        if key in seen:
            continue
        seen.add(key)
        entries.append({
            "relation": relation,
            "name": name,
            "resolved": bool(row.get("resolved", relation not in {"external_call", "unresolved_call"})),
            "hop": max(1, int(row.get("hop", 1) or 1)),
            **body_span,
            **({"call_site_line": int(row.get("line", -1))} if relation == "caller" else {}),
            "statements": statements,
        })
    return entries, warnings


def _statement_key(statement: dict[str, Any]) -> tuple[str, int]:
    return str(statement.get("file_name", "")), int(statement.get("line", -1))


def _render_statement(statement: dict[str, Any]) -> str:
    file_name, line = _statement_key(statement)
    return f"[{file_name}:{line}] {statement.get('code', '')}"


def render_compact_context(
    *,
    sink: Iterable[dict[str, Any]],
    guards: Iterable[dict[str, Any]],
    backward: Iterable[dict[str, Any]],
    symbols: Iterable[dict[str, Any]],
    calls: Iterable[dict[str, Any]],
    forward: Iterable[dict[str, Any]],
    max_lines: int,
) -> tuple[str, list[str]]:
    """Render bounded graph evidence with deterministic section priority."""
    sink_rows = sorted(sink, key=_statement_key)
    call_entries = list(calls)
    call_keys = {
        _statement_key(statement)
        for entry in call_entries
        for statement in entry.get("statements") or []
    }
    limit = max(max_lines, len({_statement_key(item) for item in sink_rows}))
    seen: set[tuple[str, int]] = set()
    omitted = False
    sections: list[str] = []

    def take(statements: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        nonlocal omitted
        selected = []
        for statement in sorted(statements, key=_statement_key):
            key = _statement_key(statement)
            if key in seen:
                continue
            if len(seen) >= limit:
                omitted = True
                continue
            seen.add(key)
            selected.append(statement)
        return selected

    def add_section(title: str, statements: Iterable[dict[str, Any]]) -> None:
        selected = take(statements)
        if selected:
            sections.append("\n".join([f"[{title}]", *map(_render_statement, selected)]))

    add_section("SINK", sink_rows)
    add_section("CONTROL GUARDS", guards)
    add_section("BACKWARD DATA FLOW", (item for item in backward if _statement_key(item) not in call_keys))
    add_section("SYMBOL CONTEXT", (item for item in symbols if _statement_key(item) not in call_keys))

    call_lines = []
    relation_order = {"call_site": 0, "external_call": 1, "caller": 2, "callee": 3, "unresolved_call": 4}

    def call_sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
        statements = sorted(item.get("statements") or [], key=_statement_key)
        first_location = _statement_key(statements[0]) if statements else ("\uffff", 2**31)
        return (
            first_location,
            relation_order.get(str(item.get("relation")), 99),
            str(item.get("name", "")),
        )

    ordered_calls = sorted(
        call_entries,
        key=call_sort_key,
    )
    for call in ordered_calls:
        selected = take(call.get("statements") or [])
        relation = str(call.get("relation", ""))
        name = str(call.get("name", "")).strip() or "unknown"
        if relation == "caller":
            if not selected and not call.get("label_only"):
                continue
            call_lines.append(f"caller {name}:")
        elif relation == "callee":
            if not selected and not call.get("label_only"):
                continue
            call_lines.append(f"callee {name}:")
        elif relation == "unresolved_call":
            if not selected:
                continue
            call_lines.append(f"unresolved call {name}:")
        elif relation in {"call_site", "external_call"}:
            if not selected:
                continue
        call_lines.extend(_render_statement(item) for item in selected)
    if call_lines:
        sections.append("\n".join(["[CALL CONTEXT]", *call_lines]))

    add_section("FORWARD DATA FLOW", (item for item in forward if _statement_key(item) not in call_keys))
    warnings = ["context_line_limit_reached"] if omitted else []
    return "\n\n".join(sections), warnings


def _project_call_context_to_target(
    entries: Iterable[dict[str, Any]],
    target: SourceUnit,
    *,
    file_name: str,
    function_start_line: int,
    function_end_line: int,
) -> list[dict[str, Any]]:
    """Prepare source-backed call evidence for the bounded compact document.

    Resolved caller/callee bodies keep their full-file locations.  Statements
    observed inside the target function are projected back to the processed
    function coordinates so Stage 3 can preserve its original sink lines.
    """
    source = target.code.splitlines()
    projected: list[dict[str, Any]] = []
    for entry in entries:
        relation = str(entry.get("relation", ""))
        name = str(entry.get("name", "unknown"))
        hop = max(1, int(entry.get("hop", 1) or 1))
        if relation in {"caller", "callee"}:
            projected.append(entry)
            continue
        if relation not in {"call_site", "external_call", "unresolved_call"}:
            continue
        statements = []
        for statement in entry.get("statements") or []:
            if not _same_file(statement.get("file_name"), file_name):
                continue
            absolute_line = int(statement.get("line", -1))
            if not function_start_line <= absolute_line <= function_end_line:
                continue
            local_line = absolute_line - function_start_line + 1
            if not 1 <= local_line <= len(source):
                continue
            statements.append({
                "file_name": target.filename,
                "line": local_line,
                "input_line": target.to_global_line(local_line),
                "code": source[local_line - 1],
            })
        if statements:
            projected.append({
                "relation": relation,
                "name": name,
                "resolved": bool(entry.get("resolved", relation == "call_site")),
                "hop": hop,
                "statements": statements,
            })
    return projected


async def build_sample_context(
    client: Any,
    source_row: dict[str, Any],
    result_row: dict[str, Any],
    *,
    language: str = "c",
    max_candidates: int = 3,
    max_operands: int = 8,
    backward_depth: int = 20,
    forward_depth: int = 10,
    call_hops: int = 1,
    max_context_lines: int = 120,
    cpg_timeout: float = 300.0,
    query_timeout: int = 60,
    include_raw: bool = False,
    primevul_source_resolver: Any = None,
    project_cpg_cache: dict[tuple[str, str], dict[str, Any]] | None = None,
    function_cpg_cache: dict[tuple[str, str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    sample_id = str(source_row["sample_id"])
    code = str(source_row.get("func", source_row.get("input", "")))
    filename = source_row.get("file_name")
    units = split_source_units(code, sample_id, language=language, filename=filename)
    candidates = list(result_row.get("sink_candidates") or [])[:max_candidates]
    cpg_cache: dict[int, dict[str, Any]] = {}
    shared_project_cpg_cache = project_cpg_cache if project_cpg_cache is not None else {}
    shared_function_cpg_cache = function_cpg_cache if function_cpg_cache is not None else {}
    project_cpgs_created = 0
    function_cpgs_created = 0
    contexts: list[dict[str, Any]] = []
    sample_errors: list[str] = []

    for rank, candidate in enumerate(candidates, 1):
        start = int(candidate.get("line_start", -1))
        end = int(candidate.get("line_end", start))
        unit = next((item for item in units if item.contains(start, end)), None)
        base = {"sink_rank": rank, "sink": _sink_snapshot(candidate)}
        if unit is None:
            contexts.append({**base, "status": "source_unit_not_found"})
            continue
        function_cache_key, canonical_filename = _function_cpg_identity(unit)
        unit = SourceUnit(
            index=unit.index,
            filename=canonical_filename,
            code=unit.code,
            start_global_line=unit.start_global_line,
            end_global_line=unit.end_global_line,
            language=unit.language,
        )
        local_start, local_end = unit.to_local_line(start), unit.to_local_line(end)
        try:
            if unit.index not in cpg_cache:
                if function_cache_key not in shared_function_cpg_cache:
                    shared_function_cpg_cache[function_cache_key] = await client.ensure_snippet_cpg(
                        unit.code,
                        language=unit.language,
                        filename=canonical_filename,
                        wait_timeout=cpg_timeout,
                    )
                    function_cpgs_created += 1
                cpg_cache[unit.index] = shared_function_cpg_cache[function_cache_key]
            cpg = cpg_cache[unit.index]
            codebase_hash = str(cpg["codebase_hash"])
            query_filename = str(cpg.get("query_filename") or unit.filename)
            nodes = await client.calls_on_lines(
                codebase_hash=codebase_hash,
                filename=query_filename,
                line_start=local_start,
                line_end=local_end,
                timeout=query_timeout,
            )
            local_candidate = {**candidate, "line_start": local_start, "line_end": local_end}
            anchor = select_anchor(local_candidate, nodes)
            if anchor["status"] != "resolved":
                contexts.append({
                    **base,
                    "status": f"anchor_{anchor['status']}",
                    "anchor": anchor,
                    "warnings": [],
                })
                continue

            backward_raw = await client.program_slice(
                codebase_hash=codebase_hash,
                node_id=anchor["node_id"],
                direction="backward",
                max_depth=backward_depth,
                include_control_flow=True,
                timeout=query_timeout,
            )
            forward_raw = await client.program_slice(
                codebase_hash=codebase_hash,
                node_id=anchor["node_id"],
                direction="forward",
                max_depth=forward_depth,
                include_control_flow=True,
                timeout=query_timeout,
            )
            backward = parse_report(backward_raw, query_filename)
            forward = parse_report(forward_raw, query_filename)

            variable_contexts = []
            variable_lines: set[int] = set()
            variable_facts = {"declarations": [], "definitions": [], "usages": []}
            for variable in anchor.get("identifiers", [])[:max_operands]:
                per_direction = {}
                for direction in ("backward", "forward"):
                    raw = await client.variable_flow(
                        codebase_hash=codebase_hash,
                        location=f"{query_filename}:{anchor['line']}",
                        variable=variable,
                        direction=direction,
                        timeout=query_timeout,
                    )
                    parsed = parse_report(raw, query_filename)
                    per_direction[direction] = parsed
                    variable_lines.update(parsed["lines"])
                    for category in variable_facts:
                        variable_facts[category].extend(parsed["facts"][category])
                variable_contexts.append({"variable": variable, **per_direction})

            sink_local_lines = list(range(local_start, local_end + 1))
            relevant_lines, call_lines_truncated = select_call_evidence_lines(
                anchor_line=int(anchor["line"]),
                sink_lines=sink_local_lines,
                variable_lines=variable_lines,
                guard_lines=backward["guard_lines"],
                backward_lines=backward["lines"],
                forward_lines=forward["lines"],
            )
            warnings = ["call_evidence_line_limit_reached"] if call_lines_truncated else []
            call_rows: list[dict[str, Any]] = []
            call_context: list[dict[str, Any]] = []
            compact_call_context: list[dict[str, Any]] | None = None
            call_context_scope = "function"
            call_context_source: dict[str, Any] | None = None
            resolved_file_source = None
            if primevul_source_resolver is not None:
                resolved_file_source, source_warning = primevul_source_resolver.resolve(unit.code)
                if source_warning:
                    warnings.append(source_warning)

            if resolved_file_source is not None:
                if resolved_file_source.file_hash_match is False:
                    warnings.append("primevul_file_hash_mismatch")
                try:
                    full_file_key = (
                        resolved_file_source.file_name,
                        hashlib.sha256(resolved_file_source.code.encode("utf-8")).hexdigest(),
                    )
                    if full_file_key not in shared_project_cpg_cache:
                        shared_project_cpg_cache[full_file_key] = await client.ensure_snippet_cpg(
                            resolved_file_source.code,
                            language=unit.language,
                            filename=resolved_file_source.file_name,
                            wait_timeout=cpg_timeout,
                        )
                        project_cpgs_created += 1
                    file_cpg = shared_project_cpg_cache[full_file_key]
                    file_codebase_hash = str(file_cpg["codebase_hash"])
                    file_query = str(file_cpg.get("query_filename") or resolved_file_source.file_name)
                    file_start = resolved_file_source.function_start_line + local_start - 1
                    file_end = resolved_file_source.function_start_line + local_end - 1
                    file_nodes = await client.calls_on_lines(
                        codebase_hash=file_codebase_hash,
                        filename=file_query,
                        line_start=file_start,
                        line_end=file_end,
                        timeout=query_timeout,
                    )
                    file_candidate = {**candidate, "line_start": file_start, "line_end": file_end}
                    file_anchor = select_anchor(file_candidate, file_nodes)
                    if file_anchor.get("status") == "resolved":
                        full_file_unit = SourceUnit(
                            index=unit.index,
                            filename=resolved_file_source.file_name,
                            code=resolved_file_source.code,
                            start_global_line=1,
                            end_global_line=max(1, len(resolved_file_source.code.splitlines())),
                            language=unit.language,
                        )
                        file_relevant_lines = sorted({
                            resolved_file_source.function_start_line + line - 1
                            for line in relevant_lines
                        })
                        call_rows = await client.call_context(
                            codebase_hash=file_codebase_hash,
                            node_id=file_anchor["node_id"],
                            relevant_lines=file_relevant_lines,
                            hop_limit=call_hops,
                            timeout=query_timeout,
                        )
                        call_context, call_warnings = normalize_call_context(
                            full_file_unit,
                            call_rows,
                            relevant_identifiers=anchor.get("identifiers", []),
                        )
                        warnings.extend(call_warnings)
                        compact_call_context = _project_call_context_to_target(
                            call_context,
                            unit,
                            file_name=resolved_file_source.file_name,
                            function_start_line=resolved_file_source.function_start_line,
                            function_end_line=resolved_file_source.function_end_line,
                        )
                        call_context_scope = "same_file"
                        call_context_source = {
                            "file_name": resolved_file_source.file_name,
                            "function_start_line": resolved_file_source.function_start_line,
                            "function_end_line": resolved_file_source.function_end_line,
                            "source_kind": resolved_file_source.source_kind,
                            "revision": resolved_file_source.revision,
                            "file_hash_match": resolved_file_source.file_hash_match,
                            "function_match_kind": resolved_file_source.function_match_kind,
                        }
                    else:
                        warnings.append(f"primevul_file_anchor_{file_anchor.get('status', 'unresolved')}")
                except Exception:
                    warnings.append("primevul_file_cpg_unavailable")

            if call_context_scope != "same_file":
                try:
                    call_rows = await client.call_context(
                        codebase_hash=codebase_hash,
                        node_id=anchor["node_id"],
                        relevant_lines=relevant_lines,
                        hop_limit=call_hops,
                        timeout=query_timeout,
                    )
                    call_context, call_warnings = normalize_call_context(
                        unit,
                        call_rows,
                        relevant_identifiers=anchor.get("identifiers", []),
                    )
                    warnings.extend(call_warnings)
                    compact_call_context = call_context
                except Exception:
                    warnings.append("call_context_unavailable")

            variable_flows = []
            raw_variable_reports: dict[str, Any] = {}
            for item in variable_contexts:
                variable = item["variable"]
                variable_flows.append({
                    "variable": variable,
                    "backward": _source_statements(unit, item["backward"]["lines"]),
                    "forward": _source_statements(unit, item["forward"]["lines"]),
                })
                if include_raw:
                    raw_variable_reports[variable] = {
                        "backward": item["backward"]["raw"],
                        "forward": item["forward"]["raw"],
                    }

            sink_statements = _source_statements(unit, sink_local_lines)
            guards = _source_statements(unit, backward["guard_lines"])
            backward_statements = _source_statements(unit, backward["lines"])
            forward_statements = _source_statements(unit, forward["lines"])
            declarations = _source_facts(unit, variable_facts["declarations"])
            definitions = _source_facts(unit, variable_facts["definitions"])
            usages = _source_facts(unit, variable_facts["usages"])
            compact_code, render_warnings = render_compact_context(
                sink=sink_statements,
                guards=guards,
                backward=backward_statements,
                symbols=[*declarations, *definitions, *usages],
                calls=compact_call_context or [],
                forward=forward_statements,
                max_lines=max_context_lines,
            )
            for warning in render_warnings:
                if warning not in warnings:
                    warnings.append(warning)

            context = {
                **base,
                "status": "ok",
                "anchor": {
                    "status": "resolved",
                    "node_id": anchor["node_id"],
                    "node_name": anchor["node_name"],
                    "file_name": unit.filename,
                    "line": anchor["line"],
                    "input_line": unit.to_global_line(anchor["line"]),
                    "code": anchor["code"],
                    "identifiers": anchor["identifiers"],
                    "codebase_hash": codebase_hash,
                },
                "backward_slice": backward_statements,
                "forward_slice": forward_statements,
                "guards": guards,
                "declarations": declarations,
                "definitions": definitions,
                "usages": usages,
                "variable_flows": variable_flows,
                "call_context": call_context,
                "call_context_scope": call_context_scope,
                "context_line_budget": max_context_lines,
                "compact_code": compact_code,
                "warnings": warnings,
            }
            if call_context_source is not None:
                context["call_context_source"] = call_context_source
            if include_raw:
                context["raw_reports"] = {
                    "backward_slice": backward["raw"],
                    "forward_slice": forward["raw"],
                    "variable_flows": raw_variable_reports,
                    "call_context": call_rows,
                }
            contexts.append(context)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            sample_errors.append(f"candidate[{rank}]: {error}")
            contexts.append({**base, "status": "error", "error": error})

    successes = sum(item.get("status") == "ok" for item in contexts)
    if not candidates:
        status = "ok"
    elif successes == len(contexts):
        status = "ok"
    elif successes:
        status = "partial"
    else:
        status = "error"
    return {
        "sample_id": sample_id,
        "idx": source_row.get("idx"),
        "status": status,
        "contexts": contexts,
        "errors": sample_errors,
        "stats": {
            "candidate_count": len(candidates),
            "context_ok": successes,
            "context_failed": len(contexts) - successes,
            "source_units": len(units),
            "cpgs_created": function_cpgs_created,
            "cpgs_used": len(cpg_cache),
            "project_cpgs_created": project_cpgs_created,
        },
    }
