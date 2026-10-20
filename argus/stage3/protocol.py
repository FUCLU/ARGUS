from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..llm.client import APIError

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = "argus-prosecutor-defender-adjudicator-v1"
MODEL_SINK_FIELDS = ("line_start", "line_end", "expression", "operation_type")
ROLES = ("prosecutor", "defender", "adjudicator")
DEFAULT_PROMPT_PATHS = {role: ROOT / "prompts" / f"{role}.txt" for role in ROLES}
TEMPLATES = {name: path.read_text(encoding="utf-8") for name, path in DEFAULT_PROMPT_PATHS.items()}


def configure_prompt_templates(prosecutor_path=None, defender_path=None, adjudicator_path=None):
    overrides = dict(prosecutor=prosecutor_path, defender=defender_path, adjudicator=adjudicator_path)
    paths = {role: Path(overrides[role]) if overrides[role] else DEFAULT_PROMPT_PATHS[role] for role in ROLES}
    loaded = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}
    TEMPLATES.update(loaded)
    return {name: str(path) for name, path in paths.items()}


def sanitize_sink(sink):
    """Construct the model allowlist; never serialize the raw oracle object."""
    clean = {key: sink[key] for key in MODEL_SINK_FIELDS if key in sink}
    clean.setdefault('line_end', clean.get('line_start'))
    for key in ('line_start', 'line_end'):
        if type(clean.get(key)) is not int or clean[key] < 1:
            raise ValueError(f'model_sink {key} must be a positive integer')
    if clean['line_end'] < clean['line_start']:
        raise ValueError('model_sink line_end precedes line_start')
    for key in ('expression', 'operation_type'):
        if key in clean and not isinstance(clean[key], str):
            raise ValueError(f'model_sink {key} must be a string')
    return clean

class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)

class PathStep(Strict):
    line: int = Field(ge=1)
    claim: str = Field(min_length=1)

class AccusedPosition(Strict):
    line: int = Field(ge=1)
    variable: str = Field(min_length=1)
    reason: str = Field(min_length=1)

class PathAssumption(Strict):
    assumption: str = Field(min_length=1)
    path_critical: bool

class ProsecutorClaim(Strict):
    claim_status: Literal['SUPPORTED', 'NOT_APPLICABLE', 'INSUFFICIENT_EVIDENCE']
    hypothesis_condition: str = Field(min_length=1)
    trigger_path: list[PathStep]
    accused_unguarded_positions: list[AccusedPosition]
    assumptions: list[PathAssumption]
    not_applicable_evidence_lines: list[int] = Field(default_factory=list)
    actual_sink_line: int | None = Field(default=None, ge=1)
    candidate_status: Literal['VALID', 'NOT_APPLICABLE', 'MISLOCATED', 'TYPE_MISMATCH'] = 'VALID'

class SafeEvidence(Strict):
    line: int = Field(ge=1)
    statement: str | None = None

class CounterEvidence(Strict):
    kind: Literal[
        'BOUNDS_CHECK', 'INPUT_VALIDATION', 'PATH_CONSTRAINT', 'TERMINATING_ERROR_HANDLING',
        'OBJECT_REINITIALIZATION', 'OWNERSHIP_TRANSFER', 'SAFE_CLEANUP',
    ]
    explanation: str = Field(min_length=1)
    evidence: list[SafeEvidence] = Field(min_length=1)

class DefenderAnalysis(Strict):
    full_slice_reviewed: bool
    counter_evidence: list[CounterEvidence]

class AdjudicatorVerdict(Strict):
    prosecutor_claim_supported: bool
    defender_evidence_effective: bool
    verdict: Literal['BENIGN', 'VULNERABLE']
    reason: str = Field(min_length=1)
    evidence_lines: list[int]

def numbered(code):
    return '\n'.join(f'L{i}: {line}' for i, line in enumerate(code.splitlines(), 1))

def line_text(code, line):
    lines = code.splitlines()
    if not 1 <= line <= len(lines):
        return None
    value = lines[line - 1]
    return value if value.strip() else None

def candidate_status(code, sink):
    line = line_text(code, sink.get('line_start'))
    expression = sink.get('expression', '')
    operation = sink.get('operation_type', '')
    if line is None:
        return 'MISLOCATED'
    stripped = line.strip()
    if not stripped or stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
        return 'MISLOCATED'
    if expression and expression.strip() not in line and line.strip() not in expression.strip():
        return 'MISLOCATED'
    if operation in ('indexed_read', 'indexed_write') and '[' not in line:
        return 'TYPE_MISMATCH'
    return 'VALID'

def materialize_defender(analysis, code):
    """Replace model-authored citation text with the exact source line."""
    items = [item.model_copy(update={'evidence': [
        evidence.model_copy(update={'statement': line_text(code, evidence.line)})
        for evidence in item.evidence]}) for item in analysis.counter_evidence]
    return analysis.model_copy(update={'counter_evidence': items})

def invalid_lines(lines, code):
    return [line for line in lines
            if type(line) is not int or line_text(code, line) is None]

def validate_claim(claim, code, sink_line, expected_candidate_status=None):
    path = [item.line for item in claim.trigger_path]
    accused_lines = [item.line for item in claim.accused_unguarded_positions]
    evidence_lines = claim.not_applicable_evidence_lines
    errors = [f'line {line} is outside slice'
              for line in invalid_lines(path + accused_lines + evidence_lines, code)]
    if (expected_candidate_status is not None
            and claim.candidate_status != expected_candidate_status):
        errors.append('candidate_status must match the supplied Sink candidate_status')
    if claim.claim_status == 'NOT_APPLICABLE':
        if claim.trigger_path:
            errors.append('NOT_APPLICABLE claim must not include trigger_path')
        if claim.accused_unguarded_positions:
            errors.append('NOT_APPLICABLE claim must not include accused positions')
        if claim.assumptions:
            errors.append('NOT_APPLICABLE claim must not include assumptions')
        if not evidence_lines:
            errors.append('NOT_APPLICABLE claim requires source evidence')
        if claim.actual_sink_line is not None and line_text(code, claim.actual_sink_line) is None:
            errors.append('NOT_APPLICABLE actual_sink_line is outside slice')
        return errors
    if claim.claim_status == 'INSUFFICIENT_EVIDENCE':
        if claim.trigger_path:
            errors.append('INSUFFICIENT_EVIDENCE claim must not assert a trigger_path')
        if claim.accused_unguarded_positions:
            errors.append('INSUFFICIENT_EVIDENCE claim must not assert accused positions')
        if claim.assumptions:
            errors.append('INSUFFICIENT_EVIDENCE claim must not use assumptions to fill evidence gaps')
        if evidence_lines:
            errors.append('INSUFFICIENT_EVIDENCE claim must leave not_applicable_evidence_lines empty')
        if claim.actual_sink_line is None or line_text(code, claim.actual_sink_line) is None:
            errors.append('INSUFFICIENT_EVIDENCE claim requires the actual sink line in the slice')
        elif sink_line is not None and claim.actual_sink_line != sink_line:
            errors.append('INSUFFICIENT_EVIDENCE actual_sink_line must match the supplied sink line')
        return errors
    if evidence_lines:
        errors.append('SUPPORTED claim must leave not_applicable_evidence_lines empty')
    if not path:
        errors.append('SUPPORTED claim requires a non-empty trigger_path')
    if not claim.accused_unguarded_positions:
        errors.append('SUPPORTED claim requires accused_unguarded_positions')
    if any(item.path_critical for item in claim.assumptions):
        errors.append('SUPPORTED claim cannot depend on an unproven path-critical assumption; use INSUFFICIENT_EVIDENCE')
    if claim.actual_sink_line is not None:
        if line_text(code, claim.actual_sink_line) is None:
            errors.append('actual_sink_line is outside slice')
        elif not path or path[-1] != claim.actual_sink_line:
            errors.append('trigger_path must end at actual_sink_line')
    elif claim.candidate_status == 'VALID' and sink_line is not None and (not path or path[-1] != sink_line):
        errors.append('trigger_path must end at the supplied sink line')
    if any(item.line not in path for item in claim.accused_unguarded_positions):
        errors.append('accused positions must be on trigger_path')
    return errors

def validate_line_evidence(evidence, code, label='evidence'):
    errors = []
    for item in evidence:
        if line_text(code, item.line) is None:
            errors.append(f'{label} line {item.line} is outside slice')
        elif item.statement != line_text(code, item.line):
            errors.append(f'{label} statement must exactly match line {item.line}')
    return errors

def validate_defender(analysis, code):
    errors = []
    if not analysis.full_slice_reviewed:
        errors.append('full_slice_reviewed must be true')
    for item in analysis.counter_evidence:
        errors.extend(validate_line_evidence(item.evidence, code, 'counter-evidence'))
    return errors

def validate_adjudication(verdict, code):
    errors = [f'line {line} is outside slice' for line in invalid_lines(verdict.evidence_lines, code)]
    if not verdict.evidence_lines:
        errors.append('verdict requires evidence_lines')
    return errors

def schema(model):
    value = model.model_json_schema()
    if model is DefenderAnalysis:
        definitions = value.get('$defs', {})
        for definition, field in (('SafeEvidence', 'statement'),):
            properties = definitions.get(definition, {}).get('properties', {})
            properties.pop(field, None)
            required = definitions.get(definition, {}).get('required', [])
            definitions.get(definition, {})['required'] = [name for name in required if name != field]
    return value

def render(template, values):
    return re.sub(r'\{([a-z_]+)\}', lambda match: values.get(match[1], match[0]), template)

def candidate_fields(row):
    sink = sanitize_sink(row['model_sink'])
    sink_json = json.dumps(dict(sink, candidate_status=row.get('candidate_status', 'VALID')), ensure_ascii=False)
    return sink_json, sink.get('expression', '')

def _context(row):
    return row.get('prompt_code') or numbered(row['input'])

def prosecutor_prompt(row):
    sink_json, api_name = candidate_fields(row)
    return render(TEMPLATES['prosecutor'], dict(
        sink_json=sink_json, api_name=api_name, function_code=_context(row)))

def defender_prompt(row):
    sink_json, api_name = candidate_fields(row)
    return render(TEMPLATES['defender'], dict(
        sink_json=sink_json, api_name=api_name, function_code=_context(row)))

def adjudicator_prompt(row, claim, analysis):
    sink_json, api_name = candidate_fields(row)
    return render(TEMPLATES['adjudicator'], dict(
        sink_json=sink_json, api_name=api_name, function_code=_context(row),
        prosecutor_json=claim.model_dump_json(), defender_json=analysis.model_dump_json()))

class ValidationEngine:
    """Prosecutor and Defender analyze the same context independently; the
    Adjudicator decides from (P_i, D_i, C_i) in a single pass."""

    def __init__(self, api):
        self.api = api

    def parse_response(self, content, model):
        if not isinstance(content, str) or not content.strip():
            raise APIError('Response has no content')
        if '```' in content:
            raise APIError('Output must be JSON only; Markdown/code fences are not allowed')
        try:
            payload = json.loads(content)
        except (json.JSONDecodeError, TypeError) as exc:
            raise APIError(f'Invalid {model.__name__} JSON-only response: {exc}') from exc
        if not isinstance(payload, dict):
            raise APIError(f'Invalid {model.__name__} response: top-level value must be one JSON object')
        try:
            return model.model_validate(payload)
        except ValidationError as exc:
            raise APIError(f'Invalid {model.__name__} schema response: {exc}') from exc

    def call(self, prompt, model):
        repair = ('\n\nREPAIR OUTPUT. Your previous response was empty, malformed, or violated JSON-only output. '
                  'Return one SHORT corrected JSON object only. Do not repeat the analysis, '
                  'do not include Markdown, code fences, comments, or explanation. '
                  'Use only the fields in the active schema and cite only existing line numbers.')
        for attempt in range(2):
            response = self.api.completion([{'role': 'user', 'content': prompt}], schema(model))
            choices = response.get('choices') or []
            content = choices[0].get('message', {}).get('content') if choices else None
            try:
                return self.parse_response(content, model)
            except APIError as exc:
                if attempt == 1:
                    raise
                prompt += repair + '\nPrevious output error: ' + str(exc)

    def call_validated(self, prompt, model, validator, stage):
        repair_history = []
        active_prompt = prompt
        for attempt in range(2):
            value = self.call(active_prompt, model)
            errors = validator(value)
            if not errors:
                if repair_history:
                    repair_history[0]['recovered'] = True
                return value, [], repair_history
            if attempt == 1:
                repair_history[0]['final_errors'] = errors
                return value, errors, repair_history
            repair_history.append(dict(stage=stage, initial_errors=errors, recovered=False))
            active_prompt = (prompt + '\n\nHARNESS VALIDATION REPAIR (one retry only). '
                'Your previous JSON parsed, but deterministic validation rejected it. '
                'Correct only the listed issues, preserving the evidence-based analysis. '
                'Return one JSON object in the required schema.\nValidation errors: '
                + json.dumps(errors, ensure_ascii=False) + '\nPrevious JSON: '
                + value.model_dump_json())
        raise RuntimeError('unreachable validation repair state')

    def validate(self, row):
        code = row['input']
        repairs = []

        def result(**values):
            return dict(validation_repairs=list(repairs), **values)

        def validate_prosecutor_claim(value):
            # The sink location comes from the validated candidate/context
            # join. Repair a model line-number slip for an insufficient claim.
            if (value.claim_status == 'INSUFFICIENT_EVIDENCE'
                    and row.get('sink_line') is not None
                    and line_text(code, row['sink_line']) is not None):
                value.actual_sink_line = row['sink_line']
            # Format-only normalization: the harness knows these fields, and an
            # insufficient claim asserts nothing, so stray content is dropped
            # instead of rejecting an otherwise usable analysis.
            if value.candidate_status != row.get('candidate_status', value.candidate_status):
                value.candidate_status = row['candidate_status']
                normalizations.append('candidate_status')
            if value.claim_status == 'INSUFFICIENT_EVIDENCE' and (
                    value.trigger_path or value.accused_unguarded_positions
                    or value.assumptions or value.not_applicable_evidence_lines):
                value.trigger_path, value.accused_unguarded_positions = [], []
                value.assumptions, value.not_applicable_evidence_lines = [], []
                normalizations.append('insufficient_evidence_fields')
            return validate_claim(value, code, row['sink_line'], row.get('candidate_status'))

        normalizations = []
        claim, errors, attempts = self.call_validated(
            prosecutor_prompt(row), ProsecutorClaim, validate_prosecutor_claim, 'prosecutor_analysis')
        repairs.extend(attempts)
        if normalizations:
            repairs.append(dict(stage='prosecutor_analysis', normalized=sorted(set(normalizations)), recovered=True))
        if errors:
            return result(verdict=None, stage='invalid_prosecutor_analysis', errors=errors,
                          prosecutor=claim.model_dump(), protocol_status='INVALID')
        analysis, errors, attempts = self.call_validated(
            defender_prompt(row), DefenderAnalysis,
            lambda value: validate_defender(materialize_defender(value, code), code), 'defender_analysis')
        repairs.extend(attempts)
        analysis = materialize_defender(analysis, code)
        if errors:
            return result(verdict=None, stage='invalid_defender_analysis', errors=errors,
                          prosecutor=claim.model_dump(), defender=analysis.model_dump(),
                          protocol_status='INVALID')
        decision, errors, attempts = self.call_validated(
            adjudicator_prompt(row, claim, analysis), AdjudicatorVerdict,
            lambda value: validate_adjudication(value, code), 'adjudication')
        repairs.extend(attempts)
        if errors:
            return result(verdict=None, stage='invalid_adjudication', errors=errors,
                          prosecutor=claim.model_dump(), defender=analysis.model_dump(),
                          adjudicator=decision.model_dump(), protocol_status='INVALID')
        return result(verdict=decision.verdict, stage='adjudicated', errors=[],
                      protocol_status='REPAIRED' if repairs else 'VALID',
                      prosecutor=claim.model_dump(), defender=analysis.model_dump(),
                      adjudicator=decision.model_dump())

    def process(self, row):
        try:
            outcome = self.validate(row)
        except APIError as exc:
            outcome = dict(verdict=None, stage='operational_error', protocol_status='OPERATIONAL_ERROR',
                           errors=[str(exc)], validation_repairs=[])
        except Exception as exc:
            outcome = dict(verdict=None, stage='unexpected_error', protocol_status='INTERNAL_ERROR',
                           errors=[f'{type(exc).__name__}: {exc}'], validation_repairs=[])
        verdict = outcome.get('verdict')
        if verdict == 'VULNERABLE':
            triage_status = 'CONFIRMED_VULNERABLE'
        elif verdict == 'BENIGN':
            triage_status = 'CONFIRMED_BENIGN'
        elif outcome['protocol_status'] in ('OPERATIONAL_ERROR', 'INTERNAL_ERROR'):
            triage_status = 'OPERATIONAL_ERROR'
        else:
            triage_status = 'INVALID'
        return dict(
            protocol=PROTOCOL, dataset=row['dataset'], id=row['id'],
            prediction=verdict, binary_prediction=verdict, semantic_verdict=verdict,
            triage_status=triage_status, protocol_status=outcome['protocol_status'],
            run_status='completed' if verdict else 'error',
            cwe_candidate=row.get('cwe_candidate'), candidate_status=row.get('candidate_status'),
            stage=outcome['stage'], prosecutor=outcome.get('prosecutor'),
            defender=outcome.get('defender'), adjudicator=outcome.get('adjudicator'),
            validation_repairs=outcome['validation_repairs'],
            error='; '.join(outcome['errors']).replace('\n', ' ')[:500] if outcome['errors'] else None)
