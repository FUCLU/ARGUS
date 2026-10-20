from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .client import APIError, STAGE_SETTINGS

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = "abp-prosecutor-defender-v17-direct-source"
MODEL_SINK_FIELDS = ("line_start", "line_end", "expression", "operation_type")
DEFAULT_PROMPT_PATHS = {
    "prosecutor": ROOT / "prompts" / "prosecutor.txt",
    "defender": ROOT / "prompts" / "defender.txt",
}
TEMPLATES = {name: path.read_text(encoding="utf-8") for name, path in DEFAULT_PROMPT_PATHS.items()}


def configure_prompt_templates(prosecutor_path=None, defender_path=None):
    paths = {
        "prosecutor": Path(prosecutor_path) if prosecutor_path else DEFAULT_PROMPT_PATHS["prosecutor"],
        "defender": Path(defender_path) if defender_path else DEFAULT_PROMPT_PATHS["defender"],
    }
    loaded = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}
    TEMPLATES.update(loaded)
    return {name: str(path) for name, path in paths.items()}


def normalize_cwe(value):
    if value is None or (isinstance(value, str) and value.strip().lower() in {"", "unknown", "not provided", "unspecified"}):
        return "not provided"
    match = re.fullmatch(r'CWE\s*-\s*([0-9]+)', value.strip(), re.IGNORECASE) if isinstance(value, str) else None
    if not match or int(match[1]) < 1:
        raise ValueError('CWE candidate must be a single CWE identifier')
    return f'CWE-{int(match[1])}'

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

class SafeProof(Strict):
    proof_type: Literal['GUARDED', 'SAFE_VALUE', 'UNREACHABLE', 'BOUNDED']
    explanation: str = Field(min_length=1)
    evidence: list[SafeEvidence] = Field(min_length=1)

class AssumptionCheck(Strict):
    assumption_index: int = Field(ge=0)
    status: Literal['PLAUSIBLE', 'CONTRADICTED', 'UNKNOWN']
    breaks_trigger_path: bool
    reason: str = Field(min_length=1)
    evidence: list[SafeEvidence]

class DefenderReview(Strict):
    full_slice_reviewed: bool
    assessment: Literal['SAFE_PROOF', 'NO_DEFENSE']
    assumptions_checked: list[AssumptionCheck]
    rebuttal: None
    safe_proof: SafeProof | None

class ProsecutorReply(Strict):
    decision: Literal['ACCEPT', 'REJECT', 'NO_DEFENSE']
    rejection_type: Literal[
        'none', 'wrong_position', 'wrong_variable_type', 'wrong_property',
        'insufficient_guard', 'invalid_safe_proof',
    ]
    reason: str = Field(min_length=1)
    evidence_lines: list[int]
    final_verdict: Literal['BENIGN', 'VULNERABLE']
    verdict_reason: str = Field(min_length=1)
    verdict_evidence_lines: list[int]

def round_triage_status(verdict, claim, review):
    """The semantic protocol has exactly two completed outcomes."""
    return 'CONFIRMED_VULNERABLE' if verdict == 'VULNERABLE' else 'CONFIRMED_BENIGN'

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

def materialize_defender_review(review, code):
    """Replace model-authored citation text with the exact source line."""
    safe_proof = review.safe_proof
    if safe_proof is not None:
        evidence = [item.model_copy(update={
            'statement': line_text(code, item.line)}) for item in safe_proof.evidence]
        safe_proof = safe_proof.model_copy(update={'evidence': evidence})
    checks = [item.model_copy(update={'evidence': [evidence.model_copy(update={
        'statement': line_text(code, evidence.line)}) for evidence in item.evidence]})
        for item in review.assumptions_checked]
    return review.model_copy(update={
        'safe_proof': safe_proof,
        'assumptions_checked': checks})

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

def validate_safe_proof(proof, code):
    return validate_line_evidence(proof.evidence, code)

def validate_defender(review, claim, code):
    errors = []
    if not review.full_slice_reviewed:
        errors.append('full_slice_reviewed must be true')
    expected = set(range(len(claim.assumptions)))
    observed = [item.assumption_index for item in review.assumptions_checked]
    if set(observed) != expected or len(observed) != len(expected):
        errors.append('assumptions_checked must cover every assumption exactly once')
    if claim.claim_status == 'INSUFFICIENT_EVIDENCE':
        if review.assessment != 'NO_DEFENSE' or review.safe_proof is not None:
            errors.append('INSUFFICIENT_EVIDENCE claim requires an empty NO_DEFENSE review')
        if review.assumptions_checked:
            errors.append('INSUFFICIENT_EVIDENCE claim must have no assumption checks')
        return errors
    for item in review.assumptions_checked:
        if item.assumption_index not in expected:
            continue
        assumption = claim.assumptions[item.assumption_index]
        errors.extend(validate_line_evidence(item.evidence, code, 'assumption evidence'))
        if item.status == 'CONTRADICTED':
            if not item.evidence:
                errors.append('CONTRADICTED assumption requires source evidence')
            if item.breaks_trigger_path != assumption.path_critical:
                errors.append('CONTRADICTED assumption breaks the path exactly when it is path-critical')
        elif item.breaks_trigger_path:
            errors.append('PLAUSIBLE or UNKNOWN assumption cannot break the trigger path')

    if review.assessment == 'NO_DEFENSE':
        if review.safe_proof is not None:
            errors.append('NO_DEFENSE must set safe_proof to null')
        if any(item.status == 'CONTRADICTED' and item.breaks_trigger_path
               for item in review.assumptions_checked):
            errors.append('NO_DEFENSE cannot contain a path-breaking contradiction')
        return errors
    if review.assessment == 'SAFE_PROOF':
        if review.safe_proof is None:
            errors.append('SAFE_PROOF assessment requires safe_proof')
        else:
            errors.extend(validate_safe_proof(review.safe_proof, code))
        return errors
    return errors

def validate_reply(reply, review, claim, code):
    errors = []
    if reply.rejection_type != 'none' and reply.decision != 'REJECT':
        errors.append('non-none rejection_type requires decision=REJECT')
    if reply.decision == 'REJECT':
        if reply.rejection_type == 'none':
            errors.append('REJECT requires a concrete rejection_type')
        if review.assessment == 'NO_DEFENSE':
            errors.append('REJECT requires a claimed SAFE_PROOF')
    elif reply.rejection_type != 'none':
        errors.append('non-REJECT decision requires rejection_type=none')
    if reply.decision == 'NO_DEFENSE' and review.assessment != 'NO_DEFENSE':
        errors.append('NO_DEFENSE decision requires Defender assessment=NO_DEFENSE')
    if reply.decision == 'ACCEPT' and review.assessment == 'NO_DEFENSE':
        errors.append('ACCEPT requires SAFE_PROOF')
    errors.extend(f'line {line} is outside slice'
                  for line in invalid_lines(reply.evidence_lines + reply.verdict_evidence_lines, code))
    if reply.decision in ('ACCEPT', 'REJECT') and not reply.evidence_lines:
        errors.append(f'{reply.decision} requires evidence_lines')
    if reply.final_verdict in ('BENIGN', 'VULNERABLE') and not reply.verdict_evidence_lines:
        errors.append('binary final_verdict requires verdict_evidence_lines')
    if claim.claim_status == 'NOT_APPLICABLE':
        if reply.final_verdict != 'BENIGN':
            errors.append(f'{claim.claim_status} claim requires final_verdict=BENIGN')
        if reply.decision != 'NO_DEFENSE':
            errors.append(f'{claim.claim_status} claim requires decision=NO_DEFENSE')
    elif claim.claim_status == 'INSUFFICIENT_EVIDENCE':
        if reply.decision != 'NO_DEFENSE':
            errors.append('INSUFFICIENT_EVIDENCE claim requires decision=NO_DEFENSE')
    elif reply.decision == 'ACCEPT' and reply.final_verdict != 'BENIGN':
        errors.append('accepted SAFE_PROOF requires final_verdict=BENIGN')
    elif reply.decision in ('REJECT', 'NO_DEFENSE') and reply.final_verdict != 'VULNERABLE':
        errors.append(f'{reply.decision} requires final_verdict=VULNERABLE for a SUPPORTED claim')
    return errors

def schema(model):
    value = model.model_json_schema()
    if model is DefenderReview:
        definitions = value.get('$defs', {})
        for definition, field in (('SafeEvidence', 'statement'),):
            properties = definitions.get(definition, {}).get('properties', {})
            properties.pop(field, None)
            required = definitions.get(definition, {}).get('required', [])
            definitions.get(definition, {})['required'] = [name for name in required if name != field]
    return value

def render(template, values):
    return re.sub(r'\{([a-z_]+)\}', lambda match: values.get(match[1], match[0]), template)

def prosecutor_template(phase):
    """Expose only the active Prosecutor phase to the model.

    The source prompt remains one audited protocol file, while Round 1 cannot see
    Round 2's schema/examples until the harness invokes the adjudication call.
    """
    source = TEMPLATES['prosecutor']
    marker1 = 'ROUND 1 CONTENT START'
    marker1_end = 'ROUND 1 CONTENT END'
    marker2 = 'ROUND 2 CONTENT START'
    marker2_end = 'ROUND 2 CONTENT END'
    round1 = source.index(marker1)
    round1_end = source.index(marker1_end)
    round2 = source.index(marker2)
    round2_end = source.index(marker2_end)
    tail = source[round2_end + len(marker2_end):]
    if phase == 'round1':
        return source[:round1] + source[round1 + len(marker1):round1_end] + tail
    if phase == 'round2':
        return source[:round1] + source[round2 + len(marker2):round2_end] + tail
    raise ValueError(f'Unknown Prosecutor prompt phase: {phase}')

def prosecutor_prompt(row, round_instruction, prior_context='', phase='round1'):
    direct_source = row.get('direct_source_mode')
    sink = None if direct_source else sanitize_sink(row['model_sink'])
    sink_json = (
        json.dumps({"analysis_scope": "full function; no preselected sink"})
        if direct_source else
        json.dumps(dict(sink, candidate_status=row.get('candidate_status', 'VALID')), ensure_ascii=False)
    )
    api_name = "no preselected sink; inspect the full function" if direct_source else sink.get('expression', '')
    prompt = render(prosecutor_template(phase), dict(
        round_instruction=round_instruction,
        sink_json=sink_json,
        function_code=row.get('prompt_code') or numbered(row['input']),
        api_name=api_name,
        prior_context=prior_context,
        candidate_status=row.get('candidate_status', 'VALID')))
    if direct_source:
        prompt = (
            "DIRECT-SOURCE MODE: no Stage 1 sink candidate was supplied. The Sink "
            "object below describes the review scope and contains no source line. "
            "Review the full function, select the strongest concrete executable "
            "security-relevant operation to audit, and ground "
            "every claim in the numbered function lines. For SUPPORTED, set "
            "actual_sink_line to the real operation line and end trigger_path there. "
            "For INSUFFICIENT_EVIDENCE, identify the real operation being considered "
            "in actual_sink_line and name the missing link. Keep candidate_status "
            "as VALID; it is a protocol marker in this mode. Do not use a function "
            "declaration or line 1 as the sink unless that line itself performs the "
            "dangerous operation. If the failure condition is not established, the "
            "Round 2 label must be BENIGN. The input source lines "
            "use L<number>: [file:line] code; cite the L number.\n\n" + prompt
        )
    return prompt

def defender_prompt(row, claim):
    direct_source = row.get('direct_source_mode')
    sink = None if direct_source else sanitize_sink(row['model_sink'])
    sink_json = (
        json.dumps({"analysis_scope": "full function; no preselected sink"})
        if direct_source else
        json.dumps(dict(sink, candidate_status=row.get('candidate_status', 'VALID')), ensure_ascii=False)
    )
    api_name = "no preselected sink; inspect the full function" if direct_source else sink.get('expression', '')
    prompt = render(TEMPLATES['defender'], dict(
        api_name=api_name,
        sink_json=sink_json, prosecutor_json=claim.model_dump_json(),
        function_code=row.get('prompt_code') or numbered(row['input'])))
    if row.get('direct_source_mode'):
        prompt = (
            "DIRECT-SOURCE MODE: there was no preselected sink. Review the full "
            "function and audit only the Prosecutor's exact source-line hypothesis. "
            "The Sink object is a mode marker, not a real operation.\n\n" + prompt
        )
    return prompt

def reply_prompt(row, claim, review):
    instruction = (
        'Round 2: adjudicate the original claim and Defender review using ROUND 2 RULES '
        'and the handoff examples. Keep the final label binary, preserve the original '
        'hypothesis, and cite source lines for the decision.'
    )
    context = (
        f'Original claim:\n{claim.model_dump_json()}\n'
        f'Defender review:\n{review.model_dump_json()}'
    )
    return prosecutor_prompt(row, instruction, context, phase='round2')

class ABPEngine:
    def __init__(self, api, rounds):
        self.api, self.rounds = api, rounds

    def parse_response(self, content, model):
        if not isinstance(content, str) or not content.strip():
            raise APIError('ABP response has no content')
        if '```' in content:
            raise APIError('ABP output must be JSON only; Markdown/code fences are not allowed')
        try:
            payload = json.loads(content)
        except (json.JSONDecodeError, TypeError) as exc:
            raise APIError(f'Invalid ABP {model.__name__} JSON-only response: {exc}') from exc
        if not isinstance(payload, dict):
            raise APIError(f'Invalid ABP {model.__name__} response: top-level value must be one JSON object')
        try:
            return model.model_validate(payload)
        except ValidationError as exc:
            raise APIError(f'Invalid ABP {model.__name__} schema response: {exc}') from exc

    def call(self, prompt, model):
        settings = dict(STAGE_SETTINGS['validation'])
        # Deterministic decoding is important for schema-constrained JSON when
        # the selected model does not support native response_format.
        settings.update(temperature=0.0, max_tokens=4096)
        repair = ('\n\nREPAIR OUTPUT. Your previous response was empty, malformed, or violated JSON-only output. '
                  'Return one SHORT corrected JSON object only. Do not repeat the analysis, '
                  'do not include Markdown, code fences, comments, or explanation. '
                  'Use only the fields in the active schema and cite only existing line numbers.')
        for attempt in range(2):
            response = self.api.completion([{'role': 'user', 'content': prompt}],
                                           schema(model), settings)
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
                'Correct only the listed issues, preserving the evidence-based decision. '
                'Do not invent a third final prediction label. The internal claim_status '
                'may be INSUFFICIENT_EVIDENCE; final_verdict must remain BENIGN or '
                'VULNERABLE. Classify assumptions explicitly and follow the binary contract. '
                'Return one JSON object in the required schema.\nValidation errors: '
                + json.dumps(errors, ensure_ascii=False) + '\nPrevious JSON: '
                + value.model_dump_json())
        raise RuntimeError('unreachable validation repair state')

    def battle(self, row, index):
        code = row['input']
        repairs = []

        def result(**values):
            return dict(round=index, validation_repairs=list(repairs), **values)

        def validate_prosecutor_claim(value):
            # The sink location comes from the validated candidate/context
            # join. Repair a model line-number slip for an insufficient claim.
            if (value.claim_status == 'INSUFFICIENT_EVIDENCE'
                    and row.get('sink_line') is not None
                    and line_text(code, row['sink_line']) is not None):
                value.actual_sink_line = row['sink_line']
            return validate_claim(
                value, code, row['sink_line'], row.get('candidate_status'))

        claim, errors, attempts = self.call_validated(prosecutor_prompt(row,
            'Round 1: apply ROUND 1 RULES to the full slice; do not assume the sink '
            'candidate is correct. Return only the active claim schema.',
            phase='round1'), ProsecutorClaim,
            validate_prosecutor_claim,
            'prosecutor_claim')
        repairs.extend(attempts)
        if errors:
            return result(verdict=None, semantic_verdict=None, triage_status='INVALID',
                        stage='invalid_prosecutor_claim', errors=errors,
                        claim=claim.model_dump(), protocol_status='INVALID')
        review, errors, attempts = self.call_validated(defender_prompt(row, claim), DefenderReview,
            lambda value: validate_defender(materialize_defender_review(value, code), claim, code),
            'defender_review')
        repairs.extend(attempts)
        review = materialize_defender_review(review, code)
        if errors:
            return result(verdict=None, semantic_verdict=None, triage_status='INVALID',
                        stage='invalid_defender_review', errors=errors,
                        claim=claim.model_dump(), defender=review.model_dump(), protocol_status='INVALID')

        def validate_prosecutor_reply(value):
            errors = validate_reply(value, review, claim, code)
            if (row.get('direct_source_mode')
                    and claim.claim_status == 'INSUFFICIENT_EVIDENCE'
                    and value.final_verdict != 'BENIGN'):
                errors.append(
                    'direct-source INSUFFICIENT_EVIDENCE requires BENIGN; '
                    'VULNERABLE requires a SUPPORTED failure condition')
            return errors

        reply, errors, attempts = self.call_validated(reply_prompt(row, claim, review),
            ProsecutorReply,
            validate_prosecutor_reply,
            'prosecutor_reply')
        repairs.extend(attempts)
        if errors:
            return result(verdict=None, semantic_verdict=None, triage_status='INVALID',
                        stage='invalid_prosecutor_reply', errors=errors,
                        claim=claim.model_dump(), defender=review.model_dump(),
                        reply=reply.model_dump(), protocol_status='INVALID')

        verdict = reply.final_verdict
        triage = round_triage_status(verdict, claim, review)
        return result(
            verdict=verdict,
            semantic_verdict=verdict,
            protocol_status='REPAIRED' if repairs else 'VALID',
            triage_status=triage,
            stage=(
                'safe_proof'
                if review.assessment == 'SAFE_PROOF' and verdict == 'BENIGN'
                else 'no_defense'
                if review.assessment == 'NO_DEFENSE'
                else 'prosecutor_reply'
            ),
            errors=[],
            claim=claim.model_dump(),
            defender=review.model_dump(),
            reply=reply.model_dump(),
        )

    def process(self, row):
        rounds = []
        for index in range(1, self.rounds + 1):
            try:
                rounds.append(self.battle(row, index))
            except APIError as exc:
                rounds.append(dict(round=index, verdict=None, semantic_verdict=None, protocol_status='OPERATIONAL_ERROR', triage_status='OPERATIONAL_ERROR',
                                   stage='operational_error', error_type=type(exc).__name__,
                                   error_message=str(exc), errors=[str(exc)]))
            except Exception as exc:
                rounds.append(dict(round=index, verdict=None, semantic_verdict=None, protocol_status='INTERNAL_ERROR', triage_status='INTERNAL_ERROR',
                                   stage='unexpected_error', error_type=type(exc).__name__,
                                   error_message=str(exc), errors=[f'{type(exc).__name__}: {exc}']))
        votes = [item['verdict'] for item in rounds if item.get('verdict') in ('VULNERABLE', 'BENIGN')]
        vulnerable = votes.count('VULNERABLE')
        benign = votes.count('BENIGN')
        # Keep the established vulnerability-first policy for conflicting
        # completed round votes.
        prediction = ('VULNERABLE' if vulnerable >= benign else 'BENIGN') if votes else None
        confidence = max(vulnerable, benign) / len(votes) if votes else None
        if not votes:
            if any(item.get('triage_status') in ('OPERATIONAL_ERROR', 'INTERNAL_ERROR') for item in rounds):
                triage_status = 'OPERATIONAL_ERROR'
            else:
                triage_status = 'INVALID'
        elif vulnerable and benign:
            triage_status = 'MIXED'
        elif vulnerable:
            triage_status = 'CONFIRMED_VULNERABLE'
        else:
            triage_status = 'CONFIRMED_BENIGN'
        return dict(protocol=PROTOCOL, dataset=row['dataset'], id=row['id'],
            semantic_verdict=prediction,
            protocol_status=('VALID' if votes and not any(item.get('protocol_status') == 'INVALID' for item in rounds) else ('INVALID' if triage_status == 'INVALID' else triage_status)),
            run_status='completed' if votes else 'error',
            prediction=prediction, binary_prediction=prediction, triage_status=triage_status,
            cwe_candidate=row.get('cwe_candidate'),
            candidate_status=row.get('candidate_status'),
            round_count=self.rounds,
            completed_rounds=sum(item.get('protocol_status') in ('VALID', 'REPAIRED')
                                 for item in rounds),
            vulnerable_votes=vulnerable, benign_votes=benign, confidence=confidence,
            rounds=rounds,
            error=None if votes else (error_summary({'rounds': rounds}) or
                   'No valid ABP vote; inspect rounds[].errors'))

def error_summary(result):
    details = []
    for item in result.get('rounds') or []:
        errors = item.get('errors') or []
        if errors:
            stage = item.get('stage', 'unknown_stage')
            details.append(f'{stage}: {"; ".join(str(error) for error in errors)}')
    if not details and result.get('error'):
        details.append(str(result['error']))
    return ' | '.join(details).replace('\n', ' ')[:500]
