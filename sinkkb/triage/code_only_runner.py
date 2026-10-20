"""Code-only two-agent triage over Sven reconstructed `input` snippets."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from jsonschema import Draft202012Validator
from tqdm.auto import tqdm

from ..io import append_jsonl, timestamped_run_output
from .client import APIError, FatalAPIError, STAGE_SETTINGS
from .compact_runner import client_for

ROOT = Path(__file__).resolve().parents[2]
PROMPT_DIR = ROOT / 'prompts'
PROTOCOL = 'sven-code-only-v7-evidence-audit'
ANALYST_PROMPT = (PROMPT_DIR / 'attack_analyst_code_only.txt').read_text(encoding='utf-8')
AUDITOR_PROMPT = (PROMPT_DIR / 'security_auditor_code_only.txt').read_text(encoding='utf-8')
ANALYST_SCHEMA = {
    'type': 'object', 'additionalProperties': False,
    'properties': {
        'scenarios': {
            'type': 'array', 'maxItems': 2,
            'items': {
                'type': 'object', 'additionalProperties': False,
                'properties': {
                    'id': {'type': 'string', 'pattern': '^S[1-2]$'},
                    'trigger': {'type': 'string', 'minLength': 1, 'maxLength': 200},
                    'operation': {'type': 'string', 'minLength': 1, 'maxLength': 180},
                    'path': {'type': 'array', 'maxItems': 5, 'items': {'type': 'string', 'minLength': 1, 'maxLength': 120}},
                    'preconditions': {'type': 'array', 'maxItems': 3, 'items': {'type': 'string', 'minLength': 1, 'maxLength': 120}},
                    'observed_guards': {'type': 'array', 'maxItems': 3, 'items': {'type': 'string', 'minLength': 1, 'maxLength': 120}},
                },
                'required': ['id', 'operation', 'trigger', 'path', 'preconditions', 'observed_guards'],
            },
        },
        'missing_context': {'type': 'array', 'maxItems': 3, 'items': {'type': 'string', 'minLength': 1, 'maxLength': 160}},
    },
    'required': ['scenarios', 'missing_context'],
}
AUDITOR_SCHEMA = {
    'type': 'object', 'additionalProperties': False,
    'properties': {
        'verdict': {'enum': ['VULNERABLE', 'BENIGN']},
        'evidence': {'anyOf': [
            {'type': 'array', 'maxItems': 2, 'items': {'type': 'string', 'minLength': 1, 'maxLength': 180}},
            {'type': 'object', 'minProperties': 1, 'maxProperties': 3,
             'additionalProperties': {'type': 'string', 'minLength': 1, 'maxLength': 180}},
        ]},
        'guard_assessment': {'enum': ['effective', 'ineffective', 'absent', 'unknown']},
        'reason': {'type': 'string', 'minLength': 1, 'maxLength': 500},
        'limitations': {'type': 'array', 'maxItems': 2, 'items': {'type': 'string', 'minLength': 1, 'maxLength': 160}},
    },
    'required': ['verdict', 'evidence', 'guard_assessment', 'reason', 'limitations'],
}
STANDALONE_AUDITOR_PROMPT = (PROMPT_DIR / 'security_auditor_code_only_standalone.txt').read_text(encoding='utf-8')


class InvalidModelOutput(ValueError):
    def __init__(self, message, usage, repairs):
        super().__init__(message)
        self.usage = usage
        self.repairs = repairs


def _read_rows(path: Path):
    text = path.read_text(encoding='utf-8')
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = [json.loads(line) for line in text.splitlines() if line.strip()]
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError('Code-only input must be a JSON array or JSONL of objects')
    return value


def _parse_json_response(content):
    if not isinstance(content, str):
        raise ValueError('Model response content is not text')
    text = content.strip()
    fenced = re.fullmatch(r'```(?:json)?\s*\n?(.*?)\n?```', text, flags=re.IGNORECASE | re.DOTALL)
    if fenced:
        text = fenced.group(1).strip()
    return json.loads(text)


def _json_call(api, prompt, code, schema, model, *, analyst=None):
    system = prompt
    user_messages = [{'role': 'user', 'content': code}]
    if analyst is not None:
        user_messages.append({
            'role': 'user',
            'content': 'Analyst report for audit (untrusted claim, not evidence):\n' + json.dumps(analyst, ensure_ascii=False),
        })
    base_messages = [{'role': 'system', 'content': system}, *user_messages]
    settings = dict(STAGE_SETTINGS['validation'], model=model, temperature=0,
                    max_tokens=1024, json_only=True, enable_thinking=False,
                    reasoning={'enabled': False}, stream=False)
    last_error = None
    usage_total = {'input_tokens': 0, 'output_tokens': 0}
    for attempt in range(2):
        messages = base_messages
        if attempt:
            messages = [
                {'role': 'system', 'content': system + '\n\nRepair instruction: return valid JSON matching the required schema. Previous validation error: ' + str(last_error)},
                *user_messages,
            ]
        response = api.completion(messages, schema, settings)
        usage = response.get('usage') or {}
        for target, key in (('input_tokens', 'prompt_tokens'), ('output_tokens', 'completion_tokens')):
            value = usage.get(key)
            if type(value) is int:
                usage_total[target] += value
        try:
            choices = response.get('choices') or []
            content = choices[0].get('message', {}).get('content') if choices else None
            result = _parse_json_response(content)
            Draft202012Validator(schema).validate(result)
            if schema is ANALYST_SCHEMA:
                scenario_ids = [scenario['id'] for scenario in result['scenarios']]
                if len(scenario_ids) != len(set(scenario_ids)):
                    raise ValueError('Analyst scenario IDs must be unique')
            api._log({'event': 'code_only_call', 'role': 'analyst' if schema is ANALYST_SCHEMA else 'auditor',
                      'attempt': attempt, 'generation_id': response.get('id'), 'valid': True})
            return result, usage_total, attempt
        except Exception as exc:
            last_error = f'{type(exc).__name__}: {exc}'
            api._log({'event': 'code_only_call', 'role': 'analyst' if schema is ANALYST_SCHEMA else 'auditor',
                      'attempt': attempt, 'valid': False, 'error': last_error[:500]})
            if attempt:
                raise InvalidModelOutput(last_error, usage_total, attempt) from exc
    raise ValueError(str(last_error))


def _process(api, row, index, model, mode):
    code = row['input']
    identity = f'sven_reconstructed_{index:04d}'
    code_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()
    tokens = {'input_tokens': 0, 'output_tokens': 0}
    repairs = 0
    analyst = auditor = None
    errors = []
    if mode == 'two-agent':
        try:
            analyst, usage, repair = _json_call(api, ANALYST_PROMPT, code, ANALYST_SCHEMA, model)
            repairs += repair
            for key in tokens:
                tokens[key] += usage[key]
        except InvalidModelOutput as exc:
            repairs += exc.repairs
            for key in tokens:
                tokens[key] += exc.usage[key]
            errors.append(f'{type(exc).__name__}: {exc}')
            return _result_row(row, index, code_hash, model, None, None, tokens, repairs, errors, mode=mode)
        except FatalAPIError:
            raise
        except (APIError, ValueError) as exc:
            errors.append(f'{type(exc).__name__}: {exc}')
            return _result_row(row, index, code_hash, model, None, None, tokens, repairs, errors, mode=mode)
    try:
        prompt = AUDITOR_PROMPT if mode == 'two-agent' else STANDALONE_AUDITOR_PROMPT
        auditor, usage, repair = _json_call(api, prompt, code, AUDITOR_SCHEMA, model,
                                            analyst=analyst if mode == 'two-agent' else None)
        repairs += repair
        for key in tokens:
            tokens[key] += usage[key]
        verdict = auditor['verdict'] if auditor['verdict'] in ('VULNERABLE', 'BENIGN') else None
    except InvalidModelOutput as exc:
        repairs += exc.repairs
        for key in tokens:
            tokens[key] += exc.usage[key]
        errors.append(f'{type(exc).__name__}: {exc}')
        verdict = None
    except FatalAPIError:
        raise
    except (APIError, ValueError) as exc:
        errors.append(f'{type(exc).__name__}: {exc}')
        verdict = None
    return _result_row(row, index, code_hash, model, analyst, auditor, tokens, repairs, errors, verdict, mode=mode)


def _result_row(row, index, code_hash, model, analyst, auditor, tokens, repairs, errors, verdict=None, mode=None):
    if verdict is None and auditor and auditor.get('verdict') in ('VULNERABLE', 'BENIGN'):
        verdict = auditor['verdict']
    status = 'completed' if verdict in ('VULNERABLE', 'BENIGN') else 'error' if errors else 'unresolved'
    return {
        'protocol': PROTOCOL, 'mode': mode, 'sample_id': f'sven_reconstructed_{index:04d}', 'idx': index,
        'input_signature': code_hash, 'prediction': verdict,
        'ground_truth': row.get('output'), 'ground_truth_cwe': row.get('cwe'),
        'run_status': status,
        'model_id': model,
        'analyst_report': analyst, 'auditor_report': auditor,
        'input_tokens': tokens['input_tokens'], 'output_tokens': tokens['output_tokens'],
        'repair_calls': repairs, 'errors': errors,
    }


def _print_row(row):
    color = sys.stdout.isatty()
    colors = {'green': '\033[32;1m', 'red': '\033[31;1m', 'yellow': '\033[33;1m',
              'cyan': '\033[36;1m', 'magenta': '\033[35;1m', 'blue': '\033[34;1m',
              'dim': '\033[2m', 'bold': '\033[1m'}
    def paint(value, shade):
        value = str(value)
        return f"{colors[shade]}{value}\033[0m" if color else value
    pred = row.get('prediction')
    gt = row.get('ground_truth')
    cwe = row.get('ground_truth_cwe')
    if row.get('run_status') == 'error':
        status, status_color = 'ERROR', 'red'
    elif not pred:
        status, status_color = 'UNRESOLVED', 'yellow'
    elif gt in ('VULNERABLE', 'BENIGN'):
        status, status_color = ('MATCH', 'green') if pred == gt else ('MISMATCH', 'red')
    else:
        status, status_color = 'PREDICTED', 'cyan'
    prediction_color = 'green' if pred and gt == pred else 'red' if pred and gt else 'yellow'
    token_value = f"IN {row['input_tokens']:,}  |  OUT {row['output_tokens']:,}"
    lines = [
        f"{paint(row['sample_id'], 'bold')}  {paint(status, status_color)}",
        f"  {paint('Prediction'.ljust(13), 'magenta')} {paint(pred or 'N/A', prediction_color)}",
        f"  {paint('Ground truth'.ljust(13), 'cyan')} {paint(gt or 'N/A', 'green' if gt == pred and pred else 'cyan')}",
        f"  {paint('CWE'.ljust(13), 'blue')} {paint(cwe or 'N/A', 'blue')}",
        f"  {paint('Tokens'.ljust(13), 'yellow')} {paint(token_value, 'yellow')}",
    ]
    visible = lambda line: re.sub(r'\033\[[0-9;]*m', '', line)
    width = max(len(visible(line)) for line in lines)
    border = '-' * (width + 2)
    tqdm.write(f"+{border}+\n" + '\n'.join(f"| {line}{' ' * (width - len(visible(line)))} |" for line in lines) + f"\n+{border}+", file=sys.stdout)


def _print_summary(summary):
    # LLMxCPG, Table 5 (SVEN); the paper's Table 1 test split contains 518 samples.
    benchmark = {
        'Samples': '518',
        'Recall (all positive)': '0.9534',
        'Precision': '0.5590',
        'FPR': 'N/R',
        'F1': '0.7048',
        'Accuracy': '0.6020',
        'TP / FP / FN / TN': 'N/R',
        'Errors': 'N/R',
        'Repair calls': 'N/R',
    }
    rows = [
        ('Samples', f"{summary['samples']}"),
        ('Recall (all positive)', _metric(summary['recall_all_positive'])),
        ('Precision', _metric(summary['precision'])),
        ('FPR', _metric(summary['fpr'])),
        ('F1', _metric(summary['f1'])),
        ('Accuracy', _metric(summary['accuracy'])),
        ('TP / FP / FN / TN', f"{summary['tp']} / {summary['fp']} / {summary['fn']} / {summary['tn']}"),
        ('Errors', f"{summary['errors']}"),
        ('Repair calls', f"{summary['repair_calls']}"),
    ]
    label_width = max(len(name) for name, _ in rows)
    value_width = max(len('Current run'), *(len(value) for _, value in rows))
    benchmark_width = max(len('LLMxCPG (SVEN)'), *(len(benchmark[name]) for name, _ in rows))
    width = label_width + value_width + benchmark_width + 8
    border = f"+{'-' * width}+"
    print()
    print('RUN SUMMARY')
    print(border)
    print(f"| {'Metric':<{label_width}} | {'Current run':>{value_width}} | {'LLMxCPG (SVEN)':>{benchmark_width}} |")
    print(border)
    for name, value in rows:
        print(f"| {name:<{label_width}} | {value:>{value_width}} | {benchmark[name]:>{benchmark_width}} |")
    print(border)
    print('LLMxCPG reference: Table 5; Table 1 reports 259 vulnerable + 259 safe test samples.')
    print('Reference only: this run may use a smaller reconstructed subset, so results are not directly comparable.')


def _metric(value):
    return 'N/A' if value is None else f'{value:.4f}'


def _write_pretty_results(path: Path, rows):
    pretty_path = path.with_name(f'{path.stem}.pretty.json')
    pretty_path.write_text(json.dumps(list(rows), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return pretty_path


def summarize_results(rows):
    rows = list(rows)
    tp = sum(r.get('ground_truth') == 'VULNERABLE' and r.get('prediction') == 'VULNERABLE' for r in rows)
    fp = sum(r.get('ground_truth') == 'BENIGN' and r.get('prediction') == 'VULNERABLE' for r in rows)
    fn = sum(r.get('ground_truth') == 'VULNERABLE' and r.get('prediction') == 'BENIGN' for r in rows)
    tn = sum(r.get('ground_truth') == 'BENIGN' and r.get('prediction') == 'BENIGN' for r in rows)
    ratio = lambda numerator, denominator: numerator / denominator if denominator else None
    positives = sum(r.get('ground_truth') == 'VULNERABLE' for r in rows)
    resolved_predictions = tp + fp + fn + tn
    return {
        'samples': len(rows),
        'labeled_samples': sum(r.get('ground_truth') in ('VULNERABLE', 'BENIGN') for r in rows),
        'resolved_samples': sum(r.get('prediction') in ('VULNERABLE', 'BENIGN') for r in rows),
        'resolved_labeled_samples': resolved_predictions,
        'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
        'precision': ratio(tp, tp + fp),
        'recall_resolved': ratio(tp, tp + fn),
        'recall_all_positive': ratio(tp, positives),
        'fpr': ratio(fp, fp + tn),
        'f1': ratio(2 * tp, 2 * tp + fp + fn),
        'accuracy': ratio(tp + tn, resolved_predictions),
        'input_tokens': sum(r.get('input_tokens') or 0 for r in rows),
        'output_tokens': sum(r.get('output_tokens') or 0 for r in rows),
        'repair_calls': sum(r.get('repair_calls') or 0 for r in rows),
        'unresolved': sum(r.get('run_status') == 'unresolved' for r in rows),
        'errors': sum(r.get('run_status') == 'error' for r in rows),
    }


def run(args):
    if args.start < 0 or args.limit < 0 or args.workers < 1:
        raise ValueError('start/limit must be non-negative and workers must be positive')
    provider = (args.provider or os.getenv('TRIAGE_PROVIDER', 'openrouter')).strip().lower()
    if provider not in ('openrouter', 'deepseek', 'openai-compatible'):
        raise ValueError('Unsupported provider')
    model = args.model or (os.getenv('TRIAGE_MODEL') or
                           ('qwen3-32b' if provider == 'openai-compatible' else 'qwen/qwen3-32b'))
    model = model.strip()
    path = Path(args.data)
    mode = getattr(args, 'code_only_mode', 'two-agent')
    if mode not in ('two-agent', 'auditor-only'):
        raise ValueError('unsupported code-only mode')
    rows = _read_rows(path)[args.start:]
    if args.limit:
        rows = rows[:args.limit]
    jobs = []
    for i, row in enumerate(rows, start=args.start):
        code = row.get('input')
        if not isinstance(code, str) or not code.strip():
            raise ValueError(f'Reconstructed row {i} has no non-empty input code')
        if row.get('output') not in ('VULNERABLE', 'BENIGN'):
            raise ValueError(f'Reconstructed row {i} has an unsupported output label')
        jobs.append((i, row))
    manifest = {
        'protocol': PROTOCOL, 'mode': mode, 'provider': provider, 'model': model,
        'data': str(path), 'selected_samples': len(jobs),
        'user_message': 'row.input only (raw code string); dataset instruction/output/cwe/file_name are excluded',
        'auditor_context': ('Auditor receives raw code and Analyst JSON as untrusted claims; code is the sole evidence'
                            if mode == 'two-agent' else 'Auditor receives only raw code'),
        'prompts': {
            'analyst': {'path': 'prompts/attack_analyst_code_only.txt',
                        'sha256': hashlib.sha256(ANALYST_PROMPT.encode()).hexdigest()} if mode == 'two-agent' else None,
            'auditor': {
                'path': 'prompts/security_auditor_code_only.txt' if mode == 'two-agent' else 'prompts/security_auditor_code_only_standalone.txt',
                'sha256': hashlib.sha256((AUDITOR_PROMPT if mode == 'two-agent' else STANDALONE_AUDITOR_PROMPT).encode()).hexdigest(),
            },
        },
        'schema': {'analyst': ANALYST_SCHEMA if mode == 'two-agent' else None, 'auditor': AUDITOR_SCHEMA},
        'data_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'max_tokens_per_call': 1024, 'temperature': 0,
    }
    print(f"Protocol: {PROTOCOL} | Mode: {mode} | Provider: {provider} | Model: {model} | Samples: {len(jobs)}")
    if args.dry_run:
        return
    output = Path(args.output) if args.output else timestamped_run_output('stage3')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.with_name('manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    api = client_for(provider, output.parent)
    pool = ThreadPoolExecutor(max_workers=args.workers)
    futures = {}
    results = []
    try:
        for index, row in jobs:
            future = pool.submit(_process, api, row, index, model, mode)
            futures[future] = (index, row)
        for future in tqdm(as_completed(futures), total=len(futures), desc='Sven code-only', unit='sample'):
            result = future.result()
            append_jsonl(output, result)
            results.append(result)
            _print_row(result)
    except KeyboardInterrupt:
        print('\nCtrl+C received. Cancelling queued samples and active API requests...', flush=True)
        for future in futures:
            future.cancel()
        api.cancel()
        pool.shutdown(wait=False, cancel_futures=True)
        raise SystemExit(130)
    except BaseException:
        for future in futures:
            future.cancel()
        api.cancel()
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True)
    finally:
        api.close()
    pretty_output = _write_pretty_results(output, results)
    summary = summarize_results(results)
    summary_path = output.with_name('summary.json')
    summary_path.write_text(json.dumps(summary, indent=2), encoding='utf-8')
    _print_summary(summary)
    print(f"\nJSON results: {output}")
    print(f"Pretty JSON: {pretty_output}")
    print(f"JSON summary: {summary_path}")
