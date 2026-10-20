"""CLI execution, immutable packet storage, resume, and abstention-aware metrics."""
from __future__ import annotations

import json
import os
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ..io import append_jsonl, timestamped_run_output
from .client import DeepSeek, FatalAPIError, OpenAICompatible, OpenRouter, STAGE_SETTINGS
from .compact import (BUNDLE, EXAMPLES, PROMPTS, PROTOCOL, CompactEngine, build_packet,
                      digest, expand_packet, store_packet, validate)


def summarize(rows):
    rows = list(rows)
    ratio = lambda a, b: a / b if b else None
    counts = Counter((r.get('ground_truth'), r.get('prediction')) for r in rows)
    tp, fp = counts['VULNERABLE', 'VULNERABLE'], counts['BENIGN', 'VULNERABLE']
    fn, tn = counts['VULNERABLE', 'BENIGN'], counts['BENIGN', 'BENIGN']
    candidates = [c for row in rows for c in row['candidate_results']]
    statuses = Counter(c['artifact']['pipeline_status'] for c in candidates)
    resolved = sum(r.get('prediction') is not None for r in rows)
    positives = sum(r.get('ground_truth') == 'VULNERABLE' for r in rows)
    from .runner import pair_consistency_metrics
    telemetry = [c['artifact']['run_metadata'] for c in candidates]
    def total(field):
        return sum(m[field] for m in telemetry) if all(m[field] is not None for m in telemetry) else None
    return dict(samples=len(rows), resolved_samples=resolved, sample_resolution_coverage=ratio(resolved, len(rows)),
                candidates=len(candidates), resolved_candidates=statuses['RESOLVED'],
                candidate_resolution_coverage=ratio(statuses['RESOLVED'], len(candidates)),
                pipeline_status_counts=dict(statuses), labeled_samples=sum(r.get('ground_truth') is not None for r in rows),
                resolved_labeled_samples=tp+fp+fn+tn, tp=tp, fp=fp, fn=fn, tn=tn,
                precision=ratio(tp, tp+fp), recall_resolved=ratio(tp, tp+fn), recall_all_positive=ratio(tp, positives),
                f1_resolved=ratio(2*tp, 2*tp+fp+fn), accuracy_resolved=ratio(tp+tn, tp+fp+fn+tn),
                false_benign_fraction=ratio(fn, tn+fn),
                repair_calls=sum(c['artifact']['run_metadata']['repair_calls'] for c in candidates),
                context_expansions=sum(c['artifact']['run_metadata']['context_expansions'] for c in candidates),
                input_tokens=total('input_tokens'), output_tokens=total('output_tokens'),
                total_candidate_latency_ms=total('latency_ms'),
                telemetry_complete_candidates=sum(all(m[k] is not None for k in ('input_tokens', 'output_tokens', 'latency_ms')) for m in telemetry),
                pair_metrics=pair_consistency_metrics(rows))


def sample_console_report(row, *, color=False):
    palette = {
        'SUCCESS': '\033[32;1m',
        'ERROR': '\033[31;1m',
        'PARTIAL': '\033[33;1m',
        'MISSING': '\033[33;1m',
        'INFO': '\033[36;1m',
    }

    def paint(value, status):
        value = str(value)
        if not color:
            return value
        return f"{palette.get(status, '')}{value}\033[0m"

    def line(label, value, status):
        return f"  {label:<13} {paint(status, status):<20} {value}"

    candidates = row.get('candidate_results') or []
    artifacts = [c.get('artifact') or {} for c in candidates]
    metadata = [a.get('run_metadata') or {} for a in artifacts]

    def token_total(name):
        values = [m.get(name) for m in metadata]
        known = [v for v in values if type(v) is int]
        status = 'SUCCESS' if values and len(known) == len(values) else 'PARTIAL' if known else 'ERROR'
        return sum(known) if known else None, status

    input_tokens, input_status = token_total('input_tokens')
    output_tokens, output_status = token_total('output_tokens')
    token_status = ('SUCCESS' if input_status == output_status == 'SUCCESS'
                    else 'PARTIAL' if 'SUCCESS' in (input_status, output_status) or 'PARTIAL' in (input_status, output_status)
                    else 'ERROR')
    token_value = (f"input={input_tokens if input_tokens is not None else 'N/A'}  "
                   f"output={output_tokens if output_tokens is not None else 'N/A'}")

    prediction = row.get('prediction')
    ground_truth = row.get('ground_truth')
    cwe = row.get('ground_truth_cwe')
    assessed = sum(c.get('prediction') is not None for c in candidates)
    candidate_status = 'SUCCESS' if candidates and assessed == len(candidates) else 'PARTIAL' if assessed else 'ERROR'
    candidate_value = f"{assessed}/{len(candidates)} resolved"
    if candidates:
        candidate_value += '  ' + ', '.join(
            f"#{c.get('sink_rank', '?')}:{(c.get('artifact') or {}).get('pipeline_status', 'UNKNOWN')}"
            for c in candidates
        )

    run_status = row.get('run_status', 'unknown')
    overall = {'completed': 'SUCCESS', 'no_candidates': 'MISSING', 'partial': 'PARTIAL'}.get(run_status, 'ERROR')
    return '\n'.join((
        f"{paint(overall, overall)}  {row.get('sample_id', 'unknown')}  idx={row.get('idx', '?')}",
        line('PREDICT', prediction or 'N/A', 'SUCCESS' if prediction else 'ERROR'),
        line('GROUND TRUTH', ground_truth or 'N/A', 'SUCCESS' if ground_truth else 'MISSING'),
        line('CWE', cwe or 'N/A', 'SUCCESS' if cwe else 'MISSING'),
        line('TOKENS', token_value, token_status),
        line('CANDIDATES', candidate_value, candidate_status),
    ))


def client_for(provider, directory):
    log = Path(directory) / 'requests.jsonl'
    if provider == 'openrouter':
        key = os.getenv('OPENROUTER_API_KEY', '').strip()
        if not key:
            raise FatalAPIError('Set OPENROUTER_API_KEY')
        api = OpenRouter(key, log)
        try:
            api.auth_check()
            api.preflight()
        except BaseException:
            api.close()
            raise
        return api
    if provider == 'deepseek':
        key = os.getenv('TRIAGE_API_KEY') or os.getenv('DEEPSEEK_API_KEY') or os.getenv('SINK_API_KEY')
        if not key:
            raise FatalAPIError('Set TRIAGE_API_KEY or DEEPSEEK_API_KEY')
        return DeepSeek(key, log, base_url=os.getenv('DEEPSEEK_BASE_URL') or os.getenv('SINK_BASE_URL') or 'https://api.deepseek.com')
    key, url = os.getenv('TRIAGE_API_KEY'), os.getenv('TRIAGE_BASE_URL')
    if not key or not url:
        raise FatalAPIError('Set TRIAGE_API_KEY and TRIAGE_BASE_URL for openai-compatible')
    return OpenAICompatible(key, log, base_url=url.rstrip('/'))


def prepare_jobs(args):
    from .runner import (read_jsonl, read_json_document, latest_by_identity, unique_index,
                         _source_from_contexts, _ground_truth, _ground_truth_cwe)
    stage2 = latest_by_identity(read_jsonl(args.stage2), 'Stage 2')
    oracle = unique_index(read_json_document(args.data), 'source/oracle') if args.data else {}
    stage1 = latest_by_identity(read_jsonl(args.stage1), 'Stage 1') if args.stage1 else None
    rows = list(stage2.values())[args.start:]
    if args.limit:
        rows = rows[:args.limit]
    jobs = []
    for row in rows:
        key = row['sample_id'], row['idx']
        source = oracle.get(key)
        if source is None or not source.get('func'):
            source = _source_from_contexts(*key, row)
            source['_source_reconstructed'] = True
        contexts = row.get('contexts') or []
        expected = row.get('stats', {}).get('candidate_count', len(contexts))
        if type(expected) is not int or expected < 0:
            raise ValueError(f'Invalid candidate count in sample {key}')
        by_rank, duplicate = {}, set()
        for context in contexts:
            rank = context.get('sink_rank') if isinstance(context, dict) else None
            if type(rank) is not int or rank < 1:
                raise ValueError(f'Invalid sink rank in sample {key}')
            if rank in by_rank:
                duplicate.add(rank)
            by_rank[rank] = context
        if any(rank > expected for rank in by_rank):
            raise ValueError(f'Stage 2 rank exceeds candidate count in sample {key}')
        tasks = []
        for rank in range(1, expected+1):
            context = by_rank.get(rank)
            candidate = (context or {}).get('sink', {})
            error = None
            if rank in duplicate:
                error = 'Duplicate Stage 2 sink_rank'
            if stage1 is not None:
                entry = stage1.get(key, {})
                candidates = entry.get('sink_candidates') or []
                if entry.get('status') != 'ok' or rank > len(candidates):
                    error = 'Missing corresponding Stage 1 candidate'
                else:
                    candidate = candidates[rank-1]
            packet = None
            if error is None:
                try:
                    packet = build_packet(source, candidate, context, max_lines=args.compact_max_lines)
                    if args.no_context_expansion:
                        packet['budget']['context_expansions_remaining'] = 0
                        packet['packet_id'] = 'packet_' + digest({k:v for k,v in packet.items() if k != 'packet_id'})
                except (ValueError, KeyError, TypeError) as exc:
                    error = str(exc)
            tasks.append(dict(rank=rank, candidate=candidate, context=context, packet=packet, error=error))
        # Fingerprint all input state, including selection and labels, for accurate resume/metrics.
        jobs.append(dict(source=source, tasks=tasks, sample_id=key[0], idx=key[1], pair_id=oracle.get(key, {}).get('pair_id'),
                         ground_truth=_ground_truth(oracle.get(key, {})), ground_truth_cwe=_ground_truth_cwe(oracle.get(key, {})),
                         input_signature=digest(dict(stage2=row, source=source, stage1=stage1.get(key) if stage1 else None))))
    return jobs


def invalid_artifact(job, task, directory, model):
    # Preserve a raw, non-oracle preflight snapshot. Not claimed to match Packet schema.
    raw = dict(sink=task['candidate'], context=task['context'])
    packet_ref = store_packet(directory, raw)
    artifact = dict(protocol_version=PROTOCOL, candidate_id='c_' + digest([job['sample_id'], job['idx'], task['rank'], raw])[:24],
                    packet_ref=packet_ref, pipeline_status='INVALID_INPUT', final_assessment=None,
                    attack_report=None, audit_report=None, validation_errors=[task['error']],
                    run_metadata=dict(run_id=Path(directory).name, model_id=model, prompt_version=digest(PROMPTS), schema_version=PROTOCOL,
                                      context_expansions=0, repair_calls=0, input_tokens=None, output_tokens=None,
                                      latency_ms=None, impact_validation='STATIC'))
    validate('Artifact', artifact)
    return artifact


def process_job(job, engine, directory, model):
    results = []
    for task in job['tasks']:
        if task['error']:
            artifact, history = invalid_artifact(job, task, directory, model), []
        else:
            recovery = lambda packet, requests: expand_packet(job['source'], task['candidate'], task['context'], packet, requests, engine.max_lines)
            artifact, history = engine.process(task['packet'], recovery)
        results.append(dict(sink_rank=task['rank'], prediction=artifact['final_assessment'], artifact=artifact, attempts=history))
    predictions = [r['prediction'] for r in results]
    prediction = 'VULNERABLE' if 'VULNERABLE' in predictions else 'BENIGN' if predictions and all(p == 'BENIGN' for p in predictions) else None
    complete = all(p is not None for p in predictions)
    return dict(protocol=PROTOCOL, sample_id=job['sample_id'], idx=job['idx'], pair_id=job['pair_id'],
                ground_truth=job['ground_truth'], ground_truth_cwe=job['ground_truth_cwe'],
                input_signature=job['input_signature'], prediction=prediction, assessment_scope='selected_candidates',
                run_status='no_candidates' if not results else 'completed' if complete else 'partial',
                candidate_count=len(results), assessed_candidate_count=sum(p is not None for p in predictions), candidate_results=results)


def run(args):
    from .runner import read_jsonl
    if args.direct_source:
        raise ValueError('--protocol compact requires Stage 2; --direct-source is unsupported (use --protocol abp for that baseline)')
    if min(args.start, args.limit) < 0 or args.workers < 1 or args.compact_max_lines < 1:
        raise ValueError('Invalid start/limit/workers/compact-max-lines')
    provider = (args.provider or os.getenv('TRIAGE_PROVIDER', 'openrouter')).strip().lower()
    if provider not in ('openrouter', 'deepseek', 'openai-compatible'):
        raise ValueError('Unsupported provider')
    model = args.model or (os.getenv('DEEPSEEK_TRIAGE_MODEL') or os.getenv('SINK_MODEL') or 'deepseek-chat' if provider == 'deepseek' else os.getenv('TRIAGE_MODEL') or ('qwen3-32b' if provider == 'openai-compatible' else 'qwen/qwen3-32b'))
    model = model.strip()
    if not model:
        raise ValueError('Model must be a non-empty string')
    for settings in STAGE_SETTINGS.values():
        settings['model'] = model
    output = Path(args.output) if args.output else timestamped_run_output('stage3')
    jobs = prepare_jobs(args)
    implementation = {name: digest(Path(__file__).with_name(name).read_text(encoding='utf-8'))
                      for name in ('compact.py', 'compact_validation.py', 'compact_runner.py', 'client.py')}
    endpoint = (os.getenv('TRIAGE_BASE_URL', '') if provider == 'openai-compatible' else
                (os.getenv('DEEPSEEK_BASE_URL') or os.getenv('SINK_BASE_URL') or 'https://api.deepseek.com') if provider == 'deepseek' else
                os.getenv('OPENROUTER_BASE_URL', 'https://openrouter.ai/api/v1'))
    signature = digest(dict(protocol=PROTOCOL, prompts=PROMPTS, schema=BUNDLE, examples=EXAMPLES if not args.no_few_shot else [],
                            implementation=implementation, endpoint=endpoint,
                            model=model, provider=provider, expansion=not args.no_context_expansion, max_lines=args.compact_max_lines))
    manifest = dict(protocol=PROTOCOL, provider=provider, model=model, run_signature=signature, stage2=str(args.stage2), data=str(args.data),
                    selected_samples=len(jobs), known_labels=sum(j['ground_truth'] is not None for j in jobs),
                    candidates=sum(len(j['tasks']) for j in jobs), ready_candidates=sum(t['packet'] is not None for j in jobs for t in j['tasks']),
                    preflight_errors=dict(Counter(t['error'] for j in jobs for t in j['tasks'] if t['error'])), dry_run=args.dry_run,
                    rounds='two role calls; --rounds applies only to ABP', context_recovery='at most one bounded full-function expansion; no invented callers')
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    if args.dry_run:
        # Persist coverage for reproducibility, without model API calls.
        output.parent.mkdir(parents=True, exist_ok=True)
        output.with_name('compact_preflight.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    previous = {}
    if output.exists() and not args.no_resume:
        for row in read_jsonl(output):
            if row.get('run_signature') == signature:
                previous[row['sample_id'], row['idx']] = row
    work, results = [], {}
    for job in jobs:
        key = job['sample_id'], job['idx']
        cached = previous.get(key)
        if cached and cached.get('input_signature') == job['input_signature'] and cached.get('run_status') in ('completed', 'no_candidates'):
            # Verify every referenced snapshot before trusting a resumed result.
            for c in cached['candidate_results']:
                ref = c['artifact']['packet_ref']
                import hashlib
                raw = (output.parent / ref['uri']).read_bytes()
                if hashlib.sha256(raw).hexdigest() != ref['sha256']:
                    raise ValueError('Resume packet hash mismatch')
            results[key] = cached
        else:
            work.append(job)
    output.with_name('manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    api = None
    try:
        if any(t['packet'] is not None for j in work for t in j['tasks']):
            api = client_for(provider, output.parent)
        engine = CompactEngine(api, output.parent, model, few_shot=not args.no_few_shot,
                               max_lines=args.compact_max_lines, expand=not args.no_context_expansion)
        pool = ThreadPoolExecutor(max_workers=args.workers)
        futures = []
        try:
            futures = [pool.submit(process_job, job, engine, output.parent, model) for job in work]
            from tqdm.auto import tqdm
            for future in tqdm(as_completed(futures), total=len(futures), desc='Stage 3 compact', unit='sample'):
                row = future.result()
                row['run_signature'] = signature
                append_jsonl(output, row)
                results[row['sample_id'], row['idx']] = row
                tqdm.write(sample_console_report(row, color=sys.stdout.isatty()), file=sys.stdout)
        except KeyboardInterrupt:
            print("\nCtrl+C received. Cancelling queued samples and aborting active API requests...", flush=True)
            for future in futures:
                future.cancel()
            if api:
                api.cancel()
            pool.shutdown(wait=False, cancel_futures=True)
            raise SystemExit(130)
        except BaseException:
            for future in futures:
                future.cancel()
            if api:
                api.cancel()
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            pool.shutdown(wait=True)
        summary = summarize(results.values())
        output.with_name('summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
        print(json.dumps(summary, indent=2))
        print(f'Results: {output}')
    finally:
        if api:
            api.close()
