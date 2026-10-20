from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

from sinkkb.codebadger import CodeBadgerClient
from sinkkb.context import build_sample_context
from sinkkb.io import append_jsonl, timestamped_run_output
from sinkkb.primevul_source import PrimeVulSourceResolver


def load_rows(path: str | Path) -> list[dict[str, Any]]:
    text = Path(path).read_text(encoding="utf-8-sig").strip()
    if not text:
        return []
    if text.startswith("["):
        rows = json.loads(text)
        if not isinstance(rows, list):
            raise ValueError("JSON input must be an array")
        return rows
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def latest_successful_results(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row.get("status") == "ok" and row.get("sample_id") is not None:
            latest[str(row["sample_id"])] = row
    return latest


def prepare_output(path: Path, *, no_resume: bool) -> None:
    """Start a fresh JSONL artifact when the CLI explicitly disables resume."""
    if no_resume and path.exists():
        path.unlink()


def context_packet_key(
    source: dict[str, Any],
    result: dict[str, Any],
    args: argparse.Namespace,
    source_resolver: PrimeVulSourceResolver | None,
) -> str:
    code = str(source.get("func", source.get("input", "")))
    file_source_signature = None
    if source_resolver is not None:
        file_source, _ = source_resolver.resolve(code)
        if file_source is not None:
            file_source_signature = {
                "file_name": file_source.file_name,
                "function_start_line": file_source.function_start_line,
                "function_end_line": file_source.function_end_line,
                "revision": file_source.revision,
                "file_hash_match": file_source.file_hash_match,
                "function_match_kind": file_source.function_match_kind,
                "content_sha256": hashlib.sha256(file_source.code.encode("utf-8")).hexdigest(),
            }
    payload = {
        "func": code,
        "sink_candidates": (result.get("sink_candidates") or [])[:args.max_candidates],
        "file_source": file_source_signature,
        "context_options": {
            "language": args.language,
            "max_candidates": args.max_candidates,
            "max_operands": args.max_operands,
            "backward_depth": args.backward_depth,
            "forward_depth": args.forward_depth,
            "call_hops": args.call_hops,
            "max_context_lines": args.max_context_lines,
            "cpg_timeout": args.cpg_timeout,
            "query_timeout": args.query_timeout,
            "include_raw": args.include_raw,
        },
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build CodeBadger/Joern context packets for localized sink candidates.")
    parser.add_argument("--data", required=True, help="Label-free source JSON/JSONL")
    parser.add_argument("--results", required=True, help="Sink-localization result JSONL")
    parser.add_argument(
        "--output", default=None,
        help="Output JSONL (default: outputs/runs/<timestamp>/stage2.jsonl)",
    )
    parser.add_argument("--codebadger-url", default="http://localhost:4242/mcp")
    parser.add_argument("--language", choices=["c", "cpp"], default="c")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--max-candidates", type=int, default=3)
    parser.add_argument("--max-operands", type=int, default=8)
    parser.add_argument("--backward-depth", type=int, default=20)
    parser.add_argument("--forward-depth", type=int, default=10)
    parser.add_argument("--call-hops", type=int, choices=range(0, 4), default=1)
    parser.add_argument("--max-context-lines", type=int, default=120)
    parser.add_argument("--cpg-timeout", type=float, default=300.0)
    parser.add_argument("--query-timeout", type=int, default=60)
    parser.add_argument("--include-raw", action="store_true", help="Include raw CodeBadger reports for debugging")
    parser.add_argument("--primevul-records", help="PrimeVul release JSONL used only to map func -> func_hash")
    parser.add_argument("--primevul-file-info", help="PrimeVul file_info.json keyed by func_hash")
    parser.add_argument("--primevul-files-root", help="Root containing PrimeVul file_contents, if local_file_path is relative")
    parser.add_argument("--primevul-source-manifest", help="Manifest of source files already fetched and function-verified")
    parser.add_argument("--no-resume", action="store_true")
    return parser


async def run(args: argparse.Namespace) -> None:
    if bool(args.primevul_records) != bool(args.primevul_file_info):
        raise SystemExit("--primevul-records and --primevul-file-info must be provided together")
    if args.primevul_files_root and not args.primevul_records:
        raise SystemExit("--primevul-files-root requires --primevul-records and --primevul-file-info")
    sources = load_rows(args.data)
    predictions = latest_successful_results(load_rows(args.results))
    source_resolver = None
    if args.primevul_records or args.primevul_file_info or args.primevul_source_manifest:
        source_resolver = PrimeVulSourceResolver(
            records_path=args.primevul_records,
            file_info_path=args.primevul_file_info,
            files_root=args.primevul_files_root,
            source_manifest_path=args.primevul_source_manifest,
        )
    selected = sources[args.start:]
    if args.limit > 0:
        selected = selected[:args.limit]

    output = Path(args.output) if args.output else timestamped_run_output("stage2")
    prepare_output(output, no_resume=args.no_resume)
    completed: set[str] = set()
    completed_rows: dict[str, dict[str, Any]] = {}
    if output.exists() and not args.no_resume:
        for row in load_rows(output):
            if row.get("status") in {"ok", "partial"}:
                key = str(row.get("sample_id"))
                completed.add(key)
                completed_rows[key] = row

    print(json.dumps({
        "selected": len(selected),
        "sink_results_available": sum(str(row.get("sample_id")) in predictions for row in selected),
        "already_completed": sum(str(row.get("sample_id")) in completed for row in selected),
        "context_input_fields": ["func", "sink_candidates"],
        "excluded_fields": ["sample_id", "idx", "label", "cwe", "pair_id"],
        "label_policy": "Processed rows may be loaded, but only func and prior sink candidates are submitted to CodeBadger.",
    }, indent=2))

    async with CodeBadgerClient(args.codebadger_url) as client:
        project_cpg_cache: dict[tuple[str, str], dict[str, Any]] = {}
        function_cpg_cache: dict[tuple[str, str], dict[str, Any]] = {}
        context_packet_cache: dict[str, dict[str, Any]] = {}
        for source in selected:
            sample_id = str(source.get("sample_id"))
            prior = completed_rows.get(sample_id)
            result = predictions.get(sample_id)
            if prior is None or result is None or result.get("idx") != source.get("idx"):
                continue
            cache_key = context_packet_key(source, result, args, source_resolver)
            context_packet_cache.setdefault(cache_key, prior)
        for position, source in enumerate(selected, 1):
            sample_id = str(source.get("sample_id"))
            if sample_id in completed:
                print(f"[{position}/{len(selected)}] {sample_id} skip=completed")
                continue
            result = predictions.get(sample_id)
            if result is None:
                row = {
                    "sample_id": sample_id,
                    "idx": source.get("idx"),
                    "status": "error",
                    "contexts": [],
                    "errors": ["missing successful sink-localization result"],
                }
            elif result.get("idx") != source.get("idx"):
                row = {
                    "sample_id": sample_id,
                    "idx": source.get("idx"),
                    "status": "error",
                    "contexts": [],
                    "errors": [
                        "source/result idx mismatch: "
                        f"source={source.get('idx')!r}, result={result.get('idx')!r}"
                    ],
                }
            else:
                cache_key = context_packet_key(source, result, args, source_resolver)
                cached_context = context_packet_cache.get(cache_key)
                if cached_context is not None:
                    row = {**cached_context, "sample_id": sample_id, "idx": source.get("idx")}
                    row["stats"] = {
                        **(cached_context.get("stats") or {}),
                        "context_cache_reused": True,
                        "cpgs_created": 0,
                        "project_cpgs_created": 0,
                    }
                else:
                    row = await build_sample_context(
                        client,
                        source,
                        result,
                        language=args.language,
                        max_candidates=args.max_candidates,
                        max_operands=args.max_operands,
                        backward_depth=args.backward_depth,
                        forward_depth=args.forward_depth,
                        call_hops=args.call_hops,
                        max_context_lines=args.max_context_lines,
                        cpg_timeout=args.cpg_timeout,
                        query_timeout=args.query_timeout,
                        include_raw=args.include_raw,
                        primevul_source_resolver=source_resolver,
                        project_cpg_cache=project_cpg_cache,
                        function_cpg_cache=function_cpg_cache,
                    )
                    if row.get("status") in {"ok", "partial"}:
                        context_packet_cache[cache_key] = row
            append_jsonl(output, row)
            stats = row.get("stats") or {}
            print(
                f"[{position}/{len(selected)}] {sample_id} status={row['status']} "
                f"contexts={stats.get('context_ok', 0)}/{stats.get('candidate_count', 0)} "
                f"function_cpgs={stats.get('cpgs_created', 0)}"
                f" file_cpgs={stats.get('project_cpgs_created', 0)}"
                f" packet_cache={stats.get('context_cache_reused', False)}"
            )


def main() -> None:
    asyncio.run(run(build_parser().parse_args()))


if __name__ == "__main__":
    main()
