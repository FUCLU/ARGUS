from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


def _normalized_source(code: str) -> str:
    """Normalize layout while preserving whitespace inside quoted literals."""
    output: list[str] = []
    quote: str | None = None
    escaped = False
    pending_space = False
    for char in code:
        if quote is not None:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            if pending_space and output:
                output.append(" ")
            pending_space = False
            quote = char
            output.append(char)
        elif char.isspace():
            pending_space = True
        else:
            if pending_space and output:
                output.append(" ")
            pending_space = False
            output.append(char)
    return "".join(output).strip()


def _normalized_source_with_lines(code: str) -> tuple[str, list[int]]:
    output: list[str] = []
    output_lines: list[int] = []
    quote: str | None = None
    escaped = False
    pending_space_line: int | None = None
    line_number = 1
    for char in code:
        if quote is not None:
            output.append(char)
            output_lines.append(line_number)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in {"'", '"'}:
            if pending_space_line is not None and output:
                output.append(" ")
                output_lines.append(pending_space_line)
            pending_space_line = None
            quote = char
            output.append(char)
            output_lines.append(line_number)
        elif char.isspace():
            if pending_space_line is None:
                pending_space_line = line_number
        else:
            if pending_space_line is not None and output:
                output.append(" ")
                output_lines.append(pending_space_line)
            pending_space_line = None
            output.append(char)
            output_lines.append(line_number)
        if char == "\n":
            line_number += 1
    return "".join(output).strip(), output_lines


def _locate_function_lines(code: str, function: str) -> tuple[int, int] | None:
    normalized_file, line_map = _normalized_source_with_lines(code)
    normalized_function = _normalized_source(function)
    if not normalized_function:
        return None
    spans: set[tuple[int, int]] = set()
    search_from = 0
    while True:
        start = normalized_file.find(normalized_function, search_from)
        if start < 0:
            break
        end = start + len(normalized_function) - 1
        start_line = line_map[start]
        end_line = line_map[end]
        lines = code.splitlines()
        if _normalized_source("\n".join(lines[start_line - 1 : end_line])) == normalized_function:
            spans.add((start_line, end_line))
        search_from = start + 1
    return next(iter(spans)) if len(spans) == 1 else None


def _read_records(path: str | Path) -> Iterable[dict[str, Any]]:
    text = Path(path).read_text(encoding="utf-8-sig").strip()
    if not text:
        return []
    if text.startswith("["):
        rows = json.loads(text)
        if not isinstance(rows, list):
            raise ValueError(f"JSON input must be an array: {path}")
        return (row for row in rows if isinstance(row, dict))
    return (json.loads(line) for line in text.splitlines() if line.strip())


@dataclass(frozen=True)
class PrimeVulFileSource:
    file_name: str
    code: str
    function_start_line: int
    function_end_line: int
    source_kind: str
    revision: str | None = None
    file_hash_match: bool | None = None
    function_match_kind: str = "metadata_lines_exact"


class PrimeVulSourceResolver:
    """Resolve a PrimeVul function to its downloaded full source file.

    Dataset labels and vulnerability metadata are intentionally ignored. The raw
    release index uses only ``func`` and ``func_hash``; file_info contributes only
    source path and function line bounds.
    """

    def __init__(
        self,
        *,
        records_path: str | Path | None = None,
        file_info_path: str | Path | None = None,
        files_root: str | Path | None = None,
        source_manifest_path: str | Path | None = None,
    ) -> None:
        self.files_root = Path(files_root).expanduser() if files_root else None
        self._hashes_by_source: dict[str, set[str]] = {}
        self._file_info: dict[str, Any] = {}
        self._manifest_rows: list[tuple[dict[str, Any], Path]] = []
        self._cache: dict[str, tuple[PrimeVulFileSource | None, str | None]] = {}

        if records_path:
            if not file_info_path:
                raise ValueError("--primevul-records requires --primevul-file-info")
            for row in _read_records(records_path):
                function = row.get("func")
                function_hash = row.get("func_hash")
                if isinstance(function, str) and function and function_hash is not None:
                    self._hashes_by_source.setdefault(_normalized_source(function), set()).add(str(function_hash))
            info = json.loads(Path(file_info_path).read_text(encoding="utf-8-sig"))
            if not isinstance(info, dict):
                raise ValueError("PrimeVul file_info must be a JSON object keyed by func_hash")
            self._file_info = info

        if source_manifest_path:
            manifest_path = Path(source_manifest_path).expanduser().resolve()
            manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
            rows = manifest.get("files", []) if isinstance(manifest, dict) else []
            if not isinstance(rows, list):
                raise ValueError("PrimeVul source manifest field 'files' must be an array")
            self._manifest_rows = [(row, manifest_path.parent) for row in rows if isinstance(row, dict)]

        if not records_path and not source_manifest_path:
            raise ValueError("Provide PrimeVul release metadata or --primevul-source-manifest")

    @staticmethod
    def _candidate_paths(
        stored_path: Any,
        *,
        files_root: Path | None,
        file_hash: Any = None,
        project_file_path: Any = None,
    ) -> list[Path]:
        candidates: list[Path] = []
        if isinstance(stored_path, str) and stored_path.strip():
            stored = Path(stored_path).expanduser()
            if stored.is_absolute():
                candidates.append(stored)
                if files_root:
                    candidates.extend([
                        files_root / stored.name,
                        files_root / "file_contents" / stored.name,
                    ])
                    parts = list(stored.parts)
                    if "file_contents" in parts:
                        suffix = Path(*parts[parts.index("file_contents") + 1 :])
                        candidates.extend([files_root / suffix, files_root / "file_contents" / suffix])
            elif files_root:
                candidates.extend([files_root / stored, files_root / stored.name])
                parts = list(stored.parts)
                if "file_contents" in parts:
                    suffix = Path(*parts[parts.index("file_contents") + 1 :])
                    candidates.extend([files_root / suffix, files_root / "file_contents" / suffix])
        if files_root and file_hash is not None:
            hashed = str(file_hash)
            candidates.extend([
                files_root / hashed,
                files_root / f"{hashed}.c",
                files_root / f"{hashed}.cpp",
                files_root / "file_contents" / hashed,
            ])
        if files_root and isinstance(project_file_path, str) and project_file_path.strip():
            relative = Path(project_file_path)
            candidates.extend([files_root / relative, files_root / "file_contents" / relative])
        unique: list[Path] = []
        seen: set[str] = set()
        for candidate in candidates:
            key = str(candidate.resolve(strict=False)).casefold()
            if key not in seen:
                seen.add(key)
                unique.append(candidate)
        return unique

    @staticmethod
    def _read_source(
        path: Path,
        *,
        file_name: Any,
        start_line: Any,
        end_line: Any,
        function: str,
        source_kind: str,
        revision: Any = None,
        file_hash_match: Any = None,
        function_match_kind: str = "metadata_lines_exact",
    ) -> tuple[PrimeVulFileSource | None, str | None]:
        if not path.is_file():
            return None, "primevul_source_file_missing"
        if not isinstance(file_name, str) or not file_name.strip():
            return None, "primevul_source_filename_missing"
        try:
            start, end = int(start_line), int(end_line)
        except (TypeError, ValueError):
            return None, "primevul_function_lines_missing"
        try:
            code = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None, "primevul_source_file_unreadable"
        lines = code.splitlines()
        if start < 1 or end < start or end > len(lines):
            return None, "primevul_function_lines_out_of_range"
        extracted = "\n".join(lines[start - 1 : end])
        if _normalized_source(extracted) != _normalized_source(function):
            return None, "primevul_function_source_mismatch"
        return PrimeVulFileSource(
            file_name=file_name.replace("\\", "/"),
            code=code,
            function_start_line=start,
            function_end_line=end,
            source_kind=source_kind,
            revision=str(revision) if revision else None,
            file_hash_match=file_hash_match if isinstance(file_hash_match, bool) else None,
            function_match_kind=function_match_kind,
        ), None

    def _release_candidates(self, function: str) -> list[PrimeVulFileSource]:
        normalized = _normalized_source(function)
        hashes = self._hashes_by_source.get(normalized, set())
        matches: list[PrimeVulFileSource] = []
        for function_hash in hashes:
            metadata = self._file_info.get(function_hash)
            if not isinstance(metadata, dict):
                continue
            paths = self._candidate_paths(
                metadata.get("local_file_path"),
                files_root=self.files_root,
                file_hash=metadata.get("file_hash"),
                project_file_path=metadata.get("project_file_path"),
            )
            for path in paths:
                source, _ = self._read_source(
                    path,
                    file_name=metadata.get("project_file_path") or metadata.get("file_name"),
                    start_line=metadata.get("start_line"),
                    end_line=metadata.get("end_line"),
                    function=function,
                    source_kind="primevul_file_info",
                )
                if source:
                    matches.append(source)
                    break
        return matches

    def _manifest_candidates(self, function: str) -> list[PrimeVulFileSource]:
        matches: list[PrimeVulFileSource] = []
        for row, base in self._manifest_rows:
            if row.get("status") != "source_match_found":
                continue
            lines = row.get("file_info_lines")
            if not isinstance(lines, list) or len(lines) != 2:
                continue
            project_path = row.get("project_file_path")
            for item in row.get("matches") or []:
                if not isinstance(item, dict) or not item.get("function_match"):
                    continue
                raw_path = item.get("path")
                if not isinstance(raw_path, str) or not raw_path:
                    continue
                path = Path(raw_path).expanduser()
                if not path.is_absolute():
                    path = base / path
                source, _ = self._read_source(
                    path,
                    file_name=project_path or path.name,
                    start_line=lines[0],
                    end_line=lines[1],
                    function=function,
                    source_kind="primevul_source_manifest",
                    revision=item.get("revision"),
                    file_hash_match=item.get("file_hash_match"),
                )
                if source is None and path.is_file():
                    try:
                        content = path.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        content = ""
                    recovered_lines = _locate_function_lines(content, function) if content else None
                    if recovered_lines is not None:
                        source, _ = self._read_source(
                            path,
                            file_name=project_path or path.name,
                            start_line=recovered_lines[0],
                            end_line=recovered_lines[1],
                            function=function,
                            source_kind="primevul_source_manifest_relocated",
                            revision=item.get("revision"),
                            file_hash_match=item.get("file_hash_match"),
                            function_match_kind="unique_relocated_match",
                        )
                if source:
                    matches.append(source)
        return matches

    def resolve(self, function: str) -> tuple[PrimeVulFileSource | None, str | None]:
        key = _normalized_source(function)
        if key in self._cache:
            return self._cache[key]
        release_candidates = self._release_candidates(function)
        candidates = release_candidates or self._manifest_candidates(function)
        unique: dict[tuple[str, int, int, str], PrimeVulFileSource] = {}
        for source in candidates:
            identity = (
                source.file_name.casefold(),
                source.function_start_line,
                source.function_end_line,
                _normalized_source(source.code),
            )
            unique.setdefault(identity, source)
        if len(unique) == 1:
            result = (next(iter(unique.values())), None)
        elif len(unique) > 1:
            result = (None, "primevul_source_ambiguous")
        elif key in self._hashes_by_source:
            result = (None, "primevul_full_file_unavailable")
        else:
            result = (None, "primevul_file_info_match_missing")
        self._cache[key] = result
        return result
