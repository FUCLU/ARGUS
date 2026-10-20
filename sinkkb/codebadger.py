from __future__ import annotations

import asyncio
import hashlib
import json
import re
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any


class CodeBadgerError(RuntimeError):
    pass


def cache_bound_source(code: str, filename: str) -> str:
    """Bind CodeBadger's content cache to a staged filename without shifting source lines."""
    digest = hashlib.sha256(filename.encode("utf-8")).hexdigest()
    return code + f"\n/* sink-context-filename-sha256:{digest} */\n"


def _model_dump(value: Any) -> dict[str, Any] | None:
    dump = getattr(value, "model_dump", None)
    if not callable(dump):
        return None
    try:
        result = dump(mode="python")
    except TypeError:
        result = dump()
    return result if isinstance(result, dict) else None


def decode_tool_result(result: Any) -> Any:
    if result is None or isinstance(result, (str, int, float, bool, list, dict)):
        return result
    dumped = _model_dump(result) or {}
    structured = (
        dumped.get("structuredContent")
        or dumped.get("structured_content")
        or getattr(result, "structuredContent", None)
        or getattr(result, "structured_content", None)
    )
    if structured is not None:
        return structured
    content = dumped.get("content") or getattr(result, "content", None) or []
    texts = []
    for item in content:
        value = item.get("text") if isinstance(item, dict) else getattr(item, "text", None)
        if isinstance(value, str):
            texts.append(value)
    joined = "\n".join(texts).strip()
    if joined:
        try:
            return json.loads(joined)
        except json.JSONDecodeError:
            return joined
    return dumped


@dataclass(frozen=True)
class ToolSpec:
    properties: frozenset[str] | None


class CodeBadgerClient:
    REQUIRED_TOOLS = frozenset({
        "generate_cpg",
        "get_cpg_status",
        "run_cpgql_query",
        "get_program_slice",
        "get_variable_flow",
    })

    def __init__(self, url: str = "http://localhost:4242/mcp") -> None:
        self.url = url
        self._stack: AsyncExitStack | None = None
        self._session: Any = None
        self.tools: dict[str, ToolSpec] = {}

    async def __aenter__(self) -> "CodeBadgerClient":
        try:
            from mcp import ClientSession
            from mcp.client.streamable_http import streamable_http_client
        except ImportError as exc:
            raise CodeBadgerError("Missing MCP SDK; install requirements.txt") from exc

        stack = AsyncExitStack()
        self._stack = stack
        try:
            streams = await stack.enter_async_context(streamable_http_client(self.url))
            self._session = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
            await self._session.initialize()
            listed = await self._session.list_tools()
            for tool in getattr(listed, "tools", None) or []:
                name = getattr(tool, "name", "")
                if not name:
                    continue
                schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", None)
                if schema is None:
                    data = _model_dump(tool) or {}
                    schema = data.get("inputSchema") or data.get("input_schema")
                properties = None
                if isinstance(schema, dict) and isinstance(schema.get("properties"), dict):
                    properties = frozenset(schema["properties"])
                self.tools[name] = ToolSpec(properties)
            missing = sorted(self.REQUIRED_TOOLS - self.tools.keys())
            if missing:
                raise CodeBadgerError("CodeBadger is missing required tools: " + ", ".join(missing))
            return self
        except BaseException:
            await stack.aclose()
            self._stack = None
            self._session = None
            self.tools.clear()
            raise

    async def __aexit__(self, exc_type, exc, tb) -> None:
        stack = self._stack
        self._stack = None
        try:
            if stack is not None:
                await stack.__aexit__(exc_type, exc, tb)
        finally:
            self._session = None
            self.tools.clear()

    def _supported_args(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        spec = self.tools.get(name)
        if spec is None or spec.properties is None:
            return args
        return {key: value for key, value in args.items() if key in spec.properties}

    async def call(self, name: str, args: dict[str, Any]) -> Any:
        if self._session is None:
            raise CodeBadgerError("Client is not connected")
        if name not in self.tools:
            raise CodeBadgerError(f"Unknown CodeBadger tool: {name}")
        result = await self._session.call_tool(name, self._supported_args(name, args))
        decoded = decode_tool_result(result)
        dumped = _model_dump(result) or {}
        if (
            getattr(result, "isError", False)
            or getattr(result, "is_error", False)
            or dumped.get("isError", False)
            or dumped.get("is_error", False)
        ):
            raise CodeBadgerError(f"{name} failed: {decoded}")
        if isinstance(decoded, dict) and decoded.get("success") is False:
            raise CodeBadgerError(f"{name} failed: {decoded.get('error') or decoded}")
        return decoded

    async def ensure_snippet_cpg(
        self,
        code: str,
        *,
        language: str,
        filename: str,
        wait_timeout: float = 300.0,
        poll_interval: float = 1.0,
    ) -> dict[str, Any]:
        generated = await self.call("generate_cpg", {
            "source_type": "snippet",
            "code": cache_bound_source(code, filename),
            "language": language,
            "filename": filename,
        })
        if not isinstance(generated, dict) or not generated.get("codebase_hash"):
            raise CodeBadgerError(f"Invalid generate_cpg result: {generated!r}")
        codebase_hash = str(generated["codebase_hash"])
        if str(generated.get("status", "")).lower() in {"ready", "cached"}:
            return {**generated, "query_filename": filename}
        deadline = asyncio.get_running_loop().time() + wait_timeout
        last: Any = generated
        while asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(poll_interval)
            last = await self.call("get_cpg_status", {"codebase_hash": codebase_hash})
            if isinstance(last, dict):
                status = str(last.get("status", "")).lower()
                if status in {"ready", "cached"}:
                    return {**last, "codebase_hash": codebase_hash, "query_filename": filename}
                if status in {"failed", "error", "not_found"}:
                    raise CodeBadgerError(f"CPG generation failed: {last!r}")
        raise CodeBadgerError(f"Timed out waiting for CPG: {last!r}")

    @staticmethod
    def _query_rows(data: Any) -> list[dict[str, Any]]:
        if isinstance(data, str):
            try:
                return CodeBadgerClient._query_rows(json.loads(data))
            except json.JSONDecodeError:
                return []
        if isinstance(data, dict):
            if "data" in data:
                return CodeBadgerClient._query_rows(data["data"])
            return [data]
        if isinstance(data, list):
            rows: list[dict[str, Any]] = []
            for item in data:
                rows.extend(CodeBadgerClient._query_rows(item))
            return rows
        return []

    async def calls_on_lines(
        self,
        *,
        codebase_hash: str,
        filename: str,
        line_start: int,
        line_end: int,
        timeout: int = 30,
    ) -> list[dict[str, Any]]:
        safe_filename = json.dumps(filename, ensure_ascii=True)
        query = f'''cpg.call
  .filter(c => {{
    val f = c.file.name.headOption.getOrElse("").replace("\\\\", "/")
    val target = {safe_filename}.replace("\\\\", "/")
    f == target || f.endsWith("/" + target) || target.endsWith("/" + f)
  }})
  .filter(c => c.lineNumber.exists(n => n >= {int(line_start)} && n <= {int(line_end)}))
  .map(c => Map(
    "node_id" -> c.id,
    "name" -> c.name,
    "code" -> c.code,
    "filename" -> c.file.name.headOption.getOrElse(""),
    "line" -> c.lineNumber.getOrElse(-1),
    "identifiers" -> c.argument.ast.isIdentifier.name.l.distinct
  )).l'''
        raw = await self.call("run_cpgql_query", {
            "codebase_hash": codebase_hash,
            "query": query,
            "timeout": timeout,
        })
        return self._query_rows(raw)

    async def call_context(
        self,
        *,
        codebase_hash: str,
        node_id: int,
        relevant_lines: list[int],
        hop_limit: int = 1,
        timeout: int = 60,
    ) -> list[dict[str, Any]]:
        lines = sorted({int(line) for line in relevant_lines if int(line) > 0})
        if not lines:
            return []
        line_set = ", ".join(str(line) for line in lines)
        max_hops = max(0, min(int(hop_limit), 3))
        query = f'''{{
val relevantLines = Set({line_set})
val maxHops = {max_hops}
cpg.call.filter(_.id == {int(node_id)}L).headOption.toList.flatMap {{ anchor =>
  val owner = anchor.method
  val anchorLine = anchor.lineNumber.getOrElse(-1)
  val selectedCalls = owner.call
    .filterNot(_.name.toLowerCase.startsWith("<operator"))
    .filter(_.code.contains("("))
    .filter(c => c.lineNumber.exists(relevantLines.contains))
    .l
    .sortBy(c => (math.abs(c.lineNumber.getOrElse(anchorLine) - anchorLine), c.lineNumber.getOrElse(-1), c.name))
    .take(16)
  val sites = selectedCalls.map {{ call =>
    val allTargets = call.callee.l
    val targets = allTargets.filterNot(_.isExternal).filter(_.lineNumber.nonEmpty)
    val hasExternalTarget = allTargets.exists(_.isExternal)
    Map(
      "relation" -> (if (targets.nonEmpty) "call_site" else if (hasExternalTarget) "external_call" else "unresolved_call"),
      "name" -> call.name,
      "file_name" -> call.file.name.headOption.getOrElse(""),
      "line" -> call.lineNumber.getOrElse(-1),
      "resolved" -> (targets.nonEmpty || hasExternalTarget),
      "callee_names" -> targets.map(_.name),
      "external_target_names" -> allTargets.filter(_.isExternal).map(_.name)
    )
  }}
  var calleeFrontier = selectedCalls.flatMap(call => call.callee.filterNot(_.isExternal).filter(_.lineNumber.nonEmpty).l).distinct
  var seenCallees = Set[Long](owner.id)
  var calleeRows = List.empty[Map[String, Any]]
  var calleeDepth = 1
  var methodBudget = 12
  while (calleeDepth <= maxHops && calleeFrontier.nonEmpty && methodBudget > 0) {{
    val fresh = calleeFrontier.filterNot(method => seenCallees.contains(method.id)).distinct.take(methodBudget)
    seenCallees ++= fresh.map(_.id)
    methodBudget -= fresh.size
    calleeRows = calleeRows ++ fresh.map(method => Map(
      "relation" -> "callee",
      "name" -> method.name,
      "file_name" -> method.filename,
      "line" -> method.lineNumber.getOrElse(-1),
      "method_line_start" -> method.lineNumber.getOrElse(-1),
      "method_line_end" -> method.lineNumberEnd.getOrElse(-1),
      "hop" -> calleeDepth,
      "resolved" -> true
    ))
    calleeFrontier = fresh.flatMap(method => method.call
      .filterNot(_.name.toLowerCase.startsWith("<operator"))
      .filter(_.code.contains("("))
      .flatMap(_.callee.filterNot(_.isExternal).filter(_.lineNumber.nonEmpty).l).l).distinct
    calleeDepth += 1
  }}
  var callerFrontier = owner.callIn.filter(_.lineNumber.nonEmpty)
    .map(call => (call.method, call.lineNumber.getOrElse(-1))).l.distinct
  var seenCallers = Set[Long](owner.id)
  var callerRows = List.empty[Map[String, Any]]
  var callerDepth = 1
  methodBudget = 12
  while (callerDepth <= maxHops && callerFrontier.nonEmpty && methodBudget > 0) {{
    val fresh = callerFrontier.filterNot(item => seenCallers.contains(item._1.id)).distinct.take(methodBudget)
    seenCallers ++= fresh.map(_._1.id)
    methodBudget -= fresh.size
    callerRows = callerRows ++ fresh.map(item => Map(
      "relation" -> "caller",
      "name" -> item._1.name,
      "file_name" -> item._1.filename,
      "line" -> item._2,
      "method_line_start" -> item._1.lineNumber.getOrElse(-1),
      "method_line_end" -> item._1.lineNumberEnd.getOrElse(-1),
      "hop" -> callerDepth,
      "resolved" -> true
    ))
    callerFrontier = fresh.flatMap(item => item._1.callIn
      .filter(_.lineNumber.nonEmpty)
      .map(call => (call.method, call.lineNumber.getOrElse(-1))).l).distinct
    callerDepth += 1
  }}
  sites ++ calleeRows ++ callerRows
}}
}}'''
        raw = await self.call("run_cpgql_query", {
            "codebase_hash": codebase_hash,
            "query": query,
            "timeout": timeout,
        })
        if isinstance(raw, dict) and isinstance(raw.get("data"), str):
            message = raw["data"]
            if "Syntax Error" in message or re.search(r"-- \[E\d+\]", message):
                raise CodeBadgerError(f"CPGQL query failed: {message}")
        return self._query_rows(raw)

    async def program_slice(
        self,
        *,
        codebase_hash: str,
        node_id: int,
        direction: str,
        max_depth: int,
        include_control_flow: bool = True,
        timeout: int = 60,
    ) -> Any:
        return await self.call("get_program_slice", {
            "codebase_hash": codebase_hash,
            "node_id": node_id,
            "direction": direction,
            "max_depth": max_depth,
            "include_control_flow": include_control_flow,
            "timeout": timeout,
            "detail": "full",
        })

    async def variable_flow(
        self,
        *,
        codebase_hash: str,
        location: str,
        variable: str,
        direction: str,
        timeout: int = 60,
    ) -> Any:
        spec = self.tools.get("get_variable_flow")
        variable_key = "variable"
        if spec and spec.properties is not None and variable_key not in spec.properties:
            variable_key = next(
                (key for key in ("variable_name", "name") if key in spec.properties),
                "",
            )
            if not variable_key:
                raise CodeBadgerError("get_variable_flow exposes no variable-name argument")
        return await self.call("get_variable_flow", {
            "codebase_hash": codebase_hash,
            "location": location,
            variable_key: variable,
            "direction": direction,
            "timeout": timeout,
            "detail": "full",
        })
