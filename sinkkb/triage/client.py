from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from ..io import append_jsonl

BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/")
MODEL_ID = os.getenv("TRIAGE_MODEL", "qwen/qwen3-32b")
STAGE_SETTINGS = {
    "hypothesis": dict(
        model=MODEL_ID,
        temperature=0,
        max_tokens=8192,
        reasoning={"enabled": True},
        provider={"require_parameters": True},
    ),
    "validation": dict(
        model=MODEL_ID,
        temperature=0,
        max_tokens=4096,
        reasoning={"enabled": True},
        provider={"require_parameters": True},
    ),
}
_LOG_LOCK = threading.RLock()


class APIError(RuntimeError):
    """A retryable model or transport failure."""


class FatalAPIError(APIError):
    """A non-retryable configuration or request failure."""


class OpenRouter:
    """Small ABP-only OpenRouter client with bounded retries and safe logs."""

    def __init__(
        self,
        key: str,
        log_path: str | Path,
        *,
        base_url: str | None = None,
        client: httpx.Client | None = None,
        sleep=time.sleep,
    ) -> None:
        self.key = key
        self.log_path = Path(log_path)
        self.base_url = (base_url or BASE_URL).rstrip("/")
        self.provider_name = "OpenRouter"
        self.sleep = sleep
        self.client = client or httpx.Client(timeout=180)
        self._cancel_event = threading.Event()

    def _log(self, event: dict[str, Any]) -> None:
        with _LOG_LOCK:
            append_jsonl(self.log_path, event)

    def request(self, method: str, route: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        for attempt in range(3):
            if self._cancel_event.is_set():
                raise FatalAPIError("request cancelled")
            started = time.monotonic()
            response = None
            try:
                response = self.client.request(
                    method,
                    self.base_url + route,
                    headers={"Authorization": "Bearer " + self.key},
                    json=payload,
                )
                event = {
                    "event": "http",
                    "route": route,
                    "attempt": attempt,
                    "elapsed_seconds": time.monotonic() - started,
                    "http_status": response.status_code,
                }
                if response.is_success:
                    try:
                        data = response.json()
                    except ValueError:
                        self._log({**event, "error": "Invalid JSON response"})
                        error = "Invalid JSON response"
                    else:
                        self._log({**event, "raw_response": data})
                        if isinstance(data, dict) and "error" not in data:
                            return data
                        error = f"{self.provider_name} error object or invalid response shape"
                else:
                    detail = response.text.replace(self.key, "[REDACTED]")[:1000]
                    self._log({**event, "error": detail})
                    if response.status_code != 429 and response.status_code < 500:
                        raise FatalAPIError(
                            f"{self.provider_name} HTTP {response.status_code}; "
                            "see the run's requests.jsonl"
                        )
                    error = f"{self.provider_name} HTTP {response.status_code}"
            except (httpx.TransportError, RuntimeError) as exc:
                if self._cancel_event.is_set():
                    raise FatalAPIError("request cancelled") from exc
                if isinstance(exc, RuntimeError):
                    raise
                error = type(exc).__name__
                self._log({
                    "event": "transport_error",
                    "route": route,
                    "attempt": attempt,
                    "error": error,
                })

            if attempt == 2:
                raise APIError(error)

            delay = 2**attempt
            if response is not None and response.headers.get("retry-after"):
                retry_after = response.headers["retry-after"]
                try:
                    delay = max(delay, float(retry_after))
                except ValueError:
                    try:
                        until = parsedate_to_datetime(retry_after)
                        delay = max(delay, (until - datetime.now(timezone.utc)).total_seconds())
                    except (TypeError, ValueError):
                        pass
            while delay > 0:
                chunk = min(delay, 30)
                if self.sleep is time.sleep:
                    self._cancel_event.wait(chunk)
                else:
                    self.sleep(chunk)
                if self._cancel_event.is_set():
                    raise FatalAPIError("request cancelled")
                delay -= chunk

        raise APIError(f"{self.provider_name} request failed")

    def auth_check(self) -> None:
        try:
            response = self.client.get(
                self.base_url + "/key",
                headers={"Authorization": "Bearer " + self.key},
            )
        except httpx.TransportError as exc:
            raise APIError(type(exc).__name__) from exc
        self._log({"event": "auth_check", "http_status": response.status_code})
        if not response.is_success:
            raise FatalAPIError(
                f"OpenRouter key check HTTP {response.status_code}; verify OPENROUTER_API_KEY"
            )

    def preflight(self) -> list[dict[str, Any]]:
        model_id = STAGE_SETTINGS["validation"]["model"]
        data = self.request("GET", "/models/" + model_id + "/endpoints")
        required = {"reasoning", "response_format", "temperature", "max_tokens"}
        compatible = [
            endpoint
            for endpoint in data.get("data", {}).get("endpoints", [])
            if required <= set(endpoint.get("supported_parameters", []))
        ]
        if not compatible:
            raise FatalAPIError(
                "No endpoint advertises the required Thinking/JSON parameters"
            )
        return [
            {
                "provider": item.get("provider_name"),
                "parameters": item.get("supported_parameters"),
            }
            for item in compatible
        ]

    def completion(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
        settings: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body = dict(settings or STAGE_SETTINGS["hypothesis"], messages=messages)
        json_only = body.pop("json_only", False)
        body["response_format"] = {
            "type": "json_schema",
            "json_schema": {
                "name": "agent_response",
                "strict": True,
                "schema": schema,
            },
        }
        if json_only:
            body["response_format"] = {"type": "json_object"}
        response = self.request("POST", "/chat/completions", body)
        generation_id = response.get("id")
        fetch_metadata = os.getenv("OPENROUTER_FETCH_GENERATION_METADATA", "0").strip().lower() in {
            "1",
            "true",
            "yes",
        }
        if generation_id and fetch_metadata:
            try:
                metadata = self.request(
                    "GET", "/generation?id=" + quote(generation_id, safe="")
                )
                response["_generation_metadata"] = {
                    key: metadata.get("data", {}).get(key)
                    for key in (
                        "provider_name",
                        "model",
                        "tokens_prompt",
                        "tokens_completion",
                        "native_tokens_reasoning",
                        "total_cost",
                    )
                }
            except APIError as exc:
                self._log({
                    "event": "generation_metadata_error",
                    "generation_id": generation_id,
                    "error": str(exc),
                })
        return response

    def cancel(self) -> None:
        """Abort in-flight HTTP work after an interactive interrupt."""
        self._cancel_event.set()
        self.client.close()

    def close(self) -> None:
        self.client.close()


class DeepSeek(OpenRouter):
    """DeepSeek transport using its OpenAI-compatible JSON-object mode."""

    def __init__(
        self,
        key: str,
        log_path: str | Path,
        *,
        base_url: str = "https://api.deepseek.com",
        client: httpx.Client | None = None,
        sleep=time.sleep,
    ) -> None:
        super().__init__(
            key,
            log_path,
            base_url=base_url,
            client=client,
            sleep=sleep,
        )
        self.provider_name = "DeepSeek"

    def completion(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
        settings: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        options = settings or STAGE_SETTINGS["hypothesis"]
        body = {
            key: options[key]
            for key in ("model", "temperature", "max_tokens")
            if key in options
        }
        body["messages"] = messages
        # DeepSeek JSON mode enforces JSON syntax; ABP's existing Pydantic
        # validation and one-repair protocol enforce the response schema.
        body["response_format"] = {"type": "json_object"}
        return self.request("POST", "/chat/completions", body)


class OpenAICompatible(DeepSeek):
    """Generic OpenAI-compatible chat-completions endpoint."""

    def __init__(self, key: str, log_path: str | Path, *, base_url: str, client=None, sleep=time.sleep) -> None:
        super().__init__(key, log_path, base_url=base_url, client=client, sleep=sleep)
        self.provider_name = "OpenAI-compatible endpoint"

    def completion(self, messages, schema, settings=None):
        """Forward the Qwen-compatible JSON, thinking, and stream options."""
        options = settings or STAGE_SETTINGS["hypothesis"]
        body = {key: options[key] for key in ("model", "temperature", "max_tokens") if key in options}
        body.update(messages=messages, stream=bool(options.get("stream", False)),
                    response_format={"type": "json_object"})
        if "enable_thinking" in options:
            body["enable_thinking"] = bool(options["enable_thinking"])
        return self.request("POST", "/chat/completions", body)
