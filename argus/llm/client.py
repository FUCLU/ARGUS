from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from ..io import append_jsonl
from .config import LLMConfig

_LOG_LOCK = threading.RLock()


class APIError(RuntimeError):
    """A retryable model or transport failure."""


class FatalAPIError(APIError):
    """A non-retryable configuration or request failure."""


class LLMClient:
    """Chat-completions client driven by an LLMConfig, with bounded retries and safe logs."""

    def __init__(
        self,
        config: LLMConfig,
        log_path: str | Path,
        *,
        client: httpx.Client | None = None,
        sleep=time.sleep,
    ) -> None:
        self.config = config
        self.key = config.api_key
        if not self.key:
            raise FatalAPIError(f"Set {config.api_key_env}")
        self.log_path = Path(log_path)
        self.base_url = config.base_url.rstrip("/")
        self.provider_name = config.provider
        self.sleep = sleep
        self.client = client or httpx.Client(timeout=config.timeout_seconds)
        self._cancel_event = threading.Event()

    def _log(self, event: dict[str, Any]) -> None:
        with _LOG_LOCK:
            append_jsonl(self.log_path, event)

    def request(self, method: str, route: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        attempts = self.config.max_attempts
        for attempt in range(attempts):
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

            if attempt == attempts - 1:
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
        """OpenRouter only: verify the key before a run."""
        if self.config.provider != "openrouter":
            return
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
                f"OpenRouter key check HTTP {response.status_code}; verify {self.config.api_key_env}"
            )

    def preflight(self) -> list[dict[str, Any]]:
        """OpenRouter only: require an endpoint that supports the parameters we send."""
        if self.config.provider != "openrouter":
            return []
        data = self.request("GET", "/models/" + self.config.model + "/endpoints")
        required = {"response_format", "temperature", "max_tokens"}
        if self.config.thinking is not None:
            required.add("reasoning")
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

    def _body(self, messages: list[dict[str, str]], schema: dict[str, Any]) -> dict[str, Any]:
        cfg = self.config
        body: dict[str, Any] = dict(
            model=cfg.model,
            temperature=cfg.temperature,
            max_tokens=cfg.max_tokens,
            messages=messages,
        )
        if cfg.provider == "openrouter":
            body["provider"] = {"require_parameters": True}
            if cfg.thinking is not None:
                body["reasoning"] = {"enabled": cfg.thinking}
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "agent_response", "strict": True, "schema": schema},
            }
        else:
            # JSON mode enforces syntax only; the protocol's Pydantic validation
            # and one-repair loop enforce the response schema.
            body["response_format"] = {"type": "json_object"}
            if cfg.provider == "openai-compatible":
                body["stream"] = False
                if cfg.thinking is not None:
                    body["enable_thinking"] = cfg.thinking
        return body

    def completion(self, messages: list[dict[str, str]], schema: dict[str, Any]) -> dict[str, Any]:
        response = self.request("POST", "/chat/completions", self._body(messages, schema))
        generation_id = response.get("id")
        if generation_id and self.config.fetch_generation_metadata and self.config.provider == "openrouter":
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
