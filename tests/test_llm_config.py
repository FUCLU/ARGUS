import pytest

from argus.llm.client import FatalAPIError, LLMClient
from argus.llm.config import DEFAULT_CONFIG_PATH, LLMConfig, load_llm_config


def test_default_yaml_loads():
    cfg = load_llm_config(DEFAULT_CONFIG_PATH)
    assert cfg.provider == "openrouter" and cfg.temperature == 0


def test_override_and_validation(tmp_path):
    path = tmp_path / "llm.yaml"
    path.write_text("provider: openai-compatible\nmodel: qwen3-32b\nbase_url: http://x/v1\napi_key_env: K\n")
    assert load_llm_config(path, model="other").model == "other"
    path.write_text("provider: nope\n")
    with pytest.raises(ValueError):
        load_llm_config(path)
    path.write_text("bogus: 1\n")
    with pytest.raises(ValueError):
        load_llm_config(path)


def test_request_body_per_provider(monkeypatch, tmp_path):
    monkeypatch.setenv("K", "secret")
    schema = {"type": "object"}
    messages = [{"role": "user", "content": "hi"}]
    base = dict(api_key_env="K", base_url="http://x/v1", model="m")
    body = LLMClient(LLMConfig(provider="openrouter", **base), tmp_path / "l.jsonl")._body(messages, schema)
    assert body["response_format"]["type"] == "json_schema" and body["reasoning"] == {"enabled": True}
    body = LLMClient(LLMConfig(provider="openai-compatible", thinking=False, **base), tmp_path / "l.jsonl")._body(messages, schema)
    assert body["response_format"] == {"type": "json_object"} and body["enable_thinking"] is False
    body = LLMClient(LLMConfig(provider="deepseek", thinking=None, **base), tmp_path / "l.jsonl")._body(messages, schema)
    assert "enable_thinking" not in body and "reasoning" not in body


def test_missing_key_is_fatal(monkeypatch, tmp_path):
    monkeypatch.delenv("K", raising=False)
    with pytest.raises(FatalAPIError):
        LLMClient(LLMConfig(api_key_env="K"), tmp_path / "l.jsonl")
