"""Minimal clients for local LLM servers: Ollama and any OpenAI-compatible API
(LM Studio, llama.cpp server, vLLM, LocalAI).

Standard library only. No SDKs, no telemetry, and proxies are bypassed so
requests to your local model server never leave the machine by accident.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Protocol, Sequence
from urllib.parse import urlparse

Message = dict  # {"role": "system" | "user" | "assistant", "content": str}

# Never route local-model traffic through HTTP(S)_PROXY.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class LLMError(RuntimeError):
    """Raised when the model server cannot be reached or returns an error."""


@dataclass
class ChatResult:
    text: str
    seconds: float
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    generation_seconds: float | None = None

    @property
    def tokens_per_second(self) -> float | None:
        secs = self.generation_seconds or self.seconds
        if self.completion_tokens and secs:
            return self.completion_tokens / secs
        return None


class ChatModel(Protocol):
    name: str

    def chat(self, messages: Sequence[Message], *, json_mode: bool = False,
             temperature: float = 0.0, max_tokens: int | None = None) -> ChatResult: ...


class Embedder(Protocol):
    name: str

    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


# --------------------------------------------------------------------------- HTTP

def _request(url: str, payload: dict | None, timeout: float, headers: dict | None = None) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url, data=data, method="POST" if payload is not None else "GET",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:500]
        raise LLMError(f"{url} returned HTTP {e.code}: {body}") from e
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as e:
        raise LLMError(
            f"Could not reach {url} ({e}). Is your local model server running? "
            "For Ollama run `ollama serve`."
        ) from e
    except json.JSONDecodeError as e:
        raise LLMError(f"{url} returned invalid JSON: {e}") from e


def is_local_endpoint(url: str) -> bool:
    """True if the URL points at this machine or a private network address."""
    host = (urlparse(url).hostname or "").lower()
    if host in {"localhost", "host.docker.internal"} or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # don't resolve hostnames: DNS lookups can leak queries
    return ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified


def _guard(url: str, allow_remote: bool) -> None:
    if not allow_remote and not is_local_endpoint(url):
        raise LLMError(
            f"Refusing to send data to non-local endpoint {url}. "
            "This tool is local-first; pass --allow-remote if you really mean it."
        )


def _normalise_base(url: str) -> str:
    url = url.strip().rstrip("/")
    return url if url.startswith(("http://", "https://")) else f"http://{url}"


# --------------------------------------------------------------------------- Ollama

class OllamaLLM:
    def __init__(self, model: str, base_url: str | None = None, timeout: float = 600,
                 allow_remote: bool = False, num_ctx: int | None = None):
        self.name = model
        self.base_url = _normalise_base(base_url or os.environ.get("OLLAMA_HOST") or "http://localhost:11434")
        self.timeout = timeout
        self.num_ctx = num_ctx
        _guard(self.base_url, allow_remote)

    def chat(self, messages, *, json_mode=False, temperature=0.0, max_tokens=None) -> ChatResult:
        options: dict = {"temperature": temperature}
        if max_tokens:
            options["num_predict"] = max_tokens
        if self.num_ctx:
            options["num_ctx"] = self.num_ctx
        payload = {"model": self.name, "messages": list(messages), "stream": False, "options": options}
        if json_mode:
            payload["format"] = "json"
        start = time.perf_counter()
        data = _request(f"{self.base_url}/api/chat", payload, self.timeout)
        elapsed = time.perf_counter() - start
        eval_ns = data.get("eval_duration") or 0
        return ChatResult(
            text=(data.get("message") or {}).get("content", ""),
            seconds=elapsed,
            prompt_tokens=data.get("prompt_eval_count"),
            completion_tokens=data.get("eval_count"),
            generation_seconds=eval_ns / 1e9 if eval_ns else None,
        )

    def list_models(self) -> list[str]:
        data = _request(f"{self.base_url}/api/tags", None, 15)
        return [m.get("name", "") for m in data.get("models", [])]


class OllamaEmbedder:
    def __init__(self, model: str = "nomic-embed-text", base_url: str | None = None,
                 timeout: float = 600, allow_remote: bool = False):
        self.name = model
        self.base_url = _normalise_base(base_url or os.environ.get("OLLAMA_HOST") or "http://localhost:11434")
        self.timeout = timeout
        _guard(self.base_url, allow_remote)

    def embed(self, texts):
        data = _request(f"{self.base_url}/api/embed", {"model": self.name, "input": list(texts)}, self.timeout)
        vectors = data.get("embeddings")
        if not isinstance(vectors, list) or len(vectors) != len(texts):
            raise LLMError(f"Unexpected embedding response from Ollama model {self.name!r}")
        return vectors


# --------------------------------------------------------------------------- OpenAI-compatible

class OpenAICompatLLM:
    """Works with LM Studio, llama.cpp `llama-server`, vLLM, LocalAI, etc."""

    def __init__(self, model: str, base_url: str | None = None, api_key: str | None = None,
                 timeout: float = 600, allow_remote: bool = False):
        self.name = model
        self.base_url = _normalise_base(base_url or os.environ.get("OPENAI_BASE_URL") or "http://localhost:1234/v1")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY") or "not-needed"
        self.timeout = timeout
        _guard(self.base_url, allow_remote)

    def chat(self, messages, *, json_mode=False, temperature=0.0, max_tokens=None) -> ChatResult:
        payload: dict = {"model": self.name, "messages": list(messages), "temperature": temperature, "stream": False}
        if max_tokens:
            payload["max_tokens"] = max_tokens
        start = time.perf_counter()
        data = _request(f"{self.base_url}/chat/completions", payload, self.timeout,
                        {"Authorization": f"Bearer {self.api_key}"})
        elapsed = time.perf_counter() - start
        try:
            text = data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError(f"Unexpected chat response: {str(data)[:300]}") from e
        usage = data.get("usage") or {}
        return ChatResult(text=text, seconds=elapsed, prompt_tokens=usage.get("prompt_tokens"),
                          completion_tokens=usage.get("completion_tokens"))

    def list_models(self) -> list[str]:
        data = _request(f"{self.base_url}/models", None, 15, {"Authorization": f"Bearer {self.api_key}"})
        return [m.get("id", "") for m in data.get("data", [])]


class OpenAICompatEmbedder:
    def __init__(self, model: str, base_url: str | None = None, api_key: str | None = None,
                 timeout: float = 600, allow_remote: bool = False):
        self.name = model
        self.base_url = _normalise_base(base_url or os.environ.get("OPENAI_BASE_URL") or "http://localhost:1234/v1")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY") or "not-needed"
        self.timeout = timeout
        _guard(self.base_url, allow_remote)

    def embed(self, texts):
        data = _request(f"{self.base_url}/embeddings", {"model": self.name, "input": list(texts)}, self.timeout,
                        {"Authorization": f"Bearer {self.api_key}"})
        items = sorted(data.get("data", []), key=lambda d: d.get("index", 0))
        if len(items) != len(texts):
            raise LLMError(f"Unexpected embedding response for model {self.name!r}")
        return [d["embedding"] for d in items]


# --------------------------------------------------------------------------- Testing

class MockLLM:
    """Deterministic stand-in for tests and dry runs."""

    def __init__(self, responder: Callable[[Sequence[Message]], str] | str = "", name: str = "mock"):
        self.name = name
        self._responder = responder
        self.calls: list[list[Message]] = []

    def chat(self, messages, *, json_mode=False, temperature=0.0, max_tokens=None) -> ChatResult:
        self.calls.append(list(messages))
        text = self._responder(messages) if callable(self._responder) else self._responder
        return ChatResult(text=text, seconds=0.0, prompt_tokens=0, completion_tokens=len(text.split()))


# --------------------------------------------------------------------------- Factories & helpers

PROVIDERS = ("ollama", "openai")


def make_llm(provider: str, model: str, base_url: str | None = None, allow_remote: bool = False,
             timeout: float = 600) -> ChatModel:
    if provider == "ollama":
        return OllamaLLM(model, base_url, timeout=timeout, allow_remote=allow_remote)
    if provider == "openai":
        return OpenAICompatLLM(model, base_url, timeout=timeout, allow_remote=allow_remote)
    raise ValueError(f"Unknown provider {provider!r}; choose one of {PROVIDERS}")


def make_embedder(provider: str, model: str, base_url: str | None = None, allow_remote: bool = False) -> Embedder:
    if provider == "ollama":
        return OllamaEmbedder(model, base_url, allow_remote=allow_remote)
    if provider == "openai":
        return OpenAICompatEmbedder(model, base_url, allow_remote=allow_remote)
    raise ValueError(f"Unknown provider {provider!r}; choose one of {PROVIDERS}")


def extract_json(text: str) -> dict | None:
    """Return the first JSON object found in model output (tolerates prose and ``` fences)."""
    text = text.strip()
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch == "{":
            try:
                value, _ = decoder.raw_decode(text[i:])
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                return value
    return None
