"""Chat-model providers for alert triage (Ollama and OpenAI-compatible).

Providers only transport text: the model's answer is returned verbatim and
validated elsewhere. Error messages never contain the API key, request
headers or the prompt.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from typing import Any

import requests

from sentinelai.ai.triage_models import (
    TriageProvider,
    TriageProviderError,
    api_key_endpoint_allowed,
)
from sentinelai.config.models import LLMConfig

#: Responses larger than this are rejected (a triage answer is a few KB).
MAX_RESPONSE_BYTES = 1_000_000
_CHUNK_BYTES = 65_536


def _normalize_endpoint(endpoint: str) -> str:
    if not isinstance(endpoint, str) or not endpoint.startswith(("http://", "https://")):
        raise TriageProviderError("LLM endpoint must start with http:// or https://")
    return endpoint.rstrip("/")


def _new_session() -> requests.Session:
    """A session that ignores proxy environment variables and ``~/.netrc``."""
    session = requests.Session()
    session.trust_env = False
    return session


def _check_api_key_endpoint(endpoint: str, api_key: str) -> None:
    if api_key and not api_key_endpoint_allowed(endpoint):
        raise TriageProviderError(
            "an API key is only sent over https (or to a loopback address)"
        )


#: Request errors caused by a bad endpoint/request, which retrying cannot fix.
_PERMANENT_REQUEST_ERRORS = (
    requests.exceptions.InvalidURL,
    requests.exceptions.MissingSchema,
    requests.exceptions.InvalidSchema,
    requests.exceptions.InvalidHeader,
    requests.exceptions.URLRequired,
)


def _read_limited(
    response: requests.Response, deadline: float | None = None
) -> bytes:
    """Read the body, refusing anything above :data:`MAX_RESPONSE_BYTES`.

    ``deadline`` is a :func:`time.monotonic` value after which reading aborts
    (a slow-drip server must not hold the worker).
    """
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=_CHUNK_BYTES):
        if deadline is not None and time.monotonic() > deadline:
            raise TriageProviderError("response too slow", transient=True)
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise TriageProviderError("LLM response exceeds the size limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _post_json(
    session: requests.Session,
    url: str,
    payload: Mapping[str, Any],
    headers: Mapping[str, str],
    timeout: float,
) -> Any:
    """POST ``payload`` and return the decoded JSON body (safe error messages)."""
    deadline = time.monotonic() + timeout
    try:
        response = session.post(
            url,
            json=payload,
            headers=dict(headers),
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
    except requests.RequestException as exc:
        raise TriageProviderError(
            f"LLM request failed ({type(exc).__name__})",
            transient=not isinstance(exc, _PERMANENT_REQUEST_ERRORS),
        ) from None
    try:
        status = response.status_code
        if not 200 <= status < 300:
            raise TriageProviderError(
                f"LLM returned HTTP {status}", transient=status == 429 or status >= 500
            )
        try:
            body = _read_limited(response, deadline)
        except requests.RequestException as exc:
            raise TriageProviderError(
                f"LLM response could not be read ({type(exc).__name__})", transient=True
            ) from None
    finally:
        response.close()
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise TriageProviderError("LLM returned a non-JSON response") from None


def _require_content(content: Any) -> str:
    if not isinstance(content, str) or not content.strip():
        raise TriageProviderError("LLM returned an empty or unusable answer")
    return content


class OllamaProvider:
    """Ollama ``/api/chat`` with a JSON-schema constrained ``format``."""

    name = "ollama"

    def __init__(
        self,
        endpoint: str,
        model: str,
        timeout: float,
        max_tokens: int,
        session: requests.Session | None = None,
    ) -> None:
        self._endpoint = _normalize_endpoint(endpoint)
        self.model = model
        self._timeout = timeout
        self._max_tokens = max_tokens
        self._owns_session = session is None
        self._session = _new_session() if session is None else session

    def close(self) -> None:
        """Close the HTTP session if this provider created it."""
        if self._owns_session:
            self._session.close()

    def complete(self, system: str, user: str, schema: Mapping[str, Any]) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "format": dict(schema),
            "options": {"temperature": 0, "num_predict": self._max_tokens},
        }
        data = _post_json(
            self._session, f"{self._endpoint}/api/chat", payload, {}, self._timeout
        )
        if not isinstance(data, dict):
            raise TriageProviderError("Ollama response has an unexpected shape")
        message = data.get("message")
        if not isinstance(message, dict):
            raise TriageProviderError("Ollama response has an unexpected shape")
        return _require_content(message.get("content"))


class OpenAICompatProvider:
    """OpenAI-compatible ``/v1/chat/completions`` with strict JSON schema output."""

    name = "openai"

    def __init__(
        self,
        endpoint: str,
        model: str,
        timeout: float,
        max_tokens: int,
        api_key: str = "",
        session: requests.Session | None = None,
    ) -> None:
        self._endpoint = _normalize_endpoint(endpoint)
        _check_api_key_endpoint(self._endpoint, api_key)
        self.model = model
        self._timeout = timeout
        self._max_tokens = max_tokens
        self._api_key = api_key
        self._owns_session = session is None
        self._session = _new_session() if session is None else session

    def __repr__(self) -> str:
        return f"OpenAICompatProvider(model={self.model!r})"

    def close(self) -> None:
        """Close the HTTP session if this provider created it."""
        if self._owns_session:
            self._session.close()

    def complete(self, system: str, user: str, schema: Mapping[str, Any]) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "max_tokens": self._max_tokens,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "triage", "schema": dict(schema), "strict": True},
            },
        }
        headers: dict[str, str] = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        data = _post_json(
            self._session,
            f"{self._endpoint}/v1/chat/completions",
            payload,
            headers,
            self._timeout,
        )
        if not isinstance(data, dict):
            raise TriageProviderError("OpenAI response has an unexpected shape")
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise TriageProviderError("OpenAI response has an unexpected shape")
        message = choices[0].get("message")
        if not isinstance(message, dict):
            raise TriageProviderError("OpenAI response has an unexpected shape")
        return _require_content(message.get("content"))


def create_provider(
    config: LLMConfig, session: requests.Session | None = None
) -> TriageProvider:
    """Build the provider selected by ``config.provider``."""
    provider = config.provider
    if provider == "ollama":
        return OllamaProvider(
            config.endpoint,
            config.model,
            config.timeout_seconds,
            config.max_tokens,
            session=session,
        )
    if provider == "openai":
        return OpenAICompatProvider(
            config.endpoint,
            config.model,
            config.timeout_seconds,
            config.max_tokens,
            api_key=config.api_key,
            session=session,
        )
    raise TriageProviderError(f"Unknown LLM provider {provider!r}; use 'ollama' or 'openai'")
