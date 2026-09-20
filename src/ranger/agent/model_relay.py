from __future__ import annotations

import logging
import os
import time
from urllib.parse import urlsplit

import requests
from flask import Flask, jsonify, request


class ModelRelayError(ValueError):
    pass


class ModelUpstreamAuthError(ModelRelayError):
    pass


class ModelUpstreamTimeoutError(ModelRelayError):
    pass


class ModelUpstreamConnectionError(ModelRelayError):
    pass


def validate_endpoint(endpoint: str, allowed: set[str]) -> str:
    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path not in {"", "/"}:
        raise ModelRelayError("model endpoint must be an explicit http(s) origin")
    if any("*" in item or "/0" in item for item in allowed) or parsed.hostname not in allowed:
        raise ModelRelayError(f"model endpoint is not approved: {parsed.hostname}")
    return endpoint.rstrip("/")


def create_model_relay_app(*, upstream: str, provider: str, model: str,
                           api_key: str | None = None,
                           allowed_endpoints: set[str] | None = None,
                           timeout: float = 180, logger: logging.Logger | None = None) -> Flask:
    allowed = allowed_endpoints or {urlsplit(upstream).hostname or ""}
    upstream = validate_endpoint(upstream, allowed)
    if provider not in {"ollama", "deepseek"} or not model:
        raise ModelRelayError("provider and model are not approved")
    log = logger or logging.getLogger("ranger.model_relay")
    app = Flask(__name__)
    request_count = 0

    @app.get("/healthz")
    def healthz():
        return jsonify({"ok": True, "provider": provider, "model": model})

    @app.route("/v1/chat/completions", methods=["POST"])
    @app.route("/api/chat", methods=["POST"])
    def chat():
        nonlocal request_count
        request_count += 1
        started = time.monotonic()
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or any(key in body for key in ("upstream", "url", "endpoint")):
            return jsonify({"error": "invalid or destination-overriding request"}), 400
        requested_provider = request.headers.get("X-Tempera-Provider", provider)
        requested_model = body.get("model", request.headers.get("X-Tempera-Model", model))
        if requested_provider != provider or requested_model != model:
            return jsonify({"error": "provider/model is not approved"}), 403
        if provider == "ollama":
            target = f"{upstream}/api/chat"
            payload = {**body, "model": model, "stream": False}
            headers = {}
        else:
            target = f"{upstream}/chat/completions"
            payload = {key: value for key, value in body.items() if key != "model"}
            payload.update(model=model, stream=False, response_format={"type": "json_object"})
            headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        try:
            response = requests.post(target, json=payload, headers=headers,
                                     timeout=(min(5, timeout), timeout))
            result = (response.json() if response.content else {})
            status = response.status_code
        except requests.Timeout as exc:
            status, result, outcome = 504, {"error": "upstream timeout", "error_code": "upstream_timeout"}, type(exc).__name__
        except requests.ConnectionError as exc:
            status, result, outcome = 502, {"error": "upstream unavailable", "error_code": "upstream_connection"}, type(exc).__name__
        except (requests.RequestException, ValueError) as exc:
            status, result, outcome = 502, {"error": "upstream unavailable", "error_code": "upstream_error"}, type(exc).__name__
        else:
            outcome = "ok" if 200 <= status < 300 else "upstream_error"
            if status == 401:
                result, outcome = {"error": "upstream authentication rejected", "error_code": "upstream_auth"}, "upstream_auth"
            elif status >= 400:
                result = {"error": "upstream rejected request", "error_code": "upstream_error"}
        log.info("model_request provider=%s model=%s request_count=%d status=%s latency_ms=%d outcome=%s",
                 provider, model, request_count, status,
                 round((time.monotonic() - started) * 1000), outcome)
        return jsonify(result), status

    @app.get("/api/tags")
    def tags():
        if provider != "ollama":
            return jsonify({"error": "provider does not expose tags"}), 404
        try:
            response = requests.get(f"{upstream}/api/tags", timeout=(min(5, timeout), timeout))
            return jsonify(response.json()), response.status_code
        except requests.Timeout:
            return jsonify({"error": "upstream timeout", "error_code": "upstream_timeout"}), 504
        except (requests.RequestException, ValueError):
            return jsonify({"error": "upstream unavailable", "error_code": "upstream_connection"}), 502

    return app


def main() -> None:
    logging.basicConfig(level=os.environ.get("RANGER_RELAY_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(message)s")
    allowed = {item.strip() for item in os.environ["RANGER_MODEL_ALLOWED_ENDPOINTS"].split(",")
               if item.strip()}
    app = create_model_relay_app(
        upstream=os.environ["RANGER_MODEL_UPSTREAM"],
        provider=os.environ["RANGER_PROVIDER"], model=os.environ["RANGER_MODEL"],
        api_key=os.environ.get("DEEPSEEK_API_KEY"), allowed_endpoints=allowed,
    )
    app.run(host="0.0.0.0", port=int(os.environ.get("RANGER_MODEL_RELAY_PORT", "8090")))


if __name__ == "__main__":
    main()