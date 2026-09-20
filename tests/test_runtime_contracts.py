from console.backend import main
from ranger.agent import load_agent_adapter
from ranger.observe.gateway import create_app


def test_gateway_health_matches_topology():
    events = []
    app = create_app("http://127.0.0.1:1", "health-test", "agent", events.append)
    response = app.test_client().get("/__ranger_gateway_health__")
    assert response.status_code == 200
    assert response.data == b"ok"
    assert events == []


def test_environment_status_uses_configured_model_endpoint(monkeypatch):
    probes = []
    monkeypatch.setenv("RANGER_MODEL_ENDPOINT", "http://127.0.0.1:18090/")
    monkeypatch.setattr(main, "_http_probe", lambda url: probes.append(url) or {"status": "ready"})
    monkeypatch.setattr(main, "_docker_preflight", lambda: {"ok": True})
    assert main.env_status()["model_relay"]["status"] == "ready"
    assert "http://127.0.0.1:18090/healthz" in probes


def test_internal_adapter_uses_runtime_default():
    assert load_agent_adapter("internal") is None
