"""Minimal Docker topology control for the container forced-gateway mode."""

from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
import os
from typing import Callable

from .runtime_control import AgentRuntimeError, ContainerAgentRuntime, DEFAULT_ATTACKER_CONTAINER

ATTACK_NETWORK = "attacker-net"
TARGET_NETWORK = "target-net"
CONTROL_NETWORK = "ranger-control-net"
MODEL_EGRESS_NETWORK = "ranger-model-egress-net"
DEFAULT_GATEWAY_CONTAINER = "ranger-gateway-forced"
DEFAULT_TARGET_CONTAINER = "ranger-juice-forced"
ATTACKER_IMAGE = "ranger-attacker:kali"
GATEWAY_IMAGE = "ranger-gateway:stage3"
TARGET_IMAGE = "ranger-juice-shop:latest"
MODEL_RELAY_IMAGE = "ranger-model-relay:stage4"
DEFAULT_MODEL_RELAY_CONTAINER = "ranger-model-relay"


class TopologyError(AgentRuntimeError):
    """The forced-gateway topology is missing or unsafe."""


@dataclass(frozen=True)
class Topology:
    attacker: str
    gateway: str
    target: str
    attack_network: str = ATTACK_NETWORK
    target_network: str = TARGET_NETWORK
    control_network: str = CONTROL_NETWORK


class ForcedGatewayTopology:
    """Create or validate only the networks and containers needed by Stage 3."""

    def __init__(self, *, attacker: str = DEFAULT_ATTACKER_CONTAINER,
                 gateway: str = DEFAULT_GATEWAY_CONTAINER,
                 target: str = DEFAULT_TARGET_CONTAINER,
                 target_image: str = TARGET_IMAGE,
                 attacker_image: str = ATTACKER_IMAGE,
                 target_port: int = 3000,
                 model_relay: str = DEFAULT_MODEL_RELAY_CONTAINER,
                 model_relay_provider: str | None = None,
                 model_relay_model: str | None = None,
                 model_relay_upstream: str | None = None,
                 model_relay_allowed_endpoints: set[str] | None = None,
                 run_dir: str | Path | None = None,
                 runner: Callable | None = None):
        self.topology = Topology(attacker, gateway, target)
        self.target_image = target_image
        self.attacker_image = attacker_image
        self.target_port = int(target_port)
        self.model_relay = model_relay
        self.model_relay_provider = model_relay_provider
        self.model_relay_model = model_relay_model
        self.model_relay_upstream = model_relay_upstream
        self.model_relay_allowed_endpoints = model_relay_allowed_endpoints
        self._relay_required = False
        self.run_dir = Path(run_dir).resolve() if run_dir else None
        self._runner = runner or subprocess.run
        self._gateway_poll_attempts = 10
        self._gateway_poll_interval = 0.3

    def _docker(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        try:
            result = self._runner(
                ["docker", *args], capture_output=True, text=True,
                encoding="utf-8", errors="replace", check=check,
            )
        except OSError as exc:
            raise TopologyError(f"docker unavailable: {exc}") from exc
        if check and result.returncode != 0:
            raise TopologyError(result.stderr.strip() or "docker command failed")
        return result

    def _exists(self, kind: str, name: str) -> bool:
        return self._docker(kind, "inspect", name, check=False).returncode == 0

    def _network(self, name: str, *, internal: bool = False) -> None:
        if self._exists("network", name):
            if internal:
                status = self._docker(
                    "network", "inspect", "--format", "{{.Internal}}", name,
                ).stdout.strip().lower()
                if status != "true":
                    raise TopologyError(f"{name} must be an internal network")
            return
        args = ["network", "create"]
        if internal:
            args.append("--internal")
        self._docker(*args, name)

    def _running(self, name: str) -> bool:
        result = self._docker("inspect", "--format", "{{.State.Running}}", name, check=False)
        return result.returncode == 0 and result.stdout.strip().lower() == "true"

    def _networks(self, name: str) -> set[str]:
        result = self._docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", name)
        try:
            return set(json.loads(result.stdout).keys())
        except (json.JSONDecodeError, AttributeError) as exc:
            raise TopologyError(f"invalid network inspection for {name}") from exc

    def _has_host_publish(self, name: str) -> bool:
        raw = self._docker(
            "inspect", "--format", "{{json .NetworkSettings.Ports}}", name,
        ).stdout.strip()
        try:
            ports = json.loads(raw or "null") or {}
        except json.JSONDecodeError as exc:
            raise TopologyError(f"invalid port inspection for {name}") from exc
        return any(value for value in ports.values())

    def _attacker_inspect(self, name: str) -> tuple[list[dict], dict[str, str]]:
        mounts = json.loads(self._docker("inspect", "--format", "{{json .Mounts}}", name).stdout or "[]")
        labels = json.loads(self._docker("inspect", "--format", "{{json .Config.Labels}}", name).stdout or "{}") or {}
        return mounts, labels

    def _attacker_matches(self, name: str) -> bool:
        if not self.run_dir:
            return True
        mounts, labels = self._attacker_inspect(name)
        expected_source = self._canonical_path(str(self.run_dir.parent))
        source_ok = any(
            item.get("Destination") == "/app/runs"
            and self._canonical_path(item.get("Source", "")) == expected_source
            for item in mounts
        )
        identity_ok = self._canonical_path(labels.get("com.ranger.runs_root", "")) == expected_source
        return source_ok and identity_ok

    def _attacker_owned(self) -> bool:
        _, labels = self._attacker_inspect(self.topology.attacker)
        return labels.get("com.ranger.owner") == "environment-attacker"

    def _image_id(self, container: str) -> str:
        return self._docker("inspect", "--format", "{{.Image}}", container).stdout.strip()

    def _expected_image_id(self) -> str:
        return self._docker(
            "inspect", "--format", "{{.Id}}", "--type", "image", self.attacker_image,
        ).stdout.strip()

    def _ensure_attacker(self) -> None:
        name = self.topology.attacker
        exists = self._exists("container", name)
        if exists and self._image_id(name) != self._expected_image_id():
            if not self._attacker_owned():
                raise TopologyError("attacker_image_mismatch: existing attacker is not environment-owned")
            self._docker("rm", "-f", name)
            exists = False
        if exists and self.run_dir and not self._attacker_matches(name):
            if not self._attacker_owned():
                raise TopologyError("attacker_mount_mismatch: existing attacker is not environment-owned")
            self._docker("rm", "-f", name)
            exists = False
        if not exists:
            args = [
                "run", "-d", "--name", name, "--network", ATTACK_NETWORK,
                "--label", "com.ranger.owner=environment-attacker",
            ]
            if self.run_dir:
                args.extend([
                    "--label", f"com.ranger.runs_root={self._canonical_path(str(self.run_dir.parent))}",
                    "--mount", f"type=bind,source={self.run_dir.parent},target=/app/runs",
                ])
            self._docker(*args, "--entrypoint", "sleep", self.attacker_image, "infinity")
        elif not self._running(name):
            self._docker("start", name)
        if self.run_dir and not self._attacker_matches(name):
            raise TopologyError("attacker_mount_mismatch: attacker runs-root mount does not match current run")
        networks = self._networks(name)
        if ATTACK_NETWORK not in networks:
            self._docker("network", "connect", ATTACK_NETWORK, name)
            networks = self._networks(name)
        if ATTACK_NETWORK not in networks or TARGET_NETWORK in networks:
            raise TopologyError("attacker must be on attacker-net and not target-net")
        if CONTROL_NETWORK not in networks:
            self._docker("network", "connect", CONTROL_NETWORK, name)

    def _ensure_target(self) -> None:
        name = self.topology.target
        if self._exists("container", name):
            self._docker("rm", "-f", name)
        if not self._exists("container", name):
            self._docker(
                "run", "-d", "--name", name, "--network", TARGET_NETWORK,
                self.target_image,
            )
        elif not self._running(name):
            self._docker("start", name)
        networks = self._networks(name)
        if networks != {TARGET_NETWORK}:
            raise TopologyError("forced target must be attached only to target-net")
        if self._has_host_publish(name):
            raise TopologyError("forced target must not publish host ports")

    @staticmethod
    def _canonical_path(value: str) -> str:
        path = str(value).replace("\\", "/")
        if path.startswith("/host_mnt/"):
            path = path[len("/host_mnt/"):]
        if len(path) >= 2 and path[1] == "/" and path[0].isalpha():
            path = f"{path[0]}:{path[1:]}"
        return os.path.normcase(os.path.normpath(path)).replace("\\", "/").rstrip("/")

    def _gateway_inspect(self, name: str) -> tuple[list[dict], dict[str, str], list[str]]:
        mounts = json.loads(self._docker("inspect", "--format", "{{json .Mounts}}", name).stdout or "[]")
        labels = json.loads(self._docker("inspect", "--format", "{{json .Config.Labels}}", name).stdout or "{}") or {}
        command = json.loads(self._docker("inspect", "--format", "{{json .Config.Cmd}}", name).stdout or "[]") or []
        return mounts, labels, command

    def _gateway_matches(self, run_id: str, upstream: str) -> bool:
        if not self.run_dir:
            return True
        mounts, labels, command = self._gateway_inspect(self.topology.gateway)
        expected_source = self._canonical_path(str(self.run_dir))
        expected_destination = f"/app/runs/{run_id}"
        source_ok = any(
            item.get("Destination") == expected_destination
            and self._canonical_path(item.get("Source", "")) == expected_source
            for item in mounts
        )
        identity_ok = not labels.get("com.ranger.run_id") or labels.get("com.ranger.run_id") == run_id
        path_ok = not labels.get("com.ranger.artifact_path") or self._canonical_path(labels["com.ranger.artifact_path"]) == expected_source
        return source_ok and identity_ok and path_ok and "--run" in command and command[command.index("--run") + 1] == run_id and "--upstream" in command and command[command.index("--upstream") + 1] == upstream

    def _gateway_owned(self) -> bool:
        _, labels, _ = self._gateway_inspect(self.topology.gateway)
        return labels.get("com.ranger.owner") == "environment-forced-gateway"

    def _gateway_startup_error(self, name: str) -> str:
        """Best-effort crash detail for a gateway container that failed to
        start, so operators get e.g. the real Python traceback (this is how
        the stale-image / config schema mismatch that caused a
        'could not resolve host <gateway>' downstream symptom was actually
        diagnosed) instead of only a bare 'gateway failed closed'."""
        logs = self._docker("logs", "--tail", "40", name, check=False)
        detail = (logs.stdout or "") + (logs.stderr or "")
        return detail.strip()[-2000:] if detail.strip() else "no container logs available"

    def _await_gateway_running(self, name: str) -> bool:
        import time
        attempts = self._gateway_poll_attempts
        interval = self._gateway_poll_interval
        for _ in range(attempts):
            if not self._running(name):
                return False
            time.sleep(interval)
        return self._running(name)

    def _ensure_gateway(self, run_id: str, *, observer_ref: str | None = None,
                        markers: tuple[str, ...] = ()) -> None:
        name = self.topology.gateway
        upstream = f"http://{self.topology.target}:{self.target_port}"
        exists = self._exists("container", name)
        if exists and self.run_dir and not self._gateway_matches(run_id, upstream):
            if not self._gateway_owned():
                raise TopologyError("gateway_mount_mismatch: existing gateway is not environment-owned")
            self._docker("rm", "-f", name)
            exists = False
        if not exists:
            args = [
                "run", "-d", "--name", name, "--network", ATTACK_NETWORK,
                "--label", "com.ranger.owner=environment-forced-gateway",
                "--label", f"com.ranger.run_id={run_id}",
            ]
            if self.run_dir:
                args.extend([
                    "--label", f"com.ranger.artifact_path={self.run_dir}",
                    "--mount", f"type=bind,source={self.run_dir},target=/app/runs/{run_id}",
                ])
            observer_args = []
            if observer_ref:
                observer_args.extend(["--observer", observer_ref])
                if markers:
                    observer_args.extend(["--markers", ",".join(markers)])
            self._docker(
                *args, GATEWAY_IMAGE, "--upstream", upstream, "--run", run_id,
                "--config", f"/app/runs/{run_id}/config.json", "--actor", "agent",
                *observer_args,
            )
            if not self._await_gateway_running(name):
                raise TopologyError(
                    f"gateway failed closed during startup: {self._gateway_startup_error(name)}"
                )
        elif not self._running(name):
            self._docker("start", name)
            if not self._await_gateway_running(name):
                raise TopologyError(
                    f"gateway failed closed during startup: {self._gateway_startup_error(name)}"
                )
        if self.run_dir and not self._gateway_matches(run_id, upstream):
            raise TopologyError("gateway_mount_mismatch: gateway artifact identity does not match current run")
        networks = self._networks(name)
        if ATTACK_NETWORK not in networks:
            self._docker("network", "connect", ATTACK_NETWORK, name)
        if TARGET_NETWORK not in networks:
            self._docker("network", "connect", TARGET_NETWORK, name)
        networks = self._networks(name)
        if networks != {ATTACK_NETWORK, TARGET_NETWORK}:
            raise TopologyError("gateway must be dual-homed")
        if not self._running(name):
            raise TopologyError(
                f"gateway failed closed after startup: {self._gateway_startup_error(name)}"
            )
    def _model_relay_config(self) -> tuple[str, str, str, set[str]]:
        upstream = self.model_relay_upstream
        provider = self.model_relay_provider
        model = self.model_relay_model
        allowed = self.model_relay_allowed_endpoints or set()
        if not all((upstream, provider, model, allowed)):
            raise TopologyError("model relay configuration is incomplete")
        from .model_relay import validate_endpoint
        try:
            upstream = validate_endpoint(upstream, allowed)
        except ValueError as exc:
            raise TopologyError(str(exc)) from exc
        return upstream, provider, model, allowed

    @staticmethod
    def _relay_identity(upstream: str, allowed: set[str]) -> tuple[str, str]:
        import hashlib
        return (
            hashlib.sha256(upstream.encode()).hexdigest(),
            hashlib.sha256(",".join(sorted(allowed)).encode()).hexdigest(),
        )

    def _relay_inspect(self) -> tuple[list[str], dict[str, str]]:
        env = json.loads(self._docker(
            "inspect", "--format", "{{json .Config.Env}}", self.model_relay,
        ).stdout or "[]")
        labels = json.loads(self._docker(
            "inspect", "--format", "{{json .Config.Labels}}", self.model_relay,
        ).stdout or "{}") or {}
        return env, labels

    def _relay_matches(self, provider: str, model: str, upstream: str,
                       allowed: set[str]) -> bool:
        env, labels = self._relay_inspect()
        values = {item.split("=", 1)[0]: item.split("=", 1)[1]
                  for item in env if "=" in item}
        upstream_hash, allowed_hash = self._relay_identity(upstream, allowed)
        return (
            labels.get("com.ranger.owner") == "environment-model-relay"
            and labels.get("com.ranger.provider") == provider
            and labels.get("com.ranger.model") == model
            and labels.get("com.ranger.upstream_sha256") == upstream_hash
            and labels.get("com.ranger.allowed_endpoints_sha256") == allowed_hash
            and values.get("RANGER_MODEL_UPSTREAM") == upstream
            and values.get("RANGER_PROVIDER") == provider
            and values.get("RANGER_MODEL") == model
            and values.get("RANGER_MODEL_ALLOWED_ENDPOINTS") == ",".join(sorted(allowed))
        )

    def _relay_owned(self) -> bool:
        _, labels = self._relay_inspect()
        return labels.get("com.ranger.owner") == "environment-model-relay"

    def _ensure_model_relay(self) -> None:
        upstream, provider, model, allowed = self._model_relay_config()
        upstream_hash, allowed_hash = self._relay_identity(upstream, allowed)
        exists = self._exists("container", self.model_relay)
        if exists and not self._relay_matches(provider, model, upstream, allowed):
            if not self._relay_owned():
                raise TopologyError("model relay configuration mismatch: existing relay is not environment-owned")
            self._docker("rm", "-f", self.model_relay)
            exists = False
        if not exists:
            self._docker(
                "run", "-d", "--name", self.model_relay, "--network", CONTROL_NETWORK,
                "--label", "com.ranger.owner=environment-model-relay",
                "--label", f"com.ranger.provider={provider}",
                "--label", f"com.ranger.model={model}",
                "--label", f"com.ranger.upstream_sha256={upstream_hash}",
                "--label", f"com.ranger.allowed_endpoints_sha256={allowed_hash}",
                "-e", f"RANGER_MODEL_UPSTREAM={upstream}",
                "-e", f"RANGER_PROVIDER={provider}", "-e", f"RANGER_MODEL={model}",
                "-e", f"RANGER_MODEL_ALLOWED_ENDPOINTS={','.join(sorted(allowed))}",
                *( ["-e", "DEEPSEEK_API_KEY"] if provider == "deepseek" and os.environ.get("DEEPSEEK_API_KEY") else [] ),
                MODEL_RELAY_IMAGE,
            )
            if not self._running(self.model_relay):
                raise TopologyError("model relay failed closed during startup")
        elif not self._running(self.model_relay):
            self._docker("start", self.model_relay)
            if not self._running(self.model_relay):
                raise TopologyError("model relay failed closed during startup")
        networks = self._networks(self.model_relay)
        if MODEL_EGRESS_NETWORK not in networks:
            self._docker("network", "connect", MODEL_EGRESS_NETWORK, self.model_relay)
            networks = self._networks(self.model_relay)
        if networks != {CONTROL_NETWORK, MODEL_EGRESS_NETWORK}:
            raise TopologyError("model relay must be on control-net and model-egress-net only")

    def ensure(self, run_id: str, *, observer_ref: str | None = None,
              markers: tuple[str, ...] = ()) -> Topology:
        self._network(ATTACK_NETWORK, internal=True)
        self._network(TARGET_NETWORK)
        self._network(CONTROL_NETWORK, internal=True)
        self._network(MODEL_EGRESS_NETWORK)
        self._ensure_attacker()
        self._ensure_target()
        self._ensure_gateway(run_id, observer_ref=observer_ref, markers=markers)
        self._relay_required = True
        self._ensure_model_relay()
        self.validate()
        return self.topology

    def cleanup(self) -> None:
        """Remove only a gateway container created with environment ownership labels."""
        name = self.topology.gateway
        if self._exists("container", name) and self._gateway_owned():
            self._docker("rm", "-f", name)

    def validate(self) -> None:
        topology = self.topology
        attacker = self._networks(topology.attacker)
        gateway = self._networks(topology.gateway)
        target = self._networks(topology.target)
        if ATTACK_NETWORK not in attacker or TARGET_NETWORK in attacker:
            raise TopologyError("attacker direct target route is possible or attacker-net is missing")
        if gateway != {ATTACK_NETWORK, TARGET_NETWORK}:
            raise TopologyError("gateway is not dual-homed")
        if target != {TARGET_NETWORK}:
            raise TopologyError("target has a non-isolated network membership")
        if self._has_host_publish(topology.target):
            raise TopologyError("target host publish is enabled")
        if self._relay_required:
            relay = self._networks(self.model_relay)
            if relay != {CONTROL_NETWORK, MODEL_EGRESS_NETWORK}:
                raise TopologyError("model relay has an unsafe network membership")

    def validate_current_arm(self, run_id: str) -> None:
        """Validate topology plus the current arm's gateway identity."""
        self.validate()
        upstream = f"http://{self.topology.target}:{self.target_port}"
        if self.run_dir and not self._gateway_matches(run_id, upstream):
            raise TopologyError("gateway_mount_mismatch: current arm artifact identity does not match")

    def smoke(self, runtime: ContainerAgentRuntime) -> dict[str, object]:
        self.validate()
        result = runtime.exec([
            "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
            f"http://{self.topology.gateway}:8080/__ranger_gateway_health__",
        ])
        if result.stdout.strip() != "200":
            raise TopologyError(f"gateway smoke returned {result.stdout.strip()!r}")
        return {"command": "GET /__ranger_gateway_health__", "status": result.stdout.strip(), "stderr": result.stderr}

    def isolation_report(self, runtime: ContainerAgentRuntime, *, timeout: float = 10) -> dict[str, str]:
        def probe(url: str) -> str:
            try:
                result = runtime.exec(
                    ["curl", "-sS", "-o", "/dev/null", "-m", "3", "-w", "%{http_code}", url],
                    timeout=timeout,
                )
            except AgentRuntimeError:
                return "blocked"
            code = result.stdout.strip()
            return "ok" if code and code != "000" else "blocked"

        target_direct = probe(f"http://{self.topology.target}:3000/")
        gateway_access = probe(f"http://{self.topology.gateway}:8080/__ranger_gateway_health__")
        relay_access = probe(f"http://{self.model_relay}:8090/healthz")
        if target_direct == "ok":
            raise TopologyError(
                "attacker can reach the target directly; the gateway is not the "
                "sole attacker-net/target-net bridge"
            )
        if gateway_access != "ok":
            raise TopologyError("attacker cannot reach the gateway")
        return {
            "target_direct_access": "blocked" if target_direct != "ok" else "ok",
            "gateway_access": gateway_access,
            "model_relay_access": relay_access,
        }