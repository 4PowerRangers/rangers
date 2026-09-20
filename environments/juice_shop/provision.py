"""Backward-compatible import path for Juice Shop fixture provisioning."""

from .lifecycle.provision import (
    _fixture_config,
    provision_scenario_fixture,
    verify_scenario_fixture,
)

__all__ = ["_fixture_config", "provision_scenario_fixture", "verify_scenario_fixture"]
