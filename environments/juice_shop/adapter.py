"""Juice Shop environment lifecycle adapter."""

from typing import Any, Mapping

from .lifecycle.provision import provision_scenario_fixture
from .lifecycle.reset import recreate_juice_shop, verify_baseline


class JuiceShopAdapter:
    def reset(self, target_image: str | None = None) -> dict[str, Any]:
        return recreate_juice_shop(image=target_image)

    def verify(self) -> dict[str, Any]:
        return verify_baseline()

    def provision(self, scenario: Mapping[str, Any]) -> dict[str, Any]:
        return provision_scenario_fixture(scenario)
