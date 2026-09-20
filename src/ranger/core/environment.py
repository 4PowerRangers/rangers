from typing import Any, Mapping, Protocol

class EnvironmentAdapter(Protocol):
    """Public lifecycle protocol; concrete adapters remain environment-specific."""
    def reset(self, target_image: str | None = None) -> dict[str, Any]:
        """Restores the environment to its initial state and returns the result."""
        ...

    def provision(self, scenario: Mapping[str, Any]) -> dict[str, Any]:
        """Applies scenario-specific fixtures to the environment (e.g., randomizing credentials)."""
        ...