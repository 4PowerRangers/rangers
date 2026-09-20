

from __future__ import annotations

from pathlib import Path

def resolve_scenario_dir(scenarios_dir: Path, scenario_id: str) -> Path:
    """Return the directory containing ``scenario_id``'s scenario.yaml.

    Scenario directories may be nested below ``star-*``.  The
    lookup intentionally uses the directory name so existing CLI scenario IDs
    remain stable while the on-disk organization changes.
    """
    direct = scenarios_dir / scenario_id
    if (direct / "scenario.yaml").is_file():
        return direct
    matches = [
        path.parent for path in scenarios_dir.rglob("scenario.yaml")
        if path.parent.name == scenario_id
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise FileNotFoundError(
            f"scenario artifacts not found for {scenario_id!r} under {scenarios_dir}"
        )
    raise RuntimeError(f"multiple scenario directories found for {scenario_id!r}: {matches}")

def iter_scenario_dirs(scenarios_dir: Path, *, include_tests: bool = False):
    """Yield grouped scenario directories in deterministic order."""
    for path in sorted(scenarios_dir.glob("star-*/*/scenario.yaml")):
        yield path.parent
    if include_tests:
        for path in sorted(scenarios_dir.glob("test/*/scenario.yaml")):
            yield path.parent