import importlib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULES = [
    ".".join(path.relative_to(base).with_suffix("").parts)
    for base, directory in [(ROOT / "src", ROOT / "src" / "ranger"), (ROOT, ROOT / "environments"), (ROOT, ROOT / "console" / "backend")]
    for path in directory.rglob("*.py")
    if path.name not in {"__main__.py", "__init__.py"}
]


@pytest.mark.parametrize("module", MODULES)
def test_runtime_module_imports(module):
    importlib.import_module(module)
