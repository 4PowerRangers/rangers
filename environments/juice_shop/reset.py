"""Backward-compatible import path for the Juice Shop lifecycle module."""

import sys

from .lifecycle import reset as _reset

sys.modules[__name__] = _reset
