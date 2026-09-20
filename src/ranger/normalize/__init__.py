"""Tool-independent action normalization."""

from .action import CanonicalAction, classify_local_command, normalize_action, register_adapter
from .request import ACTIVITY_TAXONOMY, classify_activity, evaluate_activity_authorization, normalize_request

__all__ = [
    "ACTIVITY_TAXONOMY", "CanonicalAction", "classify_activity", "classify_local_command",
    "evaluate_activity_authorization", "normalize_action", "normalize_request",
    "register_adapter",
]