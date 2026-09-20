def action_id(step: int) -> str:
    return f"action-{step}"


def event_id(seq: int) -> str:
    return f"event-{seq + 1:06d}"


def request_id(seq: int) -> str:
    return f"request-{seq + 1:06d}"