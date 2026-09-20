"""Sequelize observer; allocate seq when query execution starts."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hmac
import json
import re
import socket
from threading import Event as ThreadEvent, Lock, Thread
from typing import Any, Callable

from .normalizer import Observer, RawObservation
from ..core.event import Event
from ..core.identity import event_id as make_event_id


_BEHAVIORS = {
    "SELECT": "read",
    "INSERT": "data_creation",
    "UPDATE": "data_modification",
    "DELETE": "destructive_action",
    "DROP": "schema_modification",
    "ALTER": "schema_modification",
}
_PREFIX = re.compile(r"^\s*(?:Executing|Executed)\s+\([^)]*\):\s*", re.IGNORECASE)
_IDENT = r"(?:[`\"\[]?)([A-Za-z_][A-Za-z0-9_$]*)(?:[`\"\]]?)"
_TABLE_PATTERNS = {
    "SELECT": re.compile(rf"\bFROM\s+{_IDENT}", re.IGNORECASE),
    "INSERT": re.compile(rf"\bINTO\s+{_IDENT}", re.IGNORECASE),
    "UPDATE": re.compile(rf"\bUPDATE\s+{_IDENT}", re.IGNORECASE),
    "DELETE": re.compile(rf"\bFROM\s+{_IDENT}", re.IGNORECASE),
    "DROP": re.compile(rf"\bDROP\s+(?:TABLE\s+)?(?:IF\s+EXISTS\s+)?{_IDENT}", re.IGNORECASE),
    "ALTER": re.compile(rf"\bALTER\s+TABLE\s+{_IDENT}", re.IGNORECASE),
}


def normalize_sql(sql: str) -> dict[str, str] | None:
    """Return operation metadata only; never return SQL text or bound values."""
    statement = _PREFIX.sub("", sql, count=1)
    operation_match = re.match(r"\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b", statement, re.IGNORECASE)
    if operation_match is None:
        return None
    operation = operation_match.group(1).upper()
    table_match = _TABLE_PATTERNS[operation].search(statement)
    if table_match is None:
        return None
    return {
        "operation": operation,
        "table": table_match.group(1),
        "behavior": _BEHAVIORS[operation],
    }


class DatabaseObserver(Observer):
    """Convert an in-memory SQL observation to a sanitized Rager event."""

    def normalize(self, run_id: str, observation: RawObservation, *, seq: int) -> Event:
        sql = observation.facts.get("sql")
        facts = normalize_sql(sql) if isinstance(sql, str) else None
        if facts is None:
            raise ValueError("observation does not contain a supported SQL query")
        attributes: dict[str, Any] = dict(facts)
        affected_rows = observation.facts.get("affected_rows")
        if isinstance(affected_rows, int) and affected_rows >= 0:
            attributes["affected_rows"] = affected_rows
        return Event(
            schema_version="0.2",
            run_id=run_id,
            timestamp=observation.timestamp,
            actor=observation.actor,
            source=observation.source,
            kind="database",
            action="query",
            target=f"sqlite:{attributes['table']}",
            seq=seq,
            attributes=attributes,
            event_id=make_event_id(seq) if seq >= 0 else None,
        )


class DatabaseEventCollector:
    """Receive transient Sequelize query logs and emit only sanitized events."""

    def __init__(self, run_id: str, event_sink: Callable[[Event], None], *, token: str,
                 host: str = "127.0.0.1", port: int = 0):
        if not token:
            raise ValueError("database observer token is required")
        self.run_id = run_id
        self.event_sink = event_sink
        self._token = token
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind((host, port))
        self._socket.settimeout(0.1)
        self.address = self._socket.getsockname()
        self._stopped = ThreadEvent()
        self._thread = Thread(target=self._receive, daemon=True)
        self._started = False
        self._observer = DatabaseObserver()
        self._windows: list[list[datetime | None]] = []
        self._windows_lock = Lock()

    def __enter__(self) -> "DatabaseEventCollector":
        self.start()
        return self

    def start(self) -> None:
        if not self._started:
            self._thread.start()
            self._started = True

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def close(self) -> None:
        if not self._started:
            self._socket.close()
            return
        self._stopped.wait(0.25)
        self._stopped.set()
        self._thread.join(timeout=1)
        self._socket.close()

    @contextmanager
    def request_scope(self):
        window: list[datetime | None] = [datetime.now(timezone.utc), None]
        with self._windows_lock:
            self._windows.append(window)
        try:
            yield
        finally:
            window[1] = datetime.now(timezone.utc)

    def _within_request_window(self, timestamp: datetime, received_at: datetime) -> bool:
        grace = timedelta(milliseconds=250)
        with self._windows_lock:
            return any(
                start is not None and start <= timestamp
                and timestamp <= (end or received_at) + grace
                for start, end in self._windows
            )

    def _receive(self) -> None:
        while not self._stopped.is_set():
            try:
                payload, _ = self._socket.recvfrom(65535)
            except TimeoutError:
                continue
            try:
                document = json.loads(payload.decode("utf-8"))
                if not hmac.compare_digest(str(document["token"]), self._token):
                    continue
                timestamp = datetime.fromisoformat(
                    str(document["timestamp"]).replace("Z", "+00:00")
                )
                received_at = datetime.now(timezone.utc)
                if (abs(received_at - timestamp) > timedelta(milliseconds=250)
                        or not self._within_request_window(timestamp, received_at)):
                    continue
                event = self._observer.normalize(
                    self.run_id,
                    RawObservation(
                        timestamp=timestamp,
                        actor="target",
                        source="sequelize",
                        kind="database",
                        action="query",
                        target="sqlite",
                        facts={"sql": document["sql"]},
                    ),
                    seq=int(document["seq"]),
                )
            except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            self.event_sink(event)
