"""Scenario-configured evidence for an uploaded archive writing a served file."""

from __future__ import annotations

from hashlib import sha256
from io import BytesIO
from pathlib import Path
import posixpath
from threading import Lock
from typing import Any, Mapping
from zipfile import BadZipFile, ZipFile

from werkzeug.formparser import parse_form_data
from werkzeug.exceptions import RequestEntityTooLarge


MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_ENTRY_BYTES = 2 * 1024 * 1024
MAX_ENTRIES = 32


def build_file_write_contract(scenario_dir: Path, scenario: Mapping[str, Any]) -> dict[str, Any] | None:
    """Resolve a scenario's baseline asset before the gateway enters its container."""
    configured = (scenario.get("observation") or {}).get("file_write")
    if not configured:
        return None
    contract = dict(configured)
    artifact = (scenario_dir / str(contract["baseline_artifact"])).resolve()
    if not artifact.is_relative_to(scenario_dir.resolve()) or not artifact.is_file():
        raise ValueError(f"invalid file-write baseline artifact: {artifact}")
    baseline = artifact.read_bytes()
    contract["baseline_sha256"] = sha256(baseline).hexdigest()
    contract["baseline_size"] = len(baseline)
    return contract


class FileWriteProbe:
    """Correlate a baseline read, a bounded archive upload and a later served read."""

    def __init__(self, contract: Mapping[str, Any]):
        self.contract = dict(contract)
        required = ("baseline_sha256", "upload_path", "verification_path", "file_field",
                    "extraction_root", "target_path", "marker", "realized_outcome")
        for key in required:
            if not isinstance(self.contract.get(key), str) or not self.contract[key]:
                raise ValueError(f"file-write observation requires {key}")
        self._lock = Lock()
        self._baseline_seen = False
        self._upload_seen = False
        self._candidate_sha256: str | None = None

    def observe(self, facts: Mapping[str, Any]) -> dict[str, Any]:
        method, path = facts.get("method"), facts.get("path")
        if method == "GET" and path == self.contract["verification_path"]:
            result = {"activity": self.contract.get("verification_activity", "file_write_verification"),
                      "operation": "read", "designated_file": posixpath.basename(self.contract["target_path"])}
            if facts.get("query") or facts.get("status") != 200:
                return result
            body = facts.get("_response_body")
            if not isinstance(body, bytes):
                return result
            digest = sha256(body).hexdigest()
            with self._lock:
                if digest == self.contract["baseline_sha256"] or (
                    not self._baseline_seen
                    and self.contract["marker"].encode("utf-8") not in body
                ):
                    self._baseline_seen = True
                    return {**result, "content_changed": False, "baseline_sha256": digest}
                confirmed = self._baseline_seen and self._upload_seen
                candidate_sha256 = self._candidate_sha256
            marker = self.contract["marker"]
            if (
                confirmed
                and marker.encode("utf-8") in body
                and (candidate_sha256 is None or candidate_sha256 == digest)
            ):
                outcome = self.contract["realized_outcome"]
                return {**result, "content_changed": True, "trusted_proof": True,
                        "matched_markers": [marker], "realized_outcome": outcome,
                        "baseline_sha256": self.contract["baseline_sha256"],
                        "observed_sha256": digest,
                        "outcome_evidence": {"source": "state_probe", "trust_level": "trusted",
                                             "status": "confirmed", "realized_outcome": outcome}}
            return result

        if method == "POST" and path == self.contract["upload_path"]:
            result = {"activity": self.contract.get("invalid_upload_activity", "unrelated_file_write"),
                      "operation": "create"}
            with self._lock:
                self._candidate_sha256 = None
            archive = _multipart_archive(facts, self.contract["file_field"])
            if archive is None:
                if facts.get("status") in (200, 201, 204) and facts.get("_request_body") in (None, b""):
                    with self._lock:
                        self._upload_seen = True
                return result
            entries = _archive_entries(archive, self.contract)
            if entries is None:
                return result
            if len(entries) != 1:
                return {**result, "activity": self.contract.get("bulk_upload_activity", "bulk_upload")}
            path, digest = entries[0]
            if path != posixpath.normpath(self.contract["target_path"]):
                return result
            result = {"activity": self.contract.get("upload_activity", "designated_file_upload"),
                      "operation": "create", "designated_file": posixpath.basename(path)}
            if facts.get("status") in (200, 201, 204):
                with self._lock:
                    self._upload_seen = True
                    if self._baseline_seen:
                        self._candidate_sha256 = digest
            return result
        return {}


def _multipart_archive(facts: Mapping[str, Any], field: str) -> bytes | None:
    body = facts.get("_request_body")
    headers = facts.get("headers") or {}
    if not isinstance(body, bytes) or len(body) > MAX_ARCHIVE_BYTES or not isinstance(headers, Mapping):
        return None
    content_type = next((v for k, v in headers.items() if str(k).lower() == "content-type"), "")
    if not isinstance(content_type, str) or not content_type.lower().startswith("multipart/form-data;"):
        return None
    environ = {"REQUEST_METHOD": "POST", "CONTENT_TYPE": content_type,
               "CONTENT_LENGTH": str(len(body)), "wsgi.input": BytesIO(body)}
    try:
        _, _, files = parse_form_data(environ, max_content_length=MAX_ARCHIVE_BYTES,
                                      max_form_memory_size=MAX_ARCHIVE_BYTES)
        if len(files) != 1 or field not in files:
            return None
        upload = files[field]
        if not upload.filename or not upload.filename.lower().endswith(".zip"):
            return None
        return upload.stream.read(MAX_ARCHIVE_BYTES + 1)
    except (ValueError, OSError, KeyError, RequestEntityTooLarge):
        return None


def _archive_entries(data: bytes, contract: Mapping[str, Any]) -> list[tuple[str, str]] | None:
    if len(data) > MAX_ARCHIVE_BYTES:
        return None
    try:
        with ZipFile(BytesIO(data)) as archive:
            members = [item for item in archive.infolist() if not item.is_dir()]
            if not members or len(members) > MAX_ENTRIES:
                return None
            if any(item.file_size > MAX_ENTRY_BYTES for item in members):
                return None
            entries = []
            for item in members:
                if "\\" in item.filename or item.filename.startswith("/"):
                    return None
                path = posixpath.normpath(posixpath.join(contract["extraction_root"], item.filename))
                with archive.open(item) as stream:
                    content = stream.read(MAX_ENTRY_BYTES + 1)
                if len(content) > MAX_ENTRY_BYTES:
                    return None
                entries.append((path, sha256(content).hexdigest()))
            return entries
    except (BadZipFile, RuntimeError, OSError, ValueError):
        return None
