"""Provision one Juice Shop fixture declared by the current scenario."""

import json
import hashlib
import re
from collections.abc import Mapping
from typing import Any

from .reset import CONTAINER, _docker


_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def provision_scenario_fixture(scenario: Mapping[str, Any]) -> dict[str, Any]:
    fixture = _fixture_config(scenario)
    if fixture is None:
        return {"attempted": False, "applied": False, "verified": True}

    table, key, data = fixture
    assignments = ",".join(f'"{column}"=?' for column in data)
    predicates = " AND ".join(f'"{column}"=?' for column in key)
    payload = json.dumps([*data.values(), *key.values()], separators=(",", ":"))
    sql = f'UPDATE "{table}" SET {assignments} WHERE {predicates}'
    script = (
        "const s=require('sqlite3').verbose(),d=new s.Database('/juice-shop/data/juiceshop.sqlite');"
        f"d.run({json.dumps(sql)},{payload},function(e){{if(e)throw e;"
        "console.log(JSON.stringify({changes:this.changes}));d.close()})"
    )
    output = _docker(
        "exec", "-w", "/juice-shop", CONTAINER, "/nodejs/bin/node", "-e", script,
    ).stdout
    changes = json.loads(output.strip()).get("changes")
    if changes != 1:
        raise RuntimeError(f"scenario fixture target count was {changes!r}, expected 1")
    if not verify_scenario_fixture(scenario):
        raise RuntimeError("scenario fixture verification failed")
    fixture_id = f"{table}:{','.join(f'{key}={value}' for key, value in key.items())}"
    fixture_hash = hashlib.sha256(json.dumps(
        {"table": table, "key": key, "data": data},
        sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    return {"attempted": True, "applied": True, "verified": True,
            "type": "juice_shop", "fixture": fixture_id, "fixture_hash": fixture_hash,
            "table": table,
            "verification_checks": {"target_count": "pass", "values": "pass"}}


def verify_scenario_fixture(scenario: Mapping[str, Any]) -> bool:
    fixture = _fixture_config(scenario)
    if fixture is None:
        return False

    table, key, data = fixture
    columns = ",".join(f'"{column}"' for column in data)
    predicates = " AND ".join(f'"{column}"=?' for column in key)
    payload = json.dumps(list(key.values()), separators=(",", ":"))
    sql = f'SELECT {columns} FROM "{table}" WHERE {predicates}'
    script = (
        "const s=require('sqlite3').verbose(),d=new s.Database('/juice-shop/data/juiceshop.sqlite');"
        f"d.get({json.dumps(sql)},{payload},(e,r)=>{{if(e)throw e;"
        "console.log(JSON.stringify(r||null));d.close()})"
    )
    output = _docker(
        "exec", "-w", "/juice-shop", CONTAINER, "/nodejs/bin/node", "-e", script,
    ).stdout
    return json.loads(output.strip()) == data


def _fixture_config(
    scenario: Mapping[str, Any],
) -> tuple[str, dict[str, Any], dict[str, Any]] | None:
    fixture = scenario.get("fixture")
    if fixture is None:
        return None
    # H3 scenarios use the existing deterministic adapter fixture contract;
    # they do not mutate a SQLite row during provisioning.
    if isinstance(fixture, Mapping) and fixture.get("strategy") == "existing_fixture_adapter_contract":
        return None
    if not isinstance(fixture, Mapping) or fixture.get("type") != "juice_shop":
        raise ValueError("fixture.type must be 'juice_shop'")

    table = _identifier(fixture.get("table"), "fixture.table")
    key = _mapping(fixture.get("key"), "fixture.key")
    data = _mapping(fixture.get("data"), "fixture.data")
    for column in (*key, *data):
        _identifier(column, "fixture column")
    if set(key) & set(data):
        raise ValueError("fixture.key and fixture.data columns must not overlap")
    return table, key, data


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError(f"{name} must be a non-empty mapping")
    return dict(value)


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} must be a safe SQLite identifier")
    return value
