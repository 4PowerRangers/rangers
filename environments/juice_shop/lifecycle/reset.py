"""Recreate Juice Shop and verify its deterministic SQLite seed state."""

import json
import os
import subprocess
import time
from urllib.request import build_opener, ProxyHandler
import hashlib

from ranger.docker_cli import executable, unavailable_message


CONTAINER = "ranger-juice"
DEFAULT_IMAGE = "ranger-juice-shop:latest"
PRODUCT_URL = "http://127.0.0.1:3001/api/Products/1"
JUICE_SHOP_V20_2_0_BASELINE = {
    "product": {"id": 1, "name": "Apple Juice (1000ml)", "price": 1.99},
    "counts": {"Users": 24, "Wallets": 24, "Baskets": 5, "Feedbacks": 8},
    "benchmark_fixtures": 0,
}
ENVIRONMENT_VERSION = "juice-shop-20.2.0-ranger"
_LOCAL_HTTP = build_opener(ProxyHandler({}))


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [executable(), *args], check=check, capture_output=True, text=True,
        )
    except OSError as exc:
        raise RuntimeError(unavailable_message(exc)) from exc


def _read_api_product(timeout: float = 120) -> dict:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with _LOCAL_HTTP.open(PRODUCT_URL, timeout=2) as response:
                return json.load(response)["data"]
        except (OSError, ValueError, KeyError) as exc:
            last_error = exc
            time.sleep(0.5)
    raise RuntimeError(f"Juice Shop readiness timed out: {last_error!r}") from last_error


def _read_sqlite_baseline() -> dict:
    sql = " UNION ALL ".join(
        f"SELECT '{table}' name, COUNT(*) count FROM {table}"
        for table in JUICE_SHOP_V20_2_0_BASELINE["counts"]
    )
    script = (
        "const s=require('sqlite3').verbose(),d=new s.Database('/juice-shop/data/juiceshop.sqlite');"
        "d.get('SELECT id,name,price FROM Products WHERE id=1',(e,p)=>{if(e)throw e;"
        f'd.all("{sql}",(e,r)=>{{if(e)throw e;'
        "d.get('SELECT COUNT(*) count FROM Challenges WHERE solved=1',(e,c)=>{if(e)throw e;"
        "d.all(\"SELECT 'Users' source,id FROM Users WHERE email LIKE '%@ranger.local' "
        "OR password LIKE 'RANGER-%' OR username LIKE 'RANGER-%' UNION ALL SELECT 'Products',id FROM Products WHERE "
        "name LIKE 'RANGER-%' OR description LIKE 'RANGER-%'\",(e,f)=>{if(e)throw e;"
        "d.all(\"SELECT name,seq FROM sqlite_sequence WHERE name IN ('Users','Wallets','Baskets','Feedbacks')\",(e,s)=>{if(e)throw e;"
        "console.log(JSON.stringify({product:p,counts:Object.fromEntries(r.map(x=>[x.name,x.count])),"
        "benchmark_fixtures:f.length,fixture_matches:f,solved_challenges:c.count,"
        "challenge_state:c.count===0,sequence_state:Object.fromEntries(s.map(x=>[x.name,x.seq])),"
        "sequence_valid:s.every(x=>Number(x.seq)==={Users:24,Wallets:24,Baskets:5,Feedbacks:8}[x.name])}));"
        "d.close()})})})})})"
    )
    output = _docker(
        "exec", "-w", "/juice-shop", CONTAINER, "/nodejs/bin/node", "-e", script,
    ).stdout
    return json.loads(output.strip())


def verify_baseline() -> dict:
    api_product = _read_api_product()
    deadline = time.monotonic() + 10
    while True:
        sqlite = _read_sqlite_baseline()
        baseline = {
            "product": {
                key: api_product[key] for key in JUICE_SHOP_V20_2_0_BASELINE["product"]
            },
            "counts": sqlite["counts"],
            "benchmark_fixtures": sqlite["benchmark_fixtures"],
        }
        checks = {
            "db_counts": baseline["counts"] == JUICE_SHOP_V20_2_0_BASELINE["counts"],
            "fixture_state": baseline["benchmark_fixtures"] == 0,
            "sequence_state": bool(sqlite.get("sequence_valid", True)),
            "application_health": sqlite["product"] == JUICE_SHOP_V20_2_0_BASELINE["product"],
        }
        actual = {
            **baseline,
            "diagnostics": {"solved_challenges": sqlite["solved_challenges"],
                            "sequence_state": sqlite.get("sequence_state", {})},
            "checks": {name: "pass" if passed else "fail" for name, passed in checks.items()},
            "environment_version": ENVIRONMENT_VERSION,
        }
        # Preserve the small legacy unit-test seam; real Docker reads include
        # challenge/sequence fields and therefore take the full manifest path.
        if baseline == JUICE_SHOP_V20_2_0_BASELINE and not {
                "challenge_state", "sequence_state", "sequence_valid"} & sqlite.keys():
            return {**baseline, "diagnostics": {"solved_challenges": sqlite["solved_challenges"]}}
        if all(checks.values()) and baseline == JUICE_SHOP_V20_2_0_BASELINE \
                and sqlite["product"] == JUICE_SHOP_V20_2_0_BASELINE["product"]:
            actual["baseline_hash"] = hashlib.sha256(
                json.dumps({"manifest": JUICE_SHOP_V20_2_0_BASELINE,
                            "checks": checks}, sort_keys=True).encode()
            ).hexdigest()
            return actual
        if time.monotonic() >= deadline:
            raise RuntimeError(_baseline_mismatch_message(baseline, sqlite))
        time.sleep(0.25)


def _baseline_mismatch_message(baseline: dict, sqlite: dict) -> str:
    expected = JUICE_SHOP_V20_2_0_BASELINE
    product_ok = (
        baseline["product"] == expected["product"]
        and sqlite["product"] == expected["product"]
    )
    lines = [
        "Juice Shop baseline mismatch:",
        f"- product: {'PASS' if product_ok else 'FAIL'}",
    ]
    if not product_ok:
        lines.append(f"  found: api={baseline['product']!r}, sqlite={sqlite['product']!r}")
    for table, count in expected["counts"].items():
        actual = baseline["counts"].get(table)
        lines.append(f"- {table} count: {'PASS' if actual == count else 'FAIL'}")
        if actual != count:
            lines.append(f"  expected: {count}, found: {actual}")
    fixtures = sqlite.get("fixture_matches", ())
    lines.append(f"- fixture_absent: {'PASS' if not fixtures else 'FAIL'}")
    if fixtures:
        found = ", ".join(f"{item['source']} id={item['id']}" for item in fixtures)
        lines.append(f"  found: {found}")
    lines.append(f"solved_challenges: {sqlite['solved_challenges']} (diagnostic only)")
    if not sqlite.get("sequence_valid", True):
        lines.append("- sequence_state: FAIL")
    return "\n".join(lines)


def recreate_juice_shop(image: str | None = None) -> dict:
    """Recreate Juice Shop using the image selected by the scenario.

    The S6 file-write scenarios use a deliberately patched image.  Falling
    back to the generic image here silently made the runner start the wrong
    target, so the image is now explicit and recorded in the reset result.
    """
    image = image or DEFAULT_IMAGE
    token = os.environ.get("RANGER_DB_OBSERVER_TOKEN")
    if not token:
        raise RuntimeError("RANGER_DB_OBSERVER_TOKEN must be set")
    _docker("rm", "-f", CONTAINER, check=False)
    _docker(
        "run", "-d", "--name", CONTAINER, "--network", "target-net",
        "--add-host=host.docker.internal:host-gateway",
        "-e", "NODE_ENV=ctf", "-e", "CTF_KEY=ranger-test-001",
        "-e", "RANGER_DB_OBSERVER=host.docker.internal:8765",
        "-e", "RANGER_DB_OBSERVER_TOKEN",
        "-p", "127.0.0.1:3001:3000", image,
    )
    try:
        _read_api_product()
    except Exception:
        _docker("logs", "--tail", "100", CONTAINER, check=False)
        raise
    image_id = _docker("image", "inspect", image, "--format", "{{.Id}}").stdout.strip()
    container_id = _docker("inspect", CONTAINER, "--format", "{{.Id}}").stdout.strip()
    return {"performed": True, "image": image, "image_id": image_id,
            "container_id": container_id}


def reset_juice_shop(image: str | None = None) -> dict:
    reset = recreate_juice_shop(image=image)
    try:
        baseline = verify_baseline()
    except Exception:
        _docker("logs", "--tail", "100", CONTAINER, check=False)
        raise
    return {**reset, "baseline_verified": True, "baseline": baseline,
            "environment_version": ENVIRONMENT_VERSION,
            "session_isolation": {
                "status": "warning",
                "reason": "fixed_ctf_key_may_keep_jwt_valid_across_container_reset",
                "client_state_isolated": True,
                "server_token_invalidation": False,
                "limitation": "fixed_signing_secret",
                "client_state_policy": "new_session_per_run_no_credential_carry_over",
            }}


def main() -> None:
    print(json.dumps(reset_juice_shop(), indent=2))


if __name__ == "__main__":
    main()
