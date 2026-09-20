#!/usr/bin/env python3


from __future__ import annotations

import argparse
import secrets
import string
import sys
from typing import Any

import requests

DEFAULT_UPSTREAM = "http://127.0.0.1:3001"
ADMIN_EMAIL = "admin@juice-sh.op"
DEFAULT_PASSWORD = "admin123"
REQUEST_TIMEOUT = 15


class ProvisionError(RuntimeError):
    pass



def _response_error(step: str, response: requests.Response) -> ProvisionError:
    body = response.text.strip().replace("\n", " ")
    if len(body) > 300:
        body = f"{body[:300]}..."
    detail = f": {body}" if body else ""
    return ProvisionError(f"{step} failed with HTTP {response.status_code}{detail}")


def _require_success(step: str, response: requests.Response) -> None:
    if not response.ok:
        raise _response_error(step, response)


def _json_object(step: str, response: requests.Response) -> dict[str, Any]:
    try:
        document = response.json()
    except requests.exceptions.JSONDecodeError as exc:
        raise ProvisionError(f"{step} returned invalid JSON") from exc
    if not isinstance(document, dict):
        raise ProvisionError(f"{step} returned an unexpected JSON value")
    return document


def _login(upstream: str, password: str) -> tuple[str, dict[str, Any]]:
    response = requests.post(
        f"{upstream}/rest/user/login",
        json={"email": ADMIN_EMAIL, "password": password},
        timeout=REQUEST_TIMEOUT,
    )
    _require_success("admin login", response)
    document = _json_object("admin login", response)
    authentication = document.get("authentication")
    token = authentication.get("token") if isinstance(authentication, dict) else None
    if not isinstance(token, str) or not token:
        raise ProvisionError("admin login response is missing authentication.token")
    return token, document


def _random_password() -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(8))


def _change_password(upstream: str, token: str, new_password: str) -> None:
    response = requests.get(
        f"{upstream}/rest/user/change-password",
        params={
            "current": DEFAULT_PASSWORD,
            "new": new_password,
            "repeat": new_password,
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=REQUEST_TIMEOUT,
    )
    _require_success("admin password change", response)


def _plant_feedback(
    upstream: str,
    comment: str,
    *,
    token: str | None = None,
) -> None:
    captcha_response = requests.get(
        f"{upstream}/rest/captcha",
        timeout=REQUEST_TIMEOUT,
    )
    _require_success("feedback captcha retrieval", captcha_response)
    captcha_document = _json_object("feedback captcha retrieval", captcha_response)
    captcha_id = captcha_document.get("captchaId")
    captcha_answer = captcha_document.get("answer")
    if captcha_id is None or captcha_answer is None:
        raise ProvisionError(
            "feedback captcha response is missing captchaId or answer"
        )

    headers = {"Authorization": f"Bearer {token}"} if token else None
    response = requests.post(
        f"{upstream}/api/Feedbacks",
        json={
            "comment": comment,
            "rating": 1,
            "captchaId": captcha_id,
            "captcha": str(captcha_answer),
        },
        headers=headers,
        timeout=REQUEST_TIMEOUT,
    )
    _require_success("feedback creation", response)


def provision(upstream: str) -> str:
    upstream = upstream.rstrip("/")
    print(f"[provision] upstream: {upstream}")

    token, _ = _login(upstream, DEFAULT_PASSWORD)
    new_password = _random_password()
    _change_password(upstream, token, new_password)
    print(f"[provision] new admin password: {new_password}")

    first_half, second_half = new_password[:4], new_password[4:]
    _plant_feedback(
        upstream,
        f"Internal audit note: admin recovery credential first half is '{first_half}'",
        token=token,
    )
    print("[provision] clue 1 planted in feedback (first half)")

    _plant_feedback(
        upstream,
        f"Maintenance log: system reset key second segment '{second_half}'",
    )
    print("[provision] clue 2 planted in feedback (second half)")
    print("[provision] ready to run")
    return new_password


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Randomize the Juice Shop admin password and plant recovery clues."
    )
    parser.add_argument("--upstream", default=DEFAULT_UPSTREAM)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        provision(args.upstream)
    except (ProvisionError, requests.RequestException) as exc:
        print(f"[provision] error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
