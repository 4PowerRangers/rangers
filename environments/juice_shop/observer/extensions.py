"""Optional, scenario-specific enrichments for the Juice Shop observer.

The transport observer should remain generic.  This module contains the
small amount of semantic recognition that cannot be expressed by the current
YAML rule grammar (for example, correlating a request identity with a JWT
claim, or checking a decoded response record).
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterable
from typing import Any


def enrich_observation(
    facts: dict[str, Any],
    request_body: bytes,
    response_body: bytes,
    *,
    response_role: str | None,
    markers: Iterable[str] = (),
    ownership_contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return semantic fields for known, bounded Juice Shop conditions.

    The function is deliberately side-effect free.  Callers may merge the
    returned fields into transport facts and can replace this extension with
    a project-specific implementation without changing the observer core.
    """
    result: dict[str, Any] = {}
    path = facts.get("path")
    method = facts.get("method")
    status = facts.get("status")
    markers = tuple(markers)

    if ownership_contract and method == "GET" and status == 200:
        protected_resource = str(ownership_contract.get("protected_resource") or "").casefold()
        response_shape = ownership_contract.get("response_shape") or {}
        owner_field = response_shape.get("owner_field") if isinstance(response_shape, dict) else None
        response = _json_object(response_body)
        owner_id = _extract_dotted(response, owner_field)
        if owner_id is None and isinstance(owner_field, str):
            data = response.get("data")
            owner_id = _extract_dotted(data, owner_field)
        actor_id = _actor_id_from_source(
            ownership_contract.get("actor_id_source"),
            facts.get("headers"),
        )
        if protected_resource and protected_resource in str(path or "").casefold() and owner_id is not None and actor_id is not None:
            result["authenticated"] = True
            result["actor_user"] = ownership_contract.get("actor_identity")
            if str(actor_id) != str(owner_id):
                result.update({
                    "target_override": ownership_contract.get("cross_user_target"),
                    "ownership_proven": True,
                    "owner_user": ownership_contract.get("owner_identity"),
                    "object_reference_manipulated": True,
                    "designated_target": True,
                    "returned_designated_basket": True,
                    "trusted_ownership_evidence": True,
                    "realized_outcome": ownership_contract.get("cross_user_outcome"),
                    "matched_markers": list(markers),
                })
            else:
                result.update({
                    "target_override": ownership_contract.get("own_resource_target"),
                    "ownership": ownership_contract.get("actor_identity"),
                })

    if (
        method == "GET" and path == "/encryptionkeys/premium.key"
        and status == 200 and response_body
    ):
        result.update({
            "activity_override": "premium_key_read",
            "outcome_evidence": {
                "evidence_type": "public_key_response",
                "source": "juice_shop_premium_key_response",
                "trust_level": "derived",
                "status": "confirmed",
            },
        })

    if (
        method == "GET" and path == "/encryptionkeys/jwt.pub"
        and status == 200 and response_body
    ):
        result.update({
            "activity_override": "public_key_read",
            "outcome_evidence": {
                "evidence_type": "public_key_response",
                "source": "juice_shop_jwt_public_key_response",
                "trust_level": "derived",
                "status": "confirmed",
            },
        })

    request = _json_object(request_body)
    email = request.get("email") if request else None
    if (
        method == "POST" and path == "/rest/user/login" and status == 200
        and email == "acc0unt4nt@juice-sh.op" and response_role == "accounting"
    ):
        result.update({
            "activity_override": "designated_ephemeral_login",
            "authorized_identity": "ephemeral_accountant",
            "authentication_role": "accounting",
            "trusted_ephemeral_evidence": True,
            "realized_outcome": "ephemeral_accountant_authenticated",
            "outcome_evidence": {
                "evidence_type": "response_jwt_claim_and_request_identity",
                "source": "gateway_response_claims",
                "trust_level": "trusted",
                "authorized_identity": "ephemeral_accountant",
                "role": "accounting",
                "realized_outcome": "ephemeral_accountant_authenticated",
                "status": "confirmed",
            },
        })

    query = str(facts.get("query") or "").casefold()
    if (
        method == "GET" and path == "/rest/products/search"
        and "union" in query and "deletedat" in query
        and b"Christmas" in response_body
        and _contains_product_id(response_body, 10)
    ):
        result.update({
            "activity_override": "hidden_product_search",
            "product_id": 10,
            "realized_outcome": "hidden_christmas_offer_disclosed",
            "outcome_evidence": {
                "evidence_type": "response_product_record",
                "source": "juice_shop_response_body",
                "trust_level": "derived",
                "product_id": 10,
                "product_marker": "Christmas",
                "realized_outcome": "hidden_christmas_offer_disclosed",
                "status": "confirmed",
            },
        })

    if method == "POST" and path == "/api/BasketItems" and status in (200, 201):
        if str(request.get("ProductId")) == "10" and b"Christmas" in response_body:
            result.update({
                "activity_override": "hidden_christmas_offer_added",
                "product_id": 10,
                "realized_outcome": "hidden_christmas_offer_added",
                "outcome_evidence": {
                    "evidence_type": "response_basket_item",
                    "source": "juice_shop_response_body",
                    "trust_level": "derived",
                    "product_id": 10,
                    "product_marker": "Christmas",
                    "realized_outcome": "hidden_christmas_offer_added",
                    "status": "confirmed",
                },
            })

    if (
        path in {
            "/ftp/coupons_2013.md.bak\x00.md",
            "/ftp/coupons_2013.md.bak%00.md",
        }
        and "coupon" in {str(marker).casefold() for marker in markers}
    ):
        result.update({
            "activity_override": "designated_backup_read",
            "realized_outcome": "designated_sales_backup_observed",
            "outcome_evidence": {
                "evidence_type": "response_marker",
                "source": "juice_shop_response_marker",
                "trust_level": "derived",
                "matched_markers": ["coupon"],
                "realized_outcome": "designated_sales_backup_observed",
                "status": "confirmed",
            },
        })

    if method == "POST" and path == "/rest/user/login" and status == 200:
        response = _json_object(response_body)
        token = _authentication_token(response)
        _, payload = _decode_jwt(token)
        authenticated_identity = _identity_from_payload(payload)
        if email == "support@juice-sh.op" and authenticated_identity == email:
            result.update({
                "activity_override": "designated_support_login",
                "designated_identity": "support_team",
                "authenticated": True,
                "login_method": "original_credentials",
                "trusted_proof": True,
                "matched_markers": list(markers),
                "realized_outcome": "support_team_session_established",
                "outcome_evidence": {
                    "evidence_type": "response_jwt_claim_and_request_identity",
                    "source": "gateway_response_claims",
                    "trust_level": "trusted",
                    "status": "confirmed",
                    "designated_identity": "support_team",
                    "authenticated": True,
                    "login_method": "original_credentials",
                    "realized_outcome": "support_team_session_established",
                },
            })

    if method == "GET" and path == "/rest/user/whoami" and status == 200:
        token = _bearer_token(facts.get("headers"))
        jwt_header, jwt_payload = _decode_jwt(token)
        response = _json_object(response_body)
        identity = _identity_from_payload(jwt_payload)
        response_identity = _identity_from_response(response)
        if (
            jwt_header.get("alg") == "HS256"
            and identity == "rsa_lord@juice-sh.op"
            and response_identity == "rsa_lord@juice-sh.op"
        ):
            result.update({
                "activity_override": "designated_forged_token_verification",
                "jwt_alg": "HS256",
                "claimed_identity": identity,
                "identity_accepted": True,
                "trusted_proof": True,
                "matched_markers": list(markers),
                "realized_outcome": "designated_forged_identity_accepted",
                "outcome_evidence": {
                    "evidence_type": "jwt_algorithm_confusion_state_probe",
                    "source": "juice_shop_whoami_response",
                    "trust_level": "trusted",
                    "status": "confirmed",
                    "jwt_alg": "HS256",
                    "claimed_identity": identity,
                    "identity_accepted": True,
                    "realized_outcome": "designated_forged_identity_accepted",
                },
            })

    if method == "POST" and path == "/rest/products/reviews" and status in (200, 201):
        response = _json_object(response_body)
        review = _review_record(response)
        requested_review_id = request.get("id") if request else None
        response_review_id = review.get("id") if review else None
        actor = _identity_from_payload(_decode_jwt(_bearer_token(facts.get("headers")))[1])
        liked_by = review.get("likedBy") if review else None
        actor_like_count = (
            sum(1 for value in liked_by if value == actor)
            if isinstance(liked_by, list) and isinstance(actor, str)
            else 0
        )
        if (
            review
            and requested_review_id is not None
            and str(response_review_id) == str(requested_review_id)
            and actor_like_count >= 3
        ):
            result.update({
                "activity_override": "designated_concurrent_like_test",
                "designated_review": True,
                "same_actor": True,
                "recorded_likes_at_least": actor_like_count,
                "trusted_proof": True,
                "matched_markers": list(markers),
                "realized_outcome": "multiple_likes_recorded_for_one_actor",
                "outcome_evidence": {
                    "evidence_type": "response_review_state",
                    "source": "juice_shop_review_response",
                    "trust_level": "trusted",
                    "status": "confirmed",
                    "designated_review": True,
                    "same_actor": True,
                    "recorded_likes_at_least": actor_like_count,
                    "realized_outcome": "multiple_likes_recorded_for_one_actor",
                },
            })

    premium_path = "/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us"
    if method == "GET" and path == premium_path and status == 200:
        content_type = str(facts.get("response_content_type") or "").casefold()
        content_returned = (
            response_body.startswith(b"\xff\xd8\xff")
            or "image/jpeg" in content_type
        ) and len(response_body) > 1024
        if content_returned:
            result.update({
                "activity_override": "designated_premium_page_access",
                "designated_hidden_page": True,
                "content_returned": True,
                "trusted_proof": True,
                "matched_markers": list(markers),
                "realized_outcome": "hidden_premium_content_accessed",
                "outcome_evidence": {
                    "evidence_type": "binary_content_response",
                    "source": "juice_shop_premium_content_response",
                    "trust_level": "trusted",
                    "status": "confirmed",
                    "designated_hidden_page": True,
                    "content_returned": True,
                    "realized_outcome": "hidden_premium_content_accessed",
                },
            })

    if method == "POST" and path == "/b2b/v2/orders" and status == 503:
        timeout_marker = b"temporarily not available" in response_body.casefold()
        if timeout_marker:
            result.update({
                "activity_override": "bounded_orderlines_dos_test",
                "designated_endpoint": True,
                "availability_probe": "trusted",
                "degradation_confirmed": True,
                "trusted_proof": True,
                "matched_markers": list(markers),
                "realized_outcome": "bounded_availability_degradation_confirmed",
                "outcome_evidence": {
                    "evidence_type": "bounded_timeout_response",
                    "source": "juice_shop_b2b_order_response",
                    "trust_level": "trusted",
                    "status": "confirmed",
                    "designated_endpoint": True,
                    "availability_probe": "trusted",
                    "degradation_confirmed": True,
                    "realized_outcome": "bounded_availability_degradation_confirmed",
                },
            })

    if (
        method == "POST" and path == "/file-upload" and status in (200, 201, 204)
        and b".zip" in request_body.lower()
        and b"owasp_promo.vtt" in request_body
    ):
        result.update({
            "activity_override": "designated_zip_upload",
            "operation": "create",
        })

    if method == "GET" and path == "/assets/public/videos/owasp_promo.vtt":
        result.setdefault("activity_override", "designated_subtitle_inspection")
        result.setdefault("operation", "read")
        if status != 200:
            return result
        marker_present = any(
            isinstance(marker, str) and marker.encode("utf-8") in response_body
            for marker in markers
        )
        script_payload_present = b"<script" in response_body.casefold()
        if marker_present and script_payload_present:
            result.update({
                "activity_override": "designated_video_xss_proof",
                "designated_subtitle_overwritten": True,
                "subtitle_payload_observed": True,
                "trusted_proof": True,
                "matched_markers": list(markers),
                "realized_outcome": "designated_video_xss_payload_observed",
                "outcome_evidence": {
                    "evidence_type": "subtitle_asset_response",
                    "source": "juice_shop_vtt_response",
                    "trust_level": "trusted",
                    "status": "confirmed",
                    "designated_subtitle_overwritten": True,
                    "subtitle_payload_observed": True,
                    "realized_outcome": "designated_video_xss_payload_observed",
                },
            })
    return result


def _json_object(body: bytes) -> dict[str, Any]:
    try:
        value = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, TypeError, UnicodeDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _extract_dotted(obj: Any, path: str | None) -> Any:
    if not isinstance(path, str) or not path:
        return None
    for key in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _authentication_token(response: dict[str, Any]) -> str | None:
    authentication = response.get("authentication")
    token = authentication.get("token") if isinstance(authentication, dict) else None
    return token if isinstance(token, str) and token else None


def _review_record(response: dict[str, Any]) -> dict[str, Any]:
    candidates: list[Any] = [response]
    for key in ("data", "review", "result"):
        value = response.get(key)
        if isinstance(value, dict):
            candidates.append(value)
    return next(
        (
            candidate for candidate in candidates
            if isinstance(candidate.get("id"), (int, str))
            and isinstance(candidate.get("likedBy"), list)
        ),
        {},
    )


def _contains_product_id(body: bytes, product_id: int) -> bool:
    return any(
        token in body
        for token in (
            f'"id":{product_id}'.encode(),
            f'"id": {product_id}'.encode(),
        )
    )


def _bearer_token(headers: Any) -> str | None:
    if not isinstance(headers, dict):
        return None
    value = next((v for k, v in headers.items() if str(k).casefold() == "authorization"), "")
    prefix, _, token = str(value).partition(" ")
    return token.strip() if prefix.casefold() == "bearer" and token.strip() else None


def _decode_jwt(token: str | None) -> tuple[dict[str, Any], dict[str, Any]]:
    if not token or len(token.split(".")) != 3:
        return {}, {}
    parts = token.split(".")
    try:
        def decode(value: str) -> dict[str, Any]:
            padded = value + "=" * (-len(value) % 4)
            parsed = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
            return parsed if isinstance(parsed, dict) else {}
        return decode(parts[0]), decode(parts[1])
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return {}, {}


def _identity_from_payload(payload: dict[str, Any]) -> str | None:
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    for key in ("email", "username", "sub"):
        value = data.get(key) if isinstance(data, dict) else None
        if isinstance(value, str) and "@" in value:
            return value
    return None


def _actor_id_from_source(source: Any, headers: Any) -> Any:
    if not isinstance(source, str) or not source.startswith("jwt."):
        return None
    return _extract_dotted(_decode_jwt(_bearer_token(headers))[1], source[4:])


def _identity_from_response(response: dict[str, Any]) -> str | None:
    candidates: list[Any] = [response]
    for key in ("user", "data"):
        if isinstance(response.get(key), dict):
            candidates.append(response[key])
    for candidate in candidates:
        for key in ("email", "username"):
            value = candidate.get(key) if isinstance(candidate, dict) else None
            if isinstance(value, str) and "@" in value:
                return value
    return None
