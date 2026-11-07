"""
Static rule evaluation logic for AgentCore Policy Engine.

Evaluates deterministic static guardrails according to specs/policy-engine-spec.md §3:
  1. Administrative lock (is_frozen) -> POLICY_FROZEN
  2. Request format -> INVALID_AMOUNT_FORMAT (for amount) / INVALID_REQUEST (for other fields)
  3. Whitelist matrix (Order: Network -> Asset -> Payee -> Domain)
  4. Single-Transaction Cap -> SINGLE_TX_CAP_EXCEEDED
  5. Lifetime Budget Ceiling -> LIFETIME_BUDGET_EXCEEDED

This module performs pure in-memory rule validation without external database calls.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_core.policy.errors import PolicyErrorCode
from agent_core.policy.models import (
    SQLITE_MAX_INT,
    PaymentRequest,
    PolicyConfig,
    WhitelistMode,
    _normalize_domain_host,
)


@dataclass(frozen=True)
class StaticEvaluationResult:
    """Outcome of static rule evaluation before dynamic budget reservation."""

    passed: bool
    error_code: PolicyErrorCode | None = None
    reason: str | None = None


def evaluate_static_rules(
    config: PolicyConfig,
    request: PaymentRequest,
    lifetime_spent: int = 0,
) -> StaticEvaluationResult:
    """
    Evaluate deterministic static guardrails in strict short-circuit precedence order.

    Args:
        config: Loaded policy configuration.
        request: The incoming payment evaluation request.
        lifetime_spent: Aggregate committed spend under this policy so far.

    Returns:
        StaticEvaluationResult indicating pass/fail and specific PolicyErrorCode on failure.
    """
    # 1. Administrative lock (is_frozen)
    if config.is_frozen:
        return StaticEvaluationResult(
            passed=False,
            error_code=PolicyErrorCode.POLICY_FROZEN,
            reason=f"Policy {config.id} is administratively frozen",
        )

    # 2. Format validation (Amount must be strictly positive int within SQLite 64-bit bounds)
    if (
        not isinstance(request.amount, int)
        or isinstance(request.amount, bool)
        or not (0 < request.amount <= SQLITE_MAX_INT)
    ):
        return StaticEvaluationResult(
            passed=False,
            error_code=PolicyErrorCode.INVALID_AMOUNT_FORMAT,
            reason=f"Invalid payment amount: {request.amount!r}",
        )

    if (
        not isinstance(request.intent_id, str)
        or not request.intent_id.strip()
        or not isinstance(request.ttl_seconds, int)
        or isinstance(request.ttl_seconds, bool)
        or not (0 < request.ttl_seconds <= 86400)
    ):
        return StaticEvaluationResult(
            passed=False,
            error_code=PolicyErrorCode.INVALID_REQUEST,
            reason="Invalid payment request parameters",
        )

    # 3. Whitelist Matrix (EVM only). AgentCore's internal wallet ledger uses
    # non-EVM identifiers; its trust boundary is the required gateway domain.
    # SECURITY-REVIEW: WhitelistMode.SIMPLE allows empty whitelists on EVM path;
    # WhitelistMode.STRICT requires every whitelist dimension to be populated and matched.
    is_strict = config.whitelist_mode == WhitelistMode.STRICT
    if not request.is_agentpay_wallet:
        if (is_strict or config.whitelist_networks) and request.network not in config.whitelist_networks:
            return StaticEvaluationResult(
                passed=False,
                error_code=PolicyErrorCode.NETWORK_NOT_WHITELISTED,
                reason=f"Network {request.network} is not in whitelisted networks",
            )

        if (is_strict or config.whitelist_assets) and request.asset not in config.whitelist_assets:
            return StaticEvaluationResult(
                passed=False,
                error_code=PolicyErrorCode.ASSET_NOT_WHITELISTED,
                reason=f"Asset {request.asset} is not in whitelisted assets",
            )

        if (is_strict or config.whitelist_payees) and request.payee not in config.whitelist_payees:
            return StaticEvaluationResult(
                passed=False,
                error_code=PolicyErrorCode.PAYEE_NOT_WHITELISTED,
                reason=f"Payee {request.payee} is not in whitelisted payees",
            )

    if request.is_agentpay_wallet and request.domain is None:
        return StaticEvaluationResult(
            passed=False,
            error_code=PolicyErrorCode.DOMAIN_NOT_WHITELISTED,
            reason="AgentCore wallet requests require a whitelisted gateway domain",
        )

    if request.domain is not None:
        enforce_domain = request.is_agentpay_wallet or is_strict or bool(config.whitelist_domains)
        if enforce_domain and request.domain.lower() not in config.whitelist_domains:
            return StaticEvaluationResult(
                passed=False,
                error_code=PolicyErrorCode.DOMAIN_NOT_WHITELISTED,
                reason=f"Domain {request.domain} is not in whitelisted domains",
            )

    # 4. Single-Transaction Cap
    if request.amount > config.max_per_tx_base_units:
        return StaticEvaluationResult(
            passed=False,
            error_code=PolicyErrorCode.SINGLE_TX_CAP_EXCEEDED,
            reason=(f"Amount {request.amount} exceeds single transaction cap of {config.max_per_tx_base_units}"),
        )

    # 5. Lifetime Budget Ceiling (if configured)
    if (
        config.lifetime_budget_base_units is not None
        and lifetime_spent + request.amount > config.lifetime_budget_base_units
    ):
        return StaticEvaluationResult(
            passed=False,
            error_code=PolicyErrorCode.LIFETIME_BUDGET_EXCEEDED,
            reason=(
                f"Lifetime spend ({lifetime_spent} + {request.amount}) "
                f"exceeds limit of {config.lifetime_budget_base_units}"
            ),
        )

    return StaticEvaluationResult(passed=True)


def evaluate_metered_rules(
    config: PolicyConfig,
    amount: int,
    domain: str | None,
    lifetime_spent: int = 0,
) -> StaticEvaluationResult:
    """
    Static guardrails for credential-mode (non-402) calls  [agentpay-metering-patch].

    Network/asset/payee do not exist in this mode, so only domain, single-tx cap and
    lifetime ceiling apply. The domain is REQUIRED (fail-closed): a missing or empty
    domain is rejected, not skipped. ``is_frozen`` here reads the in-memory config; the
    engine additionally checks the authoritative DB flag before calling this.
    """
    if config.is_frozen:
        return StaticEvaluationResult(
            passed=False,
            error_code=PolicyErrorCode.POLICY_FROZEN,
            reason=f"Policy {config.id} is administratively frozen",
        )

    if not isinstance(amount, int) or isinstance(amount, bool) or not (0 < amount <= SQLITE_MAX_INT):
        return StaticEvaluationResult(
            passed=False,
            error_code=PolicyErrorCode.INVALID_AMOUNT_FORMAT,
            reason=f"Invalid estimated amount: {amount!r}",
        )

    if domain is not None and not isinstance(domain, str):
        return StaticEvaluationResult(
            passed=False,
            error_code=PolicyErrorCode.INVALID_REQUEST,
            reason=f"Invalid domain type: {type(domain).__name__}",
        )

    host = _normalize_domain_host(domain) if isinstance(domain, str) else ""
    if not host or host not in config.whitelist_domains:
        return StaticEvaluationResult(
            passed=False,
            error_code=PolicyErrorCode.DOMAIN_NOT_WHITELISTED,
            reason=f"Domain {domain!r} is not in whitelisted domains",
        )

    if amount > config.max_per_tx_base_units:
        return StaticEvaluationResult(
            passed=False,
            error_code=PolicyErrorCode.SINGLE_TX_CAP_EXCEEDED,
            reason=f"Amount {amount} exceeds single transaction cap of {config.max_per_tx_base_units}",
        )

    if config.lifetime_budget_base_units is not None and lifetime_spent + amount > config.lifetime_budget_base_units:
        return StaticEvaluationResult(
            passed=False,
            error_code=PolicyErrorCode.LIFETIME_BUDGET_EXCEEDED,
            reason=(
                f"Lifetime spend ({lifetime_spent} + {amount}) exceeds limit of {config.lifetime_budget_base_units}"
            ),
        )

    return StaticEvaluationResult(passed=True)
