"""Governance module for dual-environment security testing controls."""

from __future__ import annotations

import logging
import re
import time
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from strix.config import load_settings

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


class GovernanceError(Exception):
    """Raised when governance rules are violated."""


class ScopeAuthorizationError(GovernanceError):
    """Raised when target is not in authorized scope."""


class RateLimitExceededError(GovernanceError):
    """Raised when rate limits are exceeded."""


class EnvironmentModeError(GovernanceError):
    """Raised when environment mode restrictions are violated."""


class GovernanceManager:
    """Manages dual-environment governance controls for security testing."""

    def __init__(self) -> None:
        self._settings = load_settings()
        self._rate_limiter = RateLimiter(
            min_rate=self._settings.governance.public_target_rate_limit_min,
            max_rate=self._settings.governance.public_target_rate_limit_max,
        )
        self._environment_mode = self._settings.governance.environment_mode
        self._authorized_targets = set(self._settings.governance.authorized_targets)

    @property
    def environment_mode(self) -> str:
        """Current operating environment mode."""
        return self._environment_mode

    @property
    def is_local_lab(self) -> bool:
        """Check if running in local lab mode."""
        return self._environment_mode == "local_lab"

    @property
    def is_public_target(self) -> bool:
        """Check if running in public target mode."""
        return self._environment_mode == "public_target"

    def check_target_authorization(self, target: str) -> None:
        """Verify target is authorized for testing in current mode.

        Args:
            target: Target URL, domain, or IP address

        Raises:
            ScopeAuthorizationError: If target is not authorized
            EnvironmentModeError: If mode-specific restrictions are violated
        """
        if self.is_local_lab:
            # Local lab mode allows most targets but still validates basic safety
            logger.info("Local lab mode: allowing target %s", target)
            return

        if self.is_public_target:
            self._check_public_target_authorization(target)

    def _check_public_target_authorization(self, target: str) -> None:
        """Strict authorization check for public target mode."""
        if not self._authorized_targets:
            if self._settings.governance.require_scope_confirmation:
                raise ScopeAuthorizationError(
                    f"Target '{target}' is not in authorized scope. "
                    f"Public target mode requires pre-configured scope confirmation. "
                    f"Add targets via STRIX_AUTHORIZED_TARGETS or disable requirement with "
                    f"STRIX_REQUIRE_SCOPE_CONFIRMATION=false."
                )
            logger.warning(
                "Public target mode: no authorized targets configured, but requirement disabled. "
                "Proceeding with target %s",
                target,
            )
            return

        normalized_target = self._normalize_target(target)
        is_authorized = any(
            self._target_matches(normalized_target, auth_target)
            for auth_target in self._authorized_targets
        )

        if not is_authorized:
            raise ScopeAuthorizationError(
                f"Target '{target}' is not in authorized scope. "
                f"Authorized targets: {', '.join(self._authorized_targets)}"
            )

        logger.info("Public target mode: target %s is authorized", target)

    def _normalize_target(self, target: str) -> str:
        """Normalize target for comparison."""
        try:
            parsed = urlparse(target)
            if parsed.netloc:
                return parsed.netloc.lower()
            return target.lower()
        except Exception:
            return target.lower()

    def _target_matches(self, target: str, pattern: str) -> bool:
        """Check if target matches authorization pattern."""
        normalized_pattern = self._normalize_target(pattern)

        # Exact match
        if target == normalized_pattern:
            return True

        # Subdomain match (pattern = *.example.com)
        if normalized_pattern.startswith("*."):
            domain = normalized_pattern[2:]
            return target == domain or target.endswith(f".{domain}")

        # Regex pattern
        try:
            if re.match(normalized_pattern, target):
                return True
        except re.error:
            pass

        return False

    def check_operation_allowed(self, operation: str) -> bool:
        """Check if operation is allowed in current environment mode.

        Args:
            operation: Type of operation (e.g., 'container_escape', 'custom_script', 'aggressive_fuzzing')

        Returns:
            True if operation is allowed, False otherwise

        Raises:
            EnvironmentModeError: If operation is explicitly forbidden
        """
        if self.is_local_lab:
            if operation == "container_escape":
                return self._settings.governance.local_lab_allow_container_escape
            if operation == "custom_script":
                return self._settings.governance.local_lab_allow_custom_scripts
            if operation == "aggressive_fuzzing":
                return self._settings.governance.local_lab_aggressive_fuzzing
            return True

        if self.is_public_target:
            # Public target mode has restrictive defaults
            if operation in ("container_escape", "custom_script", "aggressive_fuzzing"):
                raise EnvironmentModeError(
                    f"Operation '{operation}' is not allowed in public target mode. "
                    f"Switch to local lab mode for advanced testing capabilities."
                )
            return True

        return True

    def check_rate_limit(self, target: str) -> None:
        """Check and enforce rate limiting for public target mode.

        Args:
            target: Target being tested

        Raises:
            RateLimitExceededError: If rate limit is exceeded
        """
        if not self.is_public_target:
            return

        if not self._rate_limiter.allow(target):
            raise RateLimitExceededError(
                f"Rate limit exceeded for target '{target}'. "
                f"Current limit: {self._settings.governance.public_target_rate_limit_min}-"
                f"{self._settings.governance.public_target_rate_limit_max} requests per second."
            )

    def get_evidence_vault_path(self, engagement_name: str, target: str) -> str:
        """Get the path for evidence vault storage.

        Args:
            engagement_name: Name of the engagement
            target: Target being tested

        Returns:
            Path to evidence vault directory
        """
        base_path = self._settings.governance.evidence_vault_path
        safe_target = self._sanitize_target_for_path(target)
        return f"{base_path}/{engagement_name}_{safe_target}"

    def _sanitize_target_for_path(self, target: str) -> str:
        """Sanitize target string for safe path usage."""
        # Remove protocol, replace special chars with underscores
        sanitized = re.sub(r"[^a-zA-Z0-9\-_.]", "_", target)
        # Remove leading/trailing special chars
        sanitized = sanitized.strip("._-")
        return sanitized or "unknown"

    def log_operation(self, operation: str, target: str, details: str = "") -> None:
        """Log security operation for audit trail.

        Args:
            operation: Type of operation performed
            target: Target affected
            details: Additional operation details
        """
        logger.info(
            "Governance audit: mode=%s operation=%s target=%s details=%s",
            self._environment_mode,
            operation,
            target,
            details,
        )


class RateLimiter:
    """Token bucket rate limiter for public target mode."""

    def __init__(self, min_rate: int, max_rate: int) -> None:
        self._min_rate = min_rate
        self._max_rate = max_rate
        self._current_rate = min_rate
        self._tokens: dict[str, float] = {}
        self._last_update: dict[str, float] = {}
        self._lock_enabled = True

    def allow(self, target: str) -> bool:
        """Check if request is allowed under rate limit.

        Args:
            target: Target being requested

        Returns:
            True if request is allowed, False otherwise
        """
        if not self._lock_enabled:
            return True

        now = time.time()
        normalized_target = self._normalize_target(target)

        # Initialize or update token bucket
        if normalized_target not in self._tokens:
            self._tokens[normalized_target] = float(self._current_rate)
            self._last_update[normalized_target] = now
            return True

        # Refill tokens based on time elapsed
        time_elapsed = now - self._last_update[normalized_target]
        self._tokens[normalized_target] += time_elapsed * self._current_rate
        self._last_update[normalized_target] = now

        # Cap tokens at max rate
        if self._tokens[normalized_target] > self._current_rate:
            self._tokens[normalized_target] = float(self._current_rate)

        # Check if we have tokens available
        if self._tokens[normalized_target] >= 1.0:
            self._tokens[normalized_target] -= 1.0
            return True

        return False

    def _normalize_target(self, target: str) -> str:
        """Normalize target for rate limiting."""
        try:
            parsed = urlparse(target)
            return parsed.netloc.lower() if parsed.netloc else target.lower()
        except Exception:
            return target.lower()

    def adjust_rate(self, new_rate: int | None = None) -> None:
        """Adjust current rate limit.

        Args:
            new_rate: New rate to set, or None to toggle between min/max
        """
        if new_rate is not None:
            self._current_rate = max(self._min_rate, min(self._max_rate, new_rate))
        else:
            # Toggle between min and max
            self._current_rate = (
                self._max_rate if self._current_rate == self._min_rate else self._min_rate
            )

    def disable(self) -> None:
        """Disable rate limiting (for testing only)."""
        self._lock_enabled = False

    def enable(self) -> None:
        """Enable rate limiting."""
        self._lock_enabled = True


# Global governance manager instance
_governance_manager: GovernanceManager | None = None


def get_governance_manager() -> GovernanceManager:
    """Get the global governance manager instance."""
    global _governance_manager
    if _governance_manager is None:
        _governance_manager = GovernanceManager()
    return _governance_manager


def reset_governance_manager() -> None:
    """Reset the global governance manager (for testing)."""
    global _governance_manager
    _governance_manager = None
