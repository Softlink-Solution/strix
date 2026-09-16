"""PII hygiene and data safety guards for security testing."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, ClassVar

from strix.config import load_settings

if TYPE_CHECKING:
    from re import Pattern

logger = logging.getLogger(__name__)


class PIIDetectionError(Exception):
    """Raised when PII is detected in sensitive data."""


class PIIGuard:
    """Detects and masks Personally Identifiable Information (PII) in data."""

    # PII Detection Patterns
    SSN_PATTERNS: ClassVar[list[str]] = [
        r"\b\d{3}-\d{2}-\d{4}\b",  # Standard SSN format
        r"\b\d{3}\s\d{2}\s\d{4}\b",  # SSN with spaces
        r"\b\d{9}\b",  # 9-digit SSN (careful with false positives)
    ]

    CREDIT_CARD_PATTERNS: ClassVar[list[str]] = [
        # Major credit cards
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|"
        r"6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|"
        r"3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b",
        r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",  # Generic 16-digit card
    ]

    EMAIL_PATTERNS: ClassVar[list[str]] = [
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    ]

    PHONE_PATTERNS: ClassVar[list[str]] = [
        r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",  # US phone format
        r"\b\+?1[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",  # US phone with country code
        r"\b\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b",  # International phone
    ]

    IP_ADDRESS_PATTERNS: ClassVar[list[str]] = [
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",  # IPv4
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",  # IPv6
    ]

    DATE_PATTERNS: ClassVar[list[str]] = [
        r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",  # Date format MM/DD/YYYY or DD/MM/YYYY
        r"\b\d{4}[/-]\d{1,2}[/-]\d{1,2}\b",  # Date format YYYY-MM-DD
    ]

    ADDRESS_PATTERNS: ClassVar[list[str]] = [
        r"\b\d+\s+[A-Za-z]+\s+(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|Boulevard|Blvd|Court|Ct|Way|Place|Pl)\b",
        r"\b\d+\s+[A-Za-z]+\s+[A-Za-z]+\s+(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|Boulevard|Blvd|Court|Ct|Way|Place|Pl)\b",
    ]

    LICENSE_PATTERNS: ClassVar[list[str]] = [
        r"\b[A-Z]{1,3}-?\d{1,6}-?[A-Z]{0,2}\b",  # Driver's license format
        r"\b[A-Z]{2}\d{6}\b",  # Some state formats
    ]

    PASSPORT_PATTERNS: ClassVar[list[str]] = [
        r"\b[A-Z]{1,2}\d{6,9}\b",  # Passport number format
    ]

    FINANCIAL_PATTERNS: ClassVar[list[str]] = [
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",  # IBAN format
        r"\b\d{9}[A-Z]{6}\d{2}\b",  # SWIFT/BIC format
    ]

    def __init__(self) -> None:
        self._settings = load_settings()
        self._enabled = self._settings.governance.pii_detection_enabled
        self._mask_threshold = self._settings.governance.pii_mask_threshold
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile all PII detection patterns."""
        self._patterns: dict[str, list[Pattern[str]]] = {
            "ssn": [re.compile(pattern, re.IGNORECASE) for pattern in self.SSN_PATTERNS],
            "credit_card": [re.compile(pattern, re.IGNORECASE) for pattern in self.CREDIT_CARD_PATTERNS],
            "email": [re.compile(pattern, re.IGNORECASE) for pattern in self.EMAIL_PATTERNS],
            "phone": [re.compile(pattern, re.IGNORECASE) for pattern in self.PHONE_PATTERNS],
            "ip_address": [re.compile(pattern, re.IGNORECASE) for pattern in self.IP_ADDRESS_PATTERNS],
            "date": [re.compile(pattern, re.IGNORECASE) for pattern in self.DATE_PATTERNS],
            "address": [re.compile(pattern, re.IGNORECASE) for pattern in self.ADDRESS_PATTERNS],
            "license": [re.compile(pattern, re.IGNORECASE) for pattern in self.LICENSE_PATTERNS],
            "passport": [re.compile(pattern, re.IGNORECASE) for pattern in self.PASSPORT_PATTERNS],
            "financial": [re.compile(pattern, re.IGNORECASE) for pattern in self.FINANCIAL_PATTERNS],
        }

    def detect_pii(self, data: str) -> dict[str, Any]:
        """Detect PII in data and return detection results.

        Args:
            data: Text data to scan for PII

        Returns:
            Dictionary with detection results:
            - has_pii: Boolean indicating if PII was detected
            - pii_types: List of PII types found
            - pii_count: Total number of PII instances
            - details: Detailed breakdown by PII type
            - should_mask: Boolean indicating if masking should occur
        """
        if not self._enabled:
            return {"has_pii": False, "pii_types": [], "pii_count": 0, "details": {}, "should_mask": False}

        results = {
            "has_pii": False,
            "pii_types": [],
            "pii_count": 0,
            "details": {},
            "should_mask": False
        }

        total_matches = 0

        for pii_type, patterns in self._patterns.items():
            type_matches = []
            for pattern in patterns:
                matches = pattern.findall(data)
                type_matches.extend(matches)

            if type_matches:
                results["has_pii"] = True
                results["pii_types"].append(pii_type)
                results["details"][pii_type] = {
                    "count": len(type_matches),
                    "matches": type_matches[:5],  # Limit to first 5 matches
                    "sample": type_matches[0] if type_matches else None
                }
                total_matches += len(type_matches)

        results["pii_count"] = total_matches
        results["should_mask"] = total_matches >= self._mask_threshold

        return results

    def mask_pii(self, data: str, detection_result: dict[str, Any] | None = None) -> str:
        """Mask PII in data based on detection results.

        Args:
            data: Text data to mask
            detection_result: Optional pre-computed detection results

        Returns:
            Data with PII masked
        """
        if not self._enabled:
            return data

        if detection_result is None:
            detection_result = self.detect_pii(data)

        if not detection_result["has_pii"]:
            return data

        masked_data = data

        # Mask each type of PII found
        for pii_type in detection_result["pii_types"]:
            patterns = self._patterns.get(pii_type, [])
            for pattern in patterns:
                masked_data = pattern.sub(self._get_mask(pii_type), masked_data)

        return masked_data

    def _get_mask(self, pii_type: str) -> str:
        """Get appropriate mask for PII type."""
        masks = {
            "ssn": "[REDACTED_SSN]",
            "credit_card": "[REDACTED_CARD]",
            "email": "[REDACTED_EMAIL]",
            "phone": "[REDACTED_PHONE]",
            "ip_address": "[REDACTED_IP]",
            "date": "[REDACTED_DATE]",
            "address": "[REDACTED_ADDRESS]",
            "license": "[REDACTED_LICENSE]",
            "passport": "[REDACTED_PASSPORT]",
            "financial": "[REDACTED_FINANCIAL]",
        }
        return masks.get(pii_type, "[REDACTED]")

    def sanitize_for_logging(self, data: str) -> str:
        """Sanitize data for safe logging.

        Args:
            data: Data to sanitize

        Returns:
            Sanitized data safe for logging
        """
        detection_result = self.detect_pii(data)

        if detection_result["should_mask"]:
            logger.warning(
                "PII detected in data - %d instances of types: %s. Masking before logging.",
                detection_result["pii_count"],
                ", ".join(detection_result["pii_types"])
            )
            return self.mask_pii(data, detection_result)

        return data

    def check_response_safety(self, response_data: dict[str, Any]) -> tuple[bool, str]:
        """Check if response data contains sensitive PII.

        Args:
            response_data: Response data to check

        Returns:
            Tuple of (is_safe, message)
        """
        if not self._enabled:
            return True, "PII detection disabled"

        # Convert response to string for analysis
        response_text = str(response_data)
        detection_result = self.detect_pii(response_text)

        if detection_result["has_pii"]:
            message = (
                f"PII detected in response: {detection_result['pii_count']} instances "
                f"of types: {', '.join(detection_result['pii_types'])}. "
                f"Data will be masked before logging."
            )
            logger.warning(message)
            return False, message

        return True, "No PII detected"

    def truncate_sensitive_data(self, data: str, max_length: int = 1000) -> str:
        """Truncate data to maximum safe length.

        Args:
            data: Data to truncate
            max_length: Maximum length to allow

        Returns:
            Truncated data with truncation indicator
        """
        if len(data) <= max_length:
            return data

        truncated = data[:max_length]
        return f"{truncated}... [TRUNCATED - {len(data) - max_length} characters hidden]"


class SafetyInterceptor:
    """Intercepts execution to enforce PII hygiene and data safety."""

    def __init__(self) -> None:
        self._pii_guard = PIIGuard()
        self._interception_enabled = True
        self._execution_blocked = False
        self._block_reason = ""

    def intercept_response(self, response_data: dict[str, Any]) -> dict[str, Any]:
        """Intercept and sanitize response data.

        Args:
            response_data: Response data to intercept

        Returns:
            Sanitized response data

        Raises:
            PIIDetectionError: If PII detection is configured to block execution
        """
        if not self._interception_enabled:
            return response_data

        # Check for PII
        is_safe, message = self._pii_guard.check_response_safety(response_data)

        if not is_safe:
            # Mask PII in the response
            sanitized_response = self._sanitize_response(response_data)

            # Check if we should block execution
            if self._should_block_on_pii():
                self._execution_blocked = True
                self._block_reason = message
                raise PIIDetectionError(f"Execution blocked: {message}")

            return sanitized_response

        return response_data

    def _sanitize_response(self, response_data: dict[str, Any]) -> dict[str, Any]:
        """Sanitize response data by masking PII."""
        if isinstance(response_data, dict):
            sanitized = {}
            for key, value in response_data.items():
                if isinstance(value, str):
                    sanitized[key] = self._pii_guard.sanitize_for_logging(value)
                elif isinstance(value, dict):
                    sanitized[key] = self._sanitize_response(value)
                elif isinstance(value, list):
                    sanitized[key] = [self._sanitize_response(item) if isinstance(item, dict) else item for item in value]
                else:
                    sanitized[key] = value
            return sanitized
        elif isinstance(response_data, str):
            return self._pii_guard.sanitize_for_logging(response_data)
        return response_data

    def _should_block_on_pii(self) -> bool:
        """Determine if execution should be blocked on PII detection."""
        # In public target mode, be more conservative
        settings = load_settings()
        if settings.governance.environment_mode == "public_target":
            return True
        return False

    def intercept_log_data(self, log_data: str) -> str:
        """Intercept and sanitize log data.

        Args:
            log_data: Log data to sanitize

        Returns:
            Sanitized log data
        """
        if not self._interception_enabled:
            return log_data

        sanitized = self._pii_guard.sanitize_for_logging(log_data)
        truncated = self._pii_guard.truncate_sensitive_data(sanitized)
        return truncated

    def is_execution_blocked(self) -> bool:
        """Check if execution was blocked."""
        return self._execution_blocked

    def get_block_reason(self) -> str:
        """Get reason for execution block."""
        return self._block_reason

    def reset(self) -> None:
        """Reset interceptor state."""
        self._execution_blocked = False
        self._block_reason = ""

    def enable_interception(self) -> None:
        """Enable PII interception."""
        self._interception_enabled = True

    def disable_interception(self) -> None:
        """Disable PII interception."""
        self._interception_enabled = False


class DataSafetyGuard:
    """Comprehensive data safety guard for security testing."""

    def __init__(self) -> None:
        self._pii_guard = PIIGuard()
        self._safety_interceptor = SafetyInterceptor()
        self._safety_checks: list["Callable[[dict[str, Any]], tuple[bool, str]]"] = [
            self._check_for_live_customer_data,
            self._check_for_user_records,
            self._check_for_production_data,
        ]

    def _check_for_live_customer_data(self, data: dict[str, Any]) -> tuple[bool, str]:
        """Check for indicators of live customer data."""
        data_str = str(data).lower()
        danger_indicators = [
            "live customer",
            "production database",
            "real user data",
            "customer data",
            "user records",
            "personal information",
        ]

        for indicator in danger_indicators:
            if indicator in data_str:
                return False, f"Potential live customer data detected: '{indicator}'"

        return True, "No live customer data indicators"

    def _check_for_user_records(self, data: dict[str, Any]) -> tuple[bool, str]:
        """Check for user record patterns."""
        data_str = str(data)
        user_record_patterns = [
            r"user[_\s]?id",
            r"customer[_\s]?id",
            r"account[_\s]?number",
            r"profile[_\s]?data",
            r"personal[_\s]?profile",
        ]

        for pattern in user_record_patterns:
            if re.search(pattern, data_str, re.IGNORECASE):
                return False, f"User record pattern detected: '{pattern}'"

        return True, "No user record patterns"

    def _check_for_production_data(self, data: dict[str, Any]) -> tuple[bool, str]:
        """Check for production data indicators."""
        data_str = str(data).lower()
        production_indicators = [
            "production",
            "prod",
            "live",
            "real-time",
            "customer database",
            "user database",
        ]

        for indicator in production_indicators:
            if indicator in data_str:
                return False, f"Production data indicator detected: '{indicator}'"

        return True, "No production data indicators"

    def check_data_safety(self, data: dict[str, Any]) -> tuple[bool, str]:
        """Comprehensive data safety check.

        Args:
            data: Data to check for safety

        Returns:
            Tuple of (is_safe, message)
        """
        # First check PII
        pii_safe, pii_message = self._pii_guard.check_response_safety(data)
        if not pii_safe:
            return False, pii_message

        # Run additional safety checks
        for safety_check in self._safety_checks:
            is_safe, message = safety_check(data)
            if not is_safe:
                return False, message

        return True, "Data passed all safety checks"

    def sanitize_for_storage(self, data: dict[str, Any]) -> dict[str, Any]:
        """Sanitize data for safe storage.

        Args:
            data: Data to sanitize

        Returns:
            Sanitized data safe for storage
        """
        # Apply PII masking
        sanitized = self._safety_interceptor._sanitize_response(data)

        # Truncate large string values
        if isinstance(sanitized, dict):
            for key, value in sanitized.items():
                if isinstance(value, str) and len(value) > 1000:
                    sanitized[key] = self._pii_guard.truncate_sensitive_data(value)

        return sanitized

    def should_halt_execution(self, data: dict[str, Any]) -> bool:
        """Determine if execution should halt based on data safety.

        Args:
            data: Data to evaluate

        Returns:
            True if execution should halt, False otherwise
        """
        is_safe, message = self.check_data_safety(data)

        if not is_safe:
            logger.error("Data safety check failed: %s. Halting execution.", message)
            return True

        return False


# Global instances
_pii_guard: PIIGuard | None = None
_safety_interceptor: SafetyInterceptor | None = None
_data_safety_guard: DataSafetyGuard | None = None


def get_pii_guard() -> PIIGuard:
    """Get global PII guard instance."""
    global _pii_guard
    if _pii_guard is None:
        _pii_guard = PIIGuard()
    return _pii_guard


def get_safety_interceptor() -> SafetyInterceptor:
    """Get global safety interceptor instance."""
    global _safety_interceptor
    if _safety_interceptor is None:
        _safety_interceptor = SafetyInterceptor()
    return _safety_interceptor


def get_data_safety_guard() -> DataSafetyGuard:
    """Get global data safety guard instance."""
    global _data_safety_guard
    if _data_safety_guard is None:
        _data_safety_guard = DataSafetyGuard()
    return _data_safety_guard


def reset_safety_guards() -> None:
    """Reset all safety guard instances (for testing)."""
    global _pii_guard, _safety_interceptor, _data_safety_guard
    _pii_guard = None
    _safety_interceptor = None
    _data_safety_guard = None