"""Local evidence vault management for engagement artifacts."""

from __future__ import annotations

import json
import logging
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from strix.config import load_settings
from strix.core.governance import get_governance_manager

logger = logging.getLogger(__name__)


class EvidenceVault:
    """Manages local evidence vault storage for engagement artifacts."""

    def __init__(self, engagement_name: str, target: str) -> None:
        self.engagement_name = engagement_name
        self.target = target
        self._settings = load_settings()
        self._governance = get_governance_manager()
        self._vault_path = self._get_vault_path()
        self._ensure_vault_structure()

    def _get_vault_path(self) -> Path:
        """Get the vault path for this engagement."""
        base_path = Path(self._settings.governance.evidence_vault_path).expanduser()
        vault_path = base_path / f"{self.engagement_name}_{self._governance._sanitize_target_for_path(self.target)}"
        return vault_path

    def _ensure_vault_structure(self) -> None:
        """Ensure the vault directory structure exists."""
        directories = [
            self._vault_path,
            self._vault_path / "raw_requests",
            self._vault_path / "raw_responses",
            self._vault_path / "recon_logs",
            self._vault_path / "screenshots",
            self._vault_path / "payloads",
            self._vault_path / "findings",
            self._vault_path / "metadata",
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

        logger.info("Evidence vault structure created at: %s", self._vault_path)

    def store_raw_request(self, request_id: str, request_data: dict[str, Any]) -> Path:
        """Store raw request data.

        Args:
            request_id: Unique identifier for the request
            request_data: Request data to store

        Returns:
            Path to stored request file
        """
        requests_dir = self._vault_path / "raw_requests"
        request_file = requests_dir / f"{request_id}.json"

        with request_file.open("w", encoding="utf-8") as f:
            json.dump(request_data, f, indent=2, default=str)

        logger.debug("Stored raw request: %s", request_file)
        return request_file

    def store_raw_response(self, request_id: str, response_data: dict[str, Any]) -> Path:
        """Store raw response data.

        Args:
            request_id: Unique identifier for the request
            response_data: Response data to store

        Returns:
            Path to stored response file
        """
        responses_dir = self._vault_path / "raw_responses"
        response_file = responses_dir / f"{request_id}.json"

        with response_file.open("w", encoding="utf-8") as f:
            json.dump(response_data, f, indent=2, default=str)

        logger.debug("Stored raw response: %s", response_file)
        return response_file

    def store_recon_log(self, log_type: str, log_data: str) -> Path:
        """Store reconnaissance log data.

        Args:
            log_type: Type of reconnaissance (e.g., "port_scan", "subdomain_enum")
            log_data: Log data to store

        Returns:
            Path to stored log file
        """
        recon_dir = self._vault_path / "recon_logs"
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        log_file = recon_dir / f"{log_type}_{timestamp}.log"

        with log_file.open("w", encoding="utf-8") as f:
            f.write(log_data)

        logger.debug("Stored recon log: %s", log_file)
        return log_file

    def store_screenshot(self, screenshot_id: str, image_data: bytes, image_format: str = "png") -> Path:
        """Store screenshot image data.

        Args:
            screenshot_id: Unique identifier for the screenshot
            image_data: Binary image data
            image_format: Image format (e.g., "png", "jpg")

        Returns:
            Path to stored screenshot file
        """
        screenshots_dir = self._vault_path / "screenshots"
        screenshot_file = screenshots_dir / f"{screenshot_id}.{image_format}"

        with screenshot_file.open("wb") as f:
            f.write(image_data)

        logger.debug("Stored screenshot: %s", screenshot_file)
        return screenshot_file

    def store_payload(self, payload_id: str, payload_data: str, payload_type: str = "generic") -> Path:
        """Store payload data.

        Args:
            payload_id: Unique identifier for the payload
            payload_data: Payload data to store
            payload_type: Type of payload (e.g., "sql_injection", "xss")

        Returns:
            Path to stored payload file
        """
        payloads_dir = self._vault_path / "payloads"
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        payload_file = payloads_dir / f"{payload_type}_{payload_id}_{timestamp}.txt"

        with payload_file.open("w", encoding="utf-8") as f:
            f.write(payload_data)

        logger.debug("Stored payload: %s", payload_file)
        return payload_file

    def store_finding(self, finding_id: str, finding_data: dict[str, Any]) -> Path:
        """Store vulnerability finding data.

        Args:
            finding_id: Unique identifier for the finding
            finding_data: Finding data to store

        Returns:
            Path to stored finding file
        """
        findings_dir = self._vault_path / "findings"
        finding_file = findings_dir / f"{finding_id}.json"

        with finding_file.open("w", encoding="utf-8") as f:
            json.dump(finding_data, f, indent=2, default=str)

        logger.debug("Stored finding: %s", finding_file)
        return finding_file

    def store_metadata(self, metadata_type: str, metadata_data: dict[str, Any]) -> Path:
        """Store engagement metadata.

        Args:
            metadata_type: Type of metadata (e.g., "engagement_info", "scan_config")
            metadata_data: Metadata data to store

        Returns:
            Path to stored metadata file
        """
        metadata_dir = self._vault_path / "metadata"
        metadata_file = metadata_dir / f"{metadata_type}.json"

        with metadata_file.open("w", encoding="utf-8") as f:
            json.dump(metadata_data, f, indent=2, default=str)

        logger.debug("Stored metadata: %s", metadata_file)
        return metadata_file

    def get_vault_path(self) -> Path:
        """Get the vault path for this engagement."""
        return self._vault_path

    def get_artifact_summary(self) -> dict[str, Any]:
        """Get summary of stored artifacts.

        Returns:
            Dictionary with artifact counts and summary information
        """
        summary = {
            "engagement_name": self.engagement_name,
            "target": self.target,
            "vault_path": str(self._vault_path),
            "artifact_counts": {
                "raw_requests": len(list((self._vault_path / "raw_requests").glob("*.json"))),
                "raw_responses": len(list((self._vault_path / "raw_responses").glob("*.json"))),
                "recon_logs": len(list((self._vault_path / "recon_logs").glob("*.log"))),
                "screenshots": len(list((self._vault_path / "screenshots").glob("*.*"))),
                "payloads": len(list((self._vault_path / "payloads").glob("*.txt"))),
                "findings": len(list((self._vault_path / "findings").glob("*.json"))),
            },
            "created_at": datetime.now(UTC).isoformat(),
        }

        return summary

    def cleanup_old_artifacts(self, days: int = 30) -> int:
        """Clean up artifacts older than specified days.

        Args:
            days: Number of days to keep artifacts

        Returns:
            Number of artifacts cleaned up
        """
        from datetime import timedelta

        cutoff_time = datetime.now(UTC) - timedelta(days=days)
        cleaned_count = 0

        for artifact_file in self._vault_path.rglob("*"):
            if artifact_file.is_file():
                file_mtime = datetime.fromtimestamp(artifact_file.stat().st_mtime, tz=UTC)
                if file_mtime < cutoff_time:
                    artifact_file.unlink()
                    cleaned_count += 1

        logger.info("Cleaned up %d artifacts older than %d days", cleaned_count, days)
        return cleaned_count

    def export_artifacts(self, export_path: Path) -> Path:
        """Export all artifacts to a compressed archive.

        Args:
            export_path: Path for the exported archive

        Returns:
            Path to the exported archive
        """
        import zipfile

        export_path = Path(export_path)
        if not export_path.suffix:
            export_path = export_path.with_suffix(".zip")

        with zipfile.ZipFile(export_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for file_path in self._vault_path.rglob("*"):
                if file_path.is_file():
                    arcname = file_path.relative_to(self._vault_path)
                    zipf.write(file_path, arcname)

        logger.info("Exported artifacts to: %s", export_path)
        return export_path

    def delete_vault(self) -> None:
        """Delete the entire vault directory."""
        if self._vault_path.exists():
            shutil.rmtree(self._vault_path)
            logger.info("Deleted evidence vault: %s", self._vault_path)


class VaultManager:
    """Manages multiple evidence vaults."""

    def __init__(self) -> None:
        self._vaults: dict[str, EvidenceVault] = {}
        self._settings = load_settings()

    def create_vault(self, engagement_name: str, target: str) -> EvidenceVault:
        """Create a new evidence vault.

        Args:
            engagement_name: Name of the engagement
            target: Target being tested

        Returns:
            EvidenceVault instance
        """
        vault_key = f"{engagement_name}_{target}"
        if vault_key in self._vaults:
            return self._vaults[vault_key]

        vault = EvidenceVault(engagement_name, target)
        self._vaults[vault_key] = vault
        return vault

    def get_vault(self, engagement_name: str, target: str) -> EvidenceVault | None:
        """Get an existing evidence vault.

        Args:
            engagement_name: Name of the engagement
            target: Target being tested

        Returns:
            EvidenceVault instance or None if not found
        """
        vault_key = f"{engagement_name}_{target}"
        return self._vaults.get(vault_key)

    def list_vaults(self) -> list[dict[str, Any]]:
        """List all managed vaults.

        Returns:
            List of vault information dictionaries
        """
        vault_list = []
        for vault_key, vault in self._vaults.items():
            vault_list.append({
                "key": vault_key,
                "engagement_name": vault.engagement_name,
                "target": vault.target,
                "path": str(vault.get_vault_path()),
                "summary": vault.get_artifact_summary()
            })
        return vault_list

    def cleanup_all_vaults(self, days: int = 30) -> int:
        """Clean up old artifacts across all vaults.

        Args:
            days: Number of days to keep artifacts

        Returns:
            Total number of artifacts cleaned up
        """
        total_cleaned = 0
        for vault in self._vaults.values():
            total_cleaned += vault.cleanup_old_artifacts(days)
        return total_cleaned


# Global vault manager instance
_vault_manager: VaultManager | None = None


def get_vault_manager() -> VaultManager:
    """Get the global vault manager instance."""
    global _vault_manager
    if _vault_manager is None:
        _vault_manager = VaultManager()
    return _vault_manager


def reset_vault_manager() -> None:
    """Reset the global vault manager (for testing)."""
    global _vault_manager
    _vault_manager = None