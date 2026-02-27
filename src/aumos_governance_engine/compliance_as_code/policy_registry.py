"""Policy registry — load, version, and hot-reload compliance policies.

The PolicyRegistry maintains an in-memory cache of active compliance policies,
keyed by (regulation, article_ref). It supports:
- Loading policies from the filesystem (Rego files)
- Version-aware policy loading from the database
- Hot-reload triggered by regulation catalog or DB changes
- Content hashing for tamper-detection

Policy files are stored under policies/{regulation}/{article_slug}.rego.
The registry holds parsed policy metadata but does NOT evaluate policies —
evaluation is handled by the ComplianceEngine via OPA or the mock evaluator.
"""

import hashlib
import importlib.resources
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aumos_common.observability import get_logger

from aumos_governance_engine.compliance_as_code.regulatory_inventory import (
    get_regulation,
    get_supported_codes,
)

logger = get_logger(__name__)


@dataclass
class LoadedPolicy:
    """A policy loaded into the registry.

    Attributes:
        policy_id: Unique identifier for this policy version.
        regulation: Regulation code this policy implements.
        article_ref: Article/section reference.
        version: Monotonically increasing version.
        content: Rego source content (or Python mock logic).
        content_hash: SHA-256 hex digest of the policy content.
        loaded_at: When this policy was loaded into the registry.
        source: Where the policy was loaded from: filesystem | database.
        metadata: Additional policy metadata.
    """

    policy_id: uuid.UUID
    regulation: str
    article_ref: str
    version: int
    content: str
    content_hash: str
    loaded_at: datetime
    source: str
    metadata: dict[str, Any]


class PolicyRegistry:
    """In-memory registry for compliance policies.

    Maintains a hot-reloadable cache of compliance policies. Policies can
    be loaded from filesystem Rego files or from database records.

    The registry uses (regulation, article_ref) as the composite key for
    policy lookup. When a new version of a policy is loaded, it replaces
    the existing entry.

    Args:
        policy_base_path: Base path for filesystem policy files.
    """

    def __init__(self, policy_base_path: Path | None = None) -> None:
        """Initialize the PolicyRegistry.

        Args:
            policy_base_path: Base directory for policy files. If None,
                uses the policies/ directory within the package.
        """
        self._policies: dict[str, LoadedPolicy] = {}
        self._policy_base_path = policy_base_path or self._resolve_policy_path()

    @staticmethod
    def _resolve_policy_path() -> Path:
        """Resolve the default policy file base path.

        Returns:
            Path to the policies/ directory within the package.
        """
        package_dir = Path(__file__).parent.parent
        return package_dir / "policies"

    @staticmethod
    def _compute_hash(content: str) -> str:
        """Compute SHA-256 hash of policy content.

        Args:
            content: Policy content string.

        Returns:
            Hex-encoded SHA-256 digest.
        """
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @staticmethod
    def _registry_key(regulation: str, article_ref: str) -> str:
        """Build the internal registry lookup key.

        Args:
            regulation: Regulation code.
            article_ref: Article reference.

        Returns:
            Composite key string.
        """
        return f"{regulation}::{article_ref}"

    def load_from_content(
        self,
        regulation: str,
        article_ref: str,
        content: str,
        version: int = 1,
        source: str = "inline",
        metadata: dict[str, Any] | None = None,
    ) -> LoadedPolicy:
        """Load a policy from content string into the registry.

        Args:
            regulation: Regulation code.
            article_ref: Article/section reference.
            content: Policy content (Rego source or mock logic).
            version: Policy version number.
            source: Content source descriptor.
            metadata: Optional additional metadata.

        Returns:
            The loaded LoadedPolicy instance.

        Raises:
            ValueError: If the regulation code is not supported.
        """
        supported = get_supported_codes()
        if regulation not in supported:
            raise ValueError(
                f"Unsupported regulation '{regulation}'. Supported: {sorted(supported)}"
            )

        content_hash = self._compute_hash(content)
        policy = LoadedPolicy(
            policy_id=uuid.uuid4(),
            regulation=regulation,
            article_ref=article_ref,
            version=version,
            content=content,
            content_hash=content_hash,
            loaded_at=datetime.now(UTC),
            source=source,
            metadata=metadata or {},
        )

        key = self._registry_key(regulation, article_ref)
        existing = self._policies.get(key)

        if existing and existing.content_hash == content_hash:
            logger.debug(
                "Policy unchanged — skipping reload",
                regulation=regulation,
                article_ref=article_ref,
                content_hash=content_hash,
            )
            return existing

        self._policies[key] = policy
        logger.info(
            "Policy loaded into registry",
            regulation=regulation,
            article_ref=article_ref,
            version=version,
            content_hash=content_hash,
            source=source,
        )
        return policy

    def load_from_filesystem(self, regulation: str, article_ref: str) -> LoadedPolicy | None:
        """Load a policy from the filesystem.

        Constructs the expected file path as:
        {policy_base_path}/{regulation}/{article_slug}.rego

        Args:
            regulation: Regulation code.
            article_ref: Article/section reference.

        Returns:
            The loaded LoadedPolicy, or None if file not found.
        """
        article_slug = article_ref.lower().replace(" ", "_").replace(".", "_").replace("/", "_")
        policy_path = self._policy_base_path / regulation / f"{article_slug}.rego"

        if not policy_path.exists():
            logger.debug(
                "Policy file not found on filesystem",
                regulation=regulation,
                article_ref=article_ref,
                path=str(policy_path),
            )
            return None

        try:
            content = policy_path.read_text(encoding="utf-8")
            return self.load_from_content(
                regulation=regulation,
                article_ref=article_ref,
                content=content,
                source="filesystem",
                metadata={"file_path": str(policy_path)},
            )
        except OSError as exc:
            logger.error(
                "Failed to read policy file",
                regulation=regulation,
                article_ref=article_ref,
                path=str(policy_path),
                error=str(exc),
            )
            return None

    def load_all_for_regulation(self, regulation: str) -> list[LoadedPolicy]:
        """Load all policy files for a regulation from the filesystem.

        Args:
            regulation: Regulation code.

        Returns:
            List of successfully loaded policies.
        """
        reg_def = get_regulation(regulation)
        if reg_def is None:
            logger.warning("Unknown regulation for policy loading", regulation=regulation)
            return []

        loaded: list[LoadedPolicy] = []
        for article in reg_def.articles:
            policy = self.load_from_filesystem(regulation, article.article_ref)
            if policy is not None:
                loaded.append(policy)
            else:
                # Create a placeholder policy for articles without files
                placeholder_content = self._generate_placeholder_policy(
                    regulation, article.article_ref, article.control_ids
                )
                policy = self.load_from_content(
                    regulation=regulation,
                    article_ref=article.article_ref,
                    content=placeholder_content,
                    source="generated",
                    metadata={
                        "control_ids": article.control_ids,
                        "automated": article.automated,
                    },
                )
                loaded.append(policy)

        logger.info(
            "Loaded policies for regulation",
            regulation=regulation,
            count=len(loaded),
        )
        return loaded

    @staticmethod
    def _generate_placeholder_policy(
        regulation: str, article_ref: str, control_ids: list[str]
    ) -> str:
        """Generate a placeholder Rego policy for articles without files.

        The placeholder checks that all required control IDs are present
        in the input's implemented_controls field.

        Args:
            regulation: Regulation code.
            article_ref: Article reference.
            control_ids: Required control IDs for this article.

        Returns:
            Rego policy source string.
        """
        controls_str = ", ".join(f'"{c}"' for c in control_ids)
        safe_ref = article_ref.replace(".", "_").replace(" ", "_").replace("/", "_")
        return f"""# Auto-generated placeholder policy for {regulation} {article_ref}
package aumos.compliance.{regulation.lower()}.{safe_ref.lower()}

import future.keywords

required_controls := [{controls_str}]

default allow := false
default violations := []

allow if {{
    all_controls_present
}}

all_controls_present if {{
    implemented := {{c | c := input.implemented_controls[_]}}
    every required in required_controls {{
        required in implemented
    }}
}}

violations contains msg if {{
    implemented := {{c | c := input.implemented_controls[_]}}
    some required in required_controls
    not required in implemented
    msg := sprintf("Missing required control: %v for {regulation} {article_ref}", [required])
}}
"""

    def get(self, regulation: str, article_ref: str) -> LoadedPolicy | None:
        """Retrieve a loaded policy from the registry.

        Args:
            regulation: Regulation code.
            article_ref: Article/section reference.

        Returns:
            The LoadedPolicy if found, None otherwise.
        """
        key = self._registry_key(regulation, article_ref)
        return self._policies.get(key)

    def get_all_for_regulation(self, regulation: str) -> list[LoadedPolicy]:
        """Return all loaded policies for a regulation.

        Args:
            regulation: Regulation code.

        Returns:
            List of LoadedPolicy instances for the regulation.
        """
        prefix = f"{regulation}::"
        return [p for key, p in self._policies.items() if key.startswith(prefix)]

    def list_all(self) -> list[LoadedPolicy]:
        """Return all loaded policies.

        Returns:
            List of all LoadedPolicy instances in the registry.
        """
        return list(self._policies.values())

    def reload_policy(
        self,
        regulation: str,
        article_ref: str,
        new_content: str,
        version: int,
        source: str = "database",
    ) -> LoadedPolicy:
        """Hot-reload a policy with new content.

        Replaces the existing policy in the registry. If content is
        identical (same hash), returns the existing policy unchanged.

        Args:
            regulation: Regulation code.
            article_ref: Article/section reference.
            new_content: New policy content.
            version: New version number.
            source: Content source descriptor.

        Returns:
            The reloaded LoadedPolicy.
        """
        logger.info(
            "Hot-reloading policy",
            regulation=regulation,
            article_ref=article_ref,
            new_version=version,
        )
        return self.load_from_content(
            regulation=regulation,
            article_ref=article_ref,
            content=new_content,
            version=version,
            source=source,
        )

    def remove(self, regulation: str, article_ref: str) -> bool:
        """Remove a policy from the registry.

        Args:
            regulation: Regulation code.
            article_ref: Article/section reference.

        Returns:
            True if the policy was removed, False if it was not found.
        """
        key = self._registry_key(regulation, article_ref)
        if key in self._policies:
            del self._policies[key]
            logger.info(
                "Policy removed from registry",
                regulation=regulation,
                article_ref=article_ref,
            )
            return True
        return False

    def get_stats(self) -> dict[str, Any]:
        """Return registry statistics.

        Returns:
            Dictionary with policy count, regulation breakdown, and load times.
        """
        by_regulation: dict[str, int] = {}
        for policy in self._policies.values():
            by_regulation[policy.regulation] = by_regulation.get(policy.regulation, 0) + 1

        return {
            "total_policies": len(self._policies),
            "by_regulation": by_regulation,
            "regulations_loaded": list(by_regulation.keys()),
        }
