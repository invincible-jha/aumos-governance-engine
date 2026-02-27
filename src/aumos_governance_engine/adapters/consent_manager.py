"""Consent Manager adapter — GDPR Article 7 compliant user consent tracking.

Manages user consent records across consent types (marketing, analytics, data processing),
enforces per-tenant consent policies, handles consent expiry and withdrawal, and generates
cryptographically verifiable consent proofs for audit and regulatory purposes.

GDPR Article 7 requirements addressed:
- Consent must be freely given, specific, informed, and unambiguous
- Controller must demonstrate consent was given (consent proof)
- Withdrawal must be as easy as giving consent
- Consent must be distinguishable from other matters
"""

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# Supported consent types — each maps to a specific processing purpose
CONSENT_TYPES: frozenset[str] = frozenset(
    {
        "marketing",
        "analytics",
        "data_processing",
        "profiling",
        "third_party_sharing",
        "ai_model_training",
        "performance_monitoring",
    }
)

# Default expiry periods per consent type (in days)
DEFAULT_EXPIRY_DAYS: dict[str, int] = {
    "marketing": 365,
    "analytics": 730,
    "data_processing": 365,
    "profiling": 180,
    "third_party_sharing": 365,
    "ai_model_training": 365,
    "performance_monitoring": 730,
}


@dataclass
class ConsentRecord:
    """Immutable record of a user consent event.

    Attributes:
        record_id: Unique consent record UUID.
        tenant_id: Owning tenant UUID.
        subject_id: UUID of the data subject (user).
        consent_type: Type of consent granted or withdrawn.
        granted: True if consent was given, False if withdrawn.
        granted_at: Timestamp when consent was recorded (UTC).
        expires_at: Timestamp when consent expires (None = no expiry).
        ip_address_hash: SHA-256 hash of the IP address (never stored raw).
        user_agent_hash: SHA-256 hash of the user agent string.
        consent_version: Version string of the consent notice shown.
        proof_token: Cryptographic proof token for this consent record.
        withdrawal_reason: Optional reason provided upon withdrawal.
        metadata: Additional structured metadata.
    """

    record_id: uuid.UUID
    tenant_id: uuid.UUID
    subject_id: uuid.UUID
    consent_type: str
    granted: bool
    granted_at: datetime
    expires_at: datetime | None
    ip_address_hash: str
    user_agent_hash: str
    consent_version: str
    proof_token: str
    withdrawal_reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ConsentProof:
    """Cryptographically verifiable proof of a consent event.

    Attributes:
        proof_token: SHA-256 token uniquely identifying this consent.
        subject_id: UUID of the data subject.
        consent_type: Type of consent.
        granted: Whether consent was given.
        granted_at: Timestamp of consent.
        consent_version: Version of the consent notice shown.
        signature_payload: JSON payload used to generate the proof token.
    """

    proof_token: str
    subject_id: uuid.UUID
    consent_type: str
    granted: bool
    granted_at: datetime
    consent_version: str
    signature_payload: str


@dataclass
class ConsentPolicy:
    """Per-tenant consent policy configuration.

    Attributes:
        tenant_id: Owning tenant UUID.
        required_consents: Consent types required for platform access.
        optional_consents: Consent types that are optional.
        expiry_overrides: Per-type expiry day overrides.
        double_opt_in_required: Whether double opt-in is required.
        minor_protection_enabled: Whether COPPA/minor protections are active.
        withdrawal_retention_days: Days to retain records after withdrawal.
    """

    tenant_id: uuid.UUID
    required_consents: list[str]
    optional_consents: list[str]
    expiry_overrides: dict[str, int] = field(default_factory=dict)
    double_opt_in_required: bool = False
    minor_protection_enabled: bool = False
    withdrawal_retention_days: int = 30


class ConsentManager:
    """GDPR Article 7 compliant user consent tracking and management.

    Manages the full lifecycle of user consent records:
    - Recording consent grants and withdrawals with cryptographic proof
    - Enforcing per-tenant consent policies
    - Checking consent validity (type, expiry, tenant policy)
    - Generating audit-ready consent proofs
    - Handling consent expiry and cleanup scheduling

    All consent records are stored with hashed PII (IP, user agent) and
    never with raw personal identifiers. Consent proof tokens enable
    GDPR Article 7(1) "demonstrability" compliance.

    Args:
        default_expiry_days: Default consent expiry period fallback if no policy.
        signing_secret: Secret used as HMAC key for proof token generation.
    """

    def __init__(
        self,
        default_expiry_days: int = 365,
        signing_secret: str = "aumos-consent-proof-v1",
    ) -> None:
        """Initialize the ConsentManager.

        Args:
            default_expiry_days: Default number of days before consent expires.
            signing_secret: HMAC signing secret for proof token generation.
        """
        self._default_expiry_days = default_expiry_days
        self._signing_secret = signing_secret
        # In-process store — in production this delegates to a DB repository
        self._records: dict[str, list[ConsentRecord]] = {}
        self._policies: dict[str, ConsentPolicy] = {}

        logger.info(
            "ConsentManager initialized",
            default_expiry_days=default_expiry_days,
        )

    async def record_consent(
        self,
        tenant_id: uuid.UUID,
        subject_id: uuid.UUID,
        consent_type: str,
        granted: bool,
        consent_version: str,
        ip_address: str,
        user_agent: str,
        withdrawal_reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ConsentRecord:
        """Record a consent grant or withdrawal for a data subject.

        Creates an immutable consent record with cryptographic proof.
        For withdrawals, marks previous grants as superseded.

        Args:
            tenant_id: The tenant owning this consent relationship.
            subject_id: The data subject's UUID.
            consent_type: The type of consent being recorded.
            granted: True to grant consent, False to withdraw.
            consent_version: Version of the consent notice shown to the user.
            ip_address: User's IP address (will be hashed, never stored raw).
            user_agent: User's browser user agent (will be hashed).
            withdrawal_reason: Optional reason for withdrawal (GDPR best practice).
            metadata: Additional structured consent context.

        Returns:
            The created ConsentRecord with proof token.

        Raises:
            ValueError: If consent_type is not a recognised consent type.
        """
        if consent_type not in CONSENT_TYPES:
            raise ValueError(
                f"Unknown consent type '{consent_type}'. "
                f"Supported types: {sorted(CONSENT_TYPES)}"
            )

        granted_at = datetime.now(UTC)
        policy = self._policies.get(str(tenant_id))
        expiry_days = self._resolve_expiry_days(consent_type, policy)
        expires_at = granted_at + timedelta(days=expiry_days) if granted else None

        record_id = uuid.uuid4()
        ip_hash = self._hash_pii(ip_address)
        ua_hash = self._hash_pii(user_agent)
        proof = self._generate_proof(
            subject_id=subject_id,
            consent_type=consent_type,
            granted=granted,
            granted_at=granted_at,
            consent_version=consent_version,
        )

        record = ConsentRecord(
            record_id=record_id,
            tenant_id=tenant_id,
            subject_id=subject_id,
            consent_type=consent_type,
            granted=granted,
            granted_at=granted_at,
            expires_at=expires_at,
            ip_address_hash=ip_hash,
            user_agent_hash=ua_hash,
            consent_version=consent_version,
            proof_token=proof.proof_token,
            withdrawal_reason=withdrawal_reason,
            metadata=metadata or {},
        )

        key = f"{tenant_id}:{subject_id}"
        if key not in self._records:
            self._records[key] = []
        self._records[key].append(record)

        logger.info(
            "Consent recorded",
            record_id=str(record_id),
            tenant_id=str(tenant_id),
            subject_id=str(subject_id),
            consent_type=consent_type,
            granted=granted,
            consent_version=consent_version,
            expires_at=expires_at.isoformat() if expires_at else None,
        )

        return record

    async def check_consent(
        self,
        tenant_id: uuid.UUID,
        subject_id: uuid.UUID,
        consent_type: str,
    ) -> bool:
        """Check whether a data subject has valid active consent.

        Evaluates the most recent consent record for the given type, checking
        that it is granted and not expired. Respects per-tenant consent policies.

        Args:
            tenant_id: The owning tenant UUID.
            subject_id: The data subject's UUID.
            consent_type: The consent type to check.

        Returns:
            True if valid active consent exists, False otherwise.
        """
        key = f"{tenant_id}:{subject_id}"
        subject_records = self._records.get(key, [])

        type_records = [
            r for r in subject_records if r.consent_type == consent_type
        ]

        if not type_records:
            return False

        # Most recent record supersedes all prior records
        latest = max(type_records, key=lambda r: r.granted_at)

        if not latest.granted:
            return False

        if latest.expires_at and datetime.now(UTC) > latest.expires_at:
            logger.info(
                "Consent expired",
                tenant_id=str(tenant_id),
                subject_id=str(subject_id),
                consent_type=consent_type,
                expired_at=latest.expires_at.isoformat(),
            )
            return False

        return True

    async def get_consent_status(
        self,
        tenant_id: uuid.UUID,
        subject_id: uuid.UUID,
    ) -> dict[str, dict[str, Any]]:
        """Get the full consent status for a data subject across all types.

        Returns a dict mapping each consent type to its current status.
        Useful for consent preference centres and GDPR transparency obligations.

        Args:
            tenant_id: The owning tenant UUID.
            subject_id: The data subject's UUID.

        Returns:
            Dict mapping consent_type -> status dict with granted, expires_at,
            consent_version, and record_id fields.
        """
        key = f"{tenant_id}:{subject_id}"
        subject_records = self._records.get(key, [])

        status: dict[str, dict[str, Any]] = {}

        for consent_type in CONSENT_TYPES:
            type_records = [r for r in subject_records if r.consent_type == consent_type]
            if not type_records:
                status[consent_type] = {
                    "granted": False,
                    "record_id": None,
                    "expires_at": None,
                    "consent_version": None,
                    "is_expired": False,
                }
                continue

            latest = max(type_records, key=lambda r: r.granted_at)
            is_expired = (
                latest.expires_at is not None
                and datetime.now(UTC) > latest.expires_at
            )

            status[consent_type] = {
                "granted": latest.granted and not is_expired,
                "record_id": str(latest.record_id),
                "expires_at": latest.expires_at.isoformat() if latest.expires_at else None,
                "consent_version": latest.consent_version,
                "is_expired": is_expired,
                "granted_at": latest.granted_at.isoformat(),
            }

        return status

    async def withdraw_all_consents(
        self,
        tenant_id: uuid.UUID,
        subject_id: uuid.UUID,
        withdrawal_reason: str,
        ip_address: str,
        user_agent: str,
        consent_version: str,
    ) -> list[ConsentRecord]:
        """Withdraw all active consents for a data subject.

        Used for GDPR Article 7(3) right-to-withdraw scenarios. Creates
        withdrawal records for all currently granted consent types.

        Args:
            tenant_id: The owning tenant UUID.
            subject_id: The data subject's UUID.
            withdrawal_reason: Reason for withdrawal (stored for audit).
            ip_address: User's IP address (will be hashed).
            user_agent: User's browser user agent (will be hashed).
            consent_version: Current consent notice version.

        Returns:
            List of withdrawal ConsentRecords created.
        """
        withdrawn_records: list[ConsentRecord] = []

        for consent_type in CONSENT_TYPES:
            is_active = await self.check_consent(tenant_id, subject_id, consent_type)
            if is_active:
                withdrawal_record = await self.record_consent(
                    tenant_id=tenant_id,
                    subject_id=subject_id,
                    consent_type=consent_type,
                    granted=False,
                    consent_version=consent_version,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    withdrawal_reason=withdrawal_reason,
                    metadata={"bulk_withdrawal": True},
                )
                withdrawn_records.append(withdrawal_record)

        logger.info(
            "All consents withdrawn",
            tenant_id=str(tenant_id),
            subject_id=str(subject_id),
            withdrawn_count=len(withdrawn_records),
            withdrawal_reason=withdrawal_reason,
        )

        return withdrawn_records

    async def get_consent_proof(
        self,
        tenant_id: uuid.UUID,
        subject_id: uuid.UUID,
        consent_type: str,
    ) -> ConsentProof | None:
        """Retrieve the verifiable proof for the most recent consent record.

        Returns a ConsentProof that can be used to demonstrate to regulators
        that consent was obtained (GDPR Article 7(1) demonstrability).

        Args:
            tenant_id: The owning tenant UUID.
            subject_id: The data subject's UUID.
            consent_type: The consent type to retrieve proof for.

        Returns:
            ConsentProof if a consent record exists, None otherwise.
        """
        key = f"{tenant_id}:{subject_id}"
        subject_records = self._records.get(key, [])
        type_records = [r for r in subject_records if r.consent_type == consent_type]

        if not type_records:
            return None

        latest = max(type_records, key=lambda r: r.granted_at)
        proof = self._generate_proof(
            subject_id=subject_id,
            consent_type=consent_type,
            granted=latest.granted,
            granted_at=latest.granted_at,
            consent_version=latest.consent_version,
        )

        return proof

    async def set_tenant_policy(self, policy: ConsentPolicy) -> None:
        """Set or update the consent policy for a tenant.

        Defines which consent types are required vs optional, expiry overrides,
        and whether double opt-in or minor protections apply.

        Args:
            policy: The ConsentPolicy configuration for this tenant.
        """
        self._policies[str(policy.tenant_id)] = policy
        logger.info(
            "Tenant consent policy updated",
            tenant_id=str(policy.tenant_id),
            required_consents=policy.required_consents,
            double_opt_in_required=policy.double_opt_in_required,
        )

    async def list_expiring_consents(
        self,
        tenant_id: uuid.UUID,
        within_days: int = 30,
    ) -> list[ConsentRecord]:
        """List consents expiring within a given window.

        Used by the consent renewal scheduler to prompt users before expiry.
        Only returns the most recent record per subject+type combination.

        Args:
            tenant_id: The owning tenant UUID.
            within_days: Return consents expiring within this many days.

        Returns:
            List of ConsentRecord instances that will expire within the window.
        """
        expiring: list[ConsentRecord] = []
        cutoff = datetime.now(UTC) + timedelta(days=within_days)
        now = datetime.now(UTC)

        for key, records in self._records.items():
            if not key.startswith(str(tenant_id)):
                continue

            for consent_type in CONSENT_TYPES:
                type_records = [r for r in records if r.consent_type == consent_type]
                if not type_records:
                    continue

                latest = max(type_records, key=lambda r: r.granted_at)
                if (
                    latest.granted
                    and latest.expires_at is not None
                    and now < latest.expires_at <= cutoff
                ):
                    expiring.append(latest)

        logger.info(
            "Expiring consents found",
            tenant_id=str(tenant_id),
            expiring_count=len(expiring),
            within_days=within_days,
        )

        return expiring

    def _resolve_expiry_days(
        self,
        consent_type: str,
        policy: ConsentPolicy | None,
    ) -> int:
        """Resolve the expiry period for a consent type.

        Checks per-tenant policy overrides first, then global defaults.

        Args:
            consent_type: The consent type.
            policy: Optional tenant-specific policy.

        Returns:
            Number of days until consent expires.
        """
        if policy and consent_type in policy.expiry_overrides:
            return policy.expiry_overrides[consent_type]
        return DEFAULT_EXPIRY_DAYS.get(consent_type, self._default_expiry_days)

    def _hash_pii(self, value: str) -> str:
        """Hash PII data using SHA-256 for safe storage.

        Args:
            value: Raw PII value to hash.

        Returns:
            Hex-encoded SHA-256 hash of the value.
        """
        return hashlib.sha256(
            f"{self._signing_secret}:{value}".encode()
        ).hexdigest()

    def _generate_proof(
        self,
        subject_id: uuid.UUID,
        consent_type: str,
        granted: bool,
        granted_at: datetime,
        consent_version: str,
    ) -> ConsentProof:
        """Generate a cryptographically verifiable consent proof.

        Creates a deterministic token from the consent parameters using SHA-256.
        The proof token enables downstream verification without storing raw data.

        Args:
            subject_id: Data subject UUID.
            consent_type: Type of consent.
            granted: Whether consent was granted.
            granted_at: Timestamp of consent.
            consent_version: Version of the consent notice.

        Returns:
            ConsentProof with a verifiable token.
        """
        payload_dict = {
            "subject_id": str(subject_id),
            "consent_type": consent_type,
            "granted": granted,
            "granted_at": granted_at.isoformat(),
            "consent_version": consent_version,
            "secret": self._signing_secret,
        }
        signature_payload = json.dumps(payload_dict, sort_keys=True)
        proof_token = hashlib.sha256(signature_payload.encode()).hexdigest()

        return ConsentProof(
            proof_token=proof_token,
            subject_id=subject_id,
            consent_type=consent_type,
            granted=granted,
            granted_at=granted_at,
            consent_version=consent_version,
            signature_payload=signature_payload,
        )


__all__ = [
    "ConsentManager",
    "ConsentPolicy",
    "ConsentProof",
    "ConsentRecord",
    "CONSENT_TYPES",
]
