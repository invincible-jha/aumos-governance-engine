"""OPA (Open Policy Agent) REST API client.

Provides async HTTP communication with the OPA sidecar for:
- Uploading Rego policy bundles when policies are activated
- Evaluating Rego policies against structured input data
- Removing policy bundles when policies are deprecated/archived
- Health-checking OPA connectivity

OPA is deployed as a Docker sidecar and exposes a REST API on :8181.
The client uses httpx for async HTTP and enforces a hard evaluation
timeout (AUMOS_GOVERNANCE_POLICY_EVAL_TIMEOUT_MS).

OPA REST API reference: https://www.openpolicyagent.org/docs/latest/rest-api/
"""

import uuid
from typing import Any

import httpx

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# Default OPA base URL — overridden by AUMOS_GOVERNANCE_OPA_URL
_DEFAULT_OPA_URL = "http://localhost:8181"

# Default evaluation timeout in milliseconds
_DEFAULT_EVAL_TIMEOUT_MS = 200

# Default bundle path prefix
_DEFAULT_BUNDLE_PREFIX = "aumos/governance"


class OPAClientError(Exception):
    """Base error for OPA client failures.

    Attributes:
        message: Human-readable error description.
        status_code: HTTP status code from OPA (if available).
    """

    def __init__(self, message: str, status_code: int | None = None) -> None:
        """Initialize OPAClientError.

        Args:
            message: Error description.
            status_code: Optional HTTP status code.
        """
        super().__init__(message)
        self.status_code = status_code


class PolicyEvaluationError(OPAClientError):
    """Raised when OPA returns an error during policy evaluation."""


class PolicyUploadError(OPAClientError):
    """Raised when OPA rejects a Rego bundle upload."""


class OPAClient:
    """Async client for the OPA REST API.

    Communicates with the OPA sidecar to manage Rego policy bundles and
    evaluate policies. All HTTP operations use httpx async client with
    configurable timeout.

    Args:
        opa_url: OPA REST API base URL.
        eval_timeout_ms: Hard timeout for policy evaluation in milliseconds.
        bundle_prefix: Path prefix for OPA policy bundles.
    """

    def __init__(
        self,
        opa_url: str = _DEFAULT_OPA_URL,
        eval_timeout_ms: int = _DEFAULT_EVAL_TIMEOUT_MS,
        bundle_prefix: str = _DEFAULT_BUNDLE_PREFIX,
    ) -> None:
        """Initialize OPAClient.

        Args:
            opa_url: OPA REST API base URL (e.g., http://localhost:8181).
            eval_timeout_ms: Hard evaluation timeout in milliseconds.
            bundle_prefix: Prefix for policy bundle paths.
        """
        self._opa_url = opa_url.rstrip("/")
        self._eval_timeout_ms = eval_timeout_ms
        self._eval_timeout_s = eval_timeout_ms / 1000.0
        self._bundle_prefix = bundle_prefix.strip("/")

    def _policy_path(self, policy_id: uuid.UUID) -> str:
        """Construct the OPA bundle path for a policy.

        Args:
            policy_id: The policy UUID.

        Returns:
            OPA bundle path, e.g., aumos/governance/{policy_id}.
        """
        return f"{self._bundle_prefix}/{policy_id}"

    async def evaluate(
        self,
        policy_id: uuid.UUID,
        input_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Evaluate a policy against input data via the OPA REST API.

        Sends a POST request to /v1/data/{bundle_path} with the structured
        input. OPA returns a result dict containing the Rego policy's output.
        The `allow` and `violations` fields are extracted and returned.

        Args:
            policy_id: The policy UUID (used to construct the OPA query path).
            input_data: Structured JSON input for the Rego policy.

        Returns:
            Dict with at minimum `allow` (bool) and `violations` (list[str]).

        Raises:
            PolicyEvaluationError: If OPA returns an error or the request times out.
        """
        path = self._policy_path(policy_id)
        # OPA data query path replaces / with /
        query_path = path.replace("/", "/")
        url = f"{self._opa_url}/v1/data/{query_path}"

        logger.debug(
            "Evaluating policy via OPA",
            policy_id=str(policy_id),
            opa_url=url,
            timeout_ms=self._eval_timeout_ms,
        )

        try:
            async with httpx.AsyncClient(timeout=self._eval_timeout_s) as client:
                response = await client.post(
                    url,
                    json={"input": input_data},
                )

                if response.status_code == 200:
                    result_body = response.json()
                    result = result_body.get("result", {})
                    allow: bool = result.get("allow", False)
                    violations: list[str] = list(result.get("violations", []))
                    logger.debug(
                        "OPA evaluation complete",
                        policy_id=str(policy_id),
                        allowed=allow,
                        violations_count=len(violations),
                    )
                    return {"allow": allow, "violations": violations, "raw": result}

                if response.status_code == 404:
                    # Policy not found in OPA — treat as deny with explanation
                    logger.warning(
                        "Policy not found in OPA — returning deny",
                        policy_id=str(policy_id),
                        opa_url=url,
                    )
                    return {
                        "allow": False,
                        "violations": [f"Policy {policy_id} is not loaded in OPA. Re-activate the policy."],
                        "raw": {},
                    }

                logger.error(
                    "OPA returned unexpected status",
                    policy_id=str(policy_id),
                    status_code=response.status_code,
                    body=response.text[:500],
                )
                raise PolicyEvaluationError(
                    message=f"OPA evaluation failed with status {response.status_code}: {response.text[:200]}",
                    status_code=response.status_code,
                )

        except httpx.TimeoutException:
            logger.warning(
                "OPA evaluation timed out",
                policy_id=str(policy_id),
                timeout_ms=self._eval_timeout_ms,
            )
            raise PolicyEvaluationError(
                message=f"OPA evaluation timed out after {self._eval_timeout_ms}ms",
            )
        except httpx.RequestError as exc:
            logger.error(
                "OPA request failed",
                policy_id=str(policy_id),
                error=str(exc),
            )
            raise PolicyEvaluationError(message=f"OPA request error: {exc}")

    async def upload_policy(
        self,
        policy_id: uuid.UUID,
        rego_content: str,
    ) -> None:
        """Upload a Rego policy bundle to OPA.

        Sends a PUT request to /v1/policies/{bundle_path} with the Rego
        source as the request body. OPA compiles and stores the policy.

        Args:
            policy_id: The policy UUID (used as the bundle identifier).
            rego_content: Full Rego source code to upload.

        Raises:
            PolicyUploadError: If OPA rejects the bundle (syntax error, etc.).
        """
        path = self._policy_path(policy_id)
        url = f"{self._opa_url}/v1/policies/{path}"

        logger.info(
            "Uploading policy bundle to OPA",
            policy_id=str(policy_id),
            opa_url=url,
            rego_content_length=len(rego_content),
        )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.put(
                    url,
                    content=rego_content.encode("utf-8"),
                    headers={"Content-Type": "text/plain"},
                )

                if response.status_code in (200, 201):
                    logger.info(
                        "Policy bundle uploaded to OPA",
                        policy_id=str(policy_id),
                        status_code=response.status_code,
                    )
                    return

                logger.error(
                    "OPA rejected policy bundle",
                    policy_id=str(policy_id),
                    status_code=response.status_code,
                    body=response.text[:500],
                )
                raise PolicyUploadError(
                    message=f"OPA rejected policy bundle with status {response.status_code}: {response.text[:300]}",
                    status_code=response.status_code,
                )

        except httpx.RequestError as exc:
            raise PolicyUploadError(message=f"OPA upload request error: {exc}")

    async def delete_policy(self, policy_id: uuid.UUID) -> None:
        """Remove a policy bundle from OPA.

        Sends a DELETE request to /v1/policies/{bundle_path}. If OPA returns
        404 (policy not found), this is treated as a no-op success.

        Args:
            policy_id: The policy UUID to remove.
        """
        path = self._policy_path(policy_id)
        url = f"{self._opa_url}/v1/policies/{path}"

        logger.info("Deleting policy bundle from OPA", policy_id=str(policy_id), opa_url=url)

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.delete(url)

                if response.status_code in (200, 204, 404):
                    logger.info(
                        "Policy bundle removed from OPA",
                        policy_id=str(policy_id),
                        status_code=response.status_code,
                    )
                    return

                logger.warning(
                    "Unexpected status deleting policy from OPA",
                    policy_id=str(policy_id),
                    status_code=response.status_code,
                )

        except httpx.RequestError as exc:
            logger.error("OPA delete request failed", policy_id=str(policy_id), error=str(exc))

    async def health_check(self) -> bool:
        """Check if OPA is reachable and healthy.

        Sends a GET request to /health. Returns True if OPA responds with
        a 200 status code, False otherwise.

        Returns:
            True if OPA is healthy, False if unreachable or unhealthy.
        """
        url = f"{self._opa_url}/health"
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                response = await client.get(url)
                healthy = response.status_code == 200
                logger.debug("OPA health check", opa_url=url, healthy=healthy)
                return healthy
        except (httpx.RequestError, httpx.TimeoutException):
            logger.warning("OPA health check failed — OPA not reachable", opa_url=url)
            return False
