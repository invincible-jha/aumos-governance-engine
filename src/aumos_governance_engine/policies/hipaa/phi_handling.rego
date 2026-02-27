# HIPAA PHI Handling — Access Control and Audit
package aumos.compliance.hipaa.phi_handling

import future.keywords

required_controls := [
    "UNIQUE_USER_ID",
    "ACCESS_CONTROL",
    "AUTH_MFA",
    "AUDIT_LOGGING",
    "LOG_RETENTION",
]

default allow := false
default violations := []

allow if {
    implemented := {c | c := input.implemented_controls[_]}
    every required in required_controls { required in implemented }
}

violations contains msg if {
    implemented := {c | c := input.implemented_controls[_]}
    some required in required_controls
    not required in implemented
    msg := sprintf("HIPAA PHI Handling: Missing required control '%v'", [required])
}
