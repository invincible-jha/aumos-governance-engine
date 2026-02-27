# SOX — Audit Trail Requirements
package aumos.compliance.sox.audit_trail

import future.keywords

required_controls := ["AUDIT_TRAIL", "DECISION_LOGGING", "RECORD_RETENTION"]

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
    msg := sprintf("SOX Audit Trail: Missing control '%v'", [required])
}
