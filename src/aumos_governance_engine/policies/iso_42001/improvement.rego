# ISO 42001 — Improvement (Section 10)
package aumos.compliance.iso_42001.improvement

import future.keywords

required_controls := ["CONTINUAL_IMPROVEMENT", "NONCONFORMITY_MANAGEMENT"]

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
    msg := sprintf("ISO 42001 Improvement: Missing control '%v'", [required])
}
