# ISO 42001 — Performance Evaluation (Section 9)
package aumos.compliance.iso_42001.performance

import future.keywords

required_controls := ["AI_MONITORING", "AI_INTERNAL_AUDIT", "AI_MANAGEMENT_REVIEW"]

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
    msg := sprintf("ISO 42001 Performance: Missing control '%v'", [required])
}
