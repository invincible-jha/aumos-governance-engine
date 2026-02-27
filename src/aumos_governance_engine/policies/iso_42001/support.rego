# ISO 42001 — Support (Section 7)
package aumos.compliance.iso_42001.support

import future.keywords

required_controls := ["AI_COMPETENCE_MANAGEMENT", "AI_AWARENESS_TRAINING", "AI_DOCUMENTATION"]

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
    msg := sprintf("ISO 42001 Support: Missing control '%v'", [required])
}
