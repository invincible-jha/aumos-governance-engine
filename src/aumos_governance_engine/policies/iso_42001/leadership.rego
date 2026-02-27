# ISO 42001 — Leadership and Commitment (Section 5)
package aumos.compliance.iso_42001.leadership

import future.keywords

required_controls := ["AI_GOVERNANCE_COMMITTEE", "EXECUTIVE_SPONSORSHIP"]

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
    msg := sprintf("ISO 42001 Leadership: Missing control '%v'", [required])
}
