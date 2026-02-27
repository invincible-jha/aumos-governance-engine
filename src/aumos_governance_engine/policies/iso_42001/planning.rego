# ISO 42001 — Planning (Section 6)
package aumos.compliance.iso_42001.planning

import future.keywords

required_controls := ["AI_RISK_ASSESSMENT", "AI_IMPACT_ANALYSIS", "OPPORTUNITY_IDENTIFICATION"]

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
    msg := sprintf("ISO 42001 Planning: Missing control '%v'", [required])
}
