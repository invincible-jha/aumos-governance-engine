# ISO 42001 — Operation (Section 8)
package aumos.compliance.iso_42001.operation

import future.keywords

required_controls := ["AI_OPERATIONAL_CONTROLS", "AI_CHANGE_MANAGEMENT", "AI_INCIDENT_RESPONSE"]

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
    msg := sprintf("ISO 42001 Operation: Missing control '%v'", [required])
}
