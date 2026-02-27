# ISO 42001 — Context of the Organization (Section 4)
package aumos.compliance.iso_42001.context

import future.keywords

required_controls := ["CONTEXT_ANALYSIS", "STAKEHOLDER_MAPPING"]

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
    msg := sprintf("ISO 42001 Context: Missing control '%v'", [required])
}
