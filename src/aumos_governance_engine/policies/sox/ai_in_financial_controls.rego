# SOX — AI in Financial Controls
package aumos.compliance.sox.ai_in_financial_controls

import future.keywords

required_controls := ["AI_FINANCIAL_CONTROLS", "EXECUTIVE_CERTIFICATION", "CONTROL_ASSESSMENT"]

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
    msg := sprintf("SOX AI Financial Controls: Missing control '%v'", [required])
}
