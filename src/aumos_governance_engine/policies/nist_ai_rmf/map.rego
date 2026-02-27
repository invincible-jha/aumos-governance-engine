# NIST AI RMF — MAP function
package aumos.compliance.nist_ai_rmf.map

import future.keywords

required_controls := ["AI_RISK_ASSESSMENT", "CONTEXT_ESTABLISHMENT", "RISK_METHODOLOGY"]

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
    msg := sprintf("NIST AI RMF MAP: Missing risk mapping control '%v'", [required])
}
