# NIST AI RMF — GOVERN function
# Evaluates organizational AI governance policies and accountability structures.
package aumos.compliance.nist_ai_rmf.govern

import future.keywords

required_controls := [
    "AI_GOVERNANCE_POLICY",
    "RISK_MANAGEMENT_PROCESS",
    "RACI_MATRIX",
    "RESPONSIBLE_AI_TEAM",
]

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
    msg := sprintf("NIST AI RMF GOVERN: Missing governance control '%v'", [required])
}
