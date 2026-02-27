# NIST AI RMF — MANAGE function
package aumos.compliance.nist_ai_rmf.manage

import future.keywords

required_controls := ["RISK_PRIORITIZATION", "INCIDENT_RESPONSE", "RISK_TREATMENT_PLAN"]

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
    msg := sprintf("NIST AI RMF MANAGE: Missing risk management control '%v'", [required])
}
