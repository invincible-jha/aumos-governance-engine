# EU AI Act Article 6 — High-Risk Classification
package aumos.compliance.eu_ai_act.art_6

import future.keywords

required_controls := ["AI_RISK_CLASSIFICATION", "HIGH_RISK_DETERMINATION"]

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
    msg := sprintf("EU AI Act Art. 6: Missing high-risk classification control '%v'", [required])
}
