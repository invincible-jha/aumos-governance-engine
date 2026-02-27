# EU AI Act Article 11 — Technical Documentation
package aumos.compliance.eu_ai_act.art_11

import future.keywords

required_controls := ["TECHNICAL_DOCUMENTATION", "MODEL_CARD", "SYSTEM_CARD"]

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
    msg := sprintf("EU AI Act Art. 11: Missing technical documentation control '%v'", [required])
}
