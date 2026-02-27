# EU AI Act Article 43 — Conformity Assessment
package aumos.compliance.eu_ai_act.art_43

import future.keywords

required_controls := ["CONFORMITY_ASSESSMENT", "THIRD_PARTY_AUDIT", "CE_MARKING"]

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
    msg := sprintf("EU AI Act Art. 43: Missing conformity assessment control '%v'", [required])
}
