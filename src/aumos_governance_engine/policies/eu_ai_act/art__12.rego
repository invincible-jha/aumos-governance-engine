# EU AI Act Article 12 — Record-keeping
package aumos.compliance.eu_ai_act.art_12

import future.keywords

required_controls := ["AUDIT_LOGGING", "LOG_RETENTION", "EVENT_RECORDING"]

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
    msg := sprintf("EU AI Act Art. 12: Missing record-keeping control '%v'", [required])
}
