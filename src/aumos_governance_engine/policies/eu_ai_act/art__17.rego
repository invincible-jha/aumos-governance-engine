# EU AI Act Article 17 — Quality Management System
package aumos.compliance.eu_ai_act.art_17

import future.keywords

required_controls := ["MLOPS_LIFECYCLE", "MODEL_VERSIONING", "DATA_GOVERNANCE", "QUALITY_MGMT"]

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
    msg := sprintf("EU AI Act Art. 17: Missing quality management control '%v'", [required])
}
