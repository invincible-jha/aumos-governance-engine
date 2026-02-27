# HIPAA Authorization — Patient consent and authorization
package aumos.compliance.hipaa.authorization

import future.keywords

required_controls := ["PATIENT_AUTHORIZATION", "CONSENT_MANAGEMENT", "DATA_USE_AGREEMENT"]

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
    msg := sprintf("HIPAA Authorization: Missing control '%v'", [required])
}
