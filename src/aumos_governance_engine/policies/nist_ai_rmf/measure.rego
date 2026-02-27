# NIST AI RMF — MEASURE function
package aumos.compliance.nist_ai_rmf.measure

import future.keywords

required_controls := ["MODEL_MONITORING", "DRIFT_DETECTION", "BIAS_DETECTION", "IMPACT_ASSESSMENT"]

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
    msg := sprintf("NIST AI RMF MEASURE: Missing risk measurement control '%v'", [required])
}
