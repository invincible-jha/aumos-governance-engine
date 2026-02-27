# HIPAA Minimum Necessary — Data Minimization
package aumos.compliance.hipaa.minimum_necessary

import future.keywords

required_controls := ["MINIMUM_NECESSARY", "DATA_MINIMIZATION", "PHI_ACCESS_CONTROLS"]

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
    msg := sprintf("HIPAA Minimum Necessary: Missing control '%v'", [required])
}
