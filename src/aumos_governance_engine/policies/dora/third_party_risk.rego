# DORA — Third-Party ICT Risk Management
package aumos.compliance.dora.third_party_risk

import future.keywords

required_controls := ["THIRD_PARTY_RISK", "VENDOR_ASSESSMENT", "SUPPLY_CHAIN_SECURITY"]

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
    msg := sprintf("DORA Third-Party Risk: Missing control '%v'", [required])
}
