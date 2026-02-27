# DORA — ICT Incident Management
package aumos.compliance.dora.incident_management

import future.keywords

required_controls := ["INCIDENT_MANAGEMENT", "INCIDENT_CLASSIFICATION", "NOTIFICATION_PROCEDURES"]

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
    msg := sprintf("DORA Incident Management: Missing control '%v'", [required])
}
