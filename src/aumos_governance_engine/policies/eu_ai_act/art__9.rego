# EU AI Act Article 9 — Risk Management System
# Evaluates whether an AI system has a compliant risk management system
# established, implemented, documented, and maintained throughout its lifecycle.
package aumos.compliance.eu_ai_act.art_9

import future.keywords

required_controls := [
    "AI_RISK_MGMT",
    "RISK_LIFECYCLE_MGMT",
    "RISK_DOCUMENTATION",
]

default allow := false
default violations := []

allow if {
    all_required_controls_present
    risk_documentation_exists
}

all_required_controls_present if {
    implemented := {c | c := input.implemented_controls[_]}
    every required in required_controls {
        required in implemented
    }
}

risk_documentation_exists if {
    input.risk_documentation_uri != null
    input.risk_documentation_uri != ""
}

risk_documentation_exists if {
    "RISK_DOCUMENTATION" in {c | c := input.implemented_controls[_]}
}

violations contains msg if {
    implemented := {c | c := input.implemented_controls[_]}
    some required in required_controls
    not required in implemented
    msg := sprintf("EU AI Act Art. 9: Missing required control '%v' for risk management system", [required])
}

violations contains msg if {
    not risk_documentation_exists
    msg := "EU AI Act Art. 9: Risk management documentation must be present (provide risk_documentation_uri or RISK_DOCUMENTATION control)"
}

# Only applies to high-risk AI systems
applies_to_this_system if {
    input.risk_tier == "high"
}

applies_to_this_system if {
    not input.risk_tier
}
