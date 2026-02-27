# EU AI Act Article 14 — Human Oversight
# Evaluates whether high-risk AI systems are designed to enable effective
# human oversight during deployment.
package aumos.compliance.eu_ai_act.art_14

import future.keywords

required_controls := [
    "HUMAN_OVERSIGHT",
    "OVERRIDE_CAPABILITY",
    "MONITORING_DASHBOARD",
]

default allow := false
default violations := []

allow if {
    all_oversight_controls_present
}

all_oversight_controls_present if {
    implemented := {c | c := input.implemented_controls[_]}
    every required in required_controls {
        required in implemented
    }
}

violations contains msg if {
    implemented := {c | c := input.implemented_controls[_]}
    some required in required_controls
    not required in implemented
    msg := sprintf("EU AI Act Art. 14: Missing human oversight control '%v'", [required])
}
