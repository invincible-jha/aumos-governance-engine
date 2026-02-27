# EU AI Act Article 15 — Accuracy, Robustness and Cybersecurity
package aumos.compliance.eu_ai_act.art_15

import future.keywords

required_controls := [
    "MODEL_ACCURACY_BENCHMARK",
    "ROBUSTNESS_TESTING",
    "SECURITY_TESTING",
]

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
    msg := sprintf("EU AI Act Art. 15: Missing accuracy/robustness control '%v'", [required])
}
