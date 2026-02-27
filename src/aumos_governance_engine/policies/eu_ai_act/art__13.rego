# EU AI Act Article 13 — Transparency and Provision of Information
# Evaluates whether a high-risk AI system provides sufficient transparency
# for deployers to interpret outputs and use the system appropriately.
package aumos.compliance.eu_ai_act.art_13

import future.keywords

required_controls := [
    "EXPLAINABILITY",
    "MODEL_CARD",
    "TRANSPARENCY_REPORT",
]

default allow := false
default violations := []

allow if {
    all_transparency_controls_present
    model_card_exists
}

all_transparency_controls_present if {
    implemented := {c | c := input.implemented_controls[_]}
    every required in required_controls {
        required in implemented
    }
}

model_card_exists if {
    input.model_card_uri != null
    input.model_card_uri != ""
}

model_card_exists if {
    "MODEL_CARD" in {c | c := input.implemented_controls[_]}
}

violations contains msg if {
    implemented := {c | c := input.implemented_controls[_]}
    some required in required_controls
    not required in implemented
    msg := sprintf("EU AI Act Art. 13: Missing transparency control '%v'", [required])
}

violations contains msg if {
    not model_card_exists
    msg := "EU AI Act Art. 13: Model card documentation required (provide model_card_uri or MODEL_CARD control)"
}
