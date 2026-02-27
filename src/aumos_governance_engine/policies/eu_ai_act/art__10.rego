# EU AI Act Article 10 — Data and Data Governance
# Evaluates data quality and governance requirements for high-risk AI systems.
package aumos.compliance.eu_ai_act.art_10

import future.keywords

required_controls := [
    "DATA_QUALITY_ASSURANCE",
    "DATASET_GOVERNANCE",
    "BIAS_DETECTION",
]

default allow := false
default violations := []

allow if {
    all_data_controls_present
}

all_data_controls_present if {
    implemented := {c | c := input.implemented_controls[_]}
    every required in required_controls {
        required in implemented
    }
}

violations contains msg if {
    implemented := {c | c := input.implemented_controls[_]}
    some required in required_controls
    not required in implemented
    msg := sprintf("EU AI Act Art. 10: Missing data governance control '%v'", [required])
}
