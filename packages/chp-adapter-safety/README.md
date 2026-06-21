# chp-adapter-safety

CHP capability adapter for risk assessment and guardrail evaluation.

## Capabilities

| Capability | Risk | Description |
|---|---|---|
| `chp.adapters.safety.assess` | low | Score the risk level of a capability invocation |
| `chp.adapters.safety.report` | medium | Full safety report with guardrail evaluation |

## Evidence Events

`safety_assessment_started`, `safety_assessment_completed`,
`safety_guardrail_triggered`, `safety_action_blocked`, `safety_action_approved`
