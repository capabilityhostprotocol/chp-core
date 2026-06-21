# chp-adapter-planning

CHP capability adapter for observable agent cognition: planning and reflection.

## Capabilities

| Capability | Risk | Description |
|---|---|---|
| `chp.adapters.planning.create_plan` | medium | Declare an agent plan with ordered steps |
| `chp.adapters.planning.step_update` | low | Record step started / completed / failed |
| `chp.adapters.planning.revise` | medium | Record a plan revision with optional new steps |
| `chp.adapters.planning.reflect` | low | Structured reflection with optional evaluation score |

## Evidence Events

`plan_created`, `plan_step_started`, `plan_step_completed`, `plan_revised`,
`reflection_started`, `outcome_scored`, `reflection_completed`
