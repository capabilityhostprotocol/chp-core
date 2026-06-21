# chp-adapter-delegation

CHP capability adapter for governed work handoff and delegation lifecycle.

## Capabilities

| Capability | Risk | Description |
|---|---|---|
| `chp.adapters.delegation.create` | medium | Open a delegation envelope |
| `chp.adapters.delegation.accept` | low | Accept a pending delegation |
| `chp.adapters.delegation.complete` | medium | Record successful completion |
| `chp.adapters.delegation.reject` | low | Reject with a stated reason |

## Evidence Events

`delegation_created`, `delegation_accepted`, `delegation_completed`, `delegation_rejected`
