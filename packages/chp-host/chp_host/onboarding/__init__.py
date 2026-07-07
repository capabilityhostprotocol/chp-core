"""chp_host.onboarding — the portable onboarding toolkit, bundled with chp-host.

Canonical home of the capability scanner (`scan.py`) and the onboarding wizard (`onboard.py`).
They ship in the chp-host wheel so `chp-host onboard` works on a fresh install with no extra
checkout. Both remain standalone, stdlib-only scripts (run directly, or via `chp-host onboard`).
The repo's `scanner/*.py` are thin back-compat shims that exec these.
"""
