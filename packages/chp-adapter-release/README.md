# chp-adapter-release

CHP capability adapter for release pipeline operations.

## Capabilities

| Capability | Risk | Description |
|-----------|------|-------------|
| `chp.adapters.release.bump` | medium | Update version in `pyproject.toml` and `package.json` |
| `chp.adapters.release.sync` | high | Run `sync-to-public.sh --pr`; evidence: PR URL/number only |
| `chp.adapters.release.tag` | high | Create and push a git version tag (governed path) |
| `chp.adapters.release.publish_pypi` | high | Build + `twine upload` to PyPI or TestPyPI |
| `chp.adapters.release.publish_npm` | high | `npm publish` a package |

## Evidence hygiene

- Build/upload output — never in evidence
- Diff/stat text from sync — never in evidence
- Tokens and credentials — never in evidence
- Evidence contains: package name, version, PR URL/number, tag name, commit SHA7, registry URL

## Policy note

Raw `git tag v*` via bash is blocked by `.chp/policy.json`. Use `chp.adapters.release.tag` as
the governed path — it creates the tag, pushes it, and emits evidence.

## Install

```bash
pip install chp-adapter-release
```

## Usage

```python
from chp_core import LocalCapabilityHost, register_adapter
from chp_core.store import SQLiteEvidenceStore
from chp_adapter_release import ReleaseAdapter, ReleaseConfig

host = LocalCapabilityHost(store=SQLiteEvidenceStore("release.sqlite"))
adapter = ReleaseAdapter(config=ReleaseConfig(default_repo_path="/path/to/chp-dev"))
register_adapter(host, adapter)

result = await host.ainvoke("chp.adapters.release.bump", {"version": "0.8.0"})
result = await host.ainvoke("chp.adapters.release.tag", {"tag_name": "v0.8.0"})
```
