# Synology NAS — CHP Host Onboarding

Run a CHP host on your Synology DS918+ as a Container Manager container, then join it to the mesh as role `nas` on port 8802. Once connected, the primary gateway gains Synology DSM capabilities — File Station, Container Manager, Download Station, and Task Scheduler — routed to the NAS automatically.

**Hardware context:** DS918+, Intel Celeron J3455, x86-64, DSM 7.3.2-86009, Container Manager runtime.

Steps tagged **[NAS]** run over SSH on the NAS. Steps tagged **[PRIMARY]** run on your primary Mac.

---

## 1. Overview

The `chp-nas` container runs `chp-host serve --profile /chp/profile.json` inside Container Manager. The profile (`environments/profiles/synology.json`) sets:

- `host_id`: `chp-nas`
- `port`: `8802`
- `adapters`: `synology`, `filesystem`, `process`
- `store`: `/var/lib/chp/nas.sqlite` (evidence store)

The Synology adapter reaches DSM's WebAPI at `http://localhost:5000` (same machine, via the Docker host network) and authenticates with a dedicated DSM service account. Auth to the CHP host itself uses the `X-CHP-Key` header; the shared key is stored in keychain on the primary as `CHP_NAS_KEY` and passed into the container as `CHP_HOST_API_KEY`.

---

## 2. [NAS] Prerequisites

Check off before starting:

- **Container Manager** installed — Package Center > All Packages > Container Manager. If only "Docker" appears, that is the legacy package; install Container Manager instead.
- **SSH enabled** — Control Panel > Terminal & SNMP > Terminal tab > Enable SSH service.
- **Tailscale** installed — Package Center > search "Tailscale" (Synology community package or official, depending on your feed). It does not need to be connected yet.
- **Your DSM account has administrator rights** when running `sudo docker` over SSH.

---

## 3. [NAS] Get the build resources

DSM has no `git`. Fetch the repo as a tarball and unpack it under `/volume1/docker`:

```sh
cd /volume1/docker
curl -L https://github.com/capabilityhostprotocol/chp-core/archive/refs/heads/main.tar.gz | tar xz
cd chp-core-main
```

> **Note:** The Synology Docker assets (`docker/Dockerfile.synology`, `docker-compose.synology.yml`) are synced to the public `chp-core` repo separately. If the tarball does not contain `docker/Dockerfile.synology`, that sync has not landed yet — check back or pull the file manually from the repo.

Confirm the key files are present before proceeding:

```sh
ls docker/Dockerfile.synology docker-compose.synology.yml environments/profiles/synology.json
```

---

## 4. [NAS] Build the image

Build from the repo root so all `COPY` paths in the Dockerfile resolve correctly. The Dockerfile copies `packages/python`, `packages/chp-host`, `packages/chp-adapter-synology`, `packages/chp-adapter-filesystem`, and `packages/chp-adapter-process`, then `pip install`s them from source.

```sh
sudo docker build -f docker/Dockerfile.synology -t chp-nas:latest .
```

This is a native `linux/amd64` build — no cross-compilation, no registry pull required. On the DS918+ (Celeron J3455) expect 3–6 minutes on first build; subsequent builds are faster due to the pip layer cache.

---

## 5. [NAS] Create a dedicated DSM user

Do not use your admin account as the DSM service account. Create a restricted user:

1. Control Panel > User & Group > Create.
2. Username: `chp-svc`, strong generated password.
3. Groups: leave at the default `users` group (do **not** add to `administrators`).
4. Shared Folder Permissions: grant **Read/Write** to the shared folders the CHP filesystem adapter will access (e.g. `homes`, `docker`, any data shares). Deny access to everything else.
5. Application Permissions: enable **File Station** and **Download Station**. Container Manager operations use the DSM WebAPI under the same credentials — no extra app permission is required, but the user must not be blocked from the DSM web console.

---

## 6. [NAS] Run the container

### Primary form — `docker run`

Replace `<STRONG_RANDOM_KEY>` with the value you will generate in step 7, and `<CHPsvc_PASSWORD>` with the password from step 5.

```sh
sudo docker run -d \
  --name chp-nas \
  --network host \
  -e CHP_HOST_API_KEY=<STRONG_RANDOM_KEY> \
  -e SYNOLOGY_URL=http://localhost:5000 \
  -e SYNOLOGY_USER=chp-svc \
  -e SYNOLOGY_PASSWORD=<CHPsvc_PASSWORD> \
  -v /volume1:/volume1 \
  -v chp-nas-data:/var/lib/chp \
  --restart unless-stopped \
  chp-nas:latest
```

`--network host` lets the Synology adapter reach DSM's WebAPI at `http://localhost:5000` without extra routing. Because the host network is used, port 8802 is bound on the NAS's interfaces automatically — omit `-p 8802:8802` when using `--network host`.

### Compose alternative

The repo ships `docker-compose.synology.yml`. It uses a named registry image (`localhost:5000/chp-nas:latest` by default); if you are not running a local registry, either push the image there first or override the image name:

```sh
# after building the image as chp-nas:latest:
export CHP_NAS_KEY=<STRONG_RANDOM_KEY>
export SYNOLOGY_USER=chp-svc
export SYNOLOGY_PASSWORD=<CHPsvc_PASSWORD>
sudo docker compose -f docker-compose.synology.yml up -d
```

The compose file maps `0.0.0.0:8802:8802` (no host networking) and sets `SYNOLOGY_URL=http://localhost:5000` — this works because Docker on DSM resolves `localhost` inside the container to the host when using bridge networking with the NAS's IP. If the adapter cannot reach DSM, switch to `--network host` via the run form above, or set `SYNOLOGY_URL=http://<NAS_LAN_IP>:5000`.

### Verify the container is healthy

```sh
curl http://127.0.0.1:8802/health
```

Expected response (abbreviated):

```json
{
  "host_id": "chp-nas",
  "host_version": "...",
  "status": "ok"
}
```

---

## 7. [NAS + PRIMARY] Generate and set the shared key

The same random key must be set in two places: inside the container as `CHP_HOST_API_KEY`, and in the primary's keychain as `CHP_NAS_KEY`.

### [PRIMARY] Generate and store the key

```sh
KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
echo "Key: $KEY"   # copy this value

chp-host secrets set CHP_NAS_KEY
# paste $KEY when prompted
```

Use this same `$KEY` value as `<STRONG_RANDOM_KEY>` in the `docker run` command in step 6. If the container is already running with a placeholder, stop it, rerun with the real key, and verify `/health` again before continuing.

---

## 8. [NAS] Connect Tailscale

1. Open the Tailscale package in Package Center (or DSM's main menu) and start it.
2. In an SSH session:
   ```sh
   sudo tailscale up
   ```
3. Approve the new device in the Tailscale admin console at `https://login.tailscale.com/admin/machines`.
4. Tag the device `tag:chp-nas` (Machines > the NAS row > Edit tags).
5. Get the NAS Tailscale IP:
   ```sh
   tailscale ip -4
   ```
   Note this address — it is used in step 9.

---

## 9. [PRIMARY] Join the mesh

```sh
chp-host mesh add http://<NAS_TS_IP>:8802 --role nas --key-name CHP_NAS_KEY
```

The gateway launchd service (`com.chp.gateway.home`) already injects `CHP_NAS_KEY` from keychain via `--secrets-from-keychain`. Restart it to pick up the new mesh entry:

```sh
launchctl kickstart -k "gui/$(id -u)/com.chp.gateway.home"
```

Confirm the NAS is reachable:

```sh
chp-host mesh list
```

The NAS row should show role `nas` and status `OK`.

---

## 10. [PRIMARY] Verify a capability end-to-end

This snippet invokes `chp.adapters.synology.file_list` through the primary gateway (port 8800), which routes it to the NAS. The `metadata: {"prefer": "nas"}` hint tells the router to prefer the NAS host for this call.

```python
import subprocess
from chp_core import RemoteCapabilityHost

# Read the key from macOS keychain (the same CHP_NAS_KEY stored in step 7)
key = subprocess.check_output([
    "security", "find-generic-password",
    "-a", "CHP_HOST_API_KEY",
    "-s", "com.chp.secrets",
    "-w",
], text=True).strip()

host = RemoteCapabilityHost("http://127.0.0.1:8800", api_key=key)

result = host.invoke(
    "chp.adapters.synology.file_list",
    {"path": "/volume1", "limit": 50},
    metadata={"prefer": "nas"},
)

print(result.output)
# Expect: {"total": N, "offset": 0, "files": [...]}
```

If the call succeeds and `files` contains entries from `/volume1`, the NAS is fully joined to the mesh and the Synology adapter is live.

Full capability IDs available on `chp-nas`:

| Capability | Required payload fields | Risk |
|---|---|---|
| `chp.adapters.synology.file_list` | `path` (string), `limit` (int, optional, max 500) | low |
| `chp.adapters.synology.file_info` | `path` (string) | low |
| `chp.adapters.synology.task_list` | _(none)_ | low |
| `chp.adapters.synology.container_list` | _(none)_ | low |
| `chp.adapters.synology.container_start` | `container_id` (string) | **high** |
| `chp.adapters.synology.container_stop` | `container_id` (string) | **high** |
| `chp.adapters.synology.download_create` | `uri`, `dest_folder` (strings) | medium |

---

## 11. Troubleshooting

**Container not starting**

```sh
sudo docker logs chp-nas
```

Common causes: wrong `SYNOLOGY_URL`, missing env vars, port 8802 already in use.

**`/health` not reachable from outside the NAS**

Check that port 8802 is not blocked by DSM's built-in firewall (Control Panel > Security > Firewall). If using `--network host`, the port binds on all NAS interfaces including Tailscale — no extra port mapping needed.

**DSM auth failures in adapter logs**

The Synology adapter authenticates via `/webapi/auth.cgi` and caches the session SID, refreshing on 403. If you see repeated auth failures:
- Verify `SYNOLOGY_USER` and `SYNOLOGY_PASSWORD` are correct.
- Check that `chp-svc` is not locked out (Control Panel > User & Group > the user row > check account status).
- Confirm DSM 7.3.2 allows WebAPI access for the `users` group (it does by default).

**Gateway not reaching the NAS**

```sh
# From PRIMARY — confirm the NAS TS IP is reachable
curl http://<NAS_TS_IP>:8802/health

# From PRIMARY — confirm the key matches
chp-host mesh list
```

If the key mismatches, the NAS returns HTTP 401. Re-run `chp-host secrets set CHP_NAS_KEY` with the correct value and restart the gateway.

**Container Manager capabilities failing**

The `SYNO.Docker.Container` WebAPI requires DSM 7+ and Container Manager (not the legacy Docker package). Verify Container Manager is installed, not the legacy Docker package. The `chp-svc` user does not need admin rights for Container Manager read operations (`container_list`), but `container_start` / `container_stop` may require it depending on DSM version — promote to a read-only admin if needed, or scope to specific containers.

**Evidence / replay**

The evidence store is at `/var/lib/chp/nas.sqlite` inside the named volume `chp-nas-data`. To inspect it from the host:

```sh
sudo docker exec chp-nas ls -lh /var/lib/chp/
```
