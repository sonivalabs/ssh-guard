# ssh-guard — auto-repair broken SSH key perms in Docker containers on Vast.ai hosts

If you run a Vast.ai host and your renters intermittently **can't SSH into their
containers no matter what they try** — and they eventually give up and leave —
this is the tool that fixed it for us.

## The failure mode

Vast injects the renter's public key into `/root/.ssh/authorized_keys` around
container start. Anything running in the image's entrypoint / onstart script
with a loose umask or a `chmod -R` / `chown -R` on `/root` can clobber the
ownership or modes of that file *after* injection. OpenSSH's `StrictModes`
then refuses **every** public-key login for the rest of the rental:

```
Authentication refused: bad ownership or modes for file /root/.ssh/authorized_keys
```

Related signatures you'll see in container logs / auth logs:

- `bad ownership or modes for file /root/.ssh/authorized_keys`
- `Authentication refused: bad ownership or modes` (sshd `AuthenticationRefused`)
- `Connection closed by authenticating user root <ip> [preauth]` repeated per attempt

The renter did nothing wrong. Their key is in the file. The perms are just
broken, and **nothing ever repairs them** — so retries fail forever and the
rental ends in frustration.

### Our evidence

Across ~3 weeks of container-session summaries on our 2-GPU host: **6 renter
containers** hit this signature on images as diverse as `vllm/vllm-openai`,
community inference images, and stock `nvidia/cuda` devel images. Two renters
explicitly ended their session frustrated with the project unfinished. The same
image families served other renters *without* issue — it's an entrypoint-perms
race, not an image-intrinsic bug, which is exactly why it's so confusing to
diagnose.

## The fix: a host-side guard daemon

`ssh_guard.py` is a tiny dependency-free Python daemon that runs as a
**non-root host user** (docker-group access is enough) and every 30 seconds:

1. Lists RUNNING containers (Vast's own bandwidth/self-test containers excluded).
2. Inside each, `stat`s `/root`, `/root/.ssh`, `/root/.ssh/authorized_keys`
   via `docker exec -u 0:0`.
3. If — and only if — they violate StrictModes (owner ≠ root, or group/world
   writable), applies the minimal fix:
   - `chown root:root <path>` (only when mis-owned)
   - `chmod go-w <path>` (only when group/world-writable)
   - i.e. `700` for `~/.ssh`, `600` for `authorized_keys`, `go-w` for `/root`
4. Re-`stat`s to verify, and records the repair in its telemetry.

**Deliberate design limits:**

- **Idempotent and minimal-touch** — a healthy `644`/`755` is never touched.
- **Never creates, deletes, or modifies keys** — only ownership/modes.
- **Never touches `sshd_config`, StrictModes, or PermitRootLogin** — the
  server-side hardening stays exactly as it is.
- **Read-only telemetry API** — `GET /api/ssh-guard` and `GET /healthz`.
  Binds to loopback by default; bind it to a private interface only if an
  internal dashboard polls it. Never expose it publicly.
- One broken container can't kill the scan loop; state survives restarts.

## Install

```bash
# as the host user that owns docker (docker group, NOT root)
cp ssh_guard.py ~/ssh_guard.py
mkdir -p ~/.config/systemd/user
cp ssh-guard.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now ssh-guard

# check it
curl -s http://127.0.0.1:8087/healthz
curl -s http://127.0.0.1:8087/api/ssh-guard | python3 -m json.tool
```

Single one-shot scan (useful for testing / cron):

```bash
python3 ~/ssh_guard.py --once
```

Tuning (environment): `SSH_GUARD_PORT=8087`, `SSH_GUARD_HOST=127.0.0.1`,
`SSH_GUARD_INTERVAL=30`, `SSH_GUARD_STATE_DIR=~/ssh-guard`.

## Telemetry shape

```json
{
  "enabled": true, "interval": 30,
  "containers_watched": 2,
  "repairs_24h": 1, "total_repairs": 1,
  "containers": [
    { "name": "C.12345001", "image": "example/inference:ssh",
      "root_mode": "755", "ssh_dir_mode": "700", "key_mode": "600",
      "ssh_dir_present": true, "key_present": true,
      "ok": true, "last_repair_ts": null, "error": null }
  ],
  "recent": [
    { "ts": 1790741843, "name": "C.12345001",
      "actions": ["chmod go-w /root", "chown root:root /root/.ssh/authorized_keys"],
      "verified": true, "error": null }
  ]
}
```

`key_present: false` is worth watching: it means Vast never injected a key for
that container at all (usually the instance has no key attached) — different
problem, but you'll spot it immediately.

## Optional: also fix your own images at the entrypoint

The guard repairs *running* containers; the race window still exists between
container start and the first sweep. If you ship your own images, normalize
perms **first thing** in the entrypoint so sshd never sees bad perms at all:

```sh
# early in your entrypoint, before anything touches /root
if [ -d /root/.ssh ]; then
  chmod 700 /root/.ssh || true
  chown -R root:root /root/.ssh || true
  chmod go-w /root || true
  [ -f /root/.ssh/authorized_keys ] && chmod 600 /root/.ssh/authorized_keys || true
fi
```

Idempotent, safe on non-SSH images, never touches sshd config or keys.
Defense in depth: entrypoint fix + host guard covers both orders of the race.

## Repro / verification (free, no rental needed)

1. Start any cached `*/ssh`-flavored image locally with `sleep infinity`.
2. `docker cp` a throwaway pubkey into it, then deliberately break perms:
   `chown 1000:1000` + `chmod 777` on `authorized_keys`, `chmod 775 /root`.
3. Start sshd in-container (`mkdir -p /run/sshd; ssh-keygen -A; /usr/sbin/sshd`).
4. Try to log in → you'll get the exact `bad ownership or modes` refusal.
5. `python3 ssh_guard.py --once` → repairs it.
6. Log in again → success. That's the whole proof.

## Result

Deployed on our host, the guard flipped the failure end-to-end in the repro
(refusal → minimal-touch repair → successful login) and has been silently
repairing real renter containers since. A dashboard KPI shows
`repairs_24h` at a glance — that number is your "how many renters did we just
save" counter.

## License

MIT
