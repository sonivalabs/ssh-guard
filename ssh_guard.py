#!/usr/bin/env python3
# ssh-guard — auto-repair broken SSH key perms in Docker containers on
# Vast.ai hosts (or anywhere a provisioner injects authorized_keys that
# image entrypoints then clobber). Minimal-touch, idempotent, no deps.
# License: MIT — see LICENSE.
"""
ssh_guard.py — SSH key-perm auto-repair for client containers on Docker hosts.

Motivated by Vast.ai: the provisioner injects the renter's pubkey into
/root/.ssh/authorized_keys around container start; image entrypoints / onstart
scripts sometimes clobber ownership/modes afterwards (umask 000, chmod -R,
chown -R on /root). sshd StrictModes then refuses EVERY pubkey login forever
with "Authentication refused: bad ownership or modes for file
/root/.ssh/authorized_keys" — renters retry, give up, leave.

Guard: every SSH_GUARD_INTERVAL seconds, for every RUNNING container (Vast
self-tests excluded): normalize ownership/modes of /root, /root/.ssh and
/root/.ssh/authorized_keys inside the container via `docker exec -u 0:0`.
Minimal-touch + idempotent: only fixes actual StrictModes violations
(owner != root, or group/world-writable bits). Never touches sshd_config,
never weakens StrictModes or PermitRootLogin. Never creates/deletes keys.

API (read-only telemetry, loopback by default):
  GET /api/ssh-guard   -> stats + per-container ssh state + recent repairs
  GET /healthz         -> {"ok": true} only while scans are fresh

THREAT MODEL (a renter controls everything inside their container):
- Everything an exec prints is RENTER-CONTROLLED. Output is size-capped on
  the host (MAX_OUT bytes total, not in-container), parsed strictly (mode
  must match ^[0-7]{3,4}$, paths must be exact), and error text is truncated
  before it reaches state or the API. Never trust size or content.
- `docker exec -u 0:0 <container> sh -c ...` runs the CONTAINER'S OWN sh —
  on a vulnerable runc (< 1.1.12) that is a known container-escape trigger
  (CVE-2019-5736; CVE-2024-21626 "attack 3b"). Only run this on runc
  >= 1.1.12 (ideally current) and keep it patched. Execs are also kept rare:
  short host-side timeouts, containers scanned in parallel, and repairs only
  when a StrictModes violation is actually observed.
- Docker-group access is effectively root on the host. The daemon runs as a
  non-root user, but protect that group accordingly.
- The API leaks container names/images/repair history: loopback bind by
  default (SSH_GUARD_HOST); expose on a private interface only if at all.
- Stalled/half-open HTTP connections are cut after 10s (Handler.timeout) so
  a flood cannot pin server threads.
- State dir is created 0700 and state is written via mkstemp inside it (no
  symlink hijack of the .tmp path by other local users).
Manual run: python3 ssh_guard.py --once   (single scan, prints JSON, exits)
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("SSH_GUARD_PORT", "8087"))
HOST = os.environ.get("SSH_GUARD_HOST", "127.0.0.1")   # loopback by default
INTERVAL = int(os.environ.get("SSH_GUARD_INTERVAL", "30"))
STATE_DIR = os.path.expanduser(
    os.environ.get("SSH_GUARD_STATE_DIR", "~/ssh-guard"))
STATE_FILE = os.path.join(STATE_DIR, "state.json")

STAT_TIMEOUT = 10       # per-exec cap, host side (seconds)
FIX_TIMEOUT = 10
MAX_OUT = 64 * 1024     # max stdout bytes READ per exec (host-side cap)
MAX_ERR = 400           # max error text stored / exposed
KEEP_EVENTS = 200       # repair-event ring size
CONTAINER_PRUNE_SECS = 6 * 3600   # forget containers not seen for 6h
SCAN_FRESH_SECS = max(120, INTERVAL * 5)  # /healthz goes stale after this

# Same exclusion as the log-capture service: Vast's automated self-tests.
IGNORE_RE = re.compile(r"(bandwidth-test|bw-test|self.?test|vastai/test|vast_self|test:)", re.I)
# Renter-controlled fields from inside containers — strict shapes only.
MODE_RE = re.compile(r"^[0-7]{3,4}$")
USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")

_LOCK = threading.Lock()
_STATE = {
    "started_at": time.time(),
    "scan_count": 0,
    "last_scan": None,
    "last_scan_seconds": None,
    "containers": {},   # cid -> {name,image,last_scan,root_mode,ssh_dir_mode,key_mode,
                        #          key_present,ssh_dir_present,ok,last_repair_ts,error}
    "recent": [],       # repair events, newest last
}


def run(cmd, timeout=STAT_TIMEOUT):
    """Run a host-side command with hard output caps. stdout/stderr are read
    by drain threads that stop after the cap (so a hostile container spewing
    gigabytes cannot balloon this process or the state file), and the whole
    exec is killed on timeout."""
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (FileNotFoundError, OSError) as e:
        return 124, "", str(e)

    def drain(stream, cap, sink):
        try:
            data = stream.read(cap + 1)
            sink.append(data[:cap])
        except Exception:
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    out_b, err_b = [], []
    to = threading.Thread(target=drain, args=(p.stdout, MAX_OUT, out_b), daemon=True)
    te = threading.Thread(target=drain, args=(p.stderr, MAX_ERR, err_b), daemon=True)
    to.start()
    te.start()
    try:
        rc = p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        try:
            rc = p.wait(timeout=5)
        except Exception:
            rc = 124
    to.join(timeout=5)
    te.join(timeout=5)
    return (rc,
            out_b[0].decode("utf-8", "replace").strip() if out_b else "",
            err_b[0].decode("utf-8", "replace").strip() if err_b else "")


def running_containers():
    rc, out, _ = run(["docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}"])
    conts = []
    if rc == 0:
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                cid, name, image = parts[0][:12], parts[1][:64], parts[2][:120]
                if IGNORE_RE.search((name + " " + image).lower()):
                    continue
                conts.append((cid, name, image))
    return conts


def stat_ssh(cid):
    """Return {path: {user, group, mode(octal str)}} for the SSH-relevant paths.

    Everything in the output except the command we sent is renter-controlled:
    parsed strictly, exact paths only, validated mode/user shapes."""
    script = ('stat -Lc "%n|%U|%G|%a" /root /root/.ssh /root/.ssh/authorized_keys '
              '2>/dev/null; echo "__DONE__"')
    rc, out, _ = run(["docker", "exec", "-u", "0:0", cid, "sh", "-c", script])
    res = {}
    for line in out.splitlines():
        line = line.strip()
        if not line or line == "__DONE__":
            continue
        parts = line.split("|")
        if len(parts) != 4 or not parts[0].startswith("/"):
            continue
        path, user, group, mode = parts
        if path not in ("/root", "/root/.ssh", "/root/.ssh/authorized_keys"):
            continue
        if not MODE_RE.match(mode) or not USER_RE.match(user):
            continue
        res[path] = {"user": user, "group": group[:32], "mode": mode}
    return res


def _is_bad(entry):
    """True if this path violates sshd StrictModes (owner != root, or group/world
    writable). Exact minimal definition — a working 644/755 is NOT touched."""
    if not entry:
        return False
    try:
        mode = int(entry["mode"], 8)
    except (ValueError, KeyError):
        return False
    return entry.get("user") != "root" or bool(mode & 0o022)


def _fixed(entry):
    if not entry:
        return False
    try:
        mode = int(entry["mode"], 8)
    except (ValueError, KeyError):
        return False
    return entry.get("user") == "root" and not (mode & 0o022)


def scan_container(cid, name, image, t0):
    """Scan (and if needed repair) one container. No lock is held here: this
    runs in its own thread, in parallel with the other containers."""
    info = {
        "name": name, "image": image, "last_scan": t0,
        "root_mode": None, "ssh_dir_mode": None, "key_mode": None,
        "ssh_dir_present": False, "key_present": False,
        "ok": True, "last_repair_ts": None, "error": None,
    }
    events = []
    try:
        st = stat_ssh(cid)
        root, sshdir, key = (st.get("/root"), st.get("/root/.ssh"),
                             st.get("/root/.ssh/authorized_keys"))
        info["root_mode"] = root["mode"] if root else None
        info["ssh_dir_present"] = sshdir is not None
        info["key_present"] = key is not None
        info["ssh_dir_mode"] = sshdir["mode"] if sshdir else None
        info["key_mode"] = key["mode"] if key else None

        acts = []
        for path, ent in (("/root", root), ("/root/.ssh", sshdir),
                          ("/root/.ssh/authorized_keys", key)):
            if ent is None:
                continue
            if ent.get("user") != "root":
                acts.append("chown root:root %s" % path)
            try:
                if int(ent["mode"], 8) & 0o022:
                    acts.append("chmod go-w %s" % path)
            except (ValueError, KeyError):
                pass

        if acts:
            script = "\n".join(acts)
            rc, _, err = run(["docker", "exec", "-u", "0:0", cid, "sh", "-c", script],
                             timeout=FIX_TIMEOUT)
            st2 = stat_ssh(cid)
            ok = ((_fixed(st2.get("/root")) if root else True)
                  and (_fixed(st2.get("/root/.ssh")) if sshdir else True)
                  and (_fixed(st2.get("/root/.ssh/authorized_keys")) if key else True))
            info["root_mode"] = st2.get("/root", {}).get("mode")
            info["ssh_dir_mode"] = st2.get("/root/.ssh", {}).get("mode")
            info["key_mode"] = st2.get("/root/.ssh/authorized_keys", {}).get("mode")
            info["ok"] = ok
            info["last_repair_ts"] = t0
            if not ok:
                info["error"] = (err or "verify failed")[:MAX_ERR]
            events.append({
                "ts": t0, "id": cid, "name": name, "image": image,
                "actions": acts, "verified": ok,
                "error": err[:MAX_ERR] if (rc != 0 and err) else None,
            })
    except Exception as e:   # never let one container kill the scan
        info["ok"] = False
        info["error"] = str(e)[:MAX_ERR]
    return cid, info, events


def scan():
    t0 = time.time()
    conts = running_containers()
    seen = set()
    events = []
    if conts:
        # Parallel: one hung or hostile container can no longer stall the
        # whole scan (each exec is short-timeout + output-capped).
        with ThreadPoolExecutor(max_workers=min(8, len(conts))) as ex:
            results = list(ex.map(lambda c: scan_container(c[0], c[1], c[2], t0),
                                  conts))
    else:
        results = []
    with _LOCK:
        for cid, info, evs in results:
            seen.add(cid)
            _STATE["containers"][cid] = info
            events.extend(evs)

        # containers no longer running: keep briefly, then prune
        now = t0
        for cid in list(_STATE["containers"].keys()):
            if cid in seen:
                continue
            c = _STATE["containers"][cid]
            if now - (c.get("last_scan") or 0) > CONTAINER_PRUNE_SECS:
                del _STATE["containers"][cid]

        _STATE["scan_count"] += 1
        _STATE["last_scan"] = t0
        _STATE["last_scan_seconds"] = round(time.time() - t0, 2)
        if events:
            _STATE["recent"].extend(events)
            del _STATE["recent"][:-KEEP_EVENTS]
    save_state()
    return events


def save_state():
    try:
        os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
        try:
            os.chmod(STATE_DIR, 0o700)
        except OSError:
            pass
        with _LOCK:
            snap = json.dumps(_STATE)
        fd, tmp = tempfile.mkstemp(prefix=".state-", dir=STATE_DIR)
        with os.fdopen(fd, "w") as f:
            f.write(snap)
        os.replace(tmp, STATE_FILE)
        try:
            os.chmod(STATE_FILE, 0o600)
        except OSError:
            pass
    except Exception:
        pass


def load_state():
    try:
        with _LOCK:
            raw = json.loads(open(STATE_FILE).read())
            _STATE.update(raw)
            _STATE.setdefault("containers", {})
            _STATE.setdefault("recent", [])
    except Exception:
        pass


def _healthy():
    with _LOCK:
        last = _STATE["last_scan"]
    return last is not None and (time.time() - last) < SCAN_FRESH_SECS


def build_response():
    now = time.time()
    with _LOCK:
        conts = sorted(_STATE["containers"].values(),
                       key=lambda c: c.get("last_scan") or 0, reverse=True)
        recent = list(_STATE["recent"])[-50:]
        recent.reverse()
        return {
            "enabled": True,
            "interval": INTERVAL,
            "started_at": _STATE["started_at"],
            "scan_count": _STATE["scan_count"],
            "last_scan": _STATE["last_scan"],
            "last_scan_seconds": _STATE.get("last_scan_seconds"),
            "containers_watched": len(conts),
            "repairs_24h": sum(1 for e in _STATE["recent"] if now - e.get("ts", 0) < 86400),
            "total_repairs": len(_STATE["recent"]),
            "containers": conts,
            "recent": recent,
            "generated_at": now,
        }


class Handler(BaseHTTPRequestHandler):
    # Cut stalled/half-open connections instead of pinning a thread each.
    timeout = 10

    def log_message(self, *a):   # silence per-request stderr noise
        pass

    def do_GET(self):
        if self.path == "/api/ssh-guard":
            body = build_response()
        elif self.path == "/healthz":
            body = {"ok": _healthy()}
        elif self.path == "/":
            body = {"service": "ssh-guard", "endpoints": ["/api/ssh-guard", "/healthz"]}
        else:
            self.send_response(404)
            self.end_headers()
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def loop():
    while True:
        try:
            scan()
        except Exception:
            pass
        time.sleep(INTERVAL)


def main():
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    try:
        os.chmod(STATE_DIR, 0o700)
    except OSError:
        pass
    load_state()
    if "--once" in sys.argv:
        events = scan()
        print(json.dumps({"scan": _STATE["scan_count"], "repairs": events,
                          "summary": build_response()}, default=str))
        return
    threading.Thread(target=loop, daemon=True).start()
    print(f"ssh-guard listening on {HOST}:{PORT}, scan interval {INTERVAL}s", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
