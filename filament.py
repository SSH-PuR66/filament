#!/usr/bin/env python3
"""
Filament - a private, local-first bridge to a physically connected iPhone.

Design constraints, in order of priority:
  1. Zero egress.  Nothing in this process or its UI ever contacts a remote
     host.  No CDN, no fonts, no telemetry, no analytics.  The UI is served
     from memory over loopback.  Verify with: netstat / Wireshark.
  2. Loopback only.  The listener binds 127.0.0.1 and refuses anything else,
     and every request must carry a token minted fresh at startup.
  3. Honest gating.  Capabilities the device currently refuses are shown as
     locked with the actual reason, never hidden or faked.

Talks to the device through two verified paths:
  - go-ios (userspace RemoteXPC tunnel, no admin, no wintun)
  - pymobiledevice3 (lockdown + AFC)
"""

import base64
import html
import json
import math
import os
import queue
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Sibling tools live next to this directory (<tools>/filament, <tools>/go-ios,
# <tools>/zsign), so their location is derived rather than hardcoded. Every
# path below can still be overridden by its environment variable.
_TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "install_flow.js"), encoding="utf-8") as _install_source:
    INSTALL_FLOW = _install_source.read()
IOS_EXE = os.environ.get("FILAMENT_IOS_EXE", os.path.join(_TOOLS, "go-ios", "ios.exe"))
PYTHON = sys.executable
HOST = "127.0.0.1"
PORT = int(os.environ.get("FILAMENT_PORT", "8733"))
TOKEN = secrets.token_urlsafe(18)
SHOT_DIR = os.path.join(HERE, ".frames")

# Windows: keep emulated go-ios from flashing console windows.
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

# The tunnel agent publishes its coordinates over a small loopback HTTP API.
# The documented default is 28100, but a flagless `ios tunnel start` in this
# build binds 60105. Pin it explicitly on the agent AND on every client call
# and the whole "which port is it this time" class of bug disappears.
TUNNEL_INFO_PORT = int(os.environ.get("FILAMENT_TUNNEL_PORT", "60105"))
DEVIMAGES = os.environ.get(
    "FILAMENT_DEVIMAGES", os.path.join(_TOOLS, "go-ios", "devimages"))
UDID = os.environ.get("FILAMENT_UDID") or None
SPAWN_COOLDOWN = 30   # hard ceiling: one agent spawn per 30s, whatever else fails


# --------------------------------------------------------------------------
# device transport
# --------------------------------------------------------------------------

class Device:
    """Thin, defensive wrapper over the two CLIs. Never raises to the handler."""

    def __init__(self):
        self._lock = threading.Lock()
        self._cache = {}

    # -- low level ---------------------------------------------------------

    def _run(self, argv, timeout=45):
        try:
            p = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout,
                creationflags=NO_WINDOW,
            )
            return p.returncode, p.stdout or "", p.stderr or ""
        except subprocess.TimeoutExpired:
            return 124, "", "timed out after %ss" % timeout
        except FileNotFoundError:
            return 127, "", "executable not found: %s" % argv[0]
        except Exception as exc:  # pragma: no cover - defensive
            return 1, "", str(exc)

    def _ios_argv(self, *args):
        # Pinned here rather than at each call site so no caller can forget
        # and end up probing a different port than the agent is bound to.
        argv = [IOS_EXE, *args, "--tunnel-info-port=%d" % TUNNEL_INFO_PORT]
        if UDID:
            argv.append("--udid=" + UDID)
        return argv

    def ios_write(self, *args, timeout=45):
        """For go-ios commands that answer with exit status, not stdout.

        `assistivetouch|voiceover|zoom enable|disable|toggle` print their JSON
        only for the `get` operation - the write path returns silently with
        code 0. Judging those by ios()'s "did a payload parse" rule reports
        every successful toggle as a failure, and hands the caller go-ios'
        "agent is not running" WARN banner as the supposed reason.
        """
        code, out, err = self._run(self._ios_argv(*args), timeout=timeout)
        if code == 0:
            return True, None
        blob = (out + '\n' + err).strip()
        msg = None
        for line in blob.splitlines():
            try:
                obj = json.loads(line.strip())
            except ValueError:
                continue
            if isinstance(obj, dict) and obj.get("level") == "ERROR":
                msg = obj.get("err") or obj.get("msg")
        # Only the ERROR line, never the WARN banner: contract 3 says the
        # reason shown must be the real one.
        return False, msg or (blob[-300:] if blob else "exit %d" % code)

    def ios(self, *args, timeout=45):
        """Run go-ios and return (ok, parsed_json_or_text, error_message).

        ok means "a payload parsed", which is the right test for reads only.
        Use ios_write() for commands that signal through exit status.
        """
        code, out, err = self._run(self._ios_argv(*args), timeout=timeout)
        blob = (out + "\n" + err).strip()

        # go-ios interleaves structured log lines with the real payload.
        # The payload is the last line that parses as JSON and carries no
        # "level" key.
        payload, error = None, None
        for line in blob.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict) and "level" in obj:
                if obj.get("level") == "ERROR":
                    error = obj.get("err") or obj.get("msg")
                continue
            payload = obj

        if payload is not None:
            return True, payload, None
        return False, None, error or (blob[-300:] if blob else "no output")

    def pmd(self, *args, timeout=45):
        code, out, err = self._run(
            [PYTHON, "-m", "pymobiledevice3", *args], timeout=timeout)
        txt = (out or err).strip()
        try:
            return True, json.loads(txt), None
        except ValueError:
            if code == 0 and txt:
                return True, txt, None
            return False, None, txt[-300:] or "no output"

    # -- cached reads ------------------------------------------------------

    def cached(self, key, fn, ttl):
        with self._lock:
            hit = self._cache.get(key)
            if hit and time.time() - hit[0] < ttl:
                return hit[1]
        val = fn()
        # Stamped on completion, not on entry: a probe that took 3s must not
        # be born 3s stale, or a 6s TTL is really a 3s one.
        with self._lock:
            self._cache[key] = (time.time(), val)
        return val

    def invalidate(self, *keys):
        with self._lock:
            for k in keys:
                self._cache.pop(k, None)

    # -- capability surface ------------------------------------------------

    def identity(self):
        ok, data, err = self.pmd("usbmux", "list")
        if not ok or not isinstance(data, list) or not data:
            return {"present": False, "error": err or "no device on usbmux"}
        d = data[0]
        return {
            "present": True,
            "name": d.get("DeviceName"),
            "udid": d.get("UniqueDeviceID"),
            "product": d.get("ProductType"),
            "version": d.get("ProductVersion"),
            "build": d.get("BuildVersion"),
            "connection": d.get("ConnectionType"),
            "model": MODEL_NAMES.get(d.get("ProductType"), d.get("ProductType")),
        }

    def tunnel(self):
        # Two different questions, and conflating them is what caused the
        # respawn storm: "is the agent answering" vs "has it attached a
        # device". Reported separately so the UI can too.
        reachable, tunnels, err = agent_tunnels()
        if not reachable:
            return {"up": False, "agent": False,
                    "error": "tunnel agent not answering on 127.0.0.1:%d (%s)"
                             % (TUNNEL_INFO_PORT, err)}
        if not tunnels:
            return {"up": False, "agent": True,
                    "error": "agent up; no device attached yet"}
        t = tunnels[0]
        return {"up": True, "agent": True, "address": t.get("address"),
                "rsdPort": t.get("rsdPort"),
                "userspace": bool(t.get("userspaceTun"))}

    def devmode(self):
        ok, data, err = self.ios("devmode", "get", timeout=30)
        if ok and isinstance(data, dict):
            return {"enabled": bool(data.get("DeveloperModeEnabled"))}
        return {"enabled": False, "error": err}

    def battery(self):
        ok, data, err = self.ios("batterycheck", timeout=30)
        if ok and isinstance(data, dict):
            return {
                "level": data.get("BatteryCurrentCapacity"),
                "charging": bool(data.get("BatteryIsCharging")),
                "external": bool(data.get("ExternalConnected")),
            }
        return {"error": err}

    def accessibility(self):
        out = {}
        for feature, cmd in (("assistivetouch", "assistivetouch"),
                             ("voiceover", "voiceover"),
                             ("zoom", "zoom")):
            # Three chained probes must finish inside /api/state's 50s join
            # budget, so this cannot be the usual 30s (3x30 = 90s > 50s and
            # the field was silently dropped from the response).
            ok, data, err = self.ios(cmd, "get", timeout=12)
            state = None
            if ok and isinstance(data, dict):
                for v in data.values():
                    if isinstance(v, bool):
                        state = v
                        break
            out[feature] = {"enabled": state, "error": None if ok else err}
        return out

    def set_accessibility(self, feature, action):
        if feature not in ("assistivetouch", "voiceover", "zoom"):
            return {"ok": False, "error": "unknown feature"}
        if action not in ("enable", "disable", "toggle"):
            return {"ok": False, "error": "unknown action"}
        ok, err = self.ios_write(feature, action, timeout=40)
        # Invalidated regardless: the write may well have landed on the phone
        # even when we could not confirm it, and a stale cache would then show
        # the old value back to the user.
        self.invalidate("ax")
        return {"ok": ok, "error": err}

    def apps(self):
        # Through _ios_argv like everything else: bypassing it meant apps()
        # pinned neither --udid nor --tunnel-info-port, so with two devices
        # attached it could enumerate the wrong phone.
        code, out, err = self._run(self._ios_argv("apps", "--list"), timeout=60)
        rows = []
        for line in (out or "").splitlines():
            line = line.strip()
            if not line or line.startswith("{"):
                continue
            parts = line.split(" ")
            if len(parts) >= 2 and "." in parts[0]:
                rows.append({"bundle": parts[0],
                             "name": " ".join(parts[1:-1]) or parts[0],
                             "version": parts[-1]})
        return rows

    def services(self):
        ok, data, err = self.ios("rsd", "ls", timeout=45)
        if ok and isinstance(data, dict):
            return sorted(
                [{"name": k, "port": (v or {}).get("Port")} for k, v in data.items()],
                key=lambda r: r["name"])
        return []

    def listdir(self, path):
        """AFC directory listing, in-process.

        Deliberately NOT `python -m pymobiledevice3 afc ls`: driven as a
        subprocess that CLI never exits - measured hanging past 50s - so the
        old shell-out could only ever return "timed out after 45s", which is
        exactly what the Files pane showed. The library call answers the same
        question in about a second and costs no interpreter start.
        """
        import asyncio
        path = path or "/"

        async def go():
            from pymobiledevice3.lockdown import create_using_usbmux
            from pymobiledevice3.services.afc import AfcService
            lockdown = await create_using_usbmux(serial=UDID)
            async with AfcService(lockdown=lockdown) as afc:
                return await afc.listdir(path)

        async def bounded():
            return await asyncio.wait_for(go(), 20)

        try:
            names = asyncio.run(bounded())
        except asyncio.TimeoutError:
            return {"path": path, "entries": [], "error": "AFC timed out after 20s"}
        except Exception as exc:
            return {"path": path, "entries": [],
                    "error": "%s: %s" % (type(exc).__name__, str(exc)[:180])}
        entries = [n for n in names if n not in (".", "..")]
        return {"path": path, "entries": sorted(entries),
                "error": None if entries else "empty directory"}

    def image_mounted(self):
        """True when the device reports a mounted developer image.

        `ios image list` does NOT answer with a JSON payload. It reports each
        mounted image as an ordinary INFO log line:

            {"level":"INFO","msg":"image signature","signature":"2808..."}

        so ios()'s "last JSON line without a level key is the payload" rule
        finds nothing and reports failure - which read as "not mounted" and
        made BringUp re-mount on every single tick. Count the signature lines
        instead; no signatures means no image.
        """
        code, out, err = self._run(self._ios_argv("image", "list"), timeout=60)
        if code != 0:
            return False
        for line in ((out or "") + "\n" + (err or "")).splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict) and obj.get("msg") == "image signature":
                return True
        return False

    def screenshot(self):
        """Returns (png_bytes, error). Gated behind Developer Mode."""
        os.makedirs(SHOT_DIR, exist_ok=True)
        # One file per request. This server is threaded, so a shared
        # frame.png means two live mirrors delete each other mid-read.
        target = os.path.join(SHOT_DIR, "f-%s.png" % secrets.token_hex(8))
        try:
            ok, _, err = self.ios("screenshot", "--output=" + target, timeout=45)
            if os.path.exists(target) and os.path.getsize(target) > 0:
                with open(target, "rb") as fh:
                    return fh.read(), None
            return None, err or "screenshot service unavailable"
        finally:
            try:
                os.remove(target)
            except OSError:
                pass


MODEL_NAMES = {
    "iPhone18,1": "iPhone 17 Pro",
    "iPhone18,2": "iPhone 17 Pro Max",
    "iPhone18,3": "iPhone 17",
    "iPhone18,4": "iPhone Air",
}

DEV = Device()


# --------------------------------------------------------------------------
# syslog fan-out: one device subscription, many browser listeners
# --------------------------------------------------------------------------

# Handed to a subscriber we had to drop, so its stream can close itself
# instead of blocking forever on a queue nobody will feed again.
STOP = object()


class Syslog:
    def __init__(self):
        self.subscribers = set()
        self.lock = threading.Lock()
        self.proc = None
        self.thread = None

    def _pump(self):
        try:
            proc = subprocess.Popen(
                DEV._ios_argv("syslog", "--nojson"),
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1, creationflags=NO_WINDOW)
            self.proc = proc
        except Exception:
            with self.lock:
                self.thread = None
            return
        try:
            for line in proc.stdout:
                line = line.rstrip()
                if not line:
                    continue
                with self.lock:
                    dead = []
                    for q in self.subscribers:
                        try:
                            q.put_nowait(line)
                        except queue.Full:
                            dead.append(q)
                    for q in dead:
                        self.subscribers.discard(q)
                        try:
                            q.get_nowait()
                            q.put_nowait(STOP)
                        except (queue.Empty, queue.Full):
                            pass
        except Exception:
            pass
        finally:
            # The device drops this stream on unplug. Without clearing the
            # thread slot, subscribe() never starts another pump and the
            # console stays dead for the rest of the session.
            self._reap(proc)
            with self.lock:
                self.thread = None
                if self.proc is proc:
                    self.proc = None

    @staticmethod
    def _reap(proc):
        try:
            if proc.stdout:
                proc.stdout.close()
        except Exception:
            pass
        try:
            if proc.poll() is None:
                proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            pass

    def subscribe(self):
        q = queue.Queue(maxsize=500)
        t = None
        with self.lock:
            self.subscribers.add(q)
            if self.thread is None:
                t = threading.Thread(target=self._pump, daemon=True)
                self.thread = t
        if t is not None:
            t.start()
        return q

    def unsubscribe(self, q):
        with self.lock:
            self.subscribers.discard(q)
            idle = not self.subscribers
            proc = self.proc
        # Nobody is watching: stop paying for a device subscription.
        # _pump's finally clause does the reaping and clears the slot, so
        # the next subscriber gets a fresh stream.
        if idle and proc is not None:
            try:
                if proc.poll() is None:
                    proc.terminate()
            except Exception:
                pass


SYSLOG = Syslog()


# --------------------------------------------------------------------------
# tunnel supervision
#
# The iOS 17+ RemoteXPC tunnel is a foreground process, and go-ios caches its
# ephemeral tunnel-info port in a state file. When the tunnel dies the cached
# port goes stale and every later subcommand fails against a refused socket.
# Nothing here may be hardcoded: the documented default (28100) is NOT what a
# foreground `tunnel start` binds, and the address, RSD port and info port all
# rotate on every restart. So Filament owns the tunnel's lifetime and always
# re-reads its coordinates rather than remembering them.
# --------------------------------------------------------------------------

def agent_tunnels(timeout=2.0):
    """(reachable, tunnels, error) from the agent's loopback tunnel-info API.

    reachable=True with tunnels=[] is a REAL and NORMAL state: the agent is
    healthy and simply has no device attached yet. Conflating that with "the
    agent is dead" is precisely what produced the six-spawns-per-minute storm
    recorded in tunnel.log. It is also ~2ms, against the 1-3s an emulated
    ios.exe costs - the old probe was so expensive it shaped the whole cadence.
    """
    url = "http://127.0.0.1:%d/tunnels" % TUNNEL_INFO_PORT
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            body = r.read().decode("utf-8", "replace")
    except Exception as exc:
        return False, [], str(exc)
    try:
        data = json.loads(body)
    except ValueError:
        return True, [], "tunnel list did not parse"
    return True, (data if isinstance(data, list) else []), None


def agent_alive(timeout=1.5):
    ok, _, _ = agent_tunnels(timeout=timeout)
    return ok


class TunnelAgent:
    """Owns at most one go-ios tunnel agent - and adopts one it did not start.

    Three facts about the agent drive this design, all of them read off
    tunnel.log rather than assumed:

      * It is device-independent. It runs happily with nothing plugged in and
        attaches devices by itself as they appear. So "no device" is never a
        reason to spawn.
      * It survives its own data plane dying. After "framedIPv6Reader: failed
        to read IPv6 header: EOF" the same PID re-attached minutes later. So
        the correct response to that error is to wait, not to respawn.
      * A second agent on a held port exits ~1.5s later with a bind error.
        Every one of the six 10:54-10:56 failures was a child losing to one
        healthy orphan that was working the entire time.

    Hence the single invariant that kills the storm outright:
    NEVER SPAWN WHILE agent_alive() IS TRUE.
    """

    def __init__(self, interval=5):
        self.interval = interval
        self.proc = None
        self.owned = False        # False => we are a tenant in someone else's agent
        self.adopted = False
        self.log_fh = None
        self.last_error = None
        self.last_spawn = 0.0
        self.spawns = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    # -- log ---------------------------------------------------------------

    def _log_handle(self):
        # One handle for the process lifetime. The old code opened a fresh one
        # per spawn and never closed it, so concurrent agents wrote at
        # independent offsets - that is the corrupted "eTunnelInfo: failed..."
        # fragment sitting in tunnel.log today.
        if self.log_fh is None:
            self.log_fh = open(os.path.join(HERE, "tunnel.log"), "ab", buffering=0)
        return self.log_fh

    def _tail_error(self):
        try:
            with open(os.path.join(HERE, "tunnel.log"), "rb") as fh:
                fh.seek(0, os.SEEK_END)
                fh.seek(max(0, fh.tell() - 4000))
                blob = fh.read().decode("utf-8", "replace")
        except OSError:
            return None
        for line in reversed(blob.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                return line[-200:]
            if isinstance(obj, dict) and obj.get("level") == "ERROR":
                return (obj.get("err") or obj.get("msg") or "")[-200:]
        return None

    # -- lifecycle ---------------------------------------------------------

    def adopt_or_spawn(self):
        """-> ('adopted'|'spawned'|'cooldown'|'wedged'|'failed', reason)"""
        # An orphan that answers is a working agent, not garbage. This is what
        # makes a hard kill of Filament survivable: the next run picks it up.
        if agent_alive():
            with self._lock:
                if self.proc is None:
                    self.owned, self.adopted = False, True
            self.last_error = None
            return "adopted", None

        now = time.time()
        if now - self.last_spawn < SPAWN_COOLDOWN:
            return "cooldown", "waiting out the spawn cooldown"

        with self._lock:
            if self.proc is not None and self.proc.poll() is not None:
                self.proc = None          # reap our own dead child
            if self.proc is not None:
                # Alive but not answering. Never overwrite it - that is the
                # orphan leak. Report it and let a human or FAULT handling act.
                return "wedged", ("agent process alive but not answering on "
                                  "127.0.0.1:%d" % TUNNEL_INFO_PORT)

        self.last_spawn = now
        try:
            proc = subprocess.Popen(
                [IOS_EXE, "tunnel", "start", "--userspace",
                 "--tunnel-info-port=%d" % TUNNEL_INFO_PORT],
                stdout=self._log_handle(), stderr=subprocess.STDOUT,
                creationflags=NO_WINDOW)
        except Exception as exc:
            self.last_error = str(exc)
            return "failed", self.last_error

        with self._lock:
            self.proc = proc
            self.spawns += 1

        # Readiness is the port answering. "Tunnel server started" is logged
        # BEFORE the bind is attempted, so the log is not evidence of success.
        # A cold agent with no device attached can take >8s to answer its first
        # /tunnels (measured), so the window is generous and the per-probe
        # timeout is well above the 1.5s steady-state one.
        deadline = time.time() + 20
        while time.time() < deadline and not self._stop.is_set():
            if agent_alive(timeout=3.0):
                with self._lock:
                    self.owned, self.adopted = True, False
                self.last_error = None
                DEV.invalidate("tunnel", "svcs")
                return "spawned", None
            if proc.poll() is not None:
                if agent_alive(timeout=3.0):
                    # Lost a race with another starter, which is still a win.
                    with self._lock:
                        self.proc = None
                        self.owned, self.adopted = False, True
                    return "adopted", None
                with self._lock:
                    self.proc = None
                self.last_error = (self._tail_error()
                                   or "agent exited %s" % proc.returncode)
                return "failed", self.last_error
            self._stop.wait(0.25)

        self._kill(proc)
        with self._lock:
            self.proc = None
        self.last_error = self._tail_error() or "agent did not answer within 8s"
        return "failed", self.last_error

    @staticmethod
    def _kill(proc):
        try:
            if proc.poll() is None:
                proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                               capture_output=True, timeout=10,
                               creationflags=NO_WINDOW)
            except Exception:
                pass

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.adopt_or_spawn()
            except Exception as exc:
                self.last_error = str(exc)
            self._stop.wait(self.interval)

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def shutdown(self):
        self._stop.set()
        t = self._thread
        if t is not None:
            # Join BEFORE killing, or the loop can spawn a replacement in the
            # gap between terminate() and the child actually exiting.
            t.join(timeout=12)
        with self._lock:
            proc, owned = self.proc, self.owned
            self.proc = None
        if proc is not None and owned:
            self._kill(proc)
        if self.log_fh is not None:
            try:
                self.log_fh.close()
            except Exception:
                pass
            self.log_fh = None

    def status(self):
        with self._lock:
            running = self.proc is not None and self.proc.poll() is None
            owned, adopted, spawns = self.owned, self.adopted, self.spawns
        reachable, tunnels, err = agent_tunnels()
        return {"agent": "up" if reachable else "down",
                "owned": bool(owned and running),
                "adopted": bool(adopted),
                "port": TUNNEL_INFO_PORT,
                "tunnels": len(tunnels),
                "spawns": spawns,
                "error": None if reachable else (self.last_error or err)}


TUNNEL = TunnelAgent()


# --------------------------------------------------------------------------
# live screen: MJPEG, proxied
#
# `ios screenshot --stream` is ~3x faster than spawning a process per frame
# (measured 4.1 fps vs 1.3), because the DVT connection stays open instead of
# being rebuilt for every picture.
#
# It cannot be pointed at the browser directly, though. go-ios ignores --port,
# hardcodes 3333, binds 0.0.0.0 rather than loopback, and sends
# Access-Control-Allow-Origin: *. Left exposed that is the whole screen of the
# phone, unauthenticated, to every host on the network - the exact opposite of
# what this file promises. So Filament consumes it on 127.0.0.1 and re-serves
# it behind its own token, and keeps the child alive only while somebody is
# actually watching.
# --------------------------------------------------------------------------

MJPEG_PORT = int(os.environ.get("FILAMENT_MJPEG_PORT", "3333"))


class ScreenStream:
    """Refcounted owner of one `ios screenshot --stream` child.

    Every failure path must give back the viewer it took. An earlier version
    returned "stream did not start within 15s" WITHOUT decrementing, which
    pinned viewers above zero forever - and since release() only kills the
    child at zero, go-ios kept broadcasting the screen on 0.0.0.0 for the life
    of the process. So acquire() takes the reference and, on any failure,
    hands it straight back through release(): one accounting path, no
    per-branch bookkeeping to get wrong.

    Nothing here does blocking IO while holding the lock. _healthy() is an
    HTTP call, and /api/state calls status() on every poll.
    """

    READY_TIMEOUT = 20.0

    def __init__(self):
        self.proc = None
        self.viewers = 0
        self.adopted = False
        self._lock = threading.Lock()

    def _healthy(self, timeout=1.0):
        try:
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d/" % MJPEG_PORT, timeout=timeout) as r:
                return r.status == 200
        except Exception:
            return False

    def _spawn(self):
        """-> (proc, error). Caller must not hold the lock."""
        try:
            return subprocess.Popen(
                [IOS_EXE, "screenshot", "--stream",
                 "--tunnel-info-port=%d" % TUNNEL_INFO_PORT]
                + (["--udid=" + UDID] if UDID else []),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=NO_WINDOW), None
        except Exception as exc:
            return None, str(exc)

    def _wait_ready(self, proc):
        """Block until the port answers. -> (ok, error)"""
        deadline = time.time() + self.READY_TIMEOUT
        while time.time() < deadline:
            if self._healthy():
                return True, None
            if proc is not None and proc.poll() is not None:
                return False, ("stream exited %s - is the developer image "
                               "mounted?" % proc.returncode)
            time.sleep(0.3)
        return False, "stream did not answer within %.0fs" % self.READY_TIMEOUT

    def acquire(self):
        """Take a viewer reference and ensure the stream answers.

        -> (ok, error). On failure the reference is handed back here, in ONE
        place, rather than at each failing branch - which is how the 15s
        timeout path came to leak one in the first place.
        """
        with self._lock:
            self.viewers += 1
        ok, err = self._ensure()
        if not ok:
            self.release()
        return ok, err

    def _ensure(self):
        """Make the stream answer. Never touches self.viewers."""
        with self._lock:
            proc = self.proc
        try:
            if proc is not None and proc.poll() is None:
                # Running, but a second viewer arriving inside the boot window
                # would otherwise be handed a socket nothing is listening on.
                return self._wait_ready(proc)
            if self._healthy():
                # Someone else's stream is already serving. Ride it rather
                # than fighting for the port - but remember we do not own it,
                # so shutdown() must not kill it.
                with self._lock:
                    if self.proc is None:
                        self.adopted = True
                return True, None

            proc, err = self._spawn()
            if proc is None:
                return False, err
            with self._lock:
                if self.proc is None:
                    self.proc, self.adopted = proc, False
                    mine = True
                else:
                    mine = False        # lost a race; keep the incumbent
            if not mine:
                self._kill(proc)
                with self._lock:
                    proc = self.proc
            return self._wait_ready(proc)
        except Exception as exc:
            return False, "%s: %s" % (type(exc).__name__, exc)

    def release(self):
        with self._lock:
            self.viewers = max(0, self.viewers - 1)
            if self.viewers or self.proc is None:
                return
            proc, self.proc = self.proc, None
            self.adopted = False
        # Nobody watching: stop broadcasting the screen to 0.0.0.0.
        self._kill(proc)

    @staticmethod
    def _kill(proc):
        try:
            if proc.poll() is None:
                proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                               capture_output=True, timeout=10,
                               creationflags=NO_WINDOW)
            except Exception:
                pass

    def shutdown(self):
        with self._lock:
            self.viewers = 0
            proc, self.proc = self.proc, None
            adopted, self.adopted = self.adopted, False
        # Only kill what we own - an adopted stream belongs to someone else.
        if proc is not None and not adopted:
            self._kill(proc)

    def status(self):
        with self._lock:
            proc, viewers, adopted = self.proc, self.viewers, self.adopted
        running = proc is not None and proc.poll() is None
        # Report exposure from the fact that something IS serving on 3333,
        # not merely from whether we spawned it. go-ios binds 0.0.0.0, so an
        # adopted stream exposes the screen exactly as much as ours does, and
        # saying otherwise would be the kind of comfortable lie contract 3
        # exists to forbid.
        serving = running or (viewers > 0 and self._healthy(timeout=0.4))
        return {"live": serving,
                "viewers": viewers,
                "owned": running and not adopted,
                "adopted": adopted,
                "port": MJPEG_PORT,
                "lan_exposed": serving}


SCREEN = ScreenStream()

# --------------------------------------------------------------------------
# bring-up
#
# The device-side half of getting to "ready", supervised the same way the
# tunnel agent is. It exists because of one fact learned the hard way:
#
#   the developer image DOES NOT SURVIVE A REBOOT.
#
# go-ios says so itself - "there is already a developer image mounted, reboot
# the device if you want to remove it" - so every restart silently drops
# screen capture until somebody remembers to run `ios image mount`. That is
# exactly the kind of manual step this file exists to remove.
#
# The first mount of a given image asks Apple's TSS server to personalize it
# for this specific device. AFTER that the device holds its own manifest and
# re-mounts are offline, which is why auto-mounting here does not quietly
# re-break the zero-egress promise on every reboot. The first one is the only
# one that leaves the machine, and FILAMENT_MOUNT_EGRESS=0 forbids even that.
# --------------------------------------------------------------------------

DDI_PATH = os.environ.get(
    "FILAMENT_DDI",
    os.path.join(_TOOLS, "go-ios", "devimages", "ddi-17E5179g", "Restore"))
MOUNT_ALLOW_EGRESS = os.environ.get("FILAMENT_MOUNT_EGRESS", "1") != "0"


class BringUp:
    """Walks the device to READY and keeps it there. One thread, no barriers."""

    LADDER = ("device", "tunnel", "devmode", "image", "capture")

    def __init__(self, interval=6):
        self.interval = interval
        self.state = "boot"
        self.reason = None
        # Born "wait", not "shut": before the first tick there is no evidence
        # of failure, and five red rungs would be an assertion we cannot back.
        self.steps = {k: {"status": "wait", "note": "starting up"}
                      for k in self.LADDER}
        self.mounts = 0
        self.last_mount_error = None
        self._mount_cooldown = 0.0
        self._mount_backoff = 0.0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def _set(self, step, status, note=""):
        with self._lock:
            self.steps[step] = {"status": status, "note": note}

    def _below(self, step, note=""):
        """Everything after `step` is WAITING on it - which is not the same
        fact as failing, and must not render as an error."""
        i = self.LADDER.index(step)
        for k in self.LADDER[i + 1:]:
            self._set(k, "wait", note)

    def _fail_mount(self, err):
        """Record a mount failure and back off. Every failure path goes
        through here - the early guards used to return without setting a
        cooldown at all, so a bad DDI path was retried at tick rate forever.

        Backoff escalates rather than sitting at a flat 60s: a mount attempted
        the instant an image is unmounted can fail simply because the device
        has not settled, and that transient deserves a fast retry. A genuinely
        broken image earns the long wait.
        """
        self.last_mount_error = err
        self._mount_backoff = min(60.0, max(10.0, self._mount_backoff * 2))
        self._mount_cooldown = time.time() + self._mount_backoff
        return False, err

    def _mount(self):
        """-> (ok, error). Never raises."""
        if time.time() < self._mount_cooldown:
            return False, self.last_mount_error or "mount cooling down"
        if not os.path.isdir(DDI_PATH):
            return self._fail_mount("no staged image at %s" % DDI_PATH)
        if not MOUNT_ALLOW_EGRESS:
            return self._fail_mount(
                "mounting needs a one-time signature from Apple TSS; "
                "FILAMENT_MOUNT_EGRESS=0 forbids it")
        ok, err = DEV.ios_write("image", "mount", "--path=" + DDI_PATH, timeout=300)
        if ok:
            self.mounts += 1
            self.last_mount_error = None
            self._mount_backoff = 0.0        # reset the ladder on success
            DEV.invalidate("svcs")
            return True, None
        # Already-mounted is a success wearing an error's clothes.
        if err and "already a developer image mounted" in err:
            self.last_mount_error = None
            self._mount_backoff = 0.0
            return True, None
        return self._fail_mount(err)

    def _tick(self):
        ident = DEV.cached("ident", DEV.identity, 5)
        if not ident.get("present"):
            self.state = "no-device"
            self.reason = ident.get("error") or "no device on usbmux"
            self._set("device", "shut", "plug in the iPhone and unlock it")
            self._below("device", "waiting for a device")
            return
        self._set("device", "open", ident.get("name") or "attached")

        tun = DEV.cached("tunnel", DEV.tunnel, 5)
        if not tun.get("agent"):
            self.state = "tunnel-down"
            self.reason = tun.get("error")
            self._set("tunnel", "shut", tun.get("error") or "agent down")
            self._below("tunnel", "waiting on the tunnel")
            return
        if not tun.get("up"):
            self.state = "tunnel-wait"
            self.reason = tun.get("error")
            self._set("tunnel", "act", "agent up; attaching device")
            self._below("tunnel", "waiting on the tunnel")
            return
        self._set("tunnel", "open",
                  "%s rsd %s" % (tun.get("address"), tun.get("rsdPort")))

        dm = DEV.cached("devmode", DEV.devmode, 8)
        if not dm.get("enabled"):
            self.state = "devmode-off"
            self.reason = dm.get("error") or "Developer Mode is off"
            # Keep the Settings row visible: the AMFI reveal lapses on reboot
            # and on reconnect, so it has to be re-sent.
            DEV.ios_write("devmode", "reveal", timeout=40)
            self._set("devmode", "act",
                      "Settings > Privacy & Security > bottom > Developer Mode")
            self._below("devmode", "waiting on Developer Mode")
            return
        self._set("devmode", "open", "on")

        if not DEV.image_mounted():
            self.state = "mounting"
            self._set("image", "act", "mounting the developer image")
            # Downstream rungs go to "wait" BEFORE the mount blocks. Without
            # this, capture kept the "open" it earned on the previous tick and
            # the UI unlocked the mirror against an image that is gone - the
            # exact contract-3 lie this ladder exists to prevent.
            self._below("image", "waiting on the developer image")
            ok, err = self._mount()
            if not ok:
                self.state = "image-failed"
                self.reason = err
                self._set("image", "shut", err or "mount failed")
                self._below("image", "waiting on the developer image")
                return
        self._set("image", "open", "mounted")
        self.reason = None

        # The only proof that counts is a real frame: `image list` can report a
        # mount that the screenshot service is not yet serving.
        png, err = DEV.screenshot()
        if not png:
            self.state = "verifying"
            self.reason = err
            self._set("capture", "act", err or "waiting for the screenshot service")
            return
        self.state = "ready"
        self.reason = None
        self._set("capture", "open", "%d KB frame" % (len(png) // 1024))

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as exc:
                self.state = "fault"
                self.reason = "%s: %s" % (type(exc).__name__, exc)
            self._stop.wait(self.interval)

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def shutdown(self, timeout=None):
        """Stop the ladder, waiting out an in-flight mount.

        A mount runs with a 300s timeout inside _tick(), so an 8s join returned
        while the worker was still inside it - and main() then tore the tunnel
        down underneath, orphaning the go-ios child mid-mount. Wait long enough
        to cover the mount, and report honestly if it still has not finished.
        """
        self._stop.set()
        if self._thread is None:
            return True
        if timeout is None:
            timeout = 310 if self.state == "mounting" else 15
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            say = getattr(sys.modules.get("builtins"), "print")
            say("  bring-up still busy after %.0fs; leaving it" % timeout,
                flush=True)
            return False
        return True

    def snapshot(self):
        with self._lock:
            steps = [dict(id=k, **self.steps[k]) for k in self.LADDER]
        return {"state": self.state, "reason": self.reason,
                "steps": steps, "mounts": self.mounts,
                "ddi": DDI_PATH, "egress_allowed": MOUNT_ALLOW_EGRESS}


BRING = BringUp()

# --------------------------------------------------------------------------
# on-screen UI structure
#
# Deliberately a SUBPROCESS, not an in-process call. inspect_ui.py reaches the
# accessibility service over pymobiledevice3's own userspace tunnel, whose
# PyTCP stack is a process-global singleton - establishing one inside this
# long-lived daemon would collide with the go-ios tunnel this process already
# supervises, and a second establishment in the same interpreter can only fail.
# One short-lived child per request keeps the two stacks apart.
# --------------------------------------------------------------------------

INSPECT_PY = os.path.join(HERE, "inspect_ui.py")


def press_ui(identifier, limit=120, timeout=200):
    """Activate one on-screen element by its platform handle.

    -> (after_elements, error). Never raises.

    The handle comes from a previous /api/ui listing, so this presses directly
    rather than re-walking the tree first: walking costs seconds and could
    focus a different element than the one the caller chose.
    """
    if not os.path.exists(INSPECT_PY):
        return [], "inspect_ui.py is missing"
    ident = "".join(c for c in (identifier or "") if c in "0123456789abcdefABCDEF")
    if not ident or len(ident) % 2:
        return [], "bad element handle"
    argv = [PYTHON, INSPECT_PY, "--json", "--press-id", ident, "--after",
            "--limit", str(int(limit))]
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, creationflags=NO_WINDOW,
                           encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return [], "press timed out after %ss" % timeout
    except Exception as exc:
        return [], str(exc)
    blob = (p.stdout or "").strip()
    start = blob.find("{")
    if start < 0:
        return [], ((p.stderr or blob).strip()[-300:] or "no output")
    try:
        data = json.loads(blob[start:])
    except ValueError:
        return [], blob[-300:]
    return (data.get("after") or []), data.get("error")


APPLEID_PY = os.path.join(HERE, "appleid.py")
SIGNING_PYTHON = os.path.join(HERE, ".signing-venv", "Scripts", "python.exe")
SIDELOAD_PY = os.path.join(HERE, "sideload.py")
try:
    with open(os.path.join(HERE, ".signing", "identity-config.json"), encoding="utf-8") as _fh:
        _identity_config = json.load(_fh)
    if not isinstance(_identity_config, dict) or not all(
            isinstance(value, str) for value in _identity_config.values()):
        raise ValueError("identity-config.json must contain string paths only")
except FileNotFoundError:
    _identity_config = {}


def _identity_path(env_key, config_key, default):
    value = os.environ.get(env_key) or _identity_config.get(config_key) or default
    return os.path.abspath(os.path.join(HERE, value))


SIGNING_IDENTITY_DIR = os.environ.get(
    "FILAMENT_IDENTITY_DIR", os.path.join(HERE, ".signing", "identity"))
SIGNING_P12 = _identity_path(
    "FILAMENT_P12", "p12", os.path.join(SIGNING_IDENTITY_DIR, "identity.p12"))
SIGNING_PEM_KEY = _identity_path(
    "FILAMENT_PEM_KEY", "pem_key", os.path.join(SIGNING_IDENTITY_DIR, "key.pem"))
SIGNING_PEM_CERT = _identity_path(
    "FILAMENT_PEM_CERT", "pem_cert", os.path.join(SIGNING_IDENTITY_DIR, "cert.pem"))
SIGNING_PROFILE = _identity_path(
    "FILAMENT_PROFILE", "profile",
    os.path.join(SIGNING_IDENTITY_DIR, "identity.mobileprovision"))
# Keep the password in this process, but do not leave it in the environment
# inherited by every go-ios/helper subprocess Filament starts.
SIGNING_P12_PASSWORD = os.environ.pop("FILAMENT_P12_PASSWORD", "filament")
os.environ.pop("P12_PASSWORD", None)
SIGNING_SESSION = os.path.join(HERE, ".signing", "session.json")


def _saved_signing_session_status():
    """Validate the saved Apple session without returning credential values."""
    status = {
        "valid": False,
        "locally_nonexpired": False,
        "session_file": os.path.abspath(SIGNING_SESSION),
    }
    try:
        with open(SIGNING_SESSION, encoding="utf-8") as fh:
            session = json.load(fh)
    except FileNotFoundError:
        status["reason"] = "saved session is missing"
        return status
    except (OSError, ValueError, TypeError) as exc:
        status["reason"] = "saved session is unreadable: %s" % exc
        return status
    if not isinstance(session, dict):
        status["reason"] = "saved session is not a JSON object"
        return status
    for field in ("token", "adsid", "apple_id"):
        if not isinstance(session.get(field), str) or not session[field].strip():
            status["reason"] = "saved session has no valid %s" % field
            return status
    expires = session.get("expires")
    if (isinstance(expires, bool) or not isinstance(expires, (int, float))
            or not math.isfinite(expires)):
        status["reason"] = "saved session has no finite numeric expiry"
        return status
    status["expires"] = expires
    if expires <= time.time():
        status["reason"] = "saved session is expired"
        return status
    status.update({
        "valid": True,
        "locally_nonexpired": True,
        "has_token": True,
        "has_adsid": True,
        "has_apple_id": True,
    })
    return status


def signing_status(timeout=90):
    """Is the complete locally provable signing chain usable? Never raises.

    appleid.py lives in its own virtualenv because the anisette provider
    pulls a CPU emulator that has no business in the main interpreter. If
    that venv is missing the answer is "not set up", which is a different
    and more actionable statement than "not signed in". `supported` and
    `performs_signing` describe what Filament implements; `ready` is true only
    when the signer, attached device, identity and profile all pass
    their independent checks. Unknown evidence is a blocker, never a pass.
    An Apple login is needed to mint/renew an identity, not to use an existing
    unexpired certificate and provisioning profile for offline signing.
    """
    report = {
        "supported": True,
        "performs_signing": True,
        "bypasses_code_signing": False,
        "readiness_scope": "local_preflight",
        "ready": False,
        "blockers": [],
        "warnings": [],
        "session": _saved_signing_session_status(),
        "identity": None,
    }
    blockers = report["blockers"]

    if not os.path.exists(APPLEID_PY):
        report["warnings"].append("appleid.py is missing; new identities cannot be created")
    if not os.path.exists(SIGNING_PYTHON):
        blockers.append("the signing venv is not set up")
        report["hint"] = ("python -m venv .signing-venv && "
                          ".signing-venv\\Scripts\\pip install anisette srp "
                          "cryptography requests")
    if not os.path.exists(SIDELOAD_PY):
        blockers.append("sideload.py is missing")

    if os.path.exists(SIGNING_PYTHON) and os.path.exists(APPLEID_PY):
        try:
            p = subprocess.run([SIGNING_PYTHON, APPLEID_PY, "status"],
                               capture_output=True, text=True, timeout=timeout,
                               creationflags=NO_WINDOW, encoding="utf-8",
                               errors="replace")
            out = ((p.stdout or "") + (p.stderr or "")).strip()
            session_valid = (
                p.returncode == 0
                and report["session"].get("locally_nonexpired") is True)
            report["session"]["valid"] = session_valid
            report["session"]["status_exit_code"] = p.returncode
            report["output"] = out[-3000:]
            if not session_valid:
                report["warnings"].append("no valid Apple ID session; identity creation/renewal needs login")
        except subprocess.TimeoutExpired:
            report["warnings"].append("checking the Apple ID session timed out")
        except Exception as exc:
            report["warnings"].append("could not check the Apple ID session: %s" % exc)

    if os.path.exists(SIGNING_PYTHON) and os.path.exists(SIDELOAD_PY):
        argv = [SIGNING_PYTHON, SIDELOAD_PY, "identity-status", "--json",
                "--profile", SIGNING_PROFILE, "--p12password-stdin"]
        if not os.path.isfile(SIGNING_P12) and os.path.isfile(SIGNING_PEM_KEY) and os.path.isfile(SIGNING_PEM_CERT):
            argv += ["--pem-key", SIGNING_PEM_KEY, "--pem-cert", SIGNING_PEM_CERT]
        else:
            argv += ["--p12", SIGNING_P12]
        child_env = os.environ.copy()
        child_env.pop("FILAMENT_P12_PASSWORD", None)
        child_env.pop("P12_PASSWORD", None)
        try:
            p = subprocess.run(argv, capture_output=True, text=True,
                               timeout=timeout, creationflags=NO_WINDOW,
                               encoding="utf-8", errors="replace",
                               env=child_env,
                               input=SIGNING_P12_PASSWORD + "\n")
            try:
                identity = json.loads((p.stdout or "").strip())
                if not isinstance(identity, dict):
                    raise ValueError("readiness output is not an object")
            except (ValueError, TypeError) as exc:
                identity = None
                blockers.append("could not parse identity readiness: %s" % exc)
                detail = ((p.stderr or "") + (p.stdout or "")).strip()
                if detail:
                    report["identity_output"] = detail[-1000:]
            report["identity"] = identity
            if identity is not None:
                contract_ok = (
                    identity.get("supported") is True
                    and identity.get("performs_signing") is True
                    and identity.get("bypasses_code_signing") is False
                    and identity.get("readiness_scope") == "local_preflight"
                    and isinstance(identity.get("ready"), bool)
                    and isinstance(identity.get("blockers"), list)
                    and all(isinstance(item, str)
                            for item in identity.get("blockers"))
                    and isinstance(identity.get("warnings"), list)
                    and all(isinstance(item, str)
                            for item in identity.get("warnings"))
                    and isinstance(identity.get("evidence"), dict)
                    and identity["ready"] == (not identity["blockers"])
                    and ((identity.get("reason") is None
                          and identity["ready"] is True)
                         or (isinstance(identity.get("reason"), str)
                             and bool(identity["reason"])
                             and identity["ready"] is False)))
                if not contract_ok:
                    blockers.append("identity readiness contract is invalid")
                else:
                    blockers.extend(identity["blockers"])
                    report["warnings"].extend(identity["warnings"])
                    if ((identity["ready"] is True and p.returncode != 0)
                            or (identity["ready"] is False
                                and p.returncode == 0)):
                        blockers.append(
                            "identity readiness result and exit code disagree")
                    elif p.returncode not in (0, 1):
                        blockers.append(
                            "identity readiness exited with code %s"
                            % p.returncode)
        except subprocess.TimeoutExpired:
            blockers.append("checking the signing identity timed out")
        except Exception as exc:
            blockers.append("could not check the signing identity: %s" % exc)

    identity_ready = bool(
        isinstance(report["identity"], dict)
        and report["identity"].get("ready") is True
        and "identity readiness contract is invalid" not in blockers)
    report["identity_creation_ready"] = bool(
        report["session"].get("valid") and os.path.isfile(APPLEID_PY)
        and os.path.isfile(SIGNING_PYTHON))
    report["ready"] = bool(identity_ready and not blockers)
    report["reason"] = None if report["ready"] else (
        blockers[0] if blockers else "signing readiness could not be proven")
    return report


def sideload_check(app=None, p12=None, p12password=None, profile=None,
                   install=False, timeout=900, use_identity=False):
    """Preflight (and optionally run) an install. -> dict. Never raises.

    Deliberately preflight-first and preflight-only by default. An install
    that is going to be refused by iOS fails with
    ApplicationVerificationFailed AFTER the whole payload has been uploaded,
    which costs a minute and says nothing useful. Every common cause is
    knowable from the files on disk beforehand.

    Note what this CANNOT do: it cannot produce a signing identity. Only Apple
    issues those. The honest job here is to say precisely what is missing.
    """
    if not os.path.exists(SIDELOAD_PY):
        return {"ok": False, "output": "", "error": "sideload.py is missing"}
    if p12password is not None and not isinstance(p12password, str):
        return {"ok": False, "output": "",
                "error": "p12password must be a string"}

    if not isinstance(use_identity, bool):
        return {"ok": False, "output": "", "error": "use_identity must be a boolean"}
    if use_identity and any(value is not None for value in (p12, profile, p12password)):
        return {"ok": False, "output": "",
                "error": "choose the configured identity or custom signing files, not both"}
    if install and not app:
        return {"ok": False, "output": "", "error": "install needs an app path"}

    interpreter = SIGNING_PYTHON if use_identity else PYTHON
    if use_identity and not os.path.isfile(interpreter):
        return {"ok": False, "output": "", "error": "the signing venv is not set up"}
    paths = [(app, None)]
    if use_identity:
        # Resolve identity material on the server; the browser does not need
        # to submit its paths or configured password. The child revalidates
        # the identity and snapshots the files again on every actual install.
        profile = SIGNING_PROFILE
        if (not os.path.isfile(SIGNING_P12)
                and os.path.isfile(SIGNING_PEM_KEY)
                and os.path.isfile(SIGNING_PEM_CERT)):
            paths.extend([(SIGNING_PEM_KEY, "--pem-key"),
                          (SIGNING_PEM_CERT, "--pem-cert")])
        else:
            paths.append((SIGNING_P12, "--p12"))
        p12password = SIGNING_P12_PASSWORD
    else:
        paths.append((p12, "--p12"))
    paths.append((profile, "--profile"))
    argv = [interpreter, SIDELOAD_PY, "install" if install else "check"]
    for path, flag in paths:
        if not path:
            continue
        if not isinstance(path, (str, bytes, os.PathLike)):
            return {"ok": False, "output": "",
                    "error": "sideload paths must be strings"}
        try:
            present = os.path.exists(path)
        except (OSError, TypeError, ValueError):
            present = False
        if not present:
            return {"ok": False, "output": "",
                    "error": "no such file: %s" % path}
        if flag:
            argv += [flag, path]
        else:
            argv.append(path)
    child_input = None
    if p12password is not None:
        argv += ["--p12password-stdin"]
        child_input = p12password + "\n"
    if len(argv) <= 3:
        return {"ok": False, "output": "",
                "error": "give an app, a profile, or a p12 to check"}

    try:
        child_env = os.environ.copy()
        child_env.pop("FILAMENT_P12_PASSWORD", None)
        child_env.pop("P12_PASSWORD", None)
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, creationflags=NO_WINDOW,
                           encoding="utf-8", errors="replace",
                           env=child_env, input=child_input)
    except subprocess.TimeoutExpired:
        return {"ok": False, "output": "", "error": "timed out after %ss" % timeout}
    except Exception as exc:
        return {"ok": False, "output": "", "error": str(exc)}

    out = ((p.stdout or "") + (p.stderr or "")).strip()
    return {"ok": p.returncode == 0, "output": out[-6000:],
            "error": None if p.returncode == 0 else "preflight found blockers"}


def _parse_sideload_request(body):
    """Validate JSON types before any value reaches filesystem/process APIs."""
    if not isinstance(body, dict):
        return None, "request body must be a JSON object"
    parsed = {}
    for name in ("app", "p12", "profile"):
        value = body.get(name)
        if value is None or value == "":
            parsed[name] = None
        elif not isinstance(value, str):
            return None, "%s must be a string" % name
        elif "\x00" in value:
            return None, "%s contains a null byte" % name
        else:
            parsed[name] = value.strip() or None
    password = body.get("p12password")
    if password is not None and not isinstance(password, str):
        return None, "p12password must be a string"
    parsed["p12password"] = password or None
    install = body.get("install", False)
    if not isinstance(install, bool):
        return None, "install must be a boolean"
    parsed["install"] = install
    use_identity = body.get("use_identity", False)
    if not isinstance(use_identity, bool):
        return None, "use_identity must be a boolean"
    if use_identity and any(parsed[name] is not None
                            for name in ("p12", "profile", "p12password")):
        return None, "choose the configured identity or custom signing files, not both"
    parsed["use_identity"] = use_identity
    return parsed, None


def read_ui(limit=120, timeout=120):
    """-> (elements, error). Never raises."""
    if not os.path.exists(INSPECT_PY):
        return [], "inspect_ui.py is missing"
    argv = [PYTHON, INSPECT_PY, "--json", "--limit", str(int(limit))]
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, creationflags=NO_WINDOW,
                           encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return [], "ui inspection timed out after %ss" % timeout
    except Exception as exc:
        return [], str(exc)
    blob = (p.stdout or "").strip()
    start = blob.find("{")
    if start < 0:
        return [], ((p.stderr or blob).strip()[-300:] or "no output")
    try:
        data = json.loads(blob[start:])
    except ValueError:
        return [], blob[-300:]
    return data.get("elements") or [], data.get("error")







# --------------------------------------------------------------------------
# http
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "Filament"
    sys_version = ""

    def log_message(self, *a):
        pass  # keep the console clean; this is a UI, not a web server

    # -- helpers -----------------------------------------------------------

    def _authed(self, qs):
        # compare_digest, not ==: byte-at-a-time short-circuiting leaks the
        # token to anything that can time loopback requests.
        # compare_digest raises TypeError on a str containing non-ASCII, which
        # would kill the request with no response at all. Compare bytes.
        want = TOKEN.encode()
        for got in (qs.get("t", [None])[0],
                    self.headers.get("X-Filament-Token")):
            if not isinstance(got, str):
                continue
            try:
                raw = got.encode("utf-8", "strict")
            except UnicodeError:
                continue
            if secrets.compare_digest(raw, want):
                return True
        return False

    def _send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # Belt and braces: forbid the page from reaching anywhere but itself.
        self.send_header(
            "Content-Security-Policy",
            # blob: is required - the mirror renders frames through
            # URL.createObjectURL, which 'self' does not cover.
            "default-src 'self'; img-src 'self' data: blob:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError):
            pass

    # -- routes ------------------------------------------------------------

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        route = u.path

        if route == "/":
            if not self._authed(qs):
                return self._send(403, "<h1>403</h1><p>Missing session token.</p>",
                                  "text/html; charset=utf-8")
            return self._send(200, UI.replace("__TOKEN__", TOKEN).replace(
                "__INSTALL_FLOW__", INSTALL_FLOW),
                              "text/html; charset=utf-8")

        if not self._authed(qs):
            return self._send(403, {"error": "forbidden"})

        if route == "/api/state":
            # Each probe shells out to an emulated binary costing 1-3s cold.
            # Run them concurrently so a cold load is one probe deep, not six.
            probes = {
                "device": ("ident", DEV.identity, 6),
                "tunnel": ("tunnel", DEV.tunnel, 8),
                "devmode": ("devmode", DEV.devmode, 8),
                "battery": ("battery", DEV.battery, 12),
                "ax": ("ax", DEV.accessibility, 10),
            }
            out, threads = {}, []

            def fill(field, key, fn, ttl):
                try:
                    out[field] = DEV.cached(key, fn, ttl)
                except Exception as exc:
                    out[field] = {"error": str(exc)}

            for field, (key, fn, ttl) in probes.items():
                t = threading.Thread(target=fill, args=(field, key, fn, ttl))
                t.start()
                threads.append(t)
            for t in threads:
                t.join(timeout=50)
            out["supervisor"] = TUNNEL.status()
            out["screen"] = SCREEN.status()
            out["bringup"] = BRING.snapshot()
            return self._send(200, out)

        if route == "/api/apps":
            return self._send(200, DEV.cached("apps", DEV.apps, 120))

        if route == "/api/signing":
            return self._send(200, signing_status())

        if route == "/api/services":
            return self._send(200, DEV.cached("svcs", DEV.services, 60))

        if route == "/api/fs":
            path = qs.get("path", ["/"])[0]
            return self._send(200, DEV.listdir(path))

        if route == "/api/ui":
            try:
                limit = int(qs.get("limit", ["120"])[0])
            except ValueError:
                limit = 120
            els, err = read_ui(limit=max(1, min(limit, 400)))
            return self._send(200 if els else 409,
                              {"elements": els, "error": err,
                               "count": len(els)})

        if route == "/api/stream.mjpeg":
            return self._stream_screen()

        if route == "/api/frame.png":
            png, err = DEV.screenshot()
            if png:
                return self._send(200, png, "image/png")
            return self._send(409, {"error": err})

        if route == "/api/syslog":
            return self._stream_syslog()

        return self._send(404, {"error": "no such route"})

    def do_POST(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if not self._authed(qs):
            return self._send(403, {"error": "forbidden"})
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            return self._send(400, {"error": "request body must be a JSON object"})

        if u.path == "/api/sideload":
            request, error = _parse_sideload_request(body)
            if error:
                return self._send(400, {"error": error})
            return self._send(200, sideload_check(**request))

        if u.path == "/api/ui/press":
            after, err = press_ui(body.get("identifier", ""))
            return self._send(200, {"ok": err is None, "error": err,
                                    "elements": after, "count": len(after)})

        if u.path == "/api/ax":
            return self._send(200, DEV.set_accessibility(
                body.get("feature", ""), body.get("action", "")))

        return self._send(404, {"error": "no such route"})

    # -- mjpeg proxy -------------------------------------------------------

    def _stream_screen(self):
        ok, err = SCREEN.acquire()
        if not ok:
            return self._send(409, {"error": err or "stream unavailable"})
        # Once the reference is held, EVERY exit runs release(). The header
        # writes used to sit outside the try, so a client that vanished
        # mid-handshake leaked a viewer permanently - and a non-zero viewer
        # count keeps go-ios broadcasting the screen on 0.0.0.0.
        up = None
        try:
            try:
                up = urllib.request.urlopen(
                    "http://127.0.0.1:%d/" % MJPEG_PORT, timeout=10)
            except Exception as exc:
                return self._send(502, {"error": "stream proxy: %s" % exc})

            ctype = up.headers.get(
                "Content-Type",
                "multipart/x-mixed-replace; boundary=--BoundaryString")
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            # A wedged reader must not pin the child alive - and with it the
            # LAN broadcast - forever.
            try:
                self.connection.settimeout(30)
            except Exception:
                pass
            while True:
                # read1(), not read(): read() blocks until the full buffer is
                # filled, which holds finished frames back behind a partial
                # one. Measured 1.8 fps with read(32768) against 4.1 straight
                # from go-ios - the proxy was the bottleneck, not the device.
                chunk = up.read1(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError,
                OSError, socket.timeout):
            pass
        finally:
            if up is not None:
                try:
                    up.close()
                except Exception:
                    pass
            SCREEN.release()

    # -- server-sent events ------------------------------------------------

    def _stream_syslog(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        # This response bypasses _send, so it has to carry its own.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.end_headers()
        q = SYSLOG.subscribe()
        try:
            while True:
                try:
                    line = q.get(timeout=15)
                    if line is STOP:
                        # Dropped for falling behind; say so and close
                        # rather than hang on a queue nobody feeds.
                        self.wfile.write(b"event: overrun\ndata: {}\n\n")
                        self.wfile.flush()
                        return
                    payload = json.dumps({"line": line})
                    self.wfile.write(("data: %s\n\n" % payload).encode())
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionAbortedError, OSError):
            pass
        finally:
            SYSLOG.unsubscribe(q)


# --------------------------------------------------------------------------
# ui  (single page, no external resources of any kind)
# --------------------------------------------------------------------------

UI = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Filament</title>
<style>
:root{
  --bg:#0B0F14; --panel:#111820; --panel2:#0E141B; --line:#1D2732;
  --ink:#DCE5EE; --dim:#7E8C9C; --faint:#4A5766;
  --wire:#4FD1C5; --wire-dim:#1B3A3B;
  --ok:#5BC98C; --warn:#E0A94A; --bad:#E0736B;
  --mono:"Cascadia Mono","SF Mono",Consolas,"Liberation Mono",monospace;
  --sans:"Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,sans-serif;
}
*{box-sizing:border-box}
/* Author display rules (.stage{display:flex}) outrank the UA sheet's
   [hidden]{display:none}, so state it explicitly or gated panels leak. */
[hidden]{display:none!important}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;
  display:grid;grid-template-columns:264px 1fr;overflow:hidden}
::selection{background:var(--wire-dim);color:#fff}

/* ---------- rail ---------- */
aside{background:var(--panel2);border-right:1px solid var(--line);display:flex;
  flex-direction:column;overflow-y:auto}
.brand{padding:20px 18px 16px;border-bottom:1px solid var(--line)}
.brand h1{margin:0;font-size:16px;letter-spacing:.18em;text-transform:uppercase;font-weight:600}
.brand .sub{margin-top:5px;font-family:var(--mono);font-size:10.5px;color:var(--faint);letter-spacing:.05em}
.dot{width:6px;height:6px;border-radius:50%;display:inline-block;margin-right:7px;vertical-align:1px}
.d-ok{background:var(--ok);box-shadow:0 0 7px var(--ok)}
.d-bad{background:var(--bad)} .d-warn{background:var(--warn)}

.block{padding:16px 18px;border-bottom:1px solid var(--line)}
.block h2{margin:0 0 11px;font-size:10px;letter-spacing:.15em;text-transform:uppercase;
  color:var(--faint);font-weight:600}
.kv{display:flex;justify-content:space-between;gap:10px;padding:3px 0;font-size:12.5px}
.kv .k{color:var(--dim)} .kv .v{font-family:var(--mono);font-size:11.5px;text-align:right;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:140px}

/* battery */
.batt{margin-top:8px}
.batt .bar{height:5px;background:var(--line);border-radius:3px;overflow:hidden}
.batt .fill{height:100%;background:var(--ok);transition:width .5s ease}

/* gates */
.gate{display:flex;align-items:center;gap:9px;padding:6px 0;font-size:12.5px}
.gate .lbl{flex:1;color:var(--dim)}
.gate .st{font-family:var(--mono);font-size:9.5px;letter-spacing:.08em;text-transform:uppercase;
  padding:2px 7px;border-radius:2px}
.st-open{background:rgba(91,201,140,.13);color:var(--ok)}
.st-wait{color:var(--dim);border-color:var(--line)}
.st-shut{background:rgba(224,115,107,.13);color:var(--bad)}
.st-act{background:rgba(224,169,74,.13);color:var(--warn)}

/* toggles */
.tog{display:flex;align-items:center;justify-content:space-between;padding:7px 0}
.tog .n{font-size:12.5px;color:var(--dim)}
.sw{width:34px;height:19px;border-radius:11px;background:var(--line);border:0;cursor:pointer;
  position:relative;transition:background .18s;flex:none}
.sw::after{content:"";position:absolute;top:2.5px;left:2.5px;width:14px;height:14px;border-radius:50%;
  background:var(--faint);transition:transform .18s,background .18s}
.sw[aria-pressed="true"]{background:var(--wire-dim)}
.sw[aria-pressed="true"]::after{transform:translateX(15px);background:var(--wire)}
.sw:disabled{opacity:.4;cursor:not-allowed}

/* ---------- main ---------- */
main{display:flex;flex-direction:column;overflow:hidden}
nav{display:flex;gap:2px;padding:0 16px;border-bottom:1px solid var(--line);background:var(--panel2);flex:none}
nav button{background:none;border:0;border-bottom:2px solid transparent;color:var(--dim);
  padding:13px 15px;font-size:12.5px;cursor:pointer;font-family:inherit;letter-spacing:.01em}
nav button:hover{color:var(--ink)}
nav button[aria-selected="true"]{color:var(--wire);border-bottom-color:var(--wire)}
.pane{flex:1;overflow:auto;padding:22px;display:none}
.pane[data-on="1"]{display:block}

.notice{border:1px solid var(--line);border-left:2px solid var(--warn);background:var(--panel);
  padding:16px 18px;border-radius:3px;max-width:640px}
.notice h3{margin:0 0 8px;font-size:14px}
.notice p{margin:0 0 8px;color:var(--dim);line-height:1.6;font-size:13px}
.notice ol{margin:8px 0 0;padding-left:18px;color:var(--dim);line-height:1.85;font-size:13px}
.notice code{font-family:var(--mono);font-size:11.5px;background:var(--panel2);padding:1px 5px;
  border:1px solid var(--line);border-radius:2px;color:var(--ink)}

/* mirror */
.stage{display:flex;flex-direction:column;align-items:center;gap:14px}
.screen{border:1px solid var(--line);border-radius:14px;background:#000;max-height:74vh;
  box-shadow:0 20px 60px rgba(0,0,0,.55)}
.ctl{display:flex;gap:9px;align-items:center}
button.act{background:var(--panel);border:1px solid var(--line);color:var(--ink);padding:7px 14px;
  border-radius:3px;cursor:pointer;font-family:inherit;font-size:12.5px}
button.act:hover{border-color:var(--wire);color:var(--wire)}
button.act:disabled{opacity:.4;cursor:not-allowed}
.fps{font-family:var(--mono);font-size:11px;color:var(--faint)}

/* tables */
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:left;font-family:var(--mono);font-size:9.5px;letter-spacing:.11em;text-transform:uppercase;
  color:var(--faint);padding:8px 12px;border-bottom:1px solid var(--line);position:sticky;top:-22px;
  background:var(--bg)}
td{padding:7px 12px;border-bottom:1px solid var(--panel);color:var(--dim)}
td.m{font-family:var(--mono);font-size:11.5px;color:var(--ink)}
tr:hover td{background:var(--panel)}

/* console */
.console{font-family:var(--mono);font-size:11.3px;line-height:1.62;background:#070A0E;
  border:1px solid var(--line);border-radius:3px;padding:12px 14px;height:calc(100vh - 190px);
  overflow-y:auto;white-space:pre-wrap;word-break:break-word;color:#9FB0C0}
.console .hl{color:var(--wire)}
.bar2{display:flex;gap:9px;margin-bottom:12px;align-items:center}
input.f{background:var(--panel);border:1px solid var(--line);color:var(--ink);padding:7px 11px;
  border-radius:3px;font-family:var(--mono);font-size:12px;flex:1;max-width:320px}
input.f:focus{outline:none;border-color:var(--wire)}

.crumb{font-family:var(--mono);font-size:11.5px;color:var(--faint);margin-bottom:12px}
.crumb a{color:var(--wire);text-decoration:none;cursor:pointer}
.fs li{list-style:none}
.fs{margin:0;padding:0;font-family:var(--mono);font-size:12px}
.fs a{display:block;padding:6px 10px;color:var(--ink);text-decoration:none;border-bottom:1px solid var(--panel);cursor:pointer}
.fs a:hover{background:var(--panel);color:var(--wire)}
.empty{color:var(--faint);font-size:12.5px;padding:14px 0}
:focus-visible{outline:1px solid var(--wire);outline-offset:2px}
/* Install workspace: named fields, visible next steps, and usable hit areas. */
.install-head h2{font-size:26px;letter-spacing:-.04em;margin:0 0 8px}
.install-head p,.install-section p{max-width:70ch;color:var(--dim);line-height:1.6}
.install-section{max-width:960px;margin-top:24px;padding-top:24px;border-top:1px solid var(--line)}
.install-section h3{font-size:18px;margin:0 0 14px}
.install-steps{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;padding:0;list-style:none}
.install-step{border:1px solid var(--line);padding:16px;border-radius:7px;background:var(--panel)}
.install-step strong{display:block;font-size:15px;margin:9px 0}
.install-step p{font-size:14px;margin:0;overflow-wrap:anywhere}
.install-step .st{font:12px var(--mono);text-transform:uppercase}
.install-route{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
.install-route .act[aria-pressed="true"]{border-color:var(--wire);background:var(--wire-dim);color:var(--wire)}
.install-field{display:flex;flex-direction:column;gap:7px;margin:16px 0;font-size:15px}
.install-field input.f,.install-field select{box-sizing:border-box;min-height:46px;max-width:100%;width:100%;font-size:15px}
.install-field select{background:var(--panel);color:var(--ink);border:1px solid var(--line);padding:10px}
.install-field small{color:var(--dim);font-size:13px;line-height:1.5}
.install-section button.act,.install-head button.act{min-height:44px;font-size:15px;padding:10px 16px}
.install-section .console{height:auto;max-height:320px;min-height:60px;font-size:13px;margin-top:16px}
.install-section a{color:var(--wire);text-underline-offset:4px}
.install-status{font-size:14px;color:var(--dim);line-height:1.6}
.install-section summary{cursor:pointer;padding:10px 0;color:var(--dim)}
#sl-install:not(:disabled){background:var(--wire);color:var(--bg);border-color:var(--wire)}
@media(max-width:900px){.install-steps{grid-template-columns:1fr}}
@media(max-width:650px){body{grid-template-columns:1fr}aside{display:none}nav{overflow:auto;padding:0 8px}.pane{padding:16px}.ctl{flex-wrap:wrap}.install-section{margin-top:18px;padding-top:18px}}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}
</style></head><body>

<aside>
  <div class="brand">
    <h1>Filament</h1>
    <div class="sub" id="linkstate"><span class="dot d-warn"></span>connecting</div>
  </div>

  <div class="block">
    <h2>Device</h2>
    <div class="kv"><span class="k">Model</span><span class="v" id="d-model">-</span></div>
    <div class="kv"><span class="k">iOS</span><span class="v" id="d-ios">-</span></div>
    <div class="kv"><span class="k">Build</span><span class="v" id="d-build">-</span></div>
    <div class="kv"><span class="k">Link</span><span class="v" id="d-conn">-</span></div>
    <div class="batt">
      <div class="kv"><span class="k">Battery</span><span class="v" id="d-batt">-</span></div>
      <div class="bar"><div class="fill" id="d-battfill" style="width:0%"></div></div>
    </div>
  </div>

  <div class="block">
    <h2>Gates</h2>
    <div class="gate"><span class="lbl">Device</span><span class="st st-shut" id="g-device">--</span></div>
    <div class="gate"><span class="lbl">Tunnel</span><span class="st st-shut" id="g-tunnel">--</span></div>
    <div class="gate"><span class="lbl">Developer Mode</span><span class="st st-shut" id="g-devmode">--</span></div>
    <div class="gate"><span class="lbl">Developer image</span><span class="st st-shut" id="g-image">--</span></div>
    <div class="gate"><span class="lbl">Screen capture</span><span class="st st-shut" id="g-capture">--</span></div>
    <div class="sub" id="ladder-note"></div>
    <div class="gate"><span class="lbl">Signing</span><span class="st st-wait" id="g-signing">unchecked</span></div>
  </div>

  <div class="block">
    <h2>Accessibility</h2>
    <div class="tog"><span class="n">AssistiveTouch</span>
      <button class="sw" id="t-assistivetouch" aria-pressed="false" disabled></button></div>
    <div class="tog"><span class="n">VoiceOver</span>
      <button class="sw" id="t-voiceover" aria-pressed="false" disabled></button></div>
    <div class="tog"><span class="n">Zoom</span>
      <button class="sw" id="t-zoom" aria-pressed="false" disabled></button></div>
  </div>

  <div class="block" style="border-bottom:0">
    <h2>Privacy</h2>
    <div class="kv"><span class="k">Bind</span><span class="v">127.0.0.1</span></div>
    <div class="kv"><span class="k">Egress</span><span class="v" style="color:var(--ok)">none</span></div>
    <div class="kv"><span class="k">Session</span><span class="v">token</span></div>
  </div>
</aside>

<main>
  <nav>
    <button data-p="mirror" aria-selected="true">Mirror</button>
    <button data-p="log" aria-selected="false">Syslog</button>
    <button data-p="files" aria-selected="false">Files</button>
    <button data-p="apps" aria-selected="false">Apps</button>
    <button data-p="svc" aria-selected="false">Services</button>
    <button data-p="ui" aria-selected="false">Elements</button>
    <button data-p="install" aria-selected="false">Install</button>
  </nav>

  <section class="pane" data-p="mirror" data-on="1">
    <div id="mirror-locked" class="notice">
      <h3>Screen capture is gated by Developer Mode</h3>
      <p>The screenshot service lives behind the personalized Developer Disk Image, which iOS
         will not mount until Developer Mode is on. Filament re-reveals the menu entry on every
         poll, because the AMFI reveal lapses on reboot and on reconnect.</p>
      <p id="mirror-why" class="m"></p>
      <ol>
        <li>Settings &rsaquo; Privacy &amp; Security &rsaquo; <strong>Developer Mode</strong></li>
        <li>Toggle on, then <strong>Restart</strong></li>
        <li>After reboot, tap <strong>Turn On</strong> and enter your passcode</li>
      </ol>
      <p style="margin-top:10px">This panel unlocks by itself once the gate opens. No signing
         or paid account is needed for capture &mdash; only for input injection.</p>
    </div>
    <div id="mirror-live" class="stage" hidden>
      <img class="screen" id="shot" alt="device screen">
      <div class="ctl">
        <button class="act" id="btn-once">Capture</button>
        <button class="act" id="btn-live">Go live</button>
        <span class="fps" id="fps"></span>
      </div>
    </div>
  </section>

  <section class="pane" data-p="log">
    <div class="bar2">
      <input class="f" id="logf" placeholder="filter (substring)" autocomplete="off">
      <button class="act" id="logclear">Clear</button>
      <span class="fps" id="logcount">0 lines</span>
    </div>
    <div class="console" id="console"></div>
  </section>

  <section class="pane" data-p="files">
    <div class="crumb" id="crumb"></div>
    <ul class="fs" id="fs"></ul>
  </section>

  <section class="pane" data-p="apps">
    <table><thead><tr><th>Bundle</th><th>Name</th><th>Version</th></tr></thead>
      <tbody id="apps"></tbody></table>
  </section>

  <section class="pane" data-p="ui">
    <div class="ctl">
      <button class="act" id="ui-read">Read screen</button>
      <span class="fps" id="ui-count"></span>
    </div>
    <p class="sub" id="ui-hint">Read the screen, then click a row to tap it on
       the phone. The list refreshes to whatever the screen became.</p>
    <table class="tbl"><thead><tr><th>#</th><th>Element</th><th></th></tr></thead>
      <tbody id="uitbl"></tbody></table>
  </section>

  <section class="pane" data-p="install">
    <div class="install-head">
      <h2>Install an app</h2>
      <p>Use a local IPA and an Apple-issued signing identity. Check the connection,
         inspect the app, then install when its preflight passes.</p>
      <button class="act" id="signing-refresh">Re-check setup</button>
    </div>
    <div class="install-section" id="signing-box">
      <h3>1. Prepare the connection</h3>
      <ol class="install-steps" id="install-steps" aria-label="Device and signing setup"></ol>
      <p class="install-status" id="signing-why" role="status">Setup has not been checked yet.</p>
      <details><summary>Signing details and account setup</summary>
        <p>The configured identity is checked locally. To create or renew one,
           use the terminal's private password prompt:</p>
        <p class="m" id="signing-cmd">.signing-venv\Scripts\python.exe appleid.py login --apple-id you@example.com</p>
        <p>Then run <code>.signing-venv\Scripts\python.exe appleid.py identity --bundle-id com.you.app</code>
           for your app's bundle ID. Expired sessions affect renewal; an existing valid identity can still pass local checks.</p>
        <div class="console" id="signing-out"></div>
      </details>
    </div>
    <div class="install-section">
      <h3>2. Choose the installation path</h3>
      <div class="install-route" role="group" aria-label="Installation path">
        <button class="act" data-install-route="native" aria-pressed="true">Local IPA</button>
        <button class="act" data-install-route="sidestore" aria-pressed="false">SideStore setup</button>
        <button class="act" data-install-route="livecontainer" aria-pressed="false">LiveContainer setup</button>
      </div>
      <div id="route-sidestore" hidden>
        <p>SideStore's current Windows guide uses iloader for the initial install and LocalDevVPN
           for on-device refreshes. It requires an Apple Account, Wi-Fi and iOS 15 or later.
           After a device update or reset, its pairing file may need to be replaced.</p>
        <p><a href="https://docs.sidestore.io/docs/installation/prerequisites" target="_blank" rel="noopener noreferrer">Open SideStore's setup guide &nearr;</a></p>
      </div>
      <div id="route-livecontainer" hidden>
        <p>Choose standalone LiveContainer or its integrated SideStore build in the official guide.
           Complete certificate import and the JIT-less diagnostic before loading your apps.
           An installed host alone does not prove guest apps will run.</p>
        <p>Guest apps share the host's trust boundary: their data is not sandboxed from one another.
           Some app features, including extensions and remote push notifications, are not supported.</p>
        <p><a href="https://livecontainer.github.io/docs/installation" target="_blank" rel="noopener noreferrer">Open LiveContainer's installation guide &nearr;</a>
           &nbsp; <a href="https://github.com/SSH-PuR66/LiveContainer-Plus" target="_blank" rel="noopener noreferrer">Review LiveContainer Plus source &nearr;</a></p>
      </div>
      <div id="route-native">
        <label class="install-field" for="sl-app">App path on this Windows PC
          <input class="f" id="sl-app" placeholder="C:\Apps\MyApp.ipa" autocomplete="off" spellcheck="false">
          <small>Paste a full .ipa or .app path. The file stays on this PC until you choose Install.</small>
        </label>
        <label class="install-field" for="sl-identity">Signing method
          <select id="sl-identity"><option value="configured">Use Filament's configured identity</option>
            <option value="custom">Already signed app or custom signing files</option></select>
          <small id="sl-identity-hint">Uses the local identity configuration, including PEM identities. No certificate paths to copy.</small>
        </label>
        <div id="sl-custom" hidden>
          <label class="install-field" for="sl-profile">Provisioning profile (optional)
            <input class="f" id="sl-profile" placeholder="C:\Signing\app.mobileprovision" autocomplete="off"></label>
          <label class="install-field" for="sl-p12">PKCS#12 certificate (optional)
            <input class="f" id="sl-p12" placeholder="C:\Signing\identity.p12" autocomplete="off"></label>
          <label class="install-field" for="sl-pw">Certificate password
            <input class="f" id="sl-pw" type="password" autocomplete="off">
            <small>Leave these empty to check the package as-is. This checks signature files are present; iOS verifies the signature during installation.</small></label>
        </div>
        <div class="ctl">
          <button class="act" id="sl-check" disabled>Check this app</button>
          <button class="act" id="sl-install" disabled>Install on iPhone</button>
        </div>
        <p class="install-status" id="sl-status" role="status">Choose an app to begin.</p>
        <details id="sl-details"><summary>Preflight and install output</summary><div class="console" id="sl-out"></div></details>
      </div>
    </div>
  </section>

  <section class="pane" data-p="svc">
    <table><thead><tr><th>Service</th><th>Port</th></tr></thead>
      <tbody id="svc"></tbody></table>
  </section>
</main>

<script>
__INSTALL_FLOW__
const T = "__TOKEN__";
const api = (p, o) => fetch(p + (p.includes("?") ? "&" : "?") + "t=" + T,
  Object.assign({headers:{"X-Filament-Token":T}}, o||{}));
const $ = s => document.querySelector(s);
/* Device-controlled text - device name, app titles, service names, file
   paths, error strings - must never be parsed as markup. An app named
   <img src=x onerror=...> would otherwise execute inside this page. */
const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

/* ---------- tabs ---------- */
document.querySelectorAll("nav button").forEach(b => b.onclick = () => {
  document.querySelectorAll("nav button").forEach(x =>
    x.setAttribute("aria-selected", x === b));
  document.querySelectorAll(".pane").forEach(p =>
    p.dataset.on = (p.dataset.p === b.dataset.p) ? "1" : "0");
  if (b.dataset.p === "apps") loadApps();
  if (b.dataset.p === "svc") loadSvc();
  if (b.dataset.p === "ui") loadUi();
  if (b.dataset.p === "install") loadSigning();
  if (b.dataset.p === "files") loadFs("/");
});

/* ---------- state ---------- */
let devmodeOn = false;
let installDevice = null, installSigning = null, installBusy = false, signingBusy = false;
let statePollBusy = false;
const installGate = FilamentInstall.createGate();
function gate(el, on, actionable) {
  el.textContent = on ? "open" : (actionable ? "action" : "shut");
  el.className = "st " + (on ? "st-open" : (actionable ? "st-act" : "st-shut"));
}
async function poll() {
  if (statePollBusy) return;
  statePollBusy = true;
  const started = Date.now();
  try {
    const response = await api("/api/state");
    if (!response.ok) throw new Error("Device endpoint unavailable (" + response.status + ")");
    const s = await response.json();
    installDevice = s;
    // A slow response must not make old device evidence appear newly observed.
    // One poll at a time also prevents older replies overwriting a disconnect.
    installGate.observe(s, started);
    paintInstallSetup();
    const d = s.device || {};
    $("#linkstate").innerHTML = d.present
      ? '<span class="dot d-ok"></span>' + esc(d.name || "linked")
      : '<span class="dot d-bad"></span>no device';
    $("#d-model").textContent = d.model || "-";
    $("#d-ios").textContent = d.version || "-";
    $("#d-build").textContent = d.build || "-";
    $("#d-conn").textContent = d.connection || "-";

    const b = s.battery || {};
    if (typeof b.level === "number") {
      $("#d-batt").textContent = b.level + "%" + (b.charging ? " chg" : "");
      $("#d-battfill").style.width = b.level + "%";
      $("#d-battfill").style.background =
        b.level < 20 ? "var(--bad)" : b.level < 50 ? "var(--warn)" : "var(--ok)";
    }
    /* One ladder, one source. Previously each gate ran its own probe, so the
       rail could paint two disagreeing answers in the same frame. Four
       statuses, and "wait" is deliberately NOT an error: "blocked by an
       earlier step" is a different fact from "this step failed", and
       conflating them is exactly the lie contract 3 forbids. */
    const bu = s.bringup || {};
    for (const st of (bu.steps || [])) {
      const el = $("#g-" + st.id);
      if (!el) continue;
      /* "wait" gets the neutral pending look, NOT st-shut. Painting
         "blocked by an earlier step" in the failure colour is precisely the
         conflation contract 3 forbids, and the previous map did exactly
         that while the comment above claimed otherwise. */
      const cls = {open:"st-open", act:"st-act", wait:"st-wait", shut:"st-shut"}[st.status]
                  || "st-shut";
      el.textContent = {open:"open", act:"action", wait:"waiting", shut:"shut"}[st.status]
                       || st.status;
      el.className = "st " + cls;
      el.title = st.note || "";
    }
    $("#ladder-note").textContent = bu.reason
      ? bu.reason.slice(0, 150)
      : (bu.state === "ready" ? "ready" : (bu.state || ""));
    devmodeOn = !!(s.devmode && s.devmode.enabled);
    /* Gate the mirror on capture actually working, not merely on Developer
       Mode: the image can be unmounted (it does not survive a reboot) with
       Developer Mode still on, and then "unlocked" would be a lie. */
    const capture = (bu.steps || []).find(x => x.id === "capture");
    const canSee = capture ? capture.status === "open" : devmodeOn;
    $("#mirror-locked").hidden = canSee;
    $("#mirror-live").hidden = !canSee;
    /* Contract 3 says locked capabilities show the ACTUAL reason. Render
       whatever the device last said instead of asserting a cause. */
    const why = [(s.devmode || {}).error, (s.tunnel || {}).error]
      .filter(Boolean).join(" / ");
    $("#mirror-why").textContent = why ? "Device reports: " + why : "";

    for (const f of ["assistivetouch","voiceover","zoom"]) {
      const st = (s.ax || {})[f] || {}, el = $("#t-" + f);
      el.disabled = (st.enabled === null || st.enabled === undefined);
      el.setAttribute("aria-pressed", st.enabled ? "true" : "false");
    }
  } catch (e) {
    installDevice = null;
    installGate.observe(null, Date.now());
    paintInstallSetup();
    $("#linkstate").innerHTML = '<span class="dot d-bad"></span>daemon unreachable';
  } finally {
    statePollBusy = false;
  }
}
for (const f of ["assistivetouch","voiceover","zoom"]) {
  $("#t-" + f).onclick = async (ev) => {
    const el = ev.currentTarget; el.disabled = true;
    await api("/api/ax", {method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({feature:f, action:"toggle"})});
    poll();
  };
}
poll(); setInterval(poll, 5000);

/* ---------- mirror ---------- */
let live = false, frames = 0, t0 = 0;
async function frame() {
  const r = await api("/api/frame.png?x=" + frames);
  if (!r.ok) { live = false; $("#btn-live").textContent = "Go live"; return false; }
  const b = await r.blob();
  const old = $("#shot").src;
  $("#shot").src = URL.createObjectURL(b);
  if (old.startsWith("blob:")) URL.revokeObjectURL(old);
  frames++;
  const dt = (performance.now() - t0) / 1000;
  if (dt > 0) $("#fps").textContent = (frames / dt).toFixed(1) + " fps";
  return true;
}
$("#btn-once").onclick = () => { t0 = performance.now(); frames = 0; frame(); };
/* Live mode is an MJPEG stream, not a polling loop: one persistent DVT
   connection instead of a process spawn per frame - measured 4.1 fps against
   1.3. Assigning the <img> src lets the browser decode the multipart stream
   natively. Clearing src is what closes it, which is what releases the
   viewer refcount server-side and stops go-ios broadcasting on 0.0.0.0. */
$("#btn-live").onclick = () => {
  live = !live;
  $("#btn-live").textContent = live ? "Stop" : "Go live";
  const img = $("#shot");
  if (live) {
    const old = img.src;
    img.src = "/api/stream.mjpeg?t=" + T;
    if (old.startsWith("blob:")) URL.revokeObjectURL(old);
    $("#fps").textContent = "streaming";
  } else {
    img.src = "";
    $("#fps").textContent = "";
    frame();            /* leave a still frame up rather than a blank pane */
  }
};

/* ---------- syslog ---------- */
let lines = [], filter = "";
$("#logf").oninput = e => { filter = e.target.value.toLowerCase(); render(); };
$("#logclear").onclick = () => { lines = []; render(); };
function render() {
  const show = filter ? lines.filter(l => l.toLowerCase().includes(filter)) : lines;
  const c = $("#console");
  const stick = c.scrollTop + c.clientHeight >= c.scrollHeight - 40;
  c.textContent = show.slice(-1200).join("\n");
  $("#logcount").textContent = show.length + " lines";
  if (stick) c.scrollTop = c.scrollHeight;
}
const es = new EventSource("/api/syslog?t=" + T);
es.onerror = () => {
  $("#logcount").textContent = lines.length + " lines (stream down)";
};
es.addEventListener("overrun", () => {
  lines.push("--- console fell behind and was dropped; reload to resume ---");
  render();
});
es.onmessage = ev => {
  try { lines.push(JSON.parse(ev.data).line); } catch (e) {}
  if (lines.length > 4000) lines = lines.slice(-3000);
  render();
};

/* ---------- files ---------- */
async function loadFs(path) {
  const r = await (await api("/api/fs?path=" + encodeURIComponent(path))).json();
  const parts = (r.path || "/").split("/").filter(Boolean);
  let acc = "", crumb = '<a data-go="/">/</a>';
  for (const p of parts) { acc += "/" + p;
    crumb += ' <a data-go="' + esc(acc) + '">' + esc(p) + "</a> /"; }
  $("#crumb").innerHTML = crumb;
  $("#crumb").querySelectorAll("a").forEach(a =>
    a.onclick = () => loadFs(a.dataset.go));
  const ul = $("#fs"); ul.innerHTML = "";
  if (!r.entries || !r.entries.length) {
    ul.innerHTML = '<li class="empty">' + esc(r.error || "empty") + "</li>"; return;
  }
  for (const e of r.entries) {
    if (e === r.path) continue;
    const li = document.createElement("li"), a = document.createElement("a");
    /* afc ls returns bare names; feeding one back as a path meant every
       click below / resolved to nothing. Join it to the current dir. */
    const base = (r.path === "/" ? "" : String(r.path).replace(/\/+$/, ""));
    a.textContent = e; a.onclick = () => loadFs(base + "/" + e);
    li.appendChild(a); ul.appendChild(li);
  }
}
/* ---------- tables ---------- */
async function loadApps() {
  const rows = await (await api("/api/apps")).json();
  $("#apps").innerHTML = rows.map(r =>
    "<tr><td class='m'>" + esc(r.bundle) + "</td><td>" + esc(r.name) +
    "</td><td class='m'>" + esc(r.version) + "</td></tr>").join("")
    || "<tr><td colspan=3 class='empty'>none</td></tr>";
}
async function loadUi() {
  const tb = $("#uitbl"), n = $("#ui-count");
  n.textContent = "reading\u2026";
  tb.innerHTML = "<tr><td colspan=3 class='empty'>walking the accessibility "
               + "tree\u2026 this takes a few seconds</td></tr>";
  try {
    const r = await (await api("/api/ui")).json();
    paintUi(r.elements || [], r.error);
  } catch (err) {
    n.textContent = "";
    tb.innerHTML = "<tr><td colspan=3 class='empty'>" + esc(String(err)) + "</td></tr>";
  }
}

function paintUi(rows, error) {
  const tb = $("#uitbl");
  $("#ui-count").textContent = rows.length + " elements";
  if (!rows.length) {
    tb.innerHTML = "<tr><td colspan=3 class='empty'>"
                 + esc(error || "nothing on screen") + "</td></tr>";
    return;
  }
  tb.innerHTML = "";
  for (const e of rows) {
    /* Built with DOM calls, not innerHTML: every caption here is written by
       whatever app is on screen, so it is device-controlled input. */
    const tr = document.createElement("tr");
    const td0 = document.createElement("td");
    td0.className = "m"; td0.textContent = e.index;
    const td1 = document.createElement("td");
    td1.textContent = e.caption || e.spoken || "";
    const td2 = document.createElement("td");
    if (e.identifier) {
      const b = document.createElement("button");
      b.className = "act"; b.textContent = "Tap";
      b.onclick = () => pressUi(e.identifier, b);
      td2.appendChild(b);
    }
    tr.appendChild(td0); tr.appendChild(td1); tr.appendChild(td2);
    tb.appendChild(tr);
  }
}

async function pressUi(identifier, btn) {
  const n = $("#ui-count");
  if (btn) { btn.disabled = true; btn.textContent = "\u2026"; }
  n.textContent = "tapping\u2026";
  try {
    const r = await (await api("/api/ui/press", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({identifier: identifier})
    })).json();
    if (!r.ok) { n.textContent = ""; $("#ui-hint").textContent = r.error || "tap failed"; return; }
    $("#ui-hint").textContent = "tapped - this is the screen now";
    paintUi(r.elements || [], r.error);
  } catch (err) {
    $("#ui-hint").textContent = String(err);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Tap"; }
  }
}
$("#ui-read").onclick = loadUi;

/* ---------- install ---------- */
function installInput() {
  const configured = $("#sl-identity").value === "configured";
  return {app: $("#sl-app").value.trim(), use_identity: configured,
    profile: configured ? null : $("#sl-profile").value.trim(),
    p12: configured ? null : $("#sl-p12").value.trim(),
    p12password: configured ? null : $("#sl-pw").value};
}
function updateInstallButtons() {
  const input = installInput();
  $("#sl-check").disabled = installBusy || !input.app;
  $("#sl-install").disabled = installBusy || !installGate.canInstall(input, Date.now());
}
function paintInstallSetup() {
  const list = $("#install-steps");
  list.replaceChildren();
  for (const step of FilamentInstall.setup(installDevice, installSigning)) {
    const li = document.createElement("li"); li.className = "install-step";
    const badge = document.createElement("span");
    badge.className = "st " + ({ready:"st-open",action:"st-act",waiting:"st-wait",unknown:"st-wait"}[step.status]);
    badge.textContent = step.status;
    const title = document.createElement("strong"); title.textContent = step.title;
    const detail = document.createElement("p"); detail.textContent = step.detail;
    li.append(badge, title, detail); list.appendChild(li);
  }
  updateInstallButtons();
}
async function sideload(install) {
  if (installBusy) return;
  const input = installInput();
  if (!input.app || (install && !installGate.canInstall(input, Date.now()))) {
    $("#sl-status").textContent = "Run a fresh app check with this device connected before installing.";
    return;
  }
  const ticket = installGate.begin(input, Date.now());
  installBusy = true;
  updateInstallButtons();
  const out = $("#sl-out"), status = $("#sl-status");
  status.textContent = install ? "Installing. Keep the iPhone connected and unlocked."
    : "Checking the app, profile, certificate and connected device...";
  out.textContent = "";
  try {
    const response = await api("/api/sideload", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(Object.assign({}, input, {install: !!install}))
    });
    const result = await response.json();
    out.textContent = result.output || result.error || "(no output)";
    const passed = response.ok && result.ok === true;
    if (install) {
      status.textContent = passed ? "Installation completed. Open the app on the phone to verify launch."
        : "Installation did not complete. Read the result below, fix the reported issue, then check again.";
    } else {
      const accepted = installGate.finish(ticket, passed, installInput(), Date.now());
      status.textContent = accepted ? "Local preflight passed. Install will re-check the files; iOS makes the final decision."
        : passed ? "Check passed, but the inputs or device state changed. Re-check with the phone connected."
        : "Preflight found a blocker. Read the result below and correct it before trying again.";
    }
    $("#sl-details").open = !passed;
  } catch (err) {
    status.textContent = "The daemon could not complete the request. Re-check setup before trying again.";
    out.textContent = String(err);
    $("#sl-details").open = true;
  } finally {
    installBusy = false;
    updateInstallButtons();
  }
}
async function loadSigning() {
  if (signingBusy) return;
  signingBusy = true;
  installGate.invalidate();
  updateInstallButtons();
  const why = $("#signing-why"), out = $("#signing-out"), rail = $("#g-signing");
  $("#signing-refresh").disabled = true;
  why.textContent = "Checking the connection and local signing identity...";
  rail.textContent = "checking"; rail.className = "st st-wait";
  try {
    const response = await api("/api/signing");
    if (!response.ok) throw new Error("Signing endpoint unavailable (" + response.status + ")");
    const result = await response.json();
    installSigning = result;
    rail.textContent = result.ready === true ? "ready" : "action";
    rail.className = "st " + (result.ready === true ? "st-open" : "st-act");
    why.textContent = result.ready === true
      ? "Configured identity passed local checks. App compatibility is checked separately."
      : result.reason || "Signing readiness could not be verified.";
    out.textContent = [result.output, ...(result.warnings || [])].filter(Boolean).join("\n");
  } catch (err) {
    installSigning = null;
    rail.textContent = "unknown"; rail.className = "st st-wait";
    why.textContent = "Signing status is unavailable. Start Filament, then re-check setup.";
    out.textContent = String(err);
  } finally {
    signingBusy = false;
    $("#signing-refresh").disabled = false;
    paintInstallSetup();
  }
}
$("#signing-refresh").onclick = () => { poll(); loadSigning(); };
$("#sl-check").onclick = () => sideload(false);
$("#sl-install").onclick = () => sideload(true);
for (const id of ["sl-app", "sl-profile", "sl-p12", "sl-pw", "sl-identity"]) {
  $("#" + id).addEventListener("input", () => {
    installGate.invalidate();
    const custom = $("#sl-identity").value === "custom";
    $("#sl-custom").hidden = !custom;
    $("#sl-identity-hint").textContent = custom
      ? "Check the package as-is, or provide your own certificate and profile. iOS verifies an existing signature."
      : "Uses the local identity configuration, including PEM identities. No certificate paths to copy.";
    $("#sl-status").textContent = $("#sl-app").value.trim()
      ? "Inputs changed. Check this app before installing." : "Choose an app to begin.";
    updateInstallButtons();
  });
}
document.querySelectorAll("[data-install-route]").forEach(button => button.onclick = () => {
  installGate.invalidate();
  document.querySelectorAll("[data-install-route]").forEach(item =>
    item.setAttribute("aria-pressed", item === button));
  for (const route of ["native", "sidestore", "livecontainer"])
    $("#route-" + route).hidden = route !== button.dataset.installRoute;
  updateInstallButtons();
});
paintInstallSetup();
setInterval(updateInstallButtons, 1000);

async function loadSvc() {
  const rows = await (await api("/api/services")).json();
  $("#svc").innerHTML = rows.map(r =>
    "<tr><td class='m'>" + esc(r.name) + "</td><td class='m'>" + esc(r.port||"") +
    "</td></tr>").join("") || "<tr><td colspan=2 class='empty'>tunnel down</td></tr>";
}
</script></body></html>
"""


# --------------------------------------------------------------------------

class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def verify_request(self, request, client_address):
        # Loopback only, enforced at accept() time.
        return client_address[0] in ("127.0.0.1", "::1")


def main():
    if not os.path.exists(IOS_EXE):
        print("! go-ios not found at %s" % IOS_EXE)
        print("  set FILAMENT_IOS_EXE to override")
    url = "http://%s:%d/?t=%s" % (HOST, PORT, TOKEN)
    srv = Server((HOST, PORT), Handler)

    # The session URL is written next to the script so it can be recovered
    # without scraping stdout. Rewritten every start; the token never repeats.
    session_file = os.path.join(HERE, "session.url")
    try:
        with open(session_file, "w", encoding="utf-8") as fh:
            fh.write(url + "\n")
    except OSError:
        session_file = "(unwritable)"

    print("", flush=True)
    print("  Filament  -  private local bridge", flush=True)
    print("  " + "-" * 52, flush=True)
    print("  bind    127.0.0.1:%d  (loopback only)" % PORT, flush=True)
    print("  egress  none", flush=True)
    print("  open    %s" % url, flush=True)
    print("  saved   %s" % session_file, flush=True)
    print("", flush=True)

    # Filament brings the tunnel agent up, adopts one that is already
    # running, and only tears down an agent it actually owns.
    TUNNEL.start()
    BRING.start()

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped", flush=True)
    finally:
        BRING.shutdown()
        SCREEN.shutdown()
        TUNNEL.shutdown()


if __name__ == "__main__":
    main()
