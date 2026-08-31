#!/usr/bin/env python3
"""Launch an app on the iPhone - and prove it actually came to the front.

This needs no signing identity. Launching is a system service (CoreDevice),
not something that requires the app under test to carry a development
signature - unlike perform_press, which only reaches apps holding
task_for_pid-allow. So the honest split is:

    launch an app        no signing needed   (this file)
    read its UI tree     no signing needed   (inspect_ui.py)
    tap inside it        signing needed      (see sideload.py)

Launch plus read already covers a lot: drive the phone to a known app, then
inspect what it is showing.

A launch that returns a PID has proved only that a process started. It has NOT
proved the app is on screen - iOS will happily start one behind a locked or
dark display. So --verify reads the accessibility tree afterwards and reports
what is actually in front.

    python launch.py --list                    # installed apps
    python launch.py com.apple.calculator      # launch
    python launch.py Calculator --verify       # launch by name, then confirm
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

# Sibling tools live next to this directory (<tools>/filament, <tools>/go-ios,
# <tools>/zsign), so their location is derived rather than hardcoded. Every
# path below can still be overridden by its environment variable.
_TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HERE = os.path.dirname(os.path.abspath(__file__))
PYTHON = sys.executable
IOS = os.environ.get("FILAMENT_IOS_EXE", os.path.join(_TOOLS, "go-ios", "ios.exe"))
TUNNEL_PORT = os.environ.get("FILAMENT_TUNNEL_PORT", "60105")
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


def apps(include_system=False):
    """[{bundle, name, version, kind}] via go-ios. Needs no tunnel.

    Two output shapes, because go-ios uses two:
      --list  gives one "bundle Name version" line per USER app, and omits
              every system app - so Calculator, Settings and Safari are
              simply absent, which is why resolving them by name used to fail.
      --all   gives a single JSON array of full Info.plist dictionaries,
              system apps included. It is ~1.5MB, so it is only fetched when
              system apps are actually wanted.
    """
    argv = [IOS, "apps", "--all" if include_system else "--list",
            "--tunnel-info-port=" + TUNNEL_PORT]
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=180,
                           creationflags=NO_WINDOW, encoding="utf-8",
                           errors="replace")
    except Exception:
        return []
    out = (p.stdout or "")

    if include_system:
        start = out.find("[")
        if start < 0:
            return []
        try:
            blob = json.loads(out[start:])
        except ValueError:
            return []
        rows = []
        for d in blob:
            if not isinstance(d, dict):
                continue
            bundle = d.get("CFBundleIdentifier")
            if not bundle:
                continue
            rows.append({
                "bundle": bundle,
                "name": (d.get("CFBundleDisplayName")
                         or d.get("CFBundleName") or bundle),
                "version": d.get("CFBundleShortVersionString") or "",
                "kind": d.get("ApplicationType") or "",
            })
        return rows

    rows = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("{"):
            continue
        parts = line.split(" ")
        if len(parts) >= 2 and "." in parts[0]:
            rows.append({"bundle": parts[0],
                         "name": " ".join(parts[1:-1]) or parts[0],
                         "version": parts[-1], "kind": "User"})
    return rows


def resolve(target):
    """Accept a bundle id or a human name. -> (bundle, error)"""
    if re.match(r"^[A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+$", target or ""):
        return target, None          # already looks like a bundle id
    # System apps are the common target (Settings, Safari, Calculator), and
    # they only appear in the --all listing.
    rows = apps(include_system=True)
    if not rows:
        return None, ("could not list installed apps - give the exact bundle "
                      "id instead")
    needle = (target or "").lower()
    exact = [r for r in rows if r["name"].lower() == needle]
    hits = exact or [r for r in rows if needle in r["name"].lower()]
    if not hits:
        return None, "no installed app matches %r" % target
    if len(hits) > 1 and not exact:
        names = ", ".join("%s (%s)" % (h["name"], h["bundle"]) for h in hits[:6])
        return None, "%r is ambiguous: %s" % (target, names)
    return hits[0]["bundle"], None


def launch(bundle, kill_existing=True, timeout=220):
    """-> (pid, error). Never raises."""
    argv = [PYTHON, "-m", "pymobiledevice3", "developer", "core-device",
            "launch-application", bundle, "", "--userspace"]
    if not kill_existing:
        argv.append("--no-kill-existing")
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, creationflags=NO_WINDOW,
                           encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return None, "launch timed out after %ss" % timeout
    except Exception as exc:
        return None, str(exc)
    blob = (p.stdout or "") + "\n" + (p.stderr or "")
    m = re.search(r'"processIdentifier"\s*:\s*(\d+)', blob)
    if m:
        return int(m.group(1)), None
    # Name the two failures that actually happen, rather than dumping a traceback.
    if "FBSOpenApplicationErrorDomain" in blob or "could not be, unlocked" in blob:
        return None, ("the device is locked - unlock the phone and retry "
                      "(this is a lock gate, not a signing gate)")
    if "not found" in blob.lower() or "NSLocalizedDescription" in blob:
        m2 = re.search(r'"NSLocalizedDescription"\s*:\s*"([^"]+)"', blob)
        if m2:
            return None, m2.group(1)
    tail = [l for l in blob.splitlines() if l.strip()]
    return None, (tail[-1][:200] if tail else "no output")


def foreground(limit=25, timeout=240):
    """What the accessibility tree says is on screen. -> (elements, error)"""
    argv = [PYTHON, os.path.join(HERE, "inspect_ui.py"), "--json",
            "--limit", str(int(limit))]
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, creationflags=NO_WINDOW,
                           encoding="utf-8", errors="replace")
    except Exception as exc:
        return [], str(exc)
    blob = (p.stdout or "").strip()
    i = blob.find("{")
    if i < 0:
        return [], "could not read the screen"
    try:
        data = json.loads(blob[i:])
    except ValueError:
        return [], "could not parse the screen listing"
    return data.get("elements") or [], data.get("error")


def main():
    ap = argparse.ArgumentParser(
        description="Launch an app on the iPhone. No signing identity needed.")
    ap.add_argument("target", nargs="?",
                    help="bundle id (com.apple.calculator) or app name (Calculator)")
    ap.add_argument("--list", action="store_true", help="list installed apps")
    ap.add_argument("--filter", help="substring filter for --list")
    ap.add_argument("--system", action="store_true",
                    help="include system apps in --list (slower; the full "
                         "Info.plist listing is large)")
    ap.add_argument("--verify", action="store_true",
                    help="after launching, read the screen and show what is "
                         "actually in front")
    ap.add_argument("--no-kill-existing", action="store_true",
                    help="do not restart the app if it is already running")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    if args.list:
        rows = apps(include_system=args.system)
        if args.filter:
            n = args.filter.lower()
            rows = [r for r in rows
                    if n in r["name"].lower() or n in r["bundle"].lower()]
        if args.json:
            print(json.dumps(rows, indent=2))
            return 0
        print("\n  %d apps\n" % len(rows))
        for r in sorted(rows, key=lambda r: r["name"].lower()):
            print("  %-38s %-9s %s"
                  % (r["name"][:38], (r.get("kind") or "")[:9], r["bundle"]))
        print()
        return 0

    if not args.target:
        ap.error("give an app to launch, or --list")

    bundle, err = resolve(args.target)
    if err:
        print("\n  %s\n" % err)
        return 1

    t0 = time.time()
    pid, err = launch(bundle, kill_existing=not args.no_kill_existing)
    if err:
        out = {"ok": False, "bundle": bundle, "error": err}
        print(json.dumps(out, indent=2) if args.json
              else "\n  could not launch %s\n  %s\n" % (bundle, err))
        return 1

    result = {"ok": True, "bundle": bundle, "pid": pid,
              "seconds": round(time.time() - t0, 1)}

    if args.verify:
        # A PID proves a process started, not that it is in front. iOS starts
        # apps happily behind a dark screen, so ask the screen itself.
        els, ferr = foreground()
        result["elements"] = els
        result["screen_error"] = ferr
        result["verified"] = bool(els)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    print("\n  launched %s  pid %d  (%.1fs)" % (bundle, pid, result["seconds"]))
    if args.verify:
        els = result.get("elements") or []
        if not els:
            print("  screen reports nothing focusable%s"
                  % ((" - " + result["screen_error"]) if result.get("screen_error") else ""))
            print("  the process started, but nothing is visibly in front")
            print("  (a dark or locked display looks exactly like this)\n")
            return 1
        print("  screen now shows %d elements:\n" % len(els))
        for e in els[:10]:
            cap = (e.get("caption") or e.get("spoken") or "").strip()
            print("    %2d  %s" % (e["index"], cap[:64]))
        print()
    else:
        print()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
