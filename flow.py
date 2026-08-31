#!/usr/bin/env python3
"""Run a multi-step task on the iPhone, checking every step.

A tap that lands on nothing looks exactly like a tap that worked - the call
returns, and the flow marches on into a screen it does not understand. So
every step here either asserts what it expects to find or reports what was
actually on screen when it could not find it. A flow stops at the first step
whose expectation fails, and says why.

Flow file: JSON, a list of steps. One key per step.

    [
      {"expect": "App Library"},
      {"tap": "Settings"},
      {"wait": 1.5},
      {"expect": "General"},
      {"shot": "settings.png"}
    ]

Steps
  {"launch": "Calculator"}    launch an app (bundle id or name) and re-read
  {"read": true}              re-walk the element tree
  {"expect": "TEXT"}          wait for a caption containing TEXT, then pass
  {"expect_absent": "TEXT"}   wait until no caption contains TEXT
  {"tap": "TEXT"}             tap the first element whose caption contains TEXT
  {"tap_index": 3}            tap by index in the current listing
  {"focus": "next"}           move focus: next | previous | first | last
  {"wait": 1.5}               seconds
  {"shot": "name.png"}        screenshot into .frames/
  {"note": "..."}             printed, does nothing

Matching is case-insensitive substring, against caption + spoken description.
Both assertions wait rather than sampling once. A launch, an animation or a
network round-trip can easily land a moment after a one-shot read, and a flow
that checks instantly is testing the clock as much as the phone. So `expect`
re-reads until the condition holds or its timeout expires (default 6s, set
per-step with {"expect": "X", "timeout": 20} or for the whole flow with
--timeout; the assertion right after a `launch` gets 45s instead, because an
app reaching the front is a slower event than a label changing). The first
check is immediate, so a screen that is already correct
costs nothing, and a passing step reports how long it actually waited - a step
that habitually waits 5.8s is telling you something.

Every step that changes the screen re-reads it, so `expect` always tests what
is on screen NOW rather than a stale listing.

  python flow.py myflow.json
  python flow.py myflow.json --dry-run    # resolve steps, touch nothing
  python flow.py --demo                   # print an example flow

Needs Developer Mode + the mounted developer image. Zero egress: USB only.

A hard limit worth knowing before writing a flow
------------------------------------------------
`tap` reaches only processes carrying the task_for_pid-allow entitlement -
i.e. development-signed apps. SpringBoard (Lock Screen, Home Screen) and App
Store apps accept the press and ignore it, with no error. So a flow that taps
system UI will fail at its next assertion, correctly, and there is nothing to
fix in the flow: the press cannot land. Read steps (`expect`, `read`) work
against everything.

`launch` has NO such limit - starting an app is a system service, not
something gated on the target app's signature. So a flow built from
launch + expect + read drives the phone across apps and verifies each screen
without any signing identity at all. Only tapping inside an app needs one.
"""
import argparse
import asyncio
import json
import os
import subprocess
import sys
import time

# Sibling tools live next to this directory (<tools>/filament, <tools>/go-ios,
# <tools>/zsign), so their location is derived rather than hardcoded. Every
# path below can still be overridden by its environment variable.
_TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# How often to re-walk the tree while waiting. The walk is in-process and
# cheap; the phone is the slow part, so polling faster buys nothing.
POLL_INTERVAL = 0.4
DEFAULT_TIMEOUT = 6.0
# An app coming to the front is a different kind of event from a label
# changing, and measurably slower: the same Calculator -> Safari switch has
# been seen to settle in 1.1s and, on a busy phone, in 21.3s. One flat timeout
# cannot serve both without either failing honest flows or making real
# failures crawl. So the assertion immediately after a launch gets its own,
# longer grace, and everything else keeps the tight default.
LAUNCH_TIMEOUT = 45.0

HERE = os.path.dirname(os.path.abspath(__file__))
FRAMES = os.path.join(HERE, ".frames")
IOS = os.environ.get("FILAMENT_IOS_EXE", os.path.join(_TOOLS, "go-ios", "ios.exe"))
TUNNEL_PORT = os.environ.get("FILAMENT_TUNNEL_PORT", "60105")
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

DEMO = [
    {"note": "open the App Library and look at Settings"},
    {"expect": "App Library"},
    {"tap": "Settings"},
    {"wait": 2.0},
    {"shot": "after-settings.png"},
]


def match(el, needle):
    hay = ((el.get("caption") or "") + " " + (el.get("spoken") or "")).lower()
    return needle.lower() in hay


def disabled(el):
    """True when the device itself reports the element as not actionable.

    iOS publishes this in the caption ("..., Not Enabled"). A press on such an
    element is accepted and ignored, so it must be caught before the tap
    rather than diagnosed from the wreckage afterwards.
    """
    hay = ((el.get("caption") or "") + " " + (el.get("spoken") or "")).lower()
    return "not enabled" in hay


def label(el):
    return (el.get("caption") or el.get("spoken") or "?").strip()


def shot(name):
    """-> (path, error). Uses go-ios; independent of the accessibility tunnel."""
    os.makedirs(FRAMES, exist_ok=True)
    dest = os.path.join(FRAMES, os.path.basename(name))
    try:
        subprocess.run([IOS, "screenshot", "--output=" + dest,
                        "--tunnel-info-port=" + TUNNEL_PORT],
                       capture_output=True, text=True, timeout=120,
                       creationflags=NO_WINDOW)
    except Exception as exc:
        return None, str(exc)
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        return dest, None
    return None, "screenshot failed"


class Flow:
    """Runs the steps against one accessibility session.

    One tunnel for the whole flow: PyTCP's stack is a process-global
    singleton, so a flow that opened a session per step would fail on the
    second one - and would also pay several seconds of setup each time.
    """

    def __init__(self, steps, dry_run=False, limit=120,
                 timeout=DEFAULT_TIMEOUT):
        self.steps = steps
        self.dry = dry_run
        self.limit = limit
        self.timeout = float(timeout)
        self.elements = []
        self.failed = None
        # In a dry run the taps do not happen, so after the first skipped
        # tap the screen no longer corresponds to the flow's position.
        # Assertions past that point cannot be tested, and calling them
        # failures would be a lie about the flow rather than a finding.
        self.stale = False
        self.tapped_something = False
        # Set by `launch`, consumed by the next assertion, then cleared.
        self.grace = None

    @staticmethod
    def took(seconds):
        """Report a wait only when there was one worth reporting."""
        return "" if seconds < 0.05 else "  (after %.1fs)" % seconds

    def say(self, mark, text):
        print("  [%s] %s" % (mark, text), flush=True)

    async def refresh(self, ax):
        from inspect_ui import _walk
        self.elements = await _walk(ax, self.limit)
        return self.elements

    def deadline_for(self, step):
        """How long this assertion may wait.

        An explicit per-step "timeout" always wins - if someone wrote it down,
        they meant it. Otherwise a pending launch grace applies once, and is
        consumed whether or not the assertion passes, so only the assertion
        that actually follows the launch gets the long window.
        """
        if "timeout" in step:
            self.grace = None
            return float(step["timeout"])
        grace, self.grace = self.grace, None
        return float(grace if grace is not None else self.timeout)

    async def settle(self, ax, needle, want_present, deadline):
        """Re-read until an assertion holds, or the deadline passes.

        -> (ok, seconds_waited). The first check uses the tree already in
        hand, so an assertion that is already true returns immediately and
        never touches the device.
        """
        t0 = time.monotonic()
        while True:
            if (self.find(needle) is not None) == want_present:
                return True, time.monotonic() - t0
            if time.monotonic() - t0 >= deadline:
                return False, time.monotonic() - t0
            await asyncio.sleep(POLL_INTERVAL)
            await self.refresh(ax)

    def find(self, needle):
        for el in self.elements:
            if match(el, needle):
                return el
        return None

    def screen_summary(self, n=8):
        if not self.elements:
            return "    (nothing focusable on screen)"
        rows = ["    %2d  %s" % (e["index"], label(e)[:66])
                for e in self.elements[:n]]
        if len(self.elements) > n:
            rows.append("    ... and %d more" % (len(self.elements) - n))
        return "\n".join(rows)

    def fail(self, step_no, why):
        self.failed = (step_no, why)
        self.say("FAIL", why)
        print("\n  what was actually on screen:")
        print(self.screen_summary())
        if self.tapped_something:
            print("\n  note: a tap ran before this step. perform_press only")
            print("  reaches development-signed apps (task_for_pid-allow);")
            print("  SpringBoard and App Store apps accept it and do nothing,")
            print("  which looks exactly like this.")
        print()

    async def run(self):
        from pymobiledevice3.remote import userspace_tunnel
        from pymobiledevice3.services.accessibilityaudit import (
            AccessibilityAudit, Direction,
        )

        rsd = await userspace_tunnel.establish_userspace_rsd()
        DIRS = {"next": Direction.Next, "previous": Direction.Previous,
                "first": Direction.First, "last": Direction.Last}

        async with AccessibilityAudit(rsd) as ax:
            await self.refresh(ax)
            self.say(" ok ", "read screen: %d elements" % len(self.elements))

            for i, step in enumerate(self.steps, 1):
                if not isinstance(step, dict) or not step:
                    self.fail(i, "step %d is not a step object" % i)
                    return False
                key = next(iter(step))
                val = step[key]
                tag = "%d/%d %s" % (i, len(self.steps), key)

                if key == "note":
                    self.say("  - ", "%s  %s" % (tag, val))

                elif key == "wait":
                    self.say("  - ", "%s  %.1fs" % (tag, float(val)))
                    if not self.dry:
                        await asyncio.sleep(float(val))

                elif key == "read":
                    await self.refresh(ax)
                    self.say(" ok ", "%s  %d elements" % (tag, len(self.elements)))

                elif key == "launch":
                    if self.dry:
                        self.say("  - ", "%s  would launch %r" % (tag, val))
                        self.stale = True
                        continue
                    # Runs out-of-process on purpose: pymobiledevice3's PyTCP
                    # stack is a process-global singleton and this flow already
                    # owns the one tunnel this interpreter can have.
                    from launch import resolve, launch as do_launch
                    bundle, err = resolve(str(val))
                    if err:
                        self.fail(i, "%s  %s" % (tag, err))
                        return False
                    pid, err = do_launch(bundle)
                    if err:
                        self.fail(i, "%s  could not launch %s: %s"
                                  % (tag, bundle, err))
                        return False
                    self.say(" ok ", "%s  %s pid %d" % (tag, bundle, pid))
                    # A PID means a process started, not that it is in front.
                    # Re-read so the next assertion tests the real screen -
                    # briefly, because `expect` now waits on its own rather
                    # than sampling once, so a fixed sleep here would only be
                    # a guess layered on top of a real one.
                    await asyncio.sleep(0.5)
                    await self.refresh(ax)
                    self.grace = LAUNCH_TIMEOUT

                elif key == "expect":
                    if self.stale:
                        self.say("  ? ", "%s  %r - UNCHECKED, the screen did not move in a dry run" % (tag, val))
                        continue
                    secs = self.deadline_for(step)
                    ok, waited = await self.settle(ax, str(val), True, secs)
                    if not ok:
                        self.fail(i, "%s  %r never appeared (waited %.1fs)"
                                  % (tag, val, waited))
                        return False
                    el = self.find(str(val))
                    self.say(" ok ", "%s  found %r%s"
                             % (tag, label(el)[:52], self.took(waited)))

                elif key == "expect_absent":
                    if self.stale:
                        self.say("  ? ", "%s  %r - UNCHECKED, the screen did not move in a dry run" % (tag, val))
                        continue
                    secs = self.deadline_for(step)
                    ok, waited = await self.settle(ax, str(val), False, secs)
                    if not ok:
                        el = self.find(str(val))
                        self.fail(i, "%s  %r is still on screen after %.1fs (%r)"
                                  % (tag, val, waited,
                                     label(el)[:40] if el else ""))
                        return False
                    self.say(" ok ", "%s  %r absent%s"
                             % (tag, val, self.took(waited)))

                elif key in ("tap", "tap_index"):
                    if key == "tap":
                        el = self.find(str(val))
                        if el is None:
                            self.fail(i, "%s  nothing matches %r" % (tag, val))
                            return False
                    else:
                        hits = [e for e in self.elements if e["index"] == int(val)]
                        if not hits:
                            self.fail(i, "%s  no element #%s" % (tag, val))
                            return False
                        el = hits[0]
                    if not el.get("identifier"):
                        self.fail(i, "%s  %r has no handle to press"
                                  % (tag, label(el)[:40]))
                        return False
                    # Learned the hard way: perform_press on an element iOS
                    # reports as disabled returns cleanly and does nothing at
                    # all. Without this check the flow taps, sees no change,
                    # and blames the NEXT assertion for a failure that
                    # happened here.
                    if disabled(el):
                        self.fail(i, "%s  %r is reported Not Enabled - a press "
                                     "on it is silently ignored by iOS"
                                  % (tag, label(el)[:46]))
                        return False
                    self.tapped_something = True
                    if self.dry:
                        self.say("  - ", "%s  would tap %r" % (tag, label(el)[:52]))
                        self.stale = True
                        continue
                    await ax.perform_press(bytes.fromhex(el["identifier"]))
                    self.say(" ok ", "%s  tapped %r" % (tag, label(el)[:52]))
                    # The screen has changed; anything asserted next must be
                    # tested against what it became, not what it was.
                    await asyncio.sleep(1.0)
                    await self.refresh(ax)

                elif key == "focus":
                    d = DIRS.get(str(val).lower())
                    if d is None:
                        self.fail(i, "%s  unknown direction %r "
                                     "(next|previous|first|last)" % (tag, val))
                        return False
                    if self.dry:
                        self.say("  - ", "%s  would move focus %s" % (tag, val))
                        self.stale = True
                        continue
                    await ax.move_focus(d)
                    await asyncio.sleep(0.4)
                    await self.refresh(ax)
                    self.say(" ok ", "%s  focus %s" % (tag, val))

                elif key == "shot":
                    if self.dry:
                        self.say("  - ", "%s  would capture %s" % (tag, val))
                        continue
                    path, err = shot(str(val))
                    if err:
                        self.fail(i, "%s  %s" % (tag, err))
                        return False
                    self.say(" ok ", "%s  %s" % (tag, path))

                else:
                    self.fail(i, "%s  unknown step %r" % (tag, key))
                    return False

        return True


def main():
    ap = argparse.ArgumentParser(
        description="Run a checked multi-step flow on the iPhone.")
    ap.add_argument("flow", nargs="?", help="path to a JSON flow file")
    ap.add_argument("--dry-run", action="store_true",
                    help="resolve every step against the current screen "
                         "without tapping anything")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help="seconds an expect/expect_absent waits for the "
                         "screen before failing (default %.0f); a step can "
                         "override it with its own \"timeout\""
                         % DEFAULT_TIMEOUT)
    ap.add_argument("--limit", type=int, default=120,
                    help="max elements per read (default 120)")
    ap.add_argument("--demo", action="store_true",
                    help="print an example flow and exit")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    if args.demo:
        print(json.dumps(DEMO, indent=2))
        return 0
    if not args.flow:
        ap.error("give a flow file, or --demo")

    try:
        steps = json.load(open(args.flow, encoding="utf-8"))
    except Exception as exc:
        print("  cannot read %s: %s" % (args.flow, exc))
        return 1
    if not isinstance(steps, list):
        print("  a flow must be a JSON list of steps")
        return 1

    print("\n  %s  (%d steps)%s"
          % (os.path.basename(args.flow), len(steps),
             "   DRY RUN - nothing will be tapped" if args.dry_run else ""))
    print("  " + "=" * 56)
    t0 = time.time()
    f = Flow(steps, dry_run=args.dry_run, limit=args.limit,
             timeout=args.timeout)
    try:
        ok = asyncio.run(f.run())
    except Exception as exc:
        print("\n  %s: %s" % (type(exc).__name__, str(exc)[:300]))
        print("  The phone must be attached, UNLOCKED, with Developer Mode on")
        print("  and the developer image mounted.")
        return 1
    dt = time.time() - t0
    print("\n  %s in %.1fs" % ("completed" if ok else "STOPPED", dt))
    if ok and args.dry_run and f.stale:
        print("  dry run: steps before the first tap were checked "
              "against the live screen; the rest could not be.")
    print()
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
