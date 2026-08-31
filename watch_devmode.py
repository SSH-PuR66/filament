#!/usr/bin/env python3
"""Poll Developer Mode + DDI state and record every transition.

The AMFI 'reveal' that makes the Developer Mode menu appear in Settings is
transient - it lapses on reboot and on reconnect. This re-reveals on every
poll while the gate is still shut, so the menu stays visible for as long as
the watcher runs, instead of vanishing between attempts.

One thing this deliberately does NOT do is trust `ios devmode get` on its own.
go-ios discards the error from that query, so a locked device, a refused
service start, or any transport hiccup all come back as
DeveloperModeEnabled=false - indistinguishable from genuinely off. A log full
of "still off" can therefore mean "never actually asked". Every reading here
is cross-checked against the raw lockdown value, which fails loudly, and the
three outcomes - off / unreadable / on - are reported as three different
things.
"""
import json
import os
import subprocess
import sys
import time

# Sibling tools live next to this directory (<tools>/filament, <tools>/go-ios,
# <tools>/zsign), so their location is derived rather than hardcoded. Every
# path below can still be overridden by its environment variable.
_TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

IOS = os.path.join(_TOOLS, "go-ios", "ios.exe")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "devmode.log")
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
AMFI_DOMAIN = "com.apple.security.mac.amfi"


def ios(*args, timeout=45):
    """(payload, raw_blob, error). Never raises."""
    try:
        p = subprocess.run([IOS, *args], capture_output=True, text=True,
                           timeout=timeout, creationflags=NO_WINDOW)
        blob = (p.stdout or "") + "\n" + (p.stderr or "")
    except Exception as exc:
        return None, "", str(exc)
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
    return payload, blob, error


def say(msg):
    stamp = time.strftime("%H:%M:%S")
    line = "[%s] %s" % (stamp, msg)
    print(line, flush=True)
    with open(OUT, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def attached():
    payload, _, _ = ios("list", timeout=30)
    if isinstance(payload, dict):
        return bool(payload.get("deviceList"))
    return False


def read_devmode():
    """-> ('on' | 'off' | 'unreadable', detail)

    Two sources. They must agree that it is off before we say it is off.
    """
    payload, _, err = ios("devmode", "get", timeout=30)
    primary = None
    if isinstance(payload, dict) and "DeveloperModeEnabled" in payload:
        primary = bool(payload["DeveloperModeEnabled"])

    if primary:
        return "on", "devmode get reported enabled"

    # The cross-check: this path surfaces its errors instead of coercing
    # them to false, so it can tell "off" apart from "could not ask".
    payload, blob, err2 = ios("lockdown", "get", "DeveloperModeStatus",
                              "--domain=" + AMFI_DOMAIN, timeout=30)
    value = payload
    if isinstance(payload, dict):
        value = payload.get("DeveloperModeStatus", payload)

    if value in (True, 1, "1", 2, "2"):
        return "on", "lockdown amfi value = %r (devmode get disagreed)" % (value,)
    if value in (False, 0, "0"):
        return "off", "both sources agree"
    if primary is False:
        return "unreadable", ("devmode get said false but the lockdown value "
                              "could not be read (%s) - 'false' here may just "
                              "mean the question never reached the device"
                              % ((err2 or (blob or "").strip()[-90:]) or "no detail"))
    return "unreadable", (err or err2 or "no usable response from either source")


def main():
    say("watching for Developer Mode; re-revealing the menu each cycle")
    last = None
    revealed_at = 0.0

    while True:
        if not attached():
            if last != "gone":
                say("no device attached - plug the iPhone in with a data cable "
                    "and unlock it")
                last = "gone"
            time.sleep(15)
            continue

        state, detail = read_devmode()

        if state == "on":
            if last != "on":
                say("DEVELOPER MODE IS ON  (%s)" % detail)
                img, _, _ = ios("image", "list", timeout=60)
                if img:
                    say("  DDI already mounted: %s" % (img,))
                    say("  -> screenshot service should answer; start filament.py")
                else:
                    say("  DDI not mounted yet. Next:")
                    say("     ios image mount --path=" + os.path.join(
                        _TOOLS, "go-ios", "devimages", "ddi-17E5179g"))
                last = "on"

        elif state == "unreadable":
            # Distinct from 'off' on purpose - this is the state the old
            # watcher silently mislabelled for hours.
            if last != "unreadable":
                say("state UNREADABLE - not the same as off: %s" % detail)
                say("  usually means the phone is locked. Unlock it and, if "
                    "prompted, tap Trust This Computer.")
                last = "unreadable"

        else:
            if last != "off":
                say("still off - menu re-revealed (%s)" % detail)
                say("  Settings > Privacy & Security > scroll to the VERY BOTTOM.")
                say("  Developer Mode sits in the 'Security' group BELOW Lockdown")
                say("  Mode - it is past everything else on that screen.")
                say("  Toggle on, tap Restart. After the reboot, UNLOCK and look")
                say("  for the 'Turn on Developer Mode?' alert on the LOCK SCREEN -")
                say("  tap Turn On and enter the passcode. That alert is the step")
                say("  people miss: Face ID unlocks instantly and a habitual swipe")
                say("  dismisses it, leaving Developer Mode off. The host cannot")
                say("  answer it for you - AMFI refuses action 2 while a passcode")
                say("  is set (tested on this device).")
                last = "off"

            # Keep the row from disappearing between checks. The reveal lapses
            # on reboot and on reconnect, so it has to be re-sent, but it does
            # not need re-sending every 15s - once a minute is plenty.
            now = time.time()
            if now - revealed_at > 60:
                ios("devmode", "reveal", timeout=40)
                revealed_at = now

        time.sleep(15)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        say("watcher stopped")
