#!/usr/bin/env python3
"""Find out why Developer Mode will not turn on - and, where possible, turn it on.

Why this exists
---------------
`ios devmode get` is not trustworthy on its own. go-ios discards the error from
its status query, so a locked device, a refused service start, or any transport
hiccup all render identically to genuinely-off: DeveloperModeEnabled=false. Six
hours of devmode.log saying "still off" may therefore mean "never actually
asked". This reads the state through three independent paths and shows all
three, so a disagreement between them is visible instead of silently resolved.

Developer Mode is driven by exactly one lockdown service, com.apple.amfi.lockdown,
which takes one plist key:

    {"action": 0}   reveal  - make the row appear in Settings (lapses on reboot
                              and on reconnect, hence the re-reveal loop)
    {"action": 1}   enable  - arm it; refused outright while a passcode is set
    {"action": 2}   accept  - answer the post-restart "Turn On" prompt

Neither CLI can send action 2 by itself: go-ios only reaches it after its own
action 1 succeeds, and pymobiledevice3 only calls it from inside
enable_developer_mode(). --accept sends it directly, which was worth trying on
a passcoded device on the theory that the human had already supplied the
security decision action 1 is refused for.

TESTED ON THIS DEVICE, 2026-08-31: that theory is WRONG. Action 2 is refused
with the same {'Error': 'Device has a passcode set'}. AMFI gates the accept
exactly as hard as the arm, so with a passcode set there is NO host-side step
of any kind - the entire flow, including the post-restart confirmation, has to
happen on the phone. --accept is kept because it is still the right call after
a passcode is removed, and because it prints the device's own refusal rather
than leaving you guessing.

Read-only unless you pass --reveal, --enable or --accept.
"""
import argparse
import asyncio
import json
import os
import subprocess
import sys

# Sibling tools live next to this directory (<tools>/filament, <tools>/go-ios,
# <tools>/zsign), so their location is derived rather than hardcoded. Every
# path below can still be overridden by its environment variable.
_TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

IOS = os.environ.get("FILAMENT_IOS_EXE", os.path.join(_TOOLS, "go-ios", "ios.exe"))
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

AMFI_DOMAIN = "com.apple.security.mac.amfi"

OK, WARN, BAD, INFO = "  ok ", " warn", "  no ", "  -  "


def say(mark, label, value=""):
    print("  [%s] %-34s %s" % (mark, label, value), flush=True)


def head(title):
    print("\n  %s\n  %s" % (title, "-" * max(len(title), 40)), flush=True)


# ---------------------------------------------------------------- go-ios

def ios(*args, timeout=45):
    """(payload, raw_blob, error_string). Never raises."""
    try:
        p = subprocess.run([IOS, *args], capture_output=True, text=True,
                           timeout=timeout, creationflags=NO_WINDOW)
    except Exception as exc:
        return None, "", str(exc)
    blob = ((p.stdout or "") + "\n" + (p.stderr or "")).strip()
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


# ---------------------------------------------------------------- reads

async def read_state(udid):
    """Three independent reads of Developer Mode, reported side by side."""
    from pymobiledevice3.lockdown import create_using_usbmux

    results = {}

    # 1. what go-ios' own devmode command says (the one that can lie)
    payload, _, err = ios("devmode", "get", timeout=30)
    if isinstance(payload, dict) and "DeveloperModeEnabled" in payload:
        results["go-ios devmode get"] = (bool(payload["DeveloperModeEnabled"]), None)
    else:
        results["go-ios devmode get"] = (None, err or "no usable payload")

    # 2. the raw lockdown value, via a code path that surfaces its errors
    payload, blob, err = ios("lockdown", "get", "DeveloperModeStatus",
                             "--domain=" + AMFI_DOMAIN, timeout=30)
    if payload is not None:
        val = payload
        if isinstance(payload, dict):
            val = payload.get("DeveloperModeStatus", payload)
        results["lockdown amfi value"] = (val, None)
    else:
        results["lockdown amfi value"] = (None, err or (blob or "")[-120:])

    # 3. second opinion from a different implementation entirely
    try:
        lockdown = await create_using_usbmux(serial=udid)
        try:
            val = await lockdown.get_value(domain=AMFI_DOMAIN,
                                           key="DeveloperModeStatus")
            results["pymobiledevice3 value"] = (val, None)
        finally:
            try:
                await lockdown.aio_close()
            except Exception:
                pass
    except Exception as exc:
        results["pymobiledevice3 value"] = (None, "%s: %s" % (type(exc).__name__, exc))

    return results


async def read_context(udid):
    """Everything that could plausibly be gating the toggle."""
    from pymobiledevice3.lockdown import create_using_usbmux

    ctx = {}
    try:
        lockdown = await create_using_usbmux(serial=udid)
    except Exception as exc:
        ctx["_error"] = "%s: %s" % (type(exc).__name__, exc)
        return ctx
    try:
        try:
            root = await lockdown.get_value()
        except Exception as exc:
            root = {}
            ctx["_root_error"] = str(exc)
        if isinstance(root, dict):
            for k in ("DeviceName", "ProductType", "ProductVersion", "BuildVersion",
                      "PasswordProtected", "ActivationState", "IsSupervised",
                      "HasSiDP", "TimeIntervalSince1970", "CPUArchitecture",
                      "DeviceClass", "TrustedHostAttached", "MobileSubscriberCountryCode"):
                if k in root:
                    ctx[k] = root[k]
    finally:
        try:
            await lockdown.aio_close()
        except Exception:
            pass
    return ctx


# ---------------------------------------------------------------- actions

async def amfi_action(udid, action):
    """Send one raw AMFI action and return the device's unmapped reply."""
    from pymobiledevice3.lockdown import create_using_usbmux

    lockdown = await create_using_usbmux(serial=udid)
    try:
        service = await lockdown.start_lockdown_service("com.apple.amfi.lockdown")
        return await service.send_recv_plist({"action": action})
    finally:
        try:
            await lockdown.aio_close()
        except Exception:
            pass


# ---------------------------------------------------------------- verdict

def verdict(states, ctx, profiles, mounted):
    head("verdict")

    vals = [v for v, e in states.values() if v is not None]
    agreed = set(str(v) for v in vals)
    truthy = [v for v in vals if v in (True, 1, "1", 2, "2")]

    if not vals:
        say(BAD, "Developer Mode state", "UNREADABLE from every path")
        print("""
  Every read failed. That is a connection problem, not a Developer Mode
  problem. Work down this list before anything else:
    1. Is the phone plugged into a DATA cable (not a charge-only one)?
    2. Is the phone UNLOCKED right now? Most lockdown reads need it unlocked.
    3. Has this computer been trusted?  Unplug, replug, and tap
       "Trust This Computer" on the phone, then enter your passcode.
    4. Re-run this script.""")
        return

    if truthy:
        say(OK, "Developer Mode", "ON")
        say(OK if mounted else WARN, "Developer disk image",
            "mounted" if mounted else "not mounted yet - run: ios image mount")
        print("\n  Nothing to unblock. Start filament.py and the gates open by themselves.")
        return

    if len(agreed) > 1:
        say(WARN, "Developer Mode state", "SOURCES DISAGREE - see above")
        print("""
  The three reads do not agree, which means at least one of them failed
  silently rather than genuinely reading 'off'. Trust the pymobiledevice3
  value; it raises on error instead of coercing to false.""")
    else:
        say(BAD, "Developer Mode", "OFF (all sources agree)")

    passcode = ctx.get("PasswordProtected")
    supervised = ctx.get("IsSupervised")

    print()
    if profiles:
        say(WARN, "Configuration profiles", "%d installed - check for MDM" % len(profiles))
        print("     A restrictions profile can suppress the Developer Mode row entirely.")
        print("     Inspect with:  %s profile list --pretty" % IOS)
    if supervised:
        say(WARN, "Supervised device", "yes - an MDM policy may block Developer Mode")

    print()
    if True:
        print("""  MOST LIKELY CAUSE: a passcode is set, so the host is NOT ALLOWED to
  flip the switch. Confirm it in one command - this is the only authority:

        python devmode_doctor.py --enable

  If it answers 'Device has a passcode set', the automated path is closed and
  you want option A below. (That probe is safe on a passcoded device: AMFI
  refuses and nothing happens. On a phone with genuinely no passcode it
  SUCCEEDS and reboots.)

  This is deliberate, not a bug and not something to work around blindly:
  AMFI answers action 1 with {'Error': 'Device has a passcode set'} because
  the real flow requires a human to type that passcode at the post-restart
  prompt. So `ios devmode enable` cannot work here, and no amount of
  re-running it will change that.

  You have two ways forward.

  A) KEEP THE PASSCODE (recommended - try this first)
     1. Leave this running so the row stays revealed:
            python watch_devmode.py
     2. On the phone:  Settings > Privacy & Security
        Scroll to the VERY BOTTOM. Developer Mode is in the "Security"
        group, BELOW Lockdown Mode. It is easy to miss - it is past
        everything else on that screen.
     3. Toggle Developer Mode ON. Tap Restart in the alert.
     4. After it reboots, unlock the phone. You should get a
        "Turn on Developer Mode?" prompt - tap Turn On, enter passcode.
     5. That Lock Screen prompt is the step people miss. Face ID
        authenticates instantly, and a habitual swipe-up dismisses it -
        Developer Mode then silently stays OFF. If you miss it, repeat
        from step 3; the host CANNOT answer it for you (tested: AMFI
        refuses action 2 with the same passcode error).

  B) REMOVE THE PASSCODE TEMPORARILY (only if A fails)
     Settings > Face ID & Passcode > Turn Passcode Off, then:
         %s devmode enable --enable-post-restart
     Re-add the passcode afterwards; Developer Mode stays on.
     Note this clears Apple Pay cards and re-encrypts the keychain, so
     it is a real cost, not a free workaround. Prefer A.""" % IOS)
    print("""
  If --enable instead reports success, the phone is rebooting and Developer
  Mode will be on once it comes back. Verify with a plain re-run.""")


# ---------------------------------------------------------------- main

async def run(args):
    print("\n  Developer Mode doctor")
    print("  " + "=" * 52)

    head("device")
    payload, _, err = ios("list", timeout=30)
    devices = (payload or {}).get("deviceList", []) if isinstance(payload, dict) else []
    if not devices:
        say(BAD, "usbmux device list", "empty")
        print("""
  No device is attached, so nothing below can run.
    - Use a cable that carries DATA, not just power.
    - Unlock the phone and tap "Trust This Computer" if asked.
    - Check Apple Mobile Device Service is running.""")
        return 1
    udid = args.udid or devices[0]
    say(OK, "attached", udid)

    ctx = await read_context(udid)
    if "_error" in ctx:
        say(BAD, "lockdown handshake", ctx["_error"])
        print("\n  The device is on usbmux but refuses lockdown. Unlock it and\n"
              "  tap Trust This Computer, then re-run.")
        return 1

    say(INFO, "name", ctx.get("DeviceName", "?"))
    say(INFO, "model / iOS", "%s / %s (%s)" % (ctx.get("ProductType", "?"),
                                               ctx.get("ProductVersion", "?"),
                                               ctx.get("BuildVersion", "?")))
    pw = ctx.get("PasswordProtected")
    # NB: PasswordProtected means "the screen is locked right now", NOT "a
    # passcode is configured". It reads False on an unlocked phone that very
    # much has one. Only AMFI knows the answer that matters, and it only tells
    # you when you ask it to enable (--enable). Reported here as what it is.
    say(INFO, "screen locked right now",
        "yes" if pw else ("no" if pw is False else "unknown"))
    say(WARN if ctx.get("IsSupervised") else OK, "supervised",
        "yes" if ctx.get("IsSupervised") else "no")
    say(INFO, "activation", ctx.get("ActivationState", "?"))

    head("developer mode - three independent reads")
    states = await read_state(udid)
    for label, (val, err) in states.items():
        if val is None:
            say(BAD, label, "FAILED: %s" % (err or "?"))
        else:
            say(OK if val in (True, 1, "1", 2, "2") else BAD, label, repr(val))

    head("environment")
    payload, _, perr = ios("profile", "list", timeout=40)
    profiles = []
    if isinstance(payload, dict):
        profiles = payload.get("ProfileMetadata") or payload.get("OrderedIdentifiers") or []
    elif isinstance(payload, list):
        profiles = payload
    say(WARN if profiles else OK, "configuration profiles",
        "%d installed" % len(profiles) if profiles else "none")
    payload, _, _ = ios("image", "list", timeout=60)
    mounted = bool(payload) and payload not in ([], {}, "")
    say(OK if mounted else INFO, "developer image", "mounted" if mounted else "not mounted")

    # ---- state-changing actions, all explicit ----
    if args.reveal or args.enable or args.accept:
        head("actions")
    if args.reveal:
        try:
            resp = await amfi_action(udid, 0)
            say(OK if resp.get("success") else BAD, "action 0 (reveal)", repr(dict(resp)))
        except Exception as exc:
            say(BAD, "action 0 (reveal)", "%s: %s" % (type(exc).__name__, exc))
    if args.enable:
        try:
            resp = await amfi_action(udid, 1)
            say(OK if resp.get("success") else BAD, "action 1 (enable) RAW", repr(dict(resp)))
            if resp.get("Error"):
                print("\n     ^ that is the device's own words, unmapped. This is the\n"
                      "       datum both CLIs throw away.")
        except Exception as exc:
            say(BAD, "action 1 (enable)", "%s: %s" % (type(exc).__name__, exc))
    if args.accept:
        try:
            resp = await amfi_action(udid, 2)
            say(OK if resp.get("success") else BAD, "action 2 (accept) RAW", repr(dict(resp)))
            if resp.get("success"):
                print("\n     Accepted. Re-run with no flags to confirm it stuck.")
        except Exception as exc:
            say(BAD, "action 2 (accept)", "%s: %s" % (type(exc).__name__, exc))

    if not (args.reveal or args.enable or args.accept):
        states = await read_state(udid)
    verdict(states, ctx, profiles, mounted)
    print()
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Diagnose (and where allowed, fix) iOS Developer Mode.")
    ap.add_argument("--udid", help="target a specific device")
    ap.add_argument("--reveal", action="store_true",
                    help="send AMFI action 0: make the Settings row appear")
    ap.add_argument("--enable", action="store_true",
                    help="send AMFI action 1 and print the RAW reply (refused if a passcode is set)")
    ap.add_argument("--accept", action="store_true",
                    help="send AMFI action 2 (answer the post-restart prompt). "
                         "Refused while a passcode is set - tested; useful only "
                         "once the passcode is off, or to see the raw refusal.")
    args = ap.parse_args()
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
