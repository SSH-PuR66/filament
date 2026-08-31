#!/usr/bin/env python3
"""Read the iPhone's on-screen UI as structure, and act on it.

A screenshot tells you what the screen looks like. This tells you what is ON
it: every focusable element, its caption, its spoken description, and a handle
you can press. That is the difference between a picture of an app and being
able to reason about one.

Why this exists at all
----------------------
The service behind this - com.apple.accessibility.axAuditDaemon - is reachable
over RSD, and an earlier attempt through go-ios failed with
"Failed connecting to service, error code:3". The wrong conclusion was drawn
from that: that RSD services could only be reached from inside go-ios, whose
--userspace tunnel handles packets in its own process.

pymobiledevice3 brings up its OWN in-process userspace tunnel (a pure-Python
PyTCP stack, no admin) whenever a developer command needs one. On iOS 17.4+
over USB that works on Windows through CoreDeviceProxy. So the service was
always reachable; it just needed its own tunnel rather than go-ios's.

    python inspect_ui.py                 # list what is on screen now
    python inspect_ui.py --json          # same, as JSON
    python inspect_ui.py --press 3       # activate element #3 from that list
    python inspect_ui.py --press-caption Settings
    python inspect_ui.py --settings      # device accessibility settings

What READING gives you, and what PRESSING does not
--------------------------------------------------
Reading the tree works against anything on screen - SpringBoard, App Store
apps, system UI. That was verified against this device.

Pressing is far narrower, and the limit is Apple's, not this tool's.
pymobiledevice3 states it plainly for perform_press:

    "Can only be used for processes that carry the task_for_pid-allow
     entitlement."

That entitlement is carried by development-signed builds. SpringBoard - the
Lock Screen and Home Screen - and App Store apps do not have it, so a press
aimed at them is accepted and silently ignored: no error, no effect. Driving
those needs a development-signed app on the device (WebDriverAgent or
DeviceKit), which means an Apple-issued signing identity. A free Apple ID is
enough for that; see sideload.py.

Do not mistake a changing screen for a successful press. A phone playing
media repaints constantly, and an early version of this note claimed a press
had "worked" on the strength of a pixel diff that was really just an
animation.

Needs Developer Mode on and the developer image mounted - the same gate as
screen capture. Zero egress: USB only.
"""
import argparse
import asyncio
import json
import sys

MAX_ELEMENTS = 400


async def _rsd(serial=None):
    """A connected RSD over pymobiledevice3's own in-process userspace tunnel.

    PyTCP's stack is a process-global singleton, so there is exactly ONE
    tunnel per process - which is why everything below runs inside a single
    asyncio.run(). Establishing a second one in the same interpreter can only
    fail, so list-then-press must share a session rather than opening two.
    """
    from pymobiledevice3.remote import userspace_tunnel
    return await userspace_tunnel.establish_userspace_rsd(serial=serial)


async def _walk(ax, limit):
    """Focusable elements of the foreground app, newest focus first."""
    rows = []
    try:
        async for el in ax.iter_elements():
            try:
                ident = el.platform_identifier
            except Exception:
                ident = None
            rows.append({
                "index": len(rows),
                "caption": el.caption,
                "spoken": el.spoken_description,
                "identifier": ident,
            })
            if len(rows) >= limit:
                break
    except TimeoutError:
        pass
    return rows


async def session(limit, press_index, press_caption, want_settings,
                  press_id=None, after=False, serial=None):
    """One tunnel, one service, every operation. -> dict result."""
    from pymobiledevice3.services.accessibilityaudit import AccessibilityAudit

    rsd = await _rsd(serial)
    out = {"elements": [], "settings": None, "pressed": None, "error": None,
           "after": None}
    async with AccessibilityAudit(rsd) as ax:
        if press_id:
            # The caller already holds the handle. Walking the tree again
            # first would cost seconds and could focus a different element,
            # so press directly and report what the screen became.
            try:
                await ax.perform_press(bytes.fromhex(press_id))
                out["pressed"] = {"identifier": press_id}
            except Exception as exc:
                out["error"] = "press failed: %s: %s" % (type(exc).__name__, exc)
                return out
            if after:
                await asyncio.sleep(1.2)   # let the UI settle
                out["after"] = await _walk(ax, limit)
            return out

        if want_settings:
            out["settings"] = [{"key": s.key, "value": s.value}
                               for s in await ax.settings()]
            return out

        try:
            out["elements"] = await _walk(ax, limit)
        except TimeoutError as exc:
            # A screen with nothing focusable (or a locked phone) simply stops
            # publishing focus events. Report what we got rather than nothing.
            out["error"] = "focus events stopped: %s" % exc

        target = None
        if press_index is not None:
            match = [e for e in out["elements"] if e["index"] == press_index]
            target = match[0] if match else None
            if target is None:
                out["error"] = ("no element #%d (found %d)"
                                % (press_index, len(out["elements"])))
        elif press_caption:
            needle = press_caption.lower()
            match = [e for e in out["elements"]
                     if needle in ((e["caption"] or "") + " "
                                   + (e["spoken"] or "")).lower()]
            target = match[0] if match else None
            if target is None:
                out["error"] = "nothing on screen matches %r" % press_caption

        if target is not None:
            if not target["identifier"]:
                out["error"] = ("element #%d carries no handle; cannot press it"
                                % target["index"])
            else:
                await ax.perform_press(bytes.fromhex(target["identifier"]))
                out["pressed"] = target
    return out


def render(elements):
    if not elements:
        print("\n  no focusable elements reported.")
        print("  The phone must be UNLOCKED and showing something.\n")
        return
    print("\n  %d elements on screen\n" % len(elements))
    for e in elements:
        cap = (e["caption"] or e["spoken"] or "").strip()
        if len(cap) > 68:
            cap = cap[:65] + "..."
        print("  %3d  %-70s %s" % (e["index"], cap, (e["identifier"] or "")[:16]))
    print()


def main():
    ap = argparse.ArgumentParser(
        description="Read and act on the iPhone's on-screen UI structure.")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--limit", type=int, default=MAX_ELEMENTS,
                    help="stop after N elements (default %d)" % MAX_ELEMENTS)
    ap.add_argument("--press", type=int, metavar="INDEX",
                    help="activate the element at INDEX from the current listing")
    ap.add_argument("--press-caption", metavar="TEXT",
                    help="activate the first element whose caption contains TEXT "
                         "(case-insensitive)")
    ap.add_argument("--press-id", metavar="HEX",
                    help="activate the element with this platform handle")
    ap.add_argument("--after", action="store_true",
                    help="after pressing, re-read the screen and report it")
    ap.add_argument("--settings", action="store_true",
                    help="show the device's accessibility settings")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    try:
        res = asyncio.run(session(args.limit, args.press, args.press_caption,
                                  args.settings, press_id=args.press_id,
                                  after=args.after))

        if args.settings:
            rows = res["settings"] or []
            print(json.dumps(rows, indent=2, default=str) if args.json
                  else "\n".join("  %-42s %s" % (r["key"], r["value"])
                                 for r in rows))
            return 0

        if args.json:
            print(json.dumps(res, indent=2, default=str))
            return 0 if not res["error"] else 1

        if res["pressed"]:
            p = res["pressed"]
            label = p.get("caption") or p.get("spoken") or p.get("identifier")
            print("  pressed %s" % (repr(label),))
            if res.get("after"):
                print()
                render(res["after"])
            return 0

        render(res["elements"])
        if res["error"]:
            print("  %s" % res["error"])
            return 1
        return 0

    except Exception as exc:
        msg = str(exc)
        print("  %s: %s" % (type(exc).__name__, msg[:300]))
        low = msg.lower()
        if "invalidservice" in low or "not mounted" in low or "-1" in low:
            print("  The developer image must be mounted. Filament mounts it")
            print("  automatically - check its bring-up ladder.")
        else:
            print("  The phone must be attached, UNLOCKED, and have Developer")
            print("  Mode on.")
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
