#!/usr/bin/env python3
"""Touch, drag, swipe and type on the iPhone - with no signing identity.

This is the file that removes Filament's one real limitation, and it is worth
being precise about why, because the project's documentation said the opposite
for a long time.

Tapping through the accessibility service (`perform_press`, used by
inspect_ui.py) only reaches processes carrying the task_for_pid-allow
entitlement - development-signed builds. SpringBoard and App Store apps accept
the press and silently ignore it. That is real, and it is what made `tap`
useless without a certificate.

But it is a property of THAT mechanism, not of iOS. CoreDevice also exposes
`com.apple.coredevice.hid.universalhidservice`, which injects input at the HID
layer as a host-registered virtual touchscreen. UIKit receives the result as
genuine UIEventTypeTouches, indistinguishable from a finger, in any app
whatsoever. No entitlement, no certificate, no WebDriverAgent.

The whole iOS automation industry runs WebDriverAgent because the premise is
that iOS "does not permit generating input events through any public API" -
which is why Appium and Maestro need a Mac. This path sidesteps the premise.

There is exactly one gate, and it is not signing: backboardd publishes our HID
surface as `eventSource: externalAccessory` and drops every report unless a
media stream is running. Starting one flips it to authenticated and routes the
events through. `touch_session()` opens that stream and discards its payload;
we hold it open for the life of a session because opening one per tap is both
slow and rude to the mirror.

Coordinates on the wire are 0..65535 normalised across the screen, which is
why `--percent` is the native unit here. Points and pixels are offered as a
convenience and need the display geometry, which costs a round trip.

    python touch.py tap 0.5 0.5                 # centre of the screen
    python touch.py tap 200 700 --units point
    python touch.py drag 0.5 0.8 0.5 0.2        # swipe up
    python touch.py type "hello"
    python touch.py button home
    python touch.py info
"""
import argparse
import asyncio
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PYTHON = sys.executable
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
DISPLAY_CACHE = os.path.join(HERE, ".frames", "display.json")

NORM_MAX = 65535


class NoHidServices(Exception):
    """The tunnel in use does not carry the HID services. See ADMIN_EXPLANATION."""

    def __init__(self, absent):
        self.absent = absent
        super().__init__("missing: " + ", ".join(absent))

# Named hardware buttons, as (usage_page, usage_code). Consumer page 0x0C
# carries the media/system keys; 0x07 is the keyboard page.
BUTTONS = {
    "home": (0x0C, 0x40),
    "lock": (0x0C, 0x30),
    "power": (0x0C, 0x30),
    "volume-up": (0x0C, 0xE9),
    "volume-down": (0x0C, 0xEA),
    "mute": (0x0C, 0xE2),
}


# --------------------------------------------------------------------------
# geometry
# --------------------------------------------------------------------------

def display_info(refresh=False, timeout=280):
    """Screen geometry. -> dict or None. Cached: the round trip is slow.

    Only needed to convert points/pixels. Percent and raw normalised units go
    straight to the wire, so the common path never pays for this.
    """
    if not refresh and os.path.exists(DISPLAY_CACHE):
        try:
            with open(DISPLAY_CACHE, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            pass

    argv = [PYTHON, "-m", "pymobiledevice3", "developer", "core-device",
            "get-display-info"]
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, creationflags=NO_WINDOW,
                           encoding="utf-8", errors="replace")
    except Exception:
        return None
    blob = (p.stdout or "") + (p.stderr or "")
    i = blob.find("{")
    if i < 0:
        return None
    try:
        data = json.loads(blob[i:])
    except ValueError:
        return None

    for d in data.get("displays") or []:
        if not d.get("primary"):
            continue
        native = d.get("nativeSize") or [0, 0]
        scale = d.get("pointScale") or 1
        if not native[0]:
            continue
        info = {
            "pixel_width": int(native[0]), "pixel_height": int(native[1]),
            "scale": int(scale),
            "point_width": int(native[0]) // int(scale),
            "point_height": int(native[1]) // int(scale),
            "orientation": (data.get("orientation") or {}).get(
                "currentDeviceNonFlatOrientation"),
        }
        try:
            os.makedirs(os.path.dirname(DISPLAY_CACHE), exist_ok=True)
            with open(DISPLAY_CACHE, "w", encoding="utf-8") as fh:
                json.dump(info, fh, indent=2)
        except Exception:
            pass
        return info
    return None


def to_norm(x, y, units="percent", info=None):
    """Any unit -> (nx, ny) in 0..65535. -> (pair, error).

    Out-of-range is an error, never a wrap. The wire format masks with
    0xFFFF, so a mistyped pixel coordinate would silently land somewhere
    plausible on the far side of the screen - which is exactly the kind of
    bug that wastes an afternoon looking at the wrong thing.
    """
    if units == "norm":
        nx, ny = int(x), int(y)
    elif units == "percent":
        nx, ny = round(float(x) * NORM_MAX), round(float(y) * NORM_MAX)
    elif units in ("point", "pixel"):
        if not info:
            return None, ("%s coordinates need the display geometry, which "
                          "could not be read - use --units percent" % units)
        w = info["point_width"] if units == "point" else info["pixel_width"]
        h = info["point_height"] if units == "point" else info["pixel_height"]
        nx, ny = round(float(x) / w * NORM_MAX), round(float(y) / h * NORM_MAX)
    else:
        return None, "unknown units %r" % units

    for name, v in (("x", nx), ("y", ny)):
        if not 0 <= v <= NORM_MAX:
            return None, ("%s is off screen (%s -> %d, outside 0..%d)"
                          % (name, x if name == "x" else y, v, NORM_MAX))
    return (nx, ny), None


# --------------------------------------------------------------------------
# the session
# --------------------------------------------------------------------------

HID_SERVICES = (
    "com.apple.coredevice.hid.universalhidservice",
    "com.apple.coredevice.hid.indigo",
    "com.apple.coredevice.displayservice",
)

ADMIN_EXPLANATION = """\
  the HID input services are not published to this host

  What is missing: %s

  This is not a signing problem and not a permissions problem. It was worth
  testing properly, so: the no-admin userspace tunnel advertises 73 services
  and none of them are these; running `pymobiledevice3 remote tunneld` as
  administrator yields a trusted tunnel with the IDENTICAL 73-service set;
  connecting anyway returns "No such service"; and `dvt proclist` shows no
  dtuhidd running, though the DeveloperDiskImage is mounted. Admin changes
  nothing here.

  Hypothesis, and it is only that: universalhidservice, displayservice and
  screencaptureservice are the trio behind macOS iPhone Mirroring, and
  pymobiledevice3's own source notes their formats were decoded by sniffing
  Xcode-mirror sessions. The device probably publishes them only to a host
  that completed the macOS-side trust. Unproven - what IS proven is that they
  are absent from Windows with and without admin.

  On Windows the working route to tapping is perform_press (inspect_ui.py),
  which needs a signing identity and only reaches apps you signed - see
  appleid.py. Reading the tree, launching apps and capturing frames need
  neither, and are unaffected."""


def missing_hid_services(rsd):
    """Which of the HID services this tunnel does not advertise. -> list."""
    have = set(((rsd.peer_info or {}).get("Services") or {}).keys())
    return [s for s in HID_SERVICES if s not in have]


class Toucher(object):
    """Holds one media-stream-gated HID session and drives it.

    Use as `async with Toucher() as t:`. Everything inside shares the one
    stream, which is what makes a multi-step flow fast - opening one per tap
    is slow and fights the Mirror tab for the tunnel.
    """

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.svc = None
        self._ctx = None
        self.rsd = None

    async def _connect(self):
        """A tunnel that actually carries the HID services, or an explanation.

        Order matters. `tunneld` is tried first because it is the only source
        of a *trusted* tunnel on Windows, and the userspace tunnel is tried
        second because it is what works with no admin - it just cannot do
        this. Falling back silently would be the wrong shape: the userspace
        tunnel connects perfectly and then fails to find a service, which is
        exactly the failure this ordering exists to explain.
        """
        from pymobiledevice3.tunneld.api import get_tunneld_devices

        try:
            for rsd in await get_tunneld_devices():
                if not missing_hid_services(rsd):
                    self._say("using the trusted tunnel from tunneld")
                    return rsd
        except Exception as exc:
            self._say("tunneld not reachable (%s)" % type(exc).__name__)

        from pymobiledevice3.remote import userspace_tunnel
        rsd = await userspace_tunnel.establish_userspace_rsd()
        # Check before connecting rather than after: otherwise this surfaces
        # as InvalidServiceError from three frames deep, reading like a bug
        # here instead of a property of the tunnel.
        absent = missing_hid_services(rsd)
        if absent:
            raise NoHidServices(absent)
        self._say("using the userspace tunnel")
        return rsd

    async def __aenter__(self):
        from pymobiledevice3.remote.core_device.hid_service import touch_session

        self.rsd = await self._connect()
        self._ctx = touch_session(self.rsd)
        self.svc = await self._ctx.__aenter__()
        return self

    async def __aexit__(self, *exc):
        if self._ctx is not None:
            try:
                await self._ctx.__aexit__(*exc)
            except Exception:
                pass
        return False

    def _say(self, msg):
        if self.verbose:
            print("  .. %s" % msg, flush=True)

    async def tap(self, nx, ny, hold=0.04):
        """One CONTACT + RELEASE at the same point.

        The brief hold exists because a contact and release in the same
        millisecond is not what a finger does, and some views debounce it.
        """
        from pymobiledevice3.remote.core_device.hid_service import (
            TOUCHSCREEN_STATE_CONTACT, TOUCHSCREEN_STATE_RELEASE)
        self._say("tap %d,%d" % (nx, ny))
        await self.svc.send_touchscreen(TOUCHSCREEN_STATE_CONTACT, nx, ny)
        if hold:
            await asyncio.sleep(hold)
        await self.svc.send_touchscreen(TOUCHSCREEN_STATE_RELEASE, nx, ny)

    async def drag(self, x1, y1, x2, y2, steps=30, duration=0.6):
        """A stream of CONTACT samples, then one RELEASE.

        There is no touch-begin/end opcode: every CONTACT means "in contact
        at this position", so a drag is just a sequence of them.
        """
        from pymobiledevice3.remote.core_device.hid_service import (
            TOUCHSCREEN_STATE_CONTACT, TOUCHSCREEN_STATE_RELEASE)
        steps = max(2, int(steps))
        gap = max(0.0, float(duration)) / steps
        self._say("drag %d,%d -> %d,%d in %d steps" % (x1, y1, x2, y2, steps))
        for i in range(steps + 1):
            t = i / steps
            x = round(x1 + (x2 - x1) * t)
            y = round(y1 + (y2 - y1) * t)
            await self.svc.send_touchscreen(TOUCHSCREEN_STATE_CONTACT, x, y)
            if gap:
                await asyncio.sleep(gap)
        await self.svc.send_touchscreen(TOUCHSCREEN_STATE_RELEASE, x2, y2)

    async def type_text(self, text, per_key=0.03):
        """Type via a host-registered virtual keyboard.

        The keyboard surface is not pre-registered the way the touchscreen is,
        so it has to be created inside the same media-stream session - which
        is why this lives here rather than standing alone.
        """
        from pymobiledevice3.remote.core_device.hid_service import (
            ASCII_TO_HID, KEY_LEFT_SHIFT)

        sid = await self.svc.create_keyboard_service()
        self._say("virtual keyboard registered as _ServiceID %s" % sid)

        unsupported = sorted({c for c in text if c not in ASCII_TO_HID})
        if unsupported:
            return ("cannot type %s - only US-layout ASCII is mapped"
                    % ", ".join(repr(c) for c in unsupported[:6]))

        for ch in text:
            usage, shift = ASCII_TO_HID[ch]
            pressed = [usage] + ([KEY_LEFT_SHIFT] if shift else [])
            # Every report carries the full pressed set, so releasing is
            # simply sending the empty set.
            await self.svc.send_keyboard(sid, pressed)
            await asyncio.sleep(per_key)
            await self.svc.send_keyboard(sid, ())
            await asyncio.sleep(per_key)
        return None


async def press_button(name, hold=0.08):
    """A hardware button, via the Indigo service. -> error or None.

    Buttons are a different service from touch and do NOT need the media
    stream, so this deliberately does not open one.
    """
    from pymobiledevice3.remote import userspace_tunnel
    from pymobiledevice3.remote.core_device.hid_service import (
        IndigoHIDService, HID_BUTTON_STATE_DOWN, HID_BUTTON_STATE_UP)

    pair = BUTTONS.get(name)
    if not pair:
        return "unknown button %r - try: %s" % (name, ", ".join(sorted(BUTTONS)))
    page, code = pair
    rsd = await userspace_tunnel.establish_userspace_rsd()
    async with IndigoHIDService(rsd) as svc:
        await svc.send_button(page, code, HID_BUTTON_STATE_DOWN)
        await asyncio.sleep(hold)
        await svc.send_button(page, code, HID_BUTTON_STATE_UP)
    return None


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

async def run(args):
    info = None
    if args.units in ("point", "pixel") or args.cmd == "info":
        info = display_info(refresh=getattr(args, "refresh", False))

    if args.cmd == "info":
        if not info:
            print("\n  could not read the display geometry\n")
            return 1
        print("\n  %d x %d px   %d x %d pt   scale %d   %s\n"
              % (info["pixel_width"], info["pixel_height"],
                 info["point_width"], info["point_height"],
                 info["scale"], info.get("orientation") or "?"))
        return 0

    if args.cmd == "button":
        err = await press_button(args.name)
        if err:
            print("\n  %s\n" % err)
            return 1
        print("\n  pressed %s\n" % args.name)
        return 0

    t0 = time.time()
    try:
        return await _gestures(args, info, t0)
    except NoHidServices as exc:
        print("\n" + ADMIN_EXPLANATION % ", ".join(exc.absent) + "\n")
        return 3


async def _gestures(args, info, t0):
    async with Toucher(verbose=args.verbose) as t:
        if args.cmd == "tap":
            pt, err = to_norm(args.x, args.y, args.units, info)
            if err:
                print("\n  %s\n" % err)
                return 1
            await t.tap(*pt)
            print("\n  tapped %s,%s (%s)  norm %d,%d  in %.1fs\n"
                  % (args.x, args.y, args.units, pt[0], pt[1], time.time() - t0))

        elif args.cmd == "drag":
            a, err = to_norm(args.x, args.y, args.units, info)
            if err:
                print("\n  start: %s\n" % err)
                return 1
            b, err = to_norm(args.x2, args.y2, args.units, info)
            if err:
                print("\n  end: %s\n" % err)
                return 1
            await t.drag(a[0], a[1], b[0], b[1], steps=args.steps,
                         duration=args.duration)
            print("\n  dragged in %.1fs\n" % (time.time() - t0))

        elif args.cmd == "type":
            err = await t.type_text(args.text)
            if err:
                print("\n  %s\n" % err)
                return 1
            print("\n  typed %d characters in %.1fs\n"
                  % (len(args.text), time.time() - t0))
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Touch input on the iPhone. Needs no signing identity.")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--units", choices=("percent", "norm", "point", "pixel"),
                    default="percent",
                    help="percent 0..1 (default), norm 0..65535, or "
                         "point/pixel (needs a display lookup)")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("tap", help="tap a point")
    p.add_argument("x", type=float)
    p.add_argument("y", type=float)

    p = sub.add_parser("drag", help="drag between two points")
    p.add_argument("x", type=float)
    p.add_argument("y", type=float)
    p.add_argument("x2", type=float)
    p.add_argument("y2", type=float)
    p.add_argument("--steps", type=int, default=30)
    p.add_argument("--duration", type=float, default=0.6)

    p = sub.add_parser("type", help="type text via a virtual keyboard")
    p.add_argument("text")

    p = sub.add_parser("button", help="press a hardware button")
    p.add_argument("name", choices=sorted(BUTTONS))

    p = sub.add_parser("info", help="screen geometry")
    p.add_argument("--refresh", action="store_true")

    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return 0
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    return asyncio.run(run(args))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
