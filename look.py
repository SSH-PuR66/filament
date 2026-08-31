#!/usr/bin/env python3
"""Grab the phone's screen right now, downscaled, for an assistant to read.

A full frame is 1206x2622 and ~1.4 MB of PNG. That is the wrong shape for
anything that has to look at it and reason - it is slow to move around and
mostly empty pixels. This writes a width-limited copy next to the original so
the picture can be opened directly.

  python look.py                 # one frame -> .frames/look.png
  python look.py --full          # keep native resolution too
  python look.py --watch 5       # a fresh frame every 5s until Ctrl+C
"""
import argparse
import os
import subprocess
import sys
import time

# Sibling tools live next to this directory (<tools>/filament, <tools>/go-ios,
# <tools>/zsign), so their location is derived rather than hardcoded. Every
# path below can still be overridden by its environment variable.
_TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HERE = os.path.dirname(os.path.abspath(__file__))
IOS = os.environ.get("FILAMENT_IOS_EXE", os.path.join(_TOOLS, "go-ios", "ios.exe"))
TUNNEL_PORT = os.environ.get("FILAMENT_TUNNEL_PORT", "60105")
FRAMES = os.path.join(HERE, ".frames")
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


def grab(dest):
    """-> (ok, error)"""
    try:
        os.remove(dest)
    except OSError:
        pass
    p = subprocess.run(
        [IOS, "screenshot", "--output=" + dest,
         "--tunnel-info-port=" + TUNNEL_PORT],
        capture_output=True, text=True, timeout=120, creationflags=NO_WINDOW)
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        return True, None
    blob = ((p.stdout or "") + "\n" + (p.stderr or "")).strip()
    import json
    err = None
    for line in blob.splitlines():
        try:
            o = json.loads(line.strip())
        except ValueError:
            continue
        if isinstance(o, dict) and o.get("level") == "ERROR":
            err = o.get("err") or o.get("msg")
    return False, err or "screenshot failed - is the developer image mounted?"


def shrink(src, dst, width):
    try:
        from PIL import Image
    except ImportError:
        return None, "Pillow not installed (pip install pillow)"
    im = Image.open(src)
    if im.width > width:
        im = im.resize((width, round(im.height * width / im.width)),
                       Image.LANCZOS)
    im.save(dst, optimize=True)
    return im.size, None


def once(args):
    os.makedirs(FRAMES, exist_ok=True)
    full = os.path.join(FRAMES, "look_full.png")
    small = os.path.join(FRAMES, "look.png")

    t0 = time.time()
    ok, err = grab(full)
    if not ok:
        print("  %s" % err)
        return 1
    size, serr = shrink(full, small, args.width)
    dt = time.time() - t0
    if serr:
        print("  %s  (full frame kept at %s)" % (serr, full))
        return 1
    kb = os.path.getsize(small) // 1024
    print("  %s  %dx%d  %dKB  in %.1fs" % (small, size[0], size[1], kb, dt))
    if not args.full:
        try:
            os.remove(full)
        except OSError:
            pass
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Capture the iPhone screen, downscaled for reading.")
    ap.add_argument("--width", type=int, default=620,
                    help="target width in px (default 620)")
    ap.add_argument("--full", action="store_true",
                    help="also keep the native-resolution frame")
    ap.add_argument("--watch", type=float, metavar="SECONDS",
                    help="re-grab every SECONDS until interrupted")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    if not args.watch:
        return once(args)
    print("  refreshing every %.1fs - Ctrl+C to stop" % args.watch)
    while True:
        once(args)
        time.sleep(args.watch)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
