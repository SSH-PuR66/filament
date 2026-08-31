#!/usr/bin/env python3
"""Get pictures of the iPhone screen without Developer Mode.

Filament's `ios screenshot` path is gated behind the Developer Disk Image,
which iOS will not mount until Developer Mode is on. That gate is real and
there is no lockdown-level substitute: `ios rsd ls` on this device with
Developer Mode off advertises 59 services and com.apple.mobile.screenshotr is
not among them.

What IS available with Developer Mode off is the camera roll. Anything the
phone captures itself - a hardware screenshot, a Control Center screen
recording - lands in the Photos library, and that library is readable over
plain AFC with nothing but the existing pairing. So:

  shutter mode   you press Volume Up + Side; the PNG appears here in ~1-3s
  pull mode      you record with Control Center; the .mov lands here

Human-triggered rather than host-triggered, which makes it useless for a
closed control loop and perfectly good for "show me what the phone is doing".
Zero egress, no DDI, no tunnel, no admin, no drivers, no purchase.

  python capture.py                 # pull the newest screenshot
  python capture.py --video         # pull the newest screen recording
  python capture.py --watch         # shutter mode: pull each new shot as it lands
  python capture.py --list          # what is in the camera roll
"""
import argparse
import asyncio
import os
import posixpath
import sys

FRAMES = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".frames")
STILL = (".png", ".jpg", ".jpeg", ".heic")
VIDEO = (".mov", ".mp4", ".m4v")


async def open_afc(udid):
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.afc import AfcService
    lockdown = await create_using_usbmux(serial=udid)
    return AfcService(lockdown=lockdown)


async def albums(afc):
    """DCIM subfolders, oldest first. iOS fills 100APPLE, then 101APPLE, ..."""
    names = await afc.listdir("DCIM")
    return sorted(n for n in names
                  if n not in (".", "..") and not n.startswith("."))


async def paths_in(afc, folders, exts):
    """Matching file paths. Names only - no stat, so this stays fast enough
    to poll. This library holds 6862 stills; stat-ing all of them per tick
    would make the shutter slower than walking over to the phone."""
    out = []
    for folder in folders:
        p = posixpath.join("DCIM", folder)
        try:
            names = await afc.listdir(p)
        except Exception:
            continue
        out.extend(posixpath.join(p, n) for n in names
                   if n.lower().endswith(exts))
    return out


async def newest(afc, folders, exts):
    """(path, stat) of the most recently modified match, or None.

    Only the tail folders are stat-ed: iOS fills DCIM albums in order, so a
    capture taken seconds ago is in the last one. st_mtime is a datetime here,
    not a Unix timestamp - stat() returns real datetimes.
    """
    best = None
    for path in await paths_in(afc, folders, exts):
        try:
            st = await afc.stat(path)
        except Exception:
            continue
        if best is None or st["st_mtime"] > best[1]["st_mtime"]:
            best = (path, st)
    return best


def human(size):
    val = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if val < 1024 or unit == "GB":
            return "%d%s" % (val, unit) if unit == "B" else "%.1f%s" % (val, unit)
        val /= 1024.0


async def pull(afc, path, st, dest_dir):
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, posixpath.basename(path))
    await afc.pull(path, dest)
    print("  %s  %8s  %s  ->  %s" % (
        st["st_mtime"].strftime("%H:%M:%S"), human(st["st_size"]),
        posixpath.basename(path), dest))
    return dest


async def run(args):
    exts = VIDEO if args.video else STILL
    kind = "screen recording" if args.video else "screenshot"

    try:
        svc = await open_afc(args.udid)
    except Exception as exc:
        print("\n  no device: %s: %s" % (type(exc).__name__, exc))
        print("  Plug the iPhone in with a data cable, unlock it, trust this computer.\n")
        return 1

    async with svc as afc:
        try:
            all_folders = await albums(afc)
        except Exception as exc:
            print("\n  cannot read DCIM: %s" % exc)
            print("  The phone must be UNLOCKED for the Photos library to be readable.\n")
            return 1
        if not all_folders:
            print("\n  camera roll is empty.\n")
            return 1

        # Recent albums only unless asked otherwise - see paths_in().
        folders = all_folders if args.all else all_folders[-args.albums:]

        if args.list:
            stills = await paths_in(afc, folders, STILL)
            vids = await paths_in(afc, folders, VIDEO)
            print("\n  DCIM albums      : %s" % ", ".join(all_folders))
            print("  scanning         : %s%s" % (", ".join(folders),
                  "" if args.all else "   (--all for every album)"))
            print("  stills / videos  : %d / %d\n" % (len(stills), len(vids)))
            rows = []
            for p in (stills + vids):
                try:
                    rows.append((p, await afc.stat(p)))
                except Exception:
                    pass
            rows.sort(key=lambda r: r[1]["st_mtime"], reverse=True)
            for p, st in rows[:args.limit]:
                print("  %s  %8s  %s" % (
                    st["st_mtime"].strftime("%Y-%m-%d %H:%M:%S"),
                    human(st["st_size"]), p))
            print()
            return 0

        if not args.watch:
            best = await newest(afc, folders, exts)
            if best is None:
                print("\n  no %s found." % kind)
                print("  Take one: press Volume Up + the Side button together.\n"
                      if not args.video else
                      "  Record one: Control Center > the record button.\n")
                return 1
            print("\n  newest %s:" % kind)
            await pull(afc, best[0], best[1], args.out)
            print()
            return 0

        # ---- shutter mode: diff names, stat only what is new ----
        print("\n  Shutter mode. Press Volume Up + Side on the phone;")
        print("  the PNG lands in %s about a second later." % args.out)
        print("  Watching %s. Ctrl+C to stop.\n" % ", ".join(folders))
        seen = set(await paths_in(afc, folders, exts))
        print("  (%d existing ignored - waiting for new ones)\n" % len(seen))
        while True:
            try:
                current = await paths_in(afc, folders, exts)
            except Exception as exc:
                print("  device went away: %s\n" % exc)
                return 1
            for path in sorted(set(current) - seen):
                seen.add(path)
                try:
                    st = await afc.stat(path)
                except Exception:
                    continue
                await pull(afc, path, st, args.out)
            await asyncio.sleep(args.interval)


def main():
    # Line-buffer stdout: --watch is a long-running tool that is almost always
    # run with its output redirected to a file, and block buffering makes it
    # look dead for minutes at a time.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    ap = argparse.ArgumentParser(
        description="Pull screenshots and screen recordings off the iPhone over "
                    "AFC. No Developer Mode required.")
    ap.add_argument("--udid", help="target a specific device")
    ap.add_argument("--video", action="store_true", help="screen recordings, not stills")
    ap.add_argument("--watch", action="store_true",
                    help="shutter mode: pull each new capture as it lands")
    ap.add_argument("--list", action="store_true", help="list the camera roll and exit")
    ap.add_argument("--all", action="store_true",
                    help="scan every DCIM album, not just the most recent")
    ap.add_argument("--albums", type=int, default=2,
                    help="how many recent albums to scan (default 2)")
    ap.add_argument("--limit", type=int, default=25, help="rows for --list")
    ap.add_argument("--interval", type=float, default=2.0,
                    help="seconds between polls in --watch (default 2)")
    ap.add_argument("--out", default=FRAMES, help="destination directory")
    args = ap.parse_args()
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n  stopped\n")
        return 130


if __name__ == "__main__":
    sys.exit(main())
