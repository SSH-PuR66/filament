#!/usr/bin/env python3
"""rcsign.py - re-sign an .ipa with rcodesign when zsign cannot.

zsign (resign.py) is the right tool for almost everything, but it seals a
framework's resources *before* it signs the frameworks nested inside it, so
any app that ships a framework-inside-a-framework - LiveContainer+SideStore
is one - installs with 0xe8008017 "A signed resource has been added, modified,
or deleted". go-ios's signer skips such a framework entirely (0xe800801c "No
code signature found"). rcodesign signs bottom-up and gets it right.

What this does, in order, all on a short path because zsign, unzip and
zipfile all fail quietly past MAX_PATH on Windows:

  1. unpack the .ipa
  2. strip PlugIns (a free-tier profile covers one app id; extensions carry
     their own and iOS rejects them unless removed) unless --keep-extensions
  3. rewrite CFBundleIdentifier when --bundle-id is given
  4. copy the provisioning profile in as embedded.mobileprovision
  5. write the profile's entitlements next to the bundle and sign with
     rcodesign, passing that file by a RELATIVE path - rcodesign reads a
     "C:" drive prefix as a scope selector, so an absolute Windows path
     silently attaches the entitlements to nothing
  6. repack

Usage:
  py rcsign.py app.ipa --pem key.pem --pem cert.pem --profile x.mobileprovision \
      --bundle-id com.example.app.TEAMID --out app-signed.ipa
  echo password | py rcsign.py app.ipa --p12 id.p12 --p12password-stdin --profile x.mobileprovision

The identity can be PEM (a key file and a cert file, e.g. what Sideloadly
keeps in %APPDATA%\\Sideloadly) or a p12. Note rcodesign 0.29 only opens p12
files written with the legacy (RC2/3DES, SHA-1 MAC) parameters reliably. This
wrapper therefore decodes a p12 locally and gives rcodesign a short-lived,
owner-only passwordless copy, then deletes it when the child returns.
"""
import argparse
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)


def find_rcodesign():
    env = os.environ.get("FILAMENT_RCODESIGN_EXE")
    if env and os.path.exists(env):
        return env
    root = os.path.join(TOOLS, "rcodesign")
    for base, _dirs, files in os.walk(root):
        if "rcodesign.exe" in files:
            return os.path.join(base, "rcodesign.exe")
    return shutil.which("rcodesign")


def read_profile(path):
    b = open(path, "rb").read()
    s, e = b.find(b"<?xml"), b.find(b"</plist>") + len(b"</plist>")
    if s < 0 or e < len(b"</plist>"):
        raise ValueError("not a provisioning profile: %s" % path)
    return plistlib.loads(b[s:e])


def _private_copy(source, work, suffix):
    """Copy one sensitive input to a random owner-only path."""
    fd, target = tempfile.mkstemp(prefix="identity-", suffix=suffix, dir=work)
    os.close(fd)
    try:
        shutil.copyfile(source, target)
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
        return target
    except Exception:
        try:
            os.unlink(target)
        except OSError:
            pass
        raise


def app_dir(payload):
    apps = [d for d in os.listdir(payload) if d.endswith(".app")]
    if len(apps) != 1:
        raise ValueError("expected exactly one .app in Payload, found %r" % apps)
    return os.path.join(payload, apps[0])


def prepare(work, ipa, profile, bundle_id=None, keep_extensions=False):
    """Unpack + strip + rewrite + embed. -> (app_path, entitlements_relpath).

    Pure file work; tested without a device or rcodesign.
    """
    with zipfile.ZipFile(ipa) as z:
        z.extractall(work)
    payload = os.path.join(work, "Payload")
    app = app_dir(payload)
    plugins = os.path.join(app, "PlugIns")
    if not keep_extensions and os.path.isdir(plugins):
        shutil.rmtree(plugins)
    info_path = os.path.join(app, "Info.plist")
    with open(info_path, "rb") as f:
        info = plistlib.load(f)
    if bundle_id:
        info["CFBundleIdentifier"] = bundle_id
        with open(info_path, "wb") as f:
            plistlib.dump(info, f)
    # Read entitlements and embed bytes from the same immutable copy. Reading
    # the source and then reopening it for copy left a profile-swap window.
    profile_copy = _private_copy(profile, work, ".mobileprovision")
    try:
        prof = read_profile(profile_copy)
        shutil.copyfile(profile_copy,
                        os.path.join(app, "embedded.mobileprovision"))
    finally:
        try:
            os.unlink(profile_copy)
        except OSError:
            pass
    ent = dict(prof.get("Entitlements", {}))
    want = ent.get("application-identifier", "")
    have = info["CFBundleIdentifier"]
    team = (prof.get("TeamIdentifier") or [""])[0]
    if want and want != "%s.%s" % (team, have) and not want.endswith(".*"):
        raise ValueError("profile is for %s but the app is %s.%s - pass "
                         "--bundle-id" % (want, team, have))
    ent_rel = "entitlements.plist"
    with open(os.path.join(work, ent_rel), "wb") as f:
        plistlib.dump(ent, f)
    return app, ent_rel


def repack(work, out):
    payload = os.path.join(work, "Payload")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for root, _dirs, files in os.walk(payload):
            for name in files:
                full = os.path.join(root, name)
                arc = os.path.relpath(full, work).replace(os.sep, "/")
                z.write(full, arc)
    return out


def sign(work, app, ent_rel, pems=(), p12=None, p12password=None,
         rcodesign=None, timeout=1800):
    exe = rcodesign or find_rcodesign()
    if not exe:
        return False, "rcodesign not found - unpack the apple-codesign release into tools/rcodesign or set FILAMENT_RCODESIGN_EXE"
    staged = []
    identity_work = None
    try:
        import sideload as S
        identity_work = S._private_tempdir()
        argv = [exe, "sign"]
        for pem in pems:
            pem_copy = _private_copy(pem, identity_work, ".pem")
            staged.append(pem_copy)
            argv += ["--pem-file", os.path.abspath(pem_copy)]
        if p12:
            p12_copy = S._passwordless_p12_copy(
                p12, p12password, identity_work)
            staged.append(p12_copy)
            argv += ["--p12-file", os.path.abspath(p12_copy)]
        argv += ["--entitlements-xml-file", ent_rel,
                 os.path.relpath(app, work).replace(os.sep, "/")]
        child_env = os.environ.copy()
        child_env.pop("FILAMENT_P12_PASSWORD", None)
        child_env.pop("P12_PASSWORD", None)
        p = subprocess.run(
            argv, cwd=work, capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace",
            env=child_env)
    except subprocess.TimeoutExpired:
        return False, "rcodesign timed out after %ss" % timeout
    except Exception as exc:
        return False, "could not stage or run rcodesign: %s" % exc
    finally:
        for path in staged:
            try:
                os.unlink(path)
            except OSError:
                pass
        if identity_work is not None:
            shutil.rmtree(identity_work, ignore_errors=True)
    return p.returncode == 0, ((p.stdout or "") + (p.stderr or "")).strip()


def short_workdir():
    # A short root matters more than a tidy one: the nested SideStore
    # frameworks in LiveContainer push paths past 260 characters under
    # %TEMP%\<anything long>.
    root = os.environ.get("FILAMENT_WORK") or os.path.join(
        os.path.splitdrive(HERE)[0] + os.sep, "Users", os.environ.get("USERNAME", "u"), ".rcs")
    os.makedirs(root, exist_ok=True)
    work = tempfile.mkdtemp(prefix="s", dir=root)
    try:
        os.chmod(work, 0o700)
    except OSError:
        pass
    return work


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("app", help=".ipa to re-sign")
    ap.add_argument("--profile", required=True, help="provisioning profile")
    ap.add_argument("--pem", action="append", default=[],
                    help="PEM file (repeat: key file, then cert file)")
    ap.add_argument("--p12", help="PKCS#12 identity (legacy encryption only)")
    passwords = ap.add_mutually_exclusive_group()
    passwords.add_argument(
        "--p12password", default=None,
        help="legacy form; password is visible in this process argv")
    passwords.add_argument(
        "--p12password-stdin", action="store_true",
        help="read one p12 password line from stdin")
    ap.add_argument("--bundle-id", help="rewrite CFBundleIdentifier first")
    ap.add_argument("--keep-extensions", action="store_true",
                    help="do not strip PlugIns")
    ap.add_argument("--out", help="output .ipa (default: <input>-rcsigned.ipa)")
    args = ap.parse_args()
    if args.p12password_stdin:
        args.p12password = sys.stdin.readline().rstrip("\r\n")
    try:
        sys.stdout.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")
    except Exception:
        pass
    if not (args.pem or args.p12):
        ap.error("an identity is required: --pem key.pem --pem cert.pem, or --p12")

    out = args.out or os.path.join(
        os.path.dirname(os.path.abspath(args.app)),
        os.path.splitext(os.path.basename(args.app))[0] + "-rcsigned.ipa")
    work = short_workdir()
    print("\n  rcsign  -  %s" % os.path.basename(args.app))
    print("  work    %s" % work)
    try:
        app, ent_rel = prepare(work, args.app, args.profile,
                               bundle_id=args.bundle_id,
                               keep_extensions=args.keep_extensions)
        print("  app     %s" % os.path.relpath(app, work))
        ok, text = sign(work, app, ent_rel, pems=args.pem, p12=args.p12,
                        p12password=args.p12password)
        tail = [l for l in text.splitlines() if l.strip()][-4:]
        for line in tail:
            print("          %s" % line)
        if not ok:
            print("\n  rcodesign failed\n")
            return 1
        repack(work, out)
        print("  output  %s  (%d bytes)" % (out, os.path.getsize(out)))
        print("\n  Install with:  py sideload.py install \"%s\"\n" % out)
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
