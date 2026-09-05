#!/usr/bin/env python3
"""Re-sign an .ipa with your own development identity, on Windows.

This is the step that was missing, and its absence explained a lot. An .ipa
downloaded from the internet carries either someone else's provisioning
profile or none at all - LiveContainer and TwinPath, sitting on this machine's
Desktop, have none. iOS refuses those before it looks at anything else, which
is why tapping an install button did nothing useful. sideload.py could SAY so
(it verifies), but it could not FIX it (it never signed anything).

Re-signing means, at minimum:

  - replacing embedded.mobileprovision with one issued for THIS device
  - rewriting the app's entitlements to match that profile, because a binary
    claiming entitlements its profile does not grant is rejected
  - re-signing every Mach-O in the bundle - the app binary, every framework,
    every extension, every dylib - with fresh CodeDirectory hashes and a CMS
    blob over them

Doing that from scratch in Python is weeks of subtle, silent failure modes,
so this wraps zsign, which is the established cross-platform implementation
and the same shape of dependency as go-ios and pymobiledevice3 already are.
The binary is pinned by SHA-256 against the digest its authors published, for
the same reason the Apple Root CA is pinned in sideload.py: a signing tool
that has been swapped underneath you is a bad thing to discover late.

What this file adds beyond calling zsign:

  - a preflight, so a doomed re-sign fails in a second with the real reason
    rather than producing an .ipa that fails on the device a minute later
  - a POST-verification, because a zero exit code is not evidence. The output
    is re-opened and checked for the profile and signature that were the
    entire point. zsign is good, but "it did not error" and "it produced a
    valid bundle" are different claims.

    python resign.py check app.ipa --p12 id.p12 --profile x.mobileprovision
    python resign.py sign  app.ipa --p12 id.p12 --profile x.mobileprovision
"""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import zipfile

# Sibling tools live next to this directory (<tools>/filament, <tools>/go-ios,
# <tools>/zsign), so their location is derived rather than hardcoded. Every
# path below can still be overridden by its environment variable.
_TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

ZSIGN = os.environ.get("FILAMENT_ZSIGN_EXE",
                       os.path.join(_TOOLS, "zsign", "zsign.exe"))
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

# zsign v1.1.2, zsign-windows-x64.zip, from the SHA256SUMS.txt published
# alongside the release at github.com/zhlynn/zsign/releases/tag/v1.1.2.
# This is the digest of the ZIP as downloaded, recorded so the provenance of
# the signing tool is checkable rather than assumed.
ZSIGN_ZIP_SHA256 = ("96b5bf7029a52c67cdb78b68b3666d8ff1e31e5c4355359"
                    "64be2a482afc09e5c")
ZSIGN_VERSION = "1.1.2"

OK, BAD, INFO = "  ok ", "  no ", "  -  "


WRONG_ISSUER = (
    "this certificate was not issued by Apple, so it cannot sign an app iOS "
    "will run. zsign rejects it with 'Unknown issuer hash ... No embedded "
    "WWDR intermediate matches'. Use appleid.py identity to get a real one.")


def issuer_is_apple(issuer):
    """Does this certificate chain to Apple's developer PKI? -> bool.

    zsign embeds Apple's WWDR intermediates and matches the issuer against
    them, so anything else fails - correctly, since iOS would refuse it too.
    Matching on the issuer string is a preflight heuristic, not a
    cryptographic check: the real verification is zsign's, and this only
    exists to say so a minute earlier and in plainer words.
    """
    text = str(issuer or "")
    return ("Worldwide Developer Relations" in text
            or "Apple Worldwide" in text
            or "Apple Inc." in text)


def say(mark, label, value=""):
    print("  [%s] %-28s %s" % (mark, label, value))


def head(title):
    print("\n  %s\n  %s" % (title, "-" * 44))


def zsign_version():
    """-> (version, error). Proves the tool is actually there and runnable."""
    if not os.path.exists(ZSIGN):
        return None, ("zsign is not installed at %s - set FILAMENT_ZSIGN_EXE "
                      "or download zsign-windows-x64.zip from "
                      "github.com/zhlynn/zsign/releases" % ZSIGN)
    try:
        child_env = os.environ.copy()
        child_env.pop("FILAMENT_P12_PASSWORD", None)
        child_env.pop("P12_PASSWORD", None)
        p = subprocess.run([ZSIGN, "-v"], capture_output=True, text=True,
                           timeout=30, creationflags=NO_WINDOW,
                           encoding="utf-8", errors="replace", env=child_env)
    except Exception as exc:
        return None, "could not run zsign: %s" % exc
    out = ((p.stdout or "") + (p.stderr or "")).strip()
    for line in out.splitlines():
        if "version" in line.lower():
            return line.split(":")[-1].strip(), None
    return out[:40] or "unknown", None


def preflight(app, p12, password, profile, udid=None):
    """Everything knowable before touching the app. -> (blockers, warnings).

    Deliberately ordered cheapest-and-most-decisive first. There is no point
    verifying a profile's CMS chain if the p12 password is wrong.
    """
    import sideload as S

    blockers, warnings = [], []

    head("tooling")
    ver, err = zsign_version()
    if err:
        say(BAD, "zsign", err)
        blockers.append(err)
    else:
        say(OK, "zsign", ver)
        if ver != ZSIGN_VERSION:
            warnings.append("zsign is %s; %s is what was pinned and tested"
                            % (ver, ZSIGN_VERSION))

    head("inputs")
    for label, path in (("app", app), ("p12", p12), ("profile", profile)):
        if not path:
            say(BAD, label, "not given")
            blockers.append("%s is required" % label)
        elif not os.path.exists(path):
            say(BAD, label, "no such file: %s" % path)
            blockers.append("%s not found: %s" % (label, path))
        else:
            say(INFO, label, path)
    if blockers:
        return blockers, warnings

    head("app")
    fatal, info = S.check_app(app)
    for k, v in info.items():
        say(INFO, k, v)
    # An app with NO profile is exactly what we are here to fix, so that
    # particular complaint from check_app is expected, not a blocker.
    for f in fatal:
        if "embedded.mobileprovision" in f:
            say(INFO, "unprovisioned", "yes - this is what re-signing fixes")
        else:
            say(BAD, "app", f)
            blockers.append(f)

    head("identity")
    fatal, info = S.check_p12(p12, password)
    for k, v in info.items():
        say(INFO, k, str(v)[:70])
    for f in fatal:
        say(BAD, "p12", f)
        blockers.append(f)

    # zsign carries Apple's WWDR intermediates and refuses any certificate it
    # cannot chain to one, with "Unknown issuer hash ... No embedded WWDR
    # intermediate matches". That is the correct behaviour - iOS would refuse
    # it too - but zsign only says so AFTER parsing the profile and starting
    # to sign frameworks. Checking the issuer here turns a confusing late
    # failure into an immediate, accurate sentence.
    issuer = str(info.get("issuer") or "")
    if issuer:
        if issuer_is_apple(issuer):
            say(OK, "issued by", "Apple - zsign will accept this chain")
        else:
            say(BAD, "issued by", issuer[:60])
            blockers.append(WRONG_ISSUER)

    head("profile")
    if udid is None:
        udid = S.device_udid()
    say(INFO, "device", udid or "no device attached")
    fatal, warn, info = S.check_profile(profile, udid)
    for k, v in info.items():
        say(INFO, k, str(v)[:70])
    for f in fatal:
        say(BAD, "profile", f)
        blockers.append(f)
    for w in warn:
        say(INFO, "note", w)
        warnings.append(w)

    return blockers, warnings


def verify_output(path):
    """Re-open what zsign produced. -> (problems, info).

    A zero exit code says the tool ran. This says the artefact is right,
    which is a different question and the one that matters.
    """
    problems, info = [], {}
    if not os.path.exists(path):
        return ["no output file was produced at %s" % path], {}
    info["size"] = "%.1f MB" % (os.path.getsize(path) / 1048576.0)
    try:
        z = zipfile.ZipFile(path)
        names = z.namelist()
    except Exception as exc:
        return ["output is not a readable .ipa: %s" % exc], info

    info["entries"] = len(names)
    has_profile = any(n.endswith("embedded.mobileprovision") for n in names)
    has_sig = any("_CodeSignature/CodeResources" in n for n in names)
    info["embedded profile"] = has_profile
    info["code signature"] = has_sig
    if not has_profile:
        problems.append("the output still has no embedded.mobileprovision - "
                        "the re-sign did not take")
    if not has_sig:
        problems.append("the output has no _CodeSignature - it is not signed")
    return problems, info


def _stage_inputs(app, p12, password, profile):
    """Snapshot every signer input into one private temporary directory."""
    import sideload as S

    work = S._private_tempdir()
    try:
        args = argparse.Namespace(
            app=app, p12=p12, p12password=password, profile=profile,
            install=True)
        return work, S._snapshot_install_args(args, work)
    except Exception:
        shutil.rmtree(work, ignore_errors=True)
        raise


def _resign_staged(app, p12, password, profile, out, work,
                   bundle_id=None, quiet=False, timeout=1800,
                   drop_extensions=False):
    """Run zsign against already-snapshotted inputs."""
    import sideload as S

    try:
        signing_p12 = S._passwordless_p12_copy(p12, password, work)
    except Exception as exc:
        return False, "could not stage the signing identity safely: %s" % exc
    argv = [ZSIGN, "-k", signing_p12, "-m", profile, "-o", out, "-f"]
    if bundle_id:
        argv += ["-b", bundle_id]
    if drop_extensions:
        argv.append("-E")
    if quiet:
        argv.append("-q")
    argv.append(app)
    try:
        child_env = os.environ.copy()
        child_env.pop("FILAMENT_P12_PASSWORD", None)
        child_env.pop("P12_PASSWORD", None)
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, creationflags=NO_WINDOW,
                           encoding="utf-8", errors="replace", env=child_env)
    except subprocess.TimeoutExpired:
        return False, "zsign timed out after %ss" % timeout
    except Exception as exc:
        return False, str(exc)
    return p.returncode == 0, ((p.stdout or "") + (p.stderr or "")).strip()


def _validate_staged(app, p12, password, profile):
    """Fail closed on the exact snapshots that will be handed to zsign."""
    import sideload as S

    blockers = []
    app_fatal, _ = S.check_app(app, will_sign=True)
    blockers.extend(app_fatal)
    p12_fatal, _ = S.check_p12(p12, password)
    blockers.extend(p12_fatal)
    profile_fatal, _, _ = S.check_profile(profile, None)
    blockers.extend(profile_fatal)
    match_fatal, _ = S.check_identity_match(p12, password, profile)
    blockers.extend(match_fatal)
    return blockers


def resign(app, p12, password, profile, out, bundle_id=None, quiet=False,
           timeout=1800, drop_extensions=False):
    """Run zsign with immutable inputs and no password in its argv/env."""
    try:
        work, staged = _stage_inputs(app, p12, password, profile)
    except Exception as exc:
        return False, "could not snapshot signing inputs: %s" % exc
    try:
        blockers = _validate_staged(
            staged.app, staged.p12, password, staged.profile)
        if blockers:
            return False, "staged signing preflight failed: %s" % blockers[0]
        return _resign_staged(
            staged.app, staged.p12, password, staged.profile, out, work,
            bundle_id=bundle_id, quiet=quiet, timeout=timeout,
            drop_extensions=drop_extensions)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(
        description="Re-sign an .ipa with your own development identity.")
    ap.add_argument("mode", choices=("check", "sign"))
    ap.add_argument("app", help=".ipa (or .app bundle) to re-sign")
    ap.add_argument("--p12", help="signing identity (PKCS#12)")
    passwords = ap.add_mutually_exclusive_group()
    passwords.add_argument(
        "--p12password", dest="password", default="",
        help="password for the p12 (legacy; visible in this process argv)")
    passwords.add_argument(
        "--p12password-stdin", action="store_true",
        help="read one p12 password line from stdin")
    ap.add_argument("--profile", help="provisioning profile (.mobileprovision)")
    ap.add_argument("--out", help="output .ipa (default: alongside the input)")
    ap.add_argument("--bundle-id", help="rewrite the bundle id while signing")
    ap.add_argument("--drop-extensions", action="store_true",
                    help="strip PlugIns before signing (zsign -E). A free-tier "
                         "profile covers one app id, and every extension "
                         "carries its own, so iOS rejects them unless removed")
    args = ap.parse_args()
    if args.p12password_stdin:
        args.password = sys.stdin.readline().rstrip("\r\n")
    try:
        sys.stdout.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")
    except Exception:
        pass

    print("\n  resign  -  %s" % os.path.basename(args.app))
    print("  " + "=" * 52)

    blockers, warnings = preflight(args.app, args.p12, args.password,
                                   args.profile)

    head("verdict")
    for w in warnings:
        say(INFO, "warning", w)
    if blockers:
        for b in blockers:
            say(BAD, "blocker", b)
        print("\n  Not signing - the result would be rejected by the device.\n")
        return 1
    say(OK, "preflight", "everything needed is present and verified")

    if args.mode == "check":
        print("\n  Run again with `sign` to produce the signed .ipa.\n")
        return 0

    out = args.out or os.path.join(
        os.path.dirname(os.path.abspath(args.app)),
        os.path.splitext(os.path.basename(args.app))[0] + "-resigned.ipa")

    head("signing")
    say(INFO, "output", out)
    ok, text = resign(args.app, args.p12, args.password, args.profile, out,
                      bundle_id=args.bundle_id,
                      drop_extensions=args.drop_extensions)
    tail = [l for l in text.splitlines() if l.strip()][-6:]
    for line in tail:
        say(INFO, "zsign", line[:70])
    if not ok:
        say(BAD, "zsign", "failed")
        print()
        return 1

    head("verifying the result")
    problems, info = verify_output(out)
    for k, v in info.items():
        say(OK if v is not False else BAD, k, v)
    if problems:
        for p in problems:
            say(BAD, "problem", p)
        print("\n  zsign exited cleanly but the output is not usable.\n")
        return 1

    say(OK, "verified", "signed, provisioned, and openable")
    print("\n  install it with:")
    print("    python sideload.py install %s --p12 %s --profile %s\n"
          % (out, args.p12, args.profile))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
