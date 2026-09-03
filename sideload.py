#!/usr/bin/env python3
"""Sign and install an app on the iPhone - with the preflight done first.

`ios install` on an app that is not signed for this device fails like this,
after uploading the whole payload:

    ApplicationVerificationFailed ... 0xe8008001 (An unknown error has occurred.)

which tells you nothing and costs a minute of your life. Every one of the
common causes is knowable from the files on disk before a byte is sent, so
this checks them first and names the actual problem.

What cannot be worked around
----------------------------
iOS verifies the provisioning profile's signature against Apple's certificate
authority. A profile you generated yourself will always be rejected, however
well-formed it looks - that is cryptography, not configuration, and no tool
gets around it. Valid profiles come from exactly two places:

  * a free Apple ID, via Xcode / AltStore / Sideloadly (7-day certificates)
  * a paid Apple Developer account, $99/yr (1-year certificates); go-ios can
    mint these itself with `ios sign provision appstoreconnect`

  python sideload.py check <app.ipa>                      # preflight only
  python sideload.py check --p12 id.p12 --profile x.mobileprovision
  python sideload.py install <app.ipa> [--p12 ... --profile ...]
"""
import argparse
import datetime
import os
import plistlib
import shutil
import subprocess
import sys
import zipfile

# Sibling tools live next to this directory (<tools>/filament, <tools>/go-ios,
# <tools>/zsign), so their location is derived rather than hardcoded. Every
# path below can still be overridden by its environment variable.
_TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

IOS = os.environ.get("FILAMENT_IOS_EXE", os.path.join(_TOOLS, "go-ios", "ios.exe"))
TUNNEL_PORT = os.environ.get("FILAMENT_TUNNEL_PORT", "60105")
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

OK, BAD, WARN, INFO = "  ok ", "  no ", " warn", "  -  "


def say(mark, label, value=""):
    print("  [%s] %-30s %s" % (mark, label, value), flush=True)


def head(title):
    print("\n  %s\n  %s" % (title, "-" * max(len(title), 44)), flush=True)


def device_udid():
    try:
        p = subprocess.run([IOS, "list"], capture_output=True, text=True,
                           timeout=40, creationflags=NO_WINDOW)
        import json
        for line in ((p.stdout or "") + "\n" + (p.stderr or "")).splitlines():
            try:
                o = json.loads(line.strip())
            except ValueError:
                continue
            if isinstance(o, dict) and "deviceList" in o:
                lst = o["deviceList"]
                return lst[0] if lst else None
    except Exception:
        pass
    return None


def read_profile(path):
    """Parse a .mobileprovision (CMS-wrapped plist) -> dict, or None."""
    try:
        d = open(path, "rb").read()
    except OSError:
        return None
    i, j = d.find(b"<?xml"), d.rfind(b"</plist>")
    if i < 0 or j < 0:
        return None
    try:
        return plistlib.loads(d[i:j + 8])
    except Exception:
        return None


APPLE_ROOT_PEM = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "certs", "AppleRootCA.pem")
# Apple Root CA, as published at
# https://www.apple.com/appleca/AppleIncRootCertificate.cer
APPLE_ROOT_SHA256 = ("B0B1730ECBC7FF4505142C49F1295E6EDA6BCAED7E2C68C5BE91B5A"
                     "11001F024")


def _trusted_root():
    """Path to a pinned Apple Root CA, or None if it is missing or wrong.

    Pinned by digest so a swapped root file cannot silently turn every forged
    profile into a valid one.
    """
    try:
        import hashlib
        import ssl
        pem = open(APPLE_ROOT_PEM, "rb").read().decode()
        der = ssl.PEM_cert_to_DER_cert(pem)
        if hashlib.sha256(der).hexdigest().upper() != APPLE_ROOT_SHA256:
            return None
        return APPLE_ROOT_PEM
    except Exception:
        return None


def verify_profile_signature(path):
    """Cryptographically verify the profile's CMS signature.

    -> (verdict, detail) where verdict is True / False / None.
       True  = the signature verifies against Apple Root CA
       False = it does not (forged, self-signed, or tampered)
       None  = could not check; detail says why

    This is a real verification, not an inspection. An earlier version read
    `certs[0]` out of the CMS blob and compared its subject to its issuer,
    which is wrong twice over: certs[0] is not necessarily the signer, so it
    could accuse a genuine Apple profile, and a forgery that simply embeds
    Apple's real certificate alongside its own signature would sail through.
    Only checking the signature answers the question iOS actually asks.
    """
    root = _trusted_root()
    if root is None:
        return None, ("pinned Apple Root CA missing or altered at %s"
                      % APPLE_ROOT_PEM)
    exe = shutil.which("openssl")
    if not exe:
        return None, "openssl not found; cannot verify the CMS signature"
    try:
        p = subprocess.run(
            [exe, "smime", "-verify", "-inform", "DER", "-in", path,
             "-CAfile", root, "-purpose", "any", "-out", os.devnull],
            capture_output=True, text=True, timeout=60,
            creationflags=NO_WINDOW)
    except Exception as exc:
        return None, str(exc)
    err = (p.stderr or "").strip()
    if p.returncode == 0:
        return True, "signature verifies against Apple Root CA"
    for line in err.splitlines():
        if "Verify error:" in line:
            return False, line.split("Verify error:")[-1].strip()
    return False, (err.splitlines()[-1][:200] if err else "verification failed")


def profile_certs(path):
    """Every certificate embedded in the profile's CMS blob, for display."""
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
        return pkcs7.load_der_pkcs7_certificates(open(path, "rb").read())
    except Exception:
        return []


def check_profile(path, udid):
    """-> (fatal_problems, warnings, info)"""
    fatal, warn, info = [], [], {}
    pl = read_profile(path)
    if pl is None:
        return ["profile unreadable or not a .mobileprovision"], [], {}

    team = pl.get("TeamIdentifier") or []
    team_id = team[0] if team else None
    info["team"] = "%s (%s)" % (pl.get("TeamName"), team_id)
    info["appid"] = (pl.get("Entitlements") or {}).get("application-identifier")

    # The only question that decides whether iOS accepts this: does the CMS
    # signature verify against Apple's root? Note this is deliberately NOT a
    # check on TeamIdentifier - a made-up id like TEAMID1234 is genuinely 10
    # uppercase alphanumerics and passes any format test.
    verdict, detail = verify_profile_signature(path)
    certs = profile_certs(path)
    if certs:
        info["embedded certs"] = "; ".join(
            c.subject.rfc4514_string()[:70] for c in certs[:3])
    if verdict is True:
        info["signature"] = detail
    elif verdict is False:
        fatal.append(
            "the profile's signature does NOT verify against Apple Root CA "
            "(%s). Only Apple can issue a valid provisioning profile; iOS "
            "checks this same signature and will reject the app with "
            "ApplicationVerificationFailed however correct everything else "
            "is." % detail)
    else:
        # Unknown is reported as unknown. Saying "usable" here because a check
        # could not run would be exactly the kind of comfortable lie this tool
        # exists to avoid.
        warn.append("could not verify the signature: %s" % detail)
        info["signature"] = "UNVERIFIED - %s" % detail

    exp = pl.get("ExpirationDate")
    if isinstance(exp, datetime.datetime):
        now = datetime.datetime.now(exp.tzinfo) if exp.tzinfo else datetime.datetime.now()
        info["expires"] = exp.strftime("%Y-%m-%d")
        if exp < now:
            fatal.append("profile expired on %s" % exp.date())
        elif (exp - now).days < 14:
            warn.append("profile expires in %d days" % (exp - now).days)

    devs = pl.get("ProvisionedDevices")
    if devs is None:
        info["devices"] = "universal (ProvisionsAllDevices)"
    else:
        info["devices"] = str(len(devs))
        if udid and udid not in devs:
            fatal.append(
                "this device (%s) is not in the profile's %d provisioned "
                "devices - add it in the developer portal and re-download"
                % (udid, len(devs)))
    return fatal, warn, info


def check_p12(path, password):
    """-> (fatal, info)"""
    try:
        from cryptography.hazmat.primitives.serialization import pkcs12
    except ImportError:
        return [], {"note": "install `cryptography` to validate the p12"}
    try:
        data = open(path, "rb").read()
    except OSError as exc:
        return ["p12 unreadable: %s" % exc], {}

    tried = [password.encode()] if password is not None else [b"", None]
    for pw in tried:
        try:
            key, cert, _ = pkcs12.load_key_and_certificates(data, pw)
        except Exception:
            continue
        info = {}
        if cert is not None:
            info["subject"] = cert.subject.rfc4514_string()
            info["issuer"] = cert.issuer.rfc4514_string()
            na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
            info["expires"] = na.strftime("%Y-%m-%d")
            if "Apple" not in info["issuer"]:
                return ([ "signing certificate was not issued by Apple (issuer: %s). "
                          "iOS only accepts Apple-issued signing identities."
                          % info["issuer"] ], info)
        return [], info
    return (["p12 could not be opened - wrong password, or the file is not a "
             "valid PKCS#12 archive"], {})


def check_app(path, will_sign=False):
    """-> (fatal, info) for an .ipa or .app.

    will_sign: a p12 and profile were supplied, so a missing embedded profile
    is the expected starting state rather than a blocker."""
    fatal, info = [], {}
    if not os.path.exists(path):
        return ["no such file: %s" % path], {}
    if os.path.isdir(path):
        info["kind"] = "app bundle"
        info["signed"] = os.path.isdir(os.path.join(path, "_CodeSignature"))
        info["profile"] = os.path.exists(os.path.join(path, "embedded.mobileprovision"))
        return fatal, info
    try:
        z = zipfile.ZipFile(path)
    except Exception as exc:
        return ["not a readable .ipa: %s" % exc], {}
    names = z.namelist()
    info["kind"] = "ipa"
    info["entries"] = len(names)
    info["signed"] = any("_CodeSignature" in n for n in names)
    info["profile"] = any(n.endswith("embedded.mobileprovision") for n in names)
    if not info["profile"]:
        if will_sign:
            info["profile"] = "none yet - signing will embed one"
        else:
            fatal.append("no embedded.mobileprovision inside - this app is not "
                         "provisioned for any device and must be re-signed")
    return fatal, info


def run(args):
    print("\n  Sideload preflight")
    print("  " + "=" * 52)

    udid = device_udid()
    head("device")
    say(OK if udid else BAD, "attached", udid or "no device on usbmux")

    fatal, warn = [], []

    if args.app:
        head("app")
        f, i = check_app(args.app, will_sign=bool(args.p12 and args.profile))
        fatal += f
        say(INFO, "path", args.app)
        for k, v in i.items():
            say(OK if v is True else (BAD if v is False else INFO), k, v)

    if args.p12:
        head("signing identity")
        f, i = check_p12(args.p12, args.p12password)
        fatal += f
        for k, v in i.items():
            say(INFO, k, v)
        if not f:
            say(OK, "p12", "opens and looks Apple-issued")

    if args.profile:
        head("provisioning profile")
        f, w, i = check_profile(args.profile, udid)
        fatal += f
        warn += w
        for k, v in i.items():
            say(INFO, k, v)
        if not f:
            say(OK if not w else WARN, "profile",
                "signature verified" if not w else "NOT fully verified")

    head("verdict")
    for w in warn:
        say(WARN, "warning", w)
    if fatal:
        for p in fatal:
            say(BAD, "blocker", p)
        print("""
  Not attempting the install - it would fail with
  ApplicationVerificationFailed after uploading the whole payload.

  A provisioning profile has to be issued by Apple. Two ways to get one:
    * free Apple ID  - Xcode, AltStore or Sideloadly; 7-day certificates
    * paid account   - $99/yr, 1-year certificates. go-ios can mint the
                       assets itself:  ios sign provision appstoreconnect
""")
        return 1

    say(OK, "preflight", "nothing blocking")
    if not args.install:
        print("\n  Re-run with `install` to sign and install.\n")
        return 0

    if not udid:
        say(BAD, "install", "no device attached")
        return 1

    head("install")
    if args.p12 and args.profile:
        cmd = [IOS, "sign", "app", "--path=" + args.app,
               "--p12file=" + args.p12, "--profile=" + args.profile,
               "--install", "--tunnel-info-port=" + TUNNEL_PORT]
        if args.p12password is not None:
            cmd.append("--p12password=" + args.p12password)
        say(INFO, "mode", "sign then install")
    else:
        cmd = [IOS, "install", "--path=" + args.app,
               "--tunnel-info-port=" + TUNNEL_PORT]
        say(INFO, "mode", "install as-is (already signed)")

    p = subprocess.run(cmd, capture_output=True, text=True, timeout=900,
                       creationflags=NO_WINDOW)
    blob = ((p.stdout or "") + "\n" + (p.stderr or "")).strip()
    import json as _json
    err = None
    for line in blob.splitlines():
        try:
            o = _json.loads(line.strip())
        except ValueError:
            continue
        if isinstance(o, dict) and o.get("level") == "ERROR":
            err = o.get("err") or o.get("msg")
    if p.returncode == 0 and not err:
        say(OK, "installed", "done")
        return 0
    say(BAD, "failed", (err or blob[-300:]))
    if err and "ApplicationVerificationFailed" in err:
        print("\n  That is iOS refusing the signature. The profile or the\n"
              "  certificate is not Apple-issued, or not valid for this device.\n")
    return 1


def main():
    ap = argparse.ArgumentParser(
        description="Preflight, sign and install an iOS app - naming the real "
                    "blocker before uploading anything.")
    ap.add_argument("mode", choices=("check", "install"))
    ap.add_argument("app", nargs="?", help=".ipa or .app to install")
    ap.add_argument("--p12", help="signing identity (PKCS#12)")
    ap.add_argument("--p12password", help="password for the p12")
    ap.add_argument("--profile", help="provisioning profile (.mobileprovision)")
    args = ap.parse_args()
    args.install = args.mode == "install"
    if args.install and not args.app:
        ap.error("install needs an app path")
    if not (args.app or args.p12 or args.profile):
        ap.error("give an app, a --p12, or a --profile to check")
    try:
        return run(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
