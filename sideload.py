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
import csv
import datetime
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

# Sibling tools live next to this directory (<tools>/filament, <tools>/go-ios,
# <tools>/zsign), so their location is derived rather than hardcoded. Every
# path below can still be overridden by its environment variable.
_TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

IOS = os.environ.get("FILAMENT_IOS_EXE", os.path.join(_TOOLS, "go-ios", "ios.exe"))
TUNNEL_PORT = os.environ.get("FILAMENT_TUNNEL_PORT", "60105")
TARGET_UDID = os.environ.get("FILAMENT_UDID") or None
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
_security_run = subprocess.run
# Consume the supported environment fallback once. It must not be inherited
# by go-ios (or any other child) after we have read it.
DEFAULT_P12_PASSWORD = os.environ.pop("FILAMENT_P12_PASSWORD", None)
os.environ.pop("P12_PASSWORD", None)

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
                if not isinstance(lst, list):
                    return None
                devices = [item for item in lst
                           if isinstance(item, str) and item]
                if len(devices) != len(lst):
                    return None
                if TARGET_UDID:
                    return TARGET_UDID if TARGET_UDID in devices else None
                # Selecting the first of several devices makes the identity
                # check ambiguous. Require an explicit FILAMENT_UDID instead.
                return devices[0] if len(devices) == 1 else None
    except Exception:
        pass
    return None


def _profile_plist(d):
    """Parse a plist only from the bytes supplied by the caller."""
    i, j = d.find(b"<?xml"), d.rfind(b"</plist>")
    if i < 0 or j < 0:
        return None
    try:
        return plistlib.loads(d[i:j + 8])
    except Exception:
        return None


def read_profile(path):
    """Parse a .mobileprovision's raw CMS bytes for diagnostics only."""
    try:
        return _profile_plist(open(path, "rb").read())
    except OSError:
        return None


def _profile_team_id(profile):
    """Return Apple's first TeamIdentifier, rejecting malformed shapes."""
    teams = profile.get("TeamIdentifier")
    if (isinstance(teams, (list, tuple)) and teams
            and isinstance(teams[0], str) and teams[0]):
        return teams[0]
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


def _openssl_executable():
    """Find the CMS verifier, including Git for Windows' bundled OpenSSL."""
    override = os.environ.get("FILAMENT_OPENSSL_EXE")
    candidates = [override, shutil.which("openssl")]
    if os.name == "nt":
        for root in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                     os.environ.get("ProgramFiles(x86)"),
                     os.path.join(os.environ.get("LOCALAPPDATA", ""),
                                  "Programs")):
            if root:
                candidates.append(os.path.join(
                    root, "Git", "usr", "bin", "openssl.exe"))
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def _verify_profile_cms(path):
    """Verify a profile and return only the exact CMS-signed payload bytes.

    -> (verdict, detail, payload) where verdict is True / False / None.
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
        return (None, "pinned Apple Root CA missing or altered at %s"
                % APPLE_ROOT_PEM, None)
    exe = _openssl_executable()
    if not exe:
        return None, "openssl not found; cannot verify the CMS signature", None
    try:
        p = subprocess.run(
            [exe, "smime", "-verify", "-inform", "DER", "-in", path,
             "-CAfile", root, "-no-CAfile", "-no-CApath", "-no-CAstore",
             "-purpose", "any"],
            capture_output=True, timeout=60,
            creationflags=NO_WINDOW)
    except Exception as exc:
        return None, str(exc), None
    err = (p.stderr or b"").decode("utf-8", "replace").strip()
    if p.returncode == 0:
        return True, "signature verifies against Apple Root CA", p.stdout
    for line in err.splitlines():
        if "Verify error:" in line:
            return False, line.split("Verify error:")[-1].strip(), None
    detail = err.splitlines()[-1][:200] if err else "verification failed"
    return False, detail, None


def verify_profile_signature(path):
    """Cryptographically verify the profile's CMS signature.

    The verified payload is intentionally kept internal so callers cannot
    accidentally validate the envelope and then parse different, unsigned
    bytes from the raw file.
    """
    verdict, detail, _ = _verify_profile_cms(path)
    return verdict, detail


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
    diagnostic_pl = read_profile(path)

    # Parse identity, entitlements and device authorization from the exact
    # content OpenSSL authenticated. Parsing the raw file after verification
    # would let appended, unsigned XML influence the verdict.
    verdict, detail, verified_payload = _verify_profile_cms(path)
    pl = (_profile_plist(verified_payload) if verdict is True
          and verified_payload is not None else diagnostic_pl)
    if pl is None:
        fatal.append("profile unreadable or not a .mobileprovision")
        if verdict is None:
            fatal.append("could not verify the profile signature: %s" % detail)
        elif verdict is False:
            fatal.append("the profile's signature does NOT verify against "
                         "Apple Root CA (%s)" % detail)
        else:
            fatal.append("verified CMS payload contains no readable plist")
        return fatal, warn, info

    team_id = _profile_team_id(pl)
    info["values_source"] = ("cms_verified" if verdict is True
                             else "unverified_raw_diagnostic")
    info["team"] = "%s (%s)" % (pl.get("TeamName"), team_id)
    entitlements = pl.get("Entitlements")
    if not isinstance(entitlements, dict):
        entitlements = {}
    info["appid"] = entitlements.get("application-identifier")
    if not team_id:
        fatal.append("profile has no TeamIdentifier")
    if not isinstance(info["appid"], str) or not info["appid"]:
        fatal.append("profile has no application-identifier entitlement")
    elif team_id and not info["appid"].startswith(team_id + "."):
        fatal.append("profile application-identifier does not match its team")

    # The profile-authenticity question is whether the CMS signature verifies
    # against Apple's root. This is deliberately NOT inferred from
    # TeamIdentifier - a made-up id like TEAMID1234 is genuinely 10 uppercase
    # alphanumerics and passes any format test.
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
        # Unknown is a blocker. Signing or installing after the verifier could
        # not run is a fail-open path: it turns "we do not know" into the much
        # stronger claim that iOS will accept the profile.
        fatal.append("could not verify the profile signature: %s" % detail)
        info["signature"] = "UNVERIFIED - %s" % detail

    exp = pl.get("ExpirationDate")
    if isinstance(exp, datetime.datetime):
        now = (datetime.datetime.now(exp.tzinfo) if exp.tzinfo
               else datetime.datetime.now())
        info["expires"] = exp.strftime("%Y-%m-%d")
        if exp < now:
            fatal.append("profile expired on %s" % exp.date())
        elif (exp - now).days < 14:
            warn.append("profile expires in %d days" % (exp - now).days)
    else:
        fatal.append("profile has no valid ExpirationDate")

    devs = pl.get("ProvisionedDevices")
    if devs is None:
        if pl.get("ProvisionsAllDevices") is True:
            info["devices"] = "universal (ProvisionsAllDevices)"
        else:
            info["devices"] = "none"
            fatal.append("profile does not authorize direct device installation")
    elif not isinstance(devs, (list, tuple)):
        info["devices"] = "malformed"
        fatal.append("profile has a malformed ProvisionedDevices field")
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
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.serialization import pkcs12
    except ImportError:
        return (["cannot validate the p12 because `cryptography` is not installed"],
                {"validated": False})
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
        fatal = []
        if key is None:
            fatal.append("p12 contains no private key")
        if cert is None:
            fatal.append("p12 contains no signing certificate")
            return fatal, info

        info["subject"] = cert.subject.rfc4514_string()
        info["issuer"] = cert.issuer.rfc4514_string()
        info["fingerprint"] = cert.fingerprint(hashes.SHA256()).hex()
        before = (getattr(cert, "not_valid_before_utc", None)
                  or cert.not_valid_before.replace(tzinfo=datetime.timezone.utc))
        after = (getattr(cert, "not_valid_after_utc", None)
                 or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc))
        now = datetime.datetime.now(datetime.timezone.utc)
        info["expires"] = after.strftime("%Y-%m-%d")
        if now < before:
            fatal.append("signing certificate is not valid until %s" % before.date())
        if now >= after:
            fatal.append("signing certificate expired on %s" % after.date())
        if "Apple" not in info["issuer"]:
            fatal.append(
                "signing certificate was not issued by Apple (issuer: %s). "
                "iOS only accepts Apple-issued signing identities."
                % info["issuer"])
        if key is not None:
            try:
                key_pub = key.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)
                cert_pub = cert.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)
                if key_pub != cert_pub:
                    fatal.append("p12 private key does not match its certificate")
            except Exception as exc:
                fatal.append("could not compare the p12 key and certificate: %s" % exc)
        info["validated"] = not fatal
        return fatal, info
    return (["p12 could not be opened - wrong password, or the file is not a "
             "valid PKCS#12 archive"], {})


def check_identity_match(p12_path, password, profile_path):
    """Prove that a p12 is the identity authorized by the Apple-signed profile.

    Checking an Apple-looking issuer string is not enough. The certificate in
    the p12 must occur byte-for-byte in DeveloperCertificates inside the CMS
    profile, and its team OU must match the profile's TeamIdentifier.
    """
    fatal, info = [], {}
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography.x509.oid import NameOID
    except ImportError:
        return ["cannot match identity because `cryptography` is not installed"], info

    try:
        raw = open(p12_path, "rb").read()
    except OSError as exc:
        return ["p12 unreadable: %s" % exc], info
    tried = [password.encode()] if password is not None else [b"", None]
    key = cert = None
    for pw in tried:
        try:
            key, cert, _ = pkcs12.load_key_and_certificates(raw, pw)
            break
        except Exception:
            continue
    if key is None or cert is None:
        return ["cannot match a p12 that has no usable key and certificate"], info

    verdict, detail, verified_payload = _verify_profile_cms(profile_path)
    if verdict is not True:
        return ["cannot match identity because the profile signature could "
                "not be verified: %s" % detail], info
    profile = _profile_plist(verified_payload or b"")
    if profile is None:
        return ["verified CMS payload contains no readable plist"], info
    authorized = profile.get("DeveloperCertificates") or []
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    matched = any(bytes(item) == cert_der for item in authorized
                  if isinstance(item, (bytes, bytearray)))
    info["certificate_profile_match"] = matched
    info["certificate_fingerprint"] = cert.fingerprint(hashes.SHA256()).hex()
    if not matched:
        fatal.append("p12 certificate is not authorized by this provisioning profile")

    team_id = _profile_team_id(profile)
    ous = [a.value for a in cert.subject.get_attributes_for_oid(
        NameOID.ORGANIZATIONAL_UNIT_NAME)]
    info["team_id"] = team_id
    info["certificate_teams"] = ous
    if not team_id:
        fatal.append("profile has no TeamIdentifier")
    elif team_id not in ous:
        fatal.append("p12 certificate team does not match the provisioning profile")
    return fatal, info


def signing_readiness(p12_path, password, profile_path, udid=None,
                      signer_path=None, pem_key=None, pem_cert=None):
    """Machine-readable, fail-closed readiness for Filament's real signer."""
    if not p12_path and pem_key and pem_cert:
        work = _private_tempdir()
        try:
            temporary_p12 = _pem_p12_copy(pem_key, pem_cert, work)
            report = signing_readiness(temporary_p12, None, profile_path,
                                       udid=udid, signer_path=signer_path)
            report["evidence"].update({"p12": None, "identity_format": "pem",
                                       "pem_key": os.path.abspath(pem_key),
                                       "pem_cert": os.path.abspath(pem_cert)})
            return report
        except Exception as exc:
            report = signing_readiness(None, None, profile_path, udid=udid,
                                       signer_path=signer_path)
            report["blockers"].append("PEM identity could not be validated: %s" % exc)
            return report
        finally:
            shutil.rmtree(work, ignore_errors=True)
    signer = signer_path or IOS
    resolved_signer = (signer if os.path.isfile(signer)
                       else shutil.which(signer))
    openssl = _openssl_executable()
    report = {
        "supported": True,
        "performs_signing": True,
        "bypasses_code_signing": False,
        "readiness_scope": "local_preflight",
        "ready": False,
        "blockers": [],
        "warnings": [],
        "evidence": {
            "signer": os.path.abspath(resolved_signer) if resolved_signer else signer,
            "signer_present": bool(resolved_signer),
            "openssl": os.path.abspath(openssl) if openssl else None,
            "openssl_present": bool(openssl),
            "device_udid": udid,
            "p12": os.path.abspath(p12_path) if p12_path else None,
            "profile": os.path.abspath(profile_path) if profile_path else None,
        },
    }
    blockers, warnings = report["blockers"], report["warnings"]
    if not resolved_signer:
        blockers.append("go-ios signer is not installed at %s" % signer)
    if not udid:
        blockers.append("no attached device was identified")
    p12_present = bool(p12_path and os.path.isfile(p12_path))
    profile_present = bool(profile_path and os.path.isfile(profile_path))
    if not p12_present:
        blockers.append("signing p12 is missing")
    if not profile_present:
        blockers.append("provisioning profile is missing")

    if p12_present:
        p12_fatal, p12_info = check_p12(p12_path, password)
        blockers.extend(p12_fatal)
        report["evidence"]["identity"] = p12_info
    if profile_present:
        profile_fatal, profile_warn, profile_info = check_profile(
            profile_path, udid)
        blockers.extend(profile_fatal)
        warnings.extend(profile_warn)
        report["evidence"]["provisioning"] = profile_info
    if p12_present and profile_present:
        match_fatal, match_info = check_identity_match(
            p12_path, password, profile_path)
        blockers.extend(match_fatal)
        report["evidence"]["match"] = match_info

    report["ready"] = not blockers
    report["reason"] = None if report["ready"] else blockers[0]
    return report


def print_signing_readiness(args):
    """Print the readiness contract without leaking the p12 password."""
    report = signing_readiness(
        args.p12, args.p12password, args.profile,
        udid=device_udid(), signer_path=IOS,
        pem_key=args.pem_key, pem_cert=args.pem_cert)
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print("\n  Signing readiness\n  " + "=" * 52)
        say(INFO, "supported", report["supported"])
        say(INFO, "performs signing", report["performs_signing"])
        say(INFO, "bypasses code signing", report["bypasses_code_signing"])
        for warning in report["warnings"]:
            say(WARN, "warning", warning)
        for blocker in report["blockers"]:
            say(BAD, "blocker", blocker)
        say(OK if report["ready"] else BAD, "ready", report["ready"])
    return 0 if report["ready"] else 1


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


def _private_tempdir(dir=None):
    """Create a best-effort owner-only directory for signing material."""
    path = tempfile.mkdtemp(prefix="filament-sideload-", dir=dir)
    try:
        if os.name == "nt":
            # chmod cannot restrict a Windows DACL on older Python versions.
            # Protect the directory before any unencrypted identity is written.
            child_env = os.environ.copy()
            child_env.pop("FILAMENT_P12_PASSWORD", None)
            child_env.pop("P12_PASSWORD", None)
            user = _security_run(
                ["whoami.exe", "/user", "/fo", "csv", "/nh"],
                capture_output=True, text=True, timeout=15,
                creationflags=NO_WINDOW, env=child_env, check=True)
            sid = next(csv.reader(user.stdout.splitlines()))[1]
            if not re.fullmatch(r"S-1-(?:\d+-)*\d+", sid):
                raise RuntimeError("could not identify the Windows account for private staging")
            _security_run(
                ["icacls.exe", path, "/inheritance:r", "/grant:r",
                 "*" + sid + ":(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
                capture_output=True, text=True, timeout=15,
                creationflags=NO_WINDOW, env=child_env, check=True)
        else:
            os.chmod(path, 0o700)
    except Exception:
        shutil.rmtree(path, ignore_errors=True)
        raise
    return path


def _snapshot_install_args(args, work):
    """Copy every install input once; validate and use those exact copies.

    Without this snapshot an app, profile, or p12 could change after preflight
    and before go-ios reopened it, making the successful check irrelevant.
    """
    snapshot = argparse.Namespace(
        app=getattr(args, "app", None),
        p12=getattr(args, "p12", None),
        p12password=getattr(args, "p12password", None),
        profile=getattr(args, "profile", None),
        install=True,
    )
    for attr, filename in (("p12", "identity.p12"),
                           ("profile", "identity.mobileprovision")):
        source = getattr(snapshot, attr)
        if source and os.path.isfile(source):
            target = os.path.join(work, filename)
            shutil.copyfile(source, target)
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
            setattr(snapshot, attr, target)
    if not snapshot.p12 and getattr(args, "pem_key", None) and getattr(args, "pem_cert", None):
        snapshot.p12 = _pem_p12_copy(args.pem_key, args.pem_cert, work)
        snapshot.p12password = None
    if snapshot.app and os.path.exists(snapshot.app):
        if os.path.isdir(snapshot.app):
            target = os.path.join(work, "Payload.app")
            shutil.copytree(snapshot.app, target)
        else:
            suffix = os.path.splitext(snapshot.app)[1] or ".ipa"
            target = os.path.join(work, "Payload" + suffix)
            shutil.copyfile(snapshot.app, target)
        snapshot.app = target
    return snapshot


def _pem_p12_copy(key_path, cert_path, work):
    """Adapt an existing PEM identity without requiring an Apple login or new certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12

    with open(key_path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    with open(cert_path, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    encoded = pkcs12.serialize_key_and_certificates(
        b"Filament PEM identity", key, cert, None, serialization.NoEncryption())
    fd, target = tempfile.mkstemp(prefix="pem-", suffix=".p12", dir=work)
    with os.fdopen(fd, "wb") as fh:
        fh.write(encoded)
    return target


def _passwordless_p12_copy(path, password, work):
    """Re-encode a validated identity for go-ios without a password argv.

    go-ios currently accepts its p12 password only as a command-line flag.
    Passing it there exposes the long-lived secret to process inspection, so
    give go-ios a short-lived, owner-only, unencrypted copy instead. The copy
    lives in the same private directory as the immutable install snapshot and
    is removed by `run` in a finally block.
    """
    from cryptography.hazmat.primitives.serialization import (
        NoEncryption, pkcs12)

    raw = open(path, "rb").read()
    passwords = [password.encode()] if password is not None else [b"", None]
    key = cert = cas = None
    for candidate in passwords:
        try:
            key, cert, cas = pkcs12.load_key_and_certificates(raw, candidate)
            break
        except Exception:
            continue
    if key is None or cert is None:
        raise ValueError("p12 has no usable key and certificate")
    encoded = pkcs12.serialize_key_and_certificates(
        b"Filament ephemeral signing identity", key, cert, cas,
        NoEncryption())
    fd, target = tempfile.mkstemp(prefix="signer-", suffix=".p12", dir=work)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(encoded)
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(target)
        except OSError:
            pass
        raise
    return target


def _run(args, work=None):
    print("\n  Sideload preflight")
    print("  " + "=" * 52)

    udid = device_udid()
    head("device")
    say(OK if udid else BAD, "attached", udid or "no device on usbmux")

    fatal, warn = [], []

    if bool(args.p12) != bool(args.profile):
        fatal.append("signing requires both a p12 and provisioning profile")

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

    if args.p12 and args.profile:
        head("identity / profile match")
        f, i = check_identity_match(
            args.p12, args.p12password, args.profile)
        fatal += f
        for k, v in i.items():
            say(INFO, k, v)
        if not f:
            say(OK, "match", "profile authorizes this exact certificate")

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
        try:
            signing_p12 = _passwordless_p12_copy(
                args.p12, args.p12password, work)
        except Exception as exc:
            say(BAD, "signing identity", "could not stage it safely: %s" % exc)
            return 1
        cmd = [IOS, "sign", "app", "--path=" + args.app,
               "--p12file=" + signing_p12, "--profile=" + args.profile,
               "--install", "--tunnel-info-port=" + TUNNEL_PORT,
               "--udid=" + udid]
        say(INFO, "mode", "sign then install")
    else:
        cmd = [IOS, "install", "--path=" + args.app,
               "--tunnel-info-port=" + TUNNEL_PORT, "--udid=" + udid]
        say(INFO, "mode", "install as-is (already signed)")

    child_env = os.environ.copy()
    child_env.pop("FILAMENT_P12_PASSWORD", None)
    child_env.pop("P12_PASSWORD", None)
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=900,
                       creationflags=NO_WINDOW, env=child_env)
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


def run(args):
    """Preflight, and for installs bind checks to immutable input copies."""
    if not getattr(args, "install", False) and not getattr(args, "pem_key", None):
        return _run(args)
    work = _private_tempdir()
    try:
        staged = _snapshot_install_args(args, work)
        staged.install = bool(getattr(args, "install", False))
        return _run(staged, work=work)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(
        description="Preflight, sign and install an iOS app - naming the real "
                    "blocker before uploading anything.")
    ap.add_argument("mode", choices=("check", "install", "identity-status"))
    ap.add_argument("app", nargs="?", help=".ipa or .app to install")
    ap.add_argument("--p12", help="signing identity (PKCS#12)")
    ap.add_argument("--pem-key", help="existing unencrypted PEM private key (instead of --p12)")
    ap.add_argument("--pem-cert", help="matching PEM certificate (instead of --p12)")
    ap.add_argument(
        "--p12password-stdin", action="store_true",
        help="read one p12 password line from stdin (keeps it out of argv)")
    ap.add_argument("--profile", help="provisioning profile (.mobileprovision)")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable output (identity-status)")
    args = ap.parse_args()
    if bool(args.pem_key) != bool(args.pem_cert):
        ap.error("--pem-key and --pem-cert must be supplied together")
    if args.p12 and args.pem_key:
        ap.error("choose either a p12 or a PEM identity")
    args.p12password = DEFAULT_P12_PASSWORD
    if args.p12password_stdin:
        args.p12password = sys.stdin.readline().rstrip("\r\n")
    args.install = args.mode == "install"
    if args.mode == "identity-status":
        return print_signing_readiness(args)
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
