#!/usr/bin/env python3
"""Regression tests for Filament.

Every test here corresponds to a defect that was actually present in this code
and was found by running it, not by reading it. The point is that none of them
can come back silently.

    C:\\Python314\\python.exe test_filament.py

Runs without a device attached. Anything that would need one is skipped and
says so, rather than passing vacuously.
"""
import io
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import filament as F

PASS, FAIL, SKIP = [], [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print("  [%s] %s%s" % ("PASS" if cond else "FAIL", name,
                           ("  - " + detail) if detail and not cond else ""))


def section(t):
    print("\n  %s\n  %s" % (t, "-" * max(len(t), 46)))


class FakeProc:
    """Stands in for a go-ios child. Alive until terminated."""

    def __init__(self, alive=True, rc=0):
        self.pid = 4242
        self._alive = alive
        self._rc = rc
        self.killed = False

    def poll(self):
        return None if self._alive else self._rc

    def terminate(self):
        self._alive = False
        self.killed = True

    def wait(self, timeout=None):
        self._alive = False
        return self._rc


# ---------------------------------------------------------------- stream

def test_stream():
    section("ScreenStream - the refcount can never leak")

    # The original defect: the readiness-timeout path returned without
    # decrementing, so viewers stayed above zero forever - and since release()
    # only kills the child at zero, go-ios kept broadcasting the screen on
    # 0.0.0.0 for the life of the process.
    s = F.ScreenStream()
    s.READY_TIMEOUT = 0.3
    s._healthy = lambda timeout=1.0: False
    s._spawn = lambda: (FakeProc(alive=True), None)
    ok, _ = s.acquire()
    check("timeout path releases the viewer", (not ok) and s.viewers == 0,
          "ok=%s viewers=%s" % (ok, s.viewers))

    s2 = F.ScreenStream()
    s2._healthy = lambda timeout=1.0: False
    s2._spawn = lambda: (None, "boom")
    ok2, _ = s2.acquire()
    check("spawn failure releases the viewer", (not ok2) and s2.viewers == 0,
          "viewers=%s" % s2.viewers)

    s3 = F.ScreenStream()
    s3.READY_TIMEOUT = 2.0
    s3._healthy = lambda timeout=1.0: False
    s3._spawn = lambda: (FakeProc(alive=False, rc=1), None)
    ok3, _ = s3.acquire()
    check("dead child releases the viewer", (not ok3) and s3.viewers == 0,
          "viewers=%s" % s3.viewers)

    s4 = F.ScreenStream()
    proc = FakeProc()
    s4._healthy = lambda timeout=1.0: True
    s4._spawn = lambda: (proc, None)
    ok4, _ = s4.acquire()
    check("acquire succeeds when healthy", ok4 and s4.viewers == 1,
          "ok=%s viewers=%s" % (ok4, s4.viewers))
    s4.release()
    check("release returns to zero", s4.viewers == 0, "viewers=%s" % s4.viewers)

    # An adopted stream belongs to someone else and must survive our shutdown.
    def boom():
        raise AssertionError("must not spawn when one is already serving")

    s5 = F.ScreenStream()
    s5._healthy = lambda timeout=1.0: True
    s5._spawn = boom
    ok5, _ = s5.acquire()
    check("adopts a stream already serving",
          ok5 and s5.adopted and s5.proc is None,
          "ok=%s adopted=%s" % (ok5, s5.adopted))

    s6 = F.ScreenStream()
    p6 = FakeProc()
    s6.proc, s6.viewers, s6.adopted = p6, 1, False
    s6.shutdown()
    check("shutdown kills an owned stream", p6.killed and s6.viewers == 0)

    p7 = FakeProc()
    s7 = F.ScreenStream()
    s7.proc, s7.viewers, s7.adopted = p7, 1, True
    s7.shutdown()
    check("shutdown spares an adopted stream", not p7.killed)

    # lan_exposed must never claim safety while something is serving.
    s8 = F.ScreenStream()
    s8.proc = FakeProc()
    st8 = s8.status()
    check("lan_exposed true while serving", st8["lan_exposed"] is True, str(st8))

    s9 = F.ScreenStream()
    s9._healthy = lambda timeout=1.0: False
    st9 = s9.status()
    check("lan_exposed false when nothing serves", st9["lan_exposed"] is False,
          str(st9))


# ---------------------------------------------------------------- bringup

def test_bringup():
    section("BringUp - honest ladder, backoff that actually arms")

    b = F.BringUp()
    check("ladder starts 'wait', not an unevidenced red 'shut'",
          all(s["status"] == "wait" for s in b.snapshot()["steps"]))

    b2 = F.BringUp()
    b2._set("device", "open", "x")
    b2._below("device", "waiting for a device")
    steps = {s["id"]: s["status"] for s in b2.snapshot()["steps"]}
    check("_below marks downstream 'wait', not 'shut'",
          all(steps[k] == "wait"
              for k in ("tunnel", "devmode", "image", "capture")), str(steps))

    # The invariant that encodes contract 3 in code rather than in a comment.
    def monotonic(snap):
        seen_bad = False
        for s in snap["steps"]:
            if s["status"] != "open":
                seen_bad = True
            elif seen_bad:
                return False
        return True

    check("no rung is 'open' below a non-open rung", monotonic(b2.snapshot()))

    saved_ddi, saved_egress = F.DDI_PATH, F.MOUNT_ALLOW_EGRESS
    try:
        # Cooldown must arm on EVERY failure path. It previously did not arm
        # on the early-return guards, so a bad image retried at tick rate.
        F.DDI_PATH = r"C:\definitely\not\here"
        b3 = F.BringUp()
        ok, _ = b3._mount()
        check("missing-image failure arms the cooldown",
              (not ok) and b3._mount_cooldown > time.time())

        first = b3._mount_backoff
        b3._mount_cooldown = 0
        b3._mount()
        check("backoff escalates", b3._mount_backoff > first,
              "%s -> %s" % (first, b3._mount_backoff))

        for _ in range(6):
            b3._mount_cooldown = 0
            b3._mount()
        check("backoff is capped at 60s", b3._mount_backoff <= 60.0,
              str(b3._mount_backoff))

        # A cooled-down mount must not touch the device at all.
        F.DDI_PATH = saved_ddi
        t0 = time.time()
        ok2, _ = b3._mount()
        check("cooldown blocks without spawning a process",
              (not ok2) and (time.time() - t0) < 0.5 and b3.mounts == 0)

        F.MOUNT_ALLOW_EGRESS = False
        b4 = F.BringUp()
        ok3, err3 = b4._mount()
        check("FILAMENT_MOUNT_EGRESS=0 refuses to mount",
              (not ok3) and "forbids" in (err3 or ""), str(err3))
    finally:
        F.DDI_PATH, F.MOUNT_ALLOW_EGRESS = saved_ddi, saved_egress


# ---------------------------------------------------------------- auth

def test_auth():
    section("token auth")

    H = F.Handler.__new__(F.Handler)
    H.headers = {}
    check("correct token accepts", H._authed({"t": [F.TOKEN]}))
    check("wrong token rejects", not H._authed({"t": ["nope"]}))
    check("absent token rejects", not H._authed({}))
    # These raised TypeError and killed the request with no response at all.
    check("accented token rejects instead of raising",
          not H._authed({"t": ["\u00e9\u00e9\u00e9"]}))
    check("emoji token rejects instead of raising",
          not H._authed({"t": ["\U0001f600"]}))
    check("empty token rejects", not H._authed({"t": [""]}))

    class Hdr(dict):
        def get(self, k, d=None):
            return dict.get(self, k, d)

    H2 = F.Handler.__new__(F.Handler)
    H2.headers = Hdr({"X-Filament-Token": F.TOKEN})
    check("header token accepts", H2._authed({}))


# ---------------------------------------------------------------- argv

def test_argv():
    section("go-ios argv pinning")

    argv = F.DEV._ios_argv("devmode", "get")
    check("tunnel-info-port pinned on every call",
          any(a.startswith("--tunnel-info-port=") for a in argv), str(argv))

    # Assert WHERE argv is built, not how many times: a count threshold would
    # happily absorb a new bypass as long as an old one was removed.
    import ast
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "filament.py")
    src = io.open(path, encoding="utf-8").read()
    tree = ast.parse(src)

    # Enclosing def/class for every line, innermost wins.
    owner = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for ln in range(node.lineno, (node.end_lineno or node.lineno) + 1):
                owner[ln] = node.name

    # _ios_argv builds it because that IS the pinning helper. TunnelAgent is
    # deliberately multi-device (no --udid) and pins the port itself.
    # ScreenStream pins both explicitly.
    #   _ios_argv       - IS the pinning helper
    #   adopt_or_spawn  - TunnelAgent; deliberately multi-device (no --udid),
    #                     pins the info port itself
    #   _spawn          - ScreenStream; pins both explicitly
    ALLOWED = {"_ios_argv", "adopt_or_spawn", "_spawn"}
    offenders = []
    for i, line in enumerate(src.splitlines(), 1):
        if "[IOS_EXE," in line and owner.get(i) not in ALLOWED:
            offenders.append("%s:%d (%s)" % ("filament.py", i, owner.get(i)))
    check("IOS_EXE argv built only in the pinning helper and the two "
          "long-lived children", not offenders, "; ".join(offenders))


# ---------------------------------------------------------------- ios_write

def test_ios_write():
    section("read vs write command discrimination")

    real = F.DEV._run
    try:
        # go-ios prints nothing for enable/disable/toggle and exits 0. Judging
        # that by "did a payload parse" reported every success as a failure.
        F.DEV._run = lambda argv, timeout=45: (0, "", "")
        ok, err = F.DEV.ios_write("zoom", "toggle")
        check("exit 0 with no stdout is SUCCESS for a write",
              ok and err is None, "ok=%s err=%r" % (ok, err))

        warn = '{"time":"t","level":"WARN","msg":"go-ios agent is not running"}'
        errl = '{"time":"t","level":"ERROR","err":"device is locked"}'
        F.DEV._run = lambda argv, timeout=45: (1, "", warn + "\n" + errl)
        ok2, err2 = F.DEV.ios_write("zoom", "toggle")
        check("failure reports the ERROR line, not the WARN banner",
              (not ok2) and err2 == "device is locked", repr(err2))
    finally:
        F.DEV._run = real


# ---------------------------------------------------------------- mounted

def test_image_mounted():
    section("image_mounted parses go-ios log lines")

    real = F.DEV._run
    try:
        # `ios image list` reports mounted images as INFO log lines, not as a
        # JSON payload. Reading it as a payload said "not mounted" forever and
        # made BringUp re-mount on every tick.
        sig = ('{"time":"t","level":"INFO","msg":"image signature",'
               '"signature":"2808"}')
        F.DEV._run = lambda argv, timeout=60: (0, "", sig)
        check("signature line means mounted", F.DEV.image_mounted() is True)

        F.DEV._run = lambda argv, timeout=60: (0, "", '{"level":"INFO","msg":"x"}')
        check("no signature line means not mounted",
              F.DEV.image_mounted() is False)

        F.DEV._run = lambda argv, timeout=60: (1, "", "")
        check("non-zero exit fails closed", F.DEV.image_mounted() is False)
    finally:
        F.DEV._run = real


# ---------------------------------------------------------------- sideload

def test_sideload_signing():
    section("sideload - real CMS verification, not name inspection")

    import sideload as S

    check("pinned Apple Root CA present and matches the published digest",
          S._trusted_root() is not None,
          "certs/AppleRootCA.pem missing or its digest does not match")

    # A profile whose CMS signature does not chain to Apple Root CA must be a
    # BLOCKER. The earlier check read certs[0] and compared subject to issuer,
    # which could both accuse a genuine Apple profile and clear a forgery that
    # merely embedded Apple's real certificate beside its own signature.
    # Built here rather than read from disk. This used to point at a file left
    # over in a temp directory, so it skipped silently the moment that file was
    # cleaned up - a test that quietly stops testing is worse than no test.
    fake = _self_signed_profile()
    if fake:
        verdict, detail = S.verify_profile_signature(fake)
        check("self-signed profile FAILS verification", verdict is False,
              "verdict=%r detail=%r" % (verdict, detail))
        fatal, warn, info = S.check_profile(fake, None)
        check("unverifiable profile is a blocker, not a pass", bool(fatal),
              str(fatal))
    else:
        SKIP.append("self-signed profile rejection")
        print("  [SKIP] self-signed profile rejection  - sample not on disk")

    # A missing or swapped trust anchor must degrade to UNKNOWN, never to
    # "valid" - failing open here would turn every forgery into a pass.
    saved = S.APPLE_ROOT_PEM
    try:
        S.APPLE_ROOT_PEM = os.path.join("C:" + os.sep, "nope", "root.pem")
        verdict, _ = S.verify_profile_signature(saved)
        check("missing trust anchor yields UNKNOWN, never True",
              verdict is None, "verdict=%r" % (verdict,))
    finally:
        S.APPLE_ROOT_PEM = saved


def test_touch_coordinates():
    """Normalising a coordinate is the one place a silent wrap would hurt.

    The wire format masks X/Y with 0xFFFF, so an off-screen value does not
    error - it lands somewhere plausible on the far side of the screen. That
    is the worst kind of bug: the tap happens, something responds, and the
    flow fails three steps later for no visible reason.
    """
    import touch as T

    section("touch - coordinate normalisation")

    info = {"pixel_width": 1206, "pixel_height": 2622, "scale": 3,
            "point_width": 402, "point_height": 874}

    pt, err = T.to_norm(0.5, 0.5, "percent")
    check("percent 0.5 maps to mid-scale", pt == (32768, 32768) and not err,
          "got %s %s" % (pt, err))
    pt, err = T.to_norm(0, 0, "percent")
    check("percent 0 maps to 0", pt == (0, 0) and not err)
    pt, err = T.to_norm(1, 1, "percent")
    check("percent 1 maps to the maximum", pt == (65535, 65535) and not err)

    pt, err = T.to_norm(201, 437, "point", info)
    check("a point at the screen centre maps to mid-scale",
          pt is not None and abs(pt[0] - 32768) < 200
          and abs(pt[1] - 32768) < 200, "got %s" % (pt,))

    pt, err = T.to_norm(603, 1311, "pixel", info)
    check("a pixel at the screen centre maps to the same place",
          pt is not None and abs(pt[0] - 32768) < 200
          and abs(pt[1] - 32768) < 200, "got %s" % (pt,))

    # The whole point of the exercise.
    for x, y, units in ((1.5, 0.5, "percent"), (-0.1, 0.5, "percent"),
                        (99999, 10, "norm"), (5000, 100, "point")):
        pt, err = T.to_norm(x, y, units, info)
        check("off-screen %s (%s,%s) is refused" % (units, x, y),
              pt is None and bool(err), "it returned %s" % (pt,))

    pt, err = T.to_norm(10, 10, "point", None)
    check("point units without display geometry is an error, not a guess",
          pt is None and "percent" in (err or ""))

    pt, err = T.to_norm(1, 1, "furlongs", info)
    check("an unknown unit is refused", pt is None and bool(err))


def test_touch_report():
    """The 58-byte mainTouchscreen report, byte for byte.

    These offsets came from sniffing a real session, not from a spec. If a
    library update shifts them, every tap silently lands in the wrong place,
    so they are pinned against the documented layout.
    """
    section("touch - HID report framing")
    try:
        from pymobiledevice3.remote.core_device.hid_service import (
            build_touchscreen_report, TOUCHSCREEN_STATE_CONTACT,
            TOUCHSCREEN_STATE_RELEASE, DIGITIZER_SURFACE_MAIN_TOUCHSCREEN)
    except Exception as exc:
        SKIP.append("touch report")
        print("  [skip] hid_service unavailable: %s" % exc)
        return

    r = build_touchscreen_report(TOUCHSCREEN_STATE_CONTACT, 0x1234, 0x5678,
                                 timestamp=0)
    check("report is 58 bytes", len(r) == 58, "got %d" % len(r))
    check("report id is 0x09", r[0] == 0x09)
    check("carries the 0x01 0x05 constants", r[1:3] == bytes([0x01, 0x05]))
    check("contact state is 0xC2", r[3] == 0xC2)
    check("X is little-endian at bytes 4-5", r[4:6] == bytes([0x34, 0x12]))
    check("Y is little-endian at bytes 6-7", r[6:8] == bytes([0x78, 0x56]))

    rel = build_touchscreen_report(TOUCHSCREEN_STATE_RELEASE, 1, 2, timestamp=0)
    check("release state is 0x02", rel[3] == 0x02)
    check("main touchscreen surface is 257",
          DIGITIZER_SURFACE_MAIN_TOUCHSCREEN == 257)

    a = build_touchscreen_report(TOUCHSCREEN_STATE_CONTACT, 5, 5, timestamp=1)
    b = build_touchscreen_report(TOUCHSCREEN_STATE_CONTACT, 5, 5, timestamp=2)
    check("the timestamp field actually varies", a != b)


def test_touch_gate_detection():
    """A missing HID service must be named, not raised from three frames deep."""
    import touch as T

    section("touch - tunnel capability detection")

    class FakeRsd:
        def __init__(self, services):
            self.peer_info = {"Services": {s: {} for s in services}}

    absent = T.missing_hid_services(FakeRsd([]))
    check("an untrusted tunnel reports every HID service missing",
          len(absent) == len(T.HID_SERVICES))

    check("a tunnel carrying them reports nothing missing",
          T.missing_hid_services(FakeRsd(T.HID_SERVICES)) == [])

    absent = T.missing_hid_services(
        FakeRsd(["com.apple.coredevice.hid.indigo"]))
    check("a partial tunnel names only what is actually absent",
          "com.apple.coredevice.hid.indigo" not in absent and len(absent) == 2)

    # This wording was wrong twice before it was right: first it claimed the
    # services needed no admin, then that admin would supply them. Both were
    # disproved by testing. What the message must now carry is the evidence
    # and the working alternative, not a theory.
    check("the explanation reports that admin changes nothing",
          "Admin changes\n  nothing" in T.ADMIN_EXPLANATION
          or "Admin changes nothing" in T.ADMIN_EXPLANATION)
    check("the explanation labels its guess as a hypothesis",
          "Hypothesis" in T.ADMIN_EXPLANATION
          and "only that" in T.ADMIN_EXPLANATION)
    check("the explanation points at the route that does work",
          "perform_press" in T.ADMIN_EXPLANATION
          and "appleid.py" in T.ADMIN_EXPLANATION)


def _self_signed_profile():
    """A .mobileprovision signed by nobody Apple has heard of. -> path or None.

    The forgery a real check has to reject: a CMS-wrapped plist that is
    structurally perfect and cryptographically valid, but whose signer chains
    to itself instead of to Apple Root CA.
    """
    try:
        import datetime
        import plistlib
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import pkcs7
        from cryptography.x509.oid import NameOID
    except ImportError:
        return None

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Not Apple"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(days=7))
            .sign(key, hashes.SHA256()))

    payload = plistlib.dumps({
        "Name": "forged", "TeamIdentifier": ["ABCDE12345"],
        "ProvisionedDevices": ["00000000-000000000000000A"],
        "ExpirationDate": now + datetime.timedelta(days=7),
        "Entitlements": {"application-identifier": "ABCDE12345.*"}})
    try:
        blob = (pkcs7.PKCS7SignatureBuilder()
                .set_data(payload)
                .add_signer(cert, key, hashes.SHA256())
                .sign(serialization.Encoding.DER, []))
    except Exception:
        return None

    path = os.path.join(tempfile.mkdtemp(prefix="filament-forged-"),
                        "forged.mobileprovision")
    with open(path, "wb") as fh:
        fh.write(blob)
    return path


def test_resign():
    """Re-signing: the step that turns an unusable .ipa into an installable one.

    These pin the two things that were learned the hard way. First, zsign
    refuses any certificate it cannot chain to Apple's WWDR intermediate -
    discovered by watching it parse a profile, start signing frameworks, and
    only then fail with "Unknown issuer hash". Second, a zero exit code is not
    evidence: the output has to be reopened and checked.
    """
    import zipfile
    import resign as R

    section("resign - certificate issuer preflight")

    check("an Apple WWDR issuer is accepted", R.issuer_is_apple(
        "CN=Apple Worldwide Developer Relations Certification Authority,"
        "OU=G3,O=Apple Inc.,C=US"))
    check("the older Apple Inc. issuer form is accepted",
          R.issuer_is_apple("CN=Apple Inc.,C=US"))
    check("a self-signed test certificate is refused",
          not R.issuer_is_apple(
              "CN=Apple Development: roundtrip test,OU=ABCDE12345,C=US"),
          "a subject that merely says Apple must not pass as an issuer")
    check("some other CA is refused",
          not R.issuer_is_apple("CN=Let's Encrypt R3,O=Let's Encrypt,C=US"))
    check("an empty issuer is refused", not R.issuer_is_apple(""))
    check("the blocker names the fix",
          "appleid.py identity" in R.WRONG_ISSUER
          and "WWDR" in R.WRONG_ISSUER)

    section("resign - output verification")

    tmp = tempfile.mkdtemp(prefix="filament-resign-test-")

    problems, info = R.verify_output(os.path.join(tmp, "nope.ipa"))
    check("a missing output is a problem", bool(problems))

    bare = os.path.join(tmp, "bare.ipa")
    with zipfile.ZipFile(bare, "w") as z:
        z.writestr("Payload/App.app/Info.plist", "x")
    problems, info = R.verify_output(bare)
    check("an unprovisioned output is caught",
          any("embedded.mobileprovision" in p for p in problems),
          "this is the exact defect re-signing exists to fix")
    check("an unsigned output is caught",
          any("_CodeSignature" in p for p in problems))

    good = os.path.join(tmp, "good.ipa")
    with zipfile.ZipFile(good, "w") as z:
        z.writestr("Payload/App.app/Info.plist", "x")
        z.writestr("Payload/App.app/embedded.mobileprovision", "x")
        z.writestr("Payload/App.app/_CodeSignature/CodeResources", "x")
    problems, info = R.verify_output(good)
    check("a provisioned, signed output passes", problems == [],
          "got %s" % problems)
    check("the verifier reports what it found",
          info.get("embedded profile") is True
          and info.get("code signature") is True)

    notzip = os.path.join(tmp, "notzip.ipa")
    with open(notzip, "wb") as fh:
        fh.write(b"this is not a zip")
    problems, info = R.verify_output(notzip)
    check("a corrupt output is caught, not raised", bool(problems))

    section("resign - tooling")
    ver, err = R.zsign_version()
    if err:
        SKIP.append("zsign")
        print("  [skip] zsign not installed: %s" % err)
    else:
        check("zsign is present and runnable", bool(ver))
        check("zsign is the pinned version", ver == R.ZSIGN_VERSION,
              "found %s, pinned %s" % (ver, R.ZSIGN_VERSION))


def main():
    print("\n  Filament regression tests")
    print("  " + "=" * 52)
    for fn in (test_stream, test_bringup, test_auth, test_argv,
               test_ios_write, test_image_mounted,
               test_sideload_signing, test_touch_coordinates,
               test_touch_report, test_touch_gate_detection, test_resign):
        try:
            fn()
        except Exception as exc:
            FAIL.append(fn.__name__)
            print("  [FAIL] %s raised %s: %s"
                  % (fn.__name__, type(exc).__name__, exc))
    print("\n  %d passed, %d failed, %d skipped\n"
          % (len(PASS), len(FAIL), len(SKIP)))
    for f in FAIL:
        print("    failed: %s" % f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
