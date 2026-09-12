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

    import datetime
    import json
    import plistlib
    import sideload as S

    check("pinned Apple Root CA present and matches the published digest",
          S._trusted_root() is not None,
          "certs/AppleRootCA.pem missing or its digest does not match")

    # Supplying a pinned CAfile is not enough by itself: OpenSSL otherwise
    # also consults its configured default stores. Keep the verification trust
    # set to exactly the checked-in, digest-pinned Apple root.
    cms_seen = {}
    real_cms_run, real_openssl = S.subprocess.run, S._openssl_executable

    class CMSResult:
        returncode = 1
        stdout = b""
        stderr = b"Verification failure"

    try:
        S._openssl_executable = lambda: "openssl"

        def fake_cms_run(argv, **kwargs):
            cms_seen["argv"] = argv
            return CMSResult()

        S.subprocess.run = fake_cms_run
        S._verify_profile_cms(S.APPLE_ROOT_PEM)
    finally:
        S.subprocess.run, S._openssl_executable = real_cms_run, real_openssl
    cms_argv = cms_seen.get("argv") or []
    check("CMS verification disables every ambient OpenSSL trust store",
          all(flag in cms_argv for flag in
              ("-CAfile", "-no-CAfile", "-no-CApath", "-no-CAstore")),
          repr(cms_argv))

    class DeviceResult:
        returncode = 0
        stderr = ""

        def __init__(self, payload):
            self.stdout = json.dumps({"deviceList": payload})

    real_device_run, real_target = S.subprocess.run, S.TARGET_UDID
    try:
        S.TARGET_UDID = None
        S.subprocess.run = lambda *a, **k: DeviceResult("not-a-list")
        malformed_device = S.device_udid()
        S.subprocess.run = lambda *a, **k: DeviceResult(["one", "two"])
        ambiguous_device = S.device_udid()
        S.TARGET_UDID = "two"
        selected_device = S.device_udid()
    finally:
        S.subprocess.run, S.TARGET_UDID = real_device_run, real_target
    check("device discovery rejects malformed or ambiguous JSON",
          malformed_device is None and ambiguous_device is None
          and selected_device == "two",
          "malformed=%r ambiguous=%r selected=%r"
          % (malformed_device, ambiguous_device, selected_device))

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

        # Positive control: temporarily pin that synthetic CA. This proves the
        # exact OpenSSL flags work together and that success returns the CMS-
        # authenticated bytes rather than the raw envelope.
        import hashlib
        import ssl
        fake_root = fake + ".root.pem"
        root_der = ssl.PEM_cert_to_DER_cert(
            open(fake_root, encoding="ascii").read())
        saved_root, saved_digest = S.APPLE_ROOT_PEM, S.APPLE_ROOT_SHA256
        try:
            S.APPLE_ROOT_PEM = fake_root
            S.APPLE_ROOT_SHA256 = hashlib.sha256(root_der).hexdigest().upper()
            trusted, trusted_detail, trusted_payload = S._verify_profile_cms(fake)
        finally:
            S.APPLE_ROOT_PEM, S.APPLE_ROOT_SHA256 = saved_root, saved_digest
        trusted_plist = S._profile_plist(trusted_payload or b"")
        check("the pinned-only CMS path has a working positive control",
              trusted is True
              and trusted_plist
              and trusted_plist.get("Name") == "forged",
              "verdict=%r detail=%r" % (trusted, trusted_detail))
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
        if fake:
            fatal, _, _ = S.check_profile(fake, None)
            check("UNKNOWN profile verification is a blocker",
                  any("could not verify the profile signature" in p
                      for p in fatal), str(fatal))
    finally:
        S.APPLE_ROOT_PEM = saved

    fixture = _matching_identity_fixture()
    if not fixture:
        SKIP.append("signing identity readiness")
        print("  [SKIP] signing identity readiness - cryptography unavailable")
        return

    _, p12, profile, signer, udid = fixture
    real_verify_cms = S._verify_profile_cms
    signed_payloads = {profile: open(profile, "rb").read()}
    try:
        # The fixture is a plist wrapped in test bytes. Its CMS verification
        # is isolated here; the forged-CMS test above exercises the real trust
        # check, while these assertions exercise identity/profile matching.
        S._verify_profile_cms = lambda path: (
            True, "signature verifies against Apple Root CA",
            signed_payloads[path])

        # Simulate a file whose raw bytes disagree with what CMS authenticated.
        # All security decisions must use the latter.
        open(profile, "wb").write(plistlib.dumps({
            "TeamName": "Unsigned Decoy",
            "TeamIdentifier": ["WRONGTEAM1"],
            "ProvisionedDevices": ["DIFFERENT-UDID"],
            "ExpirationDate": datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=30),
            "Entitlements": {
                "application-identifier": "WRONGTEAM1.com.example.decoy"},
        }))
        fatal, _, info = S.check_profile(profile, udid)
        check("unsigned raw plist cannot replace the CMS-verified payload",
              not fatal
              and info.get("appid") == "ABCDE12345.com.example.filament",
              "fatal=%r info=%r" % (fatal, info))

        ready = S.signing_readiness(
            p12, "filament", profile, udid=udid, signer_path=signer)
        check("matching usable identity reports real signing support",
              ready["supported"] is True
              and ready["performs_signing"] is True
              and ready["bypasses_code_signing"] is False,
              repr(ready))
        check("matching p12/profile/device is ready", ready["ready"] is True,
              repr(ready.get("blockers")))

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12
        key, cert, _ = pkcs12.load_key_and_certificates(open(p12, "rb").read(), b"filament")
        pem_key, pem_cert = p12 + ".key.pem", p12 + ".cert.pem"
        open(pem_key, "wb").write(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        open(pem_cert, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
        pem_ready = S.signing_readiness(None, None, profile, udid=udid,
                                        signer_path=signer, pem_key=pem_key, pem_cert=pem_cert)
        check("an existing PEM identity is validated without an Apple login",
              pem_ready["ready"] is True and pem_ready["evidence"]["identity_format"] == "pem",
              repr(pem_ready.get("blockers")))

        saved_run = S._run
        seen_pem_check = {}
        try:
            def fake_pem_check(args, work=None):
                seen_pem_check.update({"install": args.install, "p12": args.p12,
                                       "exists": os.path.isfile(args.p12)})
                return 0
            S._run = fake_pem_check
            args = type("Args", (), {"install": False, "pem_key": pem_key,
                                      "pem_cert": pem_cert, "profile": profile})()
            S.run(args)
        finally:
            S._run = saved_run
        check("PEM check stays preflight-only and removes its temporary identity",
              seen_pem_check.get("install") is False and seen_pem_check.get("exists") is True
              and not os.path.exists(seen_pem_check["p12"]), repr(seen_pem_check))

        other = _matching_identity_fixture()
        signed_payloads[other[2]] = open(other[2], "rb").read()
        mismatched = S.signing_readiness(
            other[1], "filament", profile, udid=udid, signer_path=signer)
        check("a p12 not listed in DeveloperCertificates is blocked",
              mismatched["ready"] is False
              and any("not authorized" in p
                      for p in mismatched["blockers"]),
              repr(mismatched.get("blockers")))
        args = type("Args", (), {
            "app": None, "p12": other[1], "p12password": "filament",
            "profile": profile, "install": False})()
        check("the real install preflight stops an unmatched identity",
              S.run(args) == 1)

        wrong_device = S.signing_readiness(
            p12, "filament", profile, udid="DIFFERENT-UDID",
            signer_path=signer)
        check("a device absent from the profile is blocked",
              wrong_device["ready"] is False
              and any("not in the profile" in p
                      for p in wrong_device["blockers"]),
              repr(wrong_device.get("blockers")))

        expired_cert = _matching_identity_fixture(cert_days=-1)
        signed_payloads[expired_cert[2]] = open(expired_cert[2], "rb").read()
        expired = S.signing_readiness(
            expired_cert[1], "filament", expired_cert[2], udid=udid,
            signer_path=signer)
        check("an expired signing certificate is blocked",
              expired["ready"] is False
              and any("certificate expired" in p
                      for p in expired["blockers"]),
              repr(expired.get("blockers")))

        expired_profile = _matching_identity_fixture(profile_days=-1)
        signed_payloads[expired_profile[2]] = open(
            expired_profile[2], "rb").read()
        expired = S.signing_readiness(
            expired_profile[1], "filament", expired_profile[2], udid=udid,
            signer_path=signer)
        check("an expired provisioning profile is blocked",
              expired["ready"] is False
              and any("profile expired" in p
                      for p in expired["blockers"]),
              repr(expired.get("blockers")))

        # Bind the successful preflight to the exact bytes go-ios receives.
        # The source files are deliberately replaced inside the fake signer,
        # after preflight but before it would read them.
        install_fixture = _matching_identity_fixture()
        install_tmp, install_p12, install_profile, install_signer, _ = (
            install_fixture)
        install_payload = open(install_profile, "rb").read()
        install_app = os.path.join(install_tmp, "Demo.ipa")
        import zipfile
        with zipfile.ZipFile(install_app, "w") as archive:
            archive.writestr("Payload/Demo.app/Info.plist", b"test")
        original_profile = open(install_profile, "rb").read()
        install_seen = {}

        class InstallResult:
            returncode = 0
            stdout = ""
            stderr = ""

        saved_install = (S._verify_profile_cms, S.device_udid,
                         S.subprocess.run, S.IOS)
        try:
            S._verify_profile_cms = lambda path: (
                True, "signature verifies against Apple Root CA",
                install_payload)
            S.device_udid = lambda: udid
            S.IOS = install_signer

            def fake_install(argv, **kwargs):
                install_seen["argv"] = list(argv)
                install_seen["env"] = kwargs.get("env") or {}
                app_arg = next(v.split("=", 1)[1] for v in argv
                               if v.startswith("--path="))
                p12_arg = next(v.split("=", 1)[1] for v in argv
                               if v.startswith("--p12file="))
                profile_arg = next(v.split("=", 1)[1] for v in argv
                                   if v.startswith("--profile="))
                install_seen["paths"] = (app_arg, p12_arg, profile_arg)
                install_seen["paths_existed"] = all(
                    os.path.isfile(path)
                    for path in (app_arg, p12_arg, profile_arg))
                install_seen["profile_bytes"] = open(
                    profile_arg, "rb").read()
                from cryptography.hazmat.primitives.serialization import pkcs12
                key, cert, _ = pkcs12.load_key_and_certificates(
                    open(p12_arg, "rb").read(), None)
                install_seen["passwordless_copy_usable"] = bool(key and cert)
                # If go-ios had received any source path, these replacements
                # would invalidate what preflight just approved.
                open(install_app, "wb").write(b"replaced after preflight")
                open(install_p12, "wb").write(b"replaced after preflight")
                open(install_profile, "wb").write(b"replaced after preflight")
                return InstallResult()

            S.subprocess.run = fake_install
            install_args = type("InstallArgs", (), {
                "app": install_app, "p12": install_p12,
                "p12password": "filament", "profile": install_profile,
                "install": True})()
            install_rc = S.run(install_args)
        finally:
            (S._verify_profile_cms, S.device_udid,
             S.subprocess.run, S.IOS) = saved_install

        install_argv = install_seen.get("argv") or []
        check("sign/install uses immutable snapshots after preflight",
              install_rc == 0
              and install_seen.get("paths_existed") is True
              and install_seen.get("profile_bytes") == original_profile
              and "--udid=" + udid in install_argv
              and all(source not in " ".join(install_argv)
                      for source in
                      (install_app, install_p12, install_profile)),
              repr(install_seen))
        check("go-ios receives no p12 password in argv or environment",
              "filament" not in install_argv
              and not any(arg.startswith("--p12password")
                          for arg in install_argv)
              and "FILAMENT_P12_PASSWORD" not in install_seen.get("env", {})
              and "P12_PASSWORD" not in install_seen.get("env", {})
              and install_seen.get("passwordless_copy_usable") is True,
              repr(install_seen))
        check("ephemeral install snapshots are removed on return",
              install_seen.get("paths")
              and not any(os.path.exists(path)
                          for path in install_seen["paths"]),
              repr(install_seen.get("paths")))
    finally:
        S._verify_profile_cms = real_verify_cms


def test_signing_status():
    """The daemon must require both a session and verified identity evidence."""
    import json

    section("signing API - capability is true; readiness fails closed")
    parsed, parse_error = F._parse_sideload_request({
        "app": " app.ipa ", "p12password": "  spaced secret  ",
        "install": False})
    _, bad_install = F._parse_sideload_request({"install": "false"})
    _, bad_shape = F._parse_sideload_request(["not", "an", "object"])
    check("sideload request JSON is typed and preserves password bytes",
          parse_error is None
          and parsed["app"] == "app.ipa"
          and parsed["p12password"] == "  spaced secret  "
          and bad_install == "install must be a boolean"
          and bool(bad_shape),
          "parsed=%r install=%r shape=%r"
          % (parsed, bad_install, bad_shape))
    tmp = tempfile.mkdtemp(prefix="filament-status-")
    paths = [os.path.join(tmp, name) for name in
             ("appleid.py", "python.exe", "sideload.py", "identity.p12",
              "identity.mobileprovision")]
    for path in paths:
        open(path, "wb").write(b"test")
    appleid, python, sideload, p12, profile = paths
    session = os.path.join(tmp, "session.json")

    saved = (F.APPLEID_PY, F.SIGNING_PYTHON, F.SIDELOAD_PY,
             F.SIGNING_P12, F.SIGNING_PROFILE, F.SIGNING_P12_PASSWORD,
             F.SIGNING_SESSION, F.subprocess.run)
    mode = {"session": True, "identity": True}
    seen = {}

    def write_session(kind=True):
        value = {
            "token": "real-session-shaped-token",
            "adsid": "1234567890",
            "apple_id": "owner@example.test",
            "expires": time.time() + 3600,
        }
        if kind is False:
            value["expires"] = time.time() - 1
        elif kind == "no-expiry":
            value.pop("expires")
        elif kind == "bad-type":
            value["expires"] = True
        with open(session, "w", encoding="utf-8") as fh:
            json.dump(value, fh)

    class Result:
        def __init__(self, returncode, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(argv, **kwargs):
        if argv[1] == appleid:
            # Human-readable output is deliberately always optimistic. The
            # daemon must derive readiness from typed session data instead.
            return Result(0, "  token            valid  until tomorrow\n")
        seen["argv"] = list(argv)
        seen["env"] = kwargs.get("env") or {}
        seen["input"] = kwargs.get("input")
        identity_ready = mode["identity"] is True
        payload = {
            "supported": True,
            "performs_signing": True,
            "bypasses_code_signing": False,
            "readiness_scope": "local_preflight",
            "ready": identity_ready,
            "blockers": ([] if identity_ready else
                         ["p12 certificate is not authorized by this profile"]),
            "warnings": [],
            "evidence": {"certificate_profile_match": identity_ready},
            "reason": (None if identity_ready else
                       "p12 certificate is not authorized by this profile"),
        }
        if mode["identity"] == "bad-types":
            payload["ready"] = "true"
            payload["blockers"] = "forged"
            payload["warnings"] = {"looks": "safe"}
        return Result(0 if identity_ready else 1, json.dumps(payload))

    try:
        F.APPLEID_PY, F.SIGNING_PYTHON, F.SIDELOAD_PY = (
            appleid, python, sideload)
        F.SIGNING_P12, F.SIGNING_PROFILE = p12, profile
        F.SIGNING_P12_PASSWORD = "unit-secret"
        F.SIGNING_SESSION = session
        F.subprocess.run = fake_run

        write_session(True)
        report = F.signing_status()
        check("API exposes supported/performs_signing without claiming bypass",
              report["supported"] is True
              and report["performs_signing"] is True
              and report["bypasses_code_signing"] is False,
              repr(report))
        check("valid session plus validated identity is ready",
              report["ready"] is True, repr(report.get("blockers")))
        check("identity password uses stdin, never argv or child environment",
              "unit-secret" not in seen.get("argv", [])
              and seen.get("input") == "unit-secret\n"
              and "FILAMENT_P12_PASSWORD" not in seen.get("env", {})
              and "P12_PASSWORD" not in seen.get("env", {}), repr(seen))

        sideload_result = F.sideload_check(
            p12=p12, p12password="web-secret")
        check("sideload API also keeps its p12 password out of argv and env",
              sideload_result["ok"] is True
              and "web-secret" not in seen.get("argv", [])
              and "--p12password-stdin" in seen.get("argv", [])
              and seen.get("input") == "web-secret\n"
              and "FILAMENT_P12_PASSWORD" not in seen.get("env", {})
              and "P12_PASSWORD" not in seen.get("env", {}), repr(seen))

        write_session(False)
        report = F.signing_status()
        check("an existing verified identity can sign without an Apple session",
              report["ready"] is True
              and report["identity_creation_ready"] is False,
              repr(report))

        write_session("no-expiry")
        report = F.signing_status()
        check("a session with no provable expiry cannot create new identities",
              report["ready"] is True
              and report["identity_creation_ready"] is False,
              repr(report))

        write_session("bad-type")
        report = F.signing_status()
        check("boolean or otherwise mistyped session expiry fails closed",
              report["identity_creation_ready"] is False
              and report["session"].get("valid") is False,
              repr(report))

        write_session(True)
        mode["identity"] = "bad-types"
        report = F.signing_status()
        check("malformed identity JSON cannot masquerade as ready",
              report["ready"] is False
              and report["blockers"] == [
                  "identity readiness contract is invalid"],
              repr(report))

        mode["identity"] = False
        report = F.signing_status()
        check("session alone cannot hide an unusable identity",
              report["ready"] is False
              and any("not authorized" in p for p in report["blockers"]),
              repr(report))

        F.SIGNING_PYTHON = os.path.join(tmp, "missing-python.exe")
        report = F.signing_status()
        check("capability flags survive missing runtime prerequisites",
              report["supported"] is True
              and report["performs_signing"] is True
              and report["ready"] is False
              and "signing venv" in report["reason"],
              repr(report))
    finally:
        (F.APPLEID_PY, F.SIGNING_PYTHON, F.SIDELOAD_PY,
         F.SIGNING_P12, F.SIGNING_PROFILE, F.SIGNING_P12_PASSWORD,
         F.SIGNING_SESSION, F.subprocess.run) = saved


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
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
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
    with open(path + ".root.pem", "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    return path


def _matching_identity_fixture(cert_days=30, profile_days=30, password="filament"):
    """Synthetic p12/profile pair for matching logic (not a trust fixture)."""
    try:
        import datetime
        import plistlib
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography.x509.oid import NameOID
    except ImportError:
        return None

    team, udid = "ABCDE12345", "00000000-000000000000000A"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Apple Development: Test"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, team),
    ])
    issuer = x509.Name([
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            "Apple Worldwide Developer Relations Certification Authority"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert_before = (now - datetime.timedelta(hours=1)
                   if cert_days > 0 else now - datetime.timedelta(days=2))
    cert_after = (now + datetime.timedelta(days=cert_days)
                  if cert_days > 0 else now - datetime.timedelta(minutes=1))
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(cert_before)
            .not_valid_after(cert_after)
            .sign(key, hashes.SHA256()))

    tmp = tempfile.mkdtemp(prefix="filament-identity-")
    p12 = os.path.join(tmp, "identity.p12")
    profile = os.path.join(tmp, "identity.mobileprovision")
    signer = os.path.join(tmp, "ios.exe")
    p12_blob = pkcs12.serialize_key_and_certificates(
        b"Filament", key, cert, None,
        serialization.BestAvailableEncryption(password.encode()))
    open(p12, "wb").write(p12_blob)
    profile_blob = plistlib.dumps({
        "TeamName": "Test Team",
        "TeamIdentifier": [team],
        "DeveloperCertificates": [
            cert.public_bytes(serialization.Encoding.DER)],
        "ProvisionedDevices": [udid],
        "ExpirationDate": now + datetime.timedelta(days=profile_days),
        "Entitlements": {
            "application-identifier": team + ".com.example.filament"},
    })
    open(profile, "wb").write(b"test wrapper\n" + profile_blob + b"\nend")
    open(signer, "wb").write(b"test executable marker")
    return tmp, p12, profile, signer, udid


def test_resign_secret_handling():
    """zsign must only see immutable inputs and a disposable identity."""
    import zipfile
    import resign as R

    section("resign - secret-free immutable zsign invocation")
    fixture = _matching_identity_fixture(password="resign-secret")
    if not fixture:
        SKIP.append("resign secret handling")
        print("  [SKIP] resign secret handling - cryptography unavailable")
        return
    tmp, p12, profile, _signer, _udid = fixture
    app = os.path.join(tmp, "source.ipa")
    with zipfile.ZipFile(app, "w") as archive:
        archive.writestr("Payload/App.app/Info.plist", b"test")
    out = os.path.join(tmp, "out.ipa")
    original_app = open(app, "rb").read()
    original_profile = open(profile, "rb").read()
    seen = {}

    class P:
        returncode = 0
        stdout = "ok"
        stderr = ""

    real_run, real_validate = R.subprocess.run, R._validate_staged
    old_env = {name: os.environ.get(name) for name in
               ("FILAMENT_P12_PASSWORD", "P12_PASSWORD")}
    try:
        R._validate_staged = lambda *args: []
        os.environ["FILAMENT_P12_PASSWORD"] = "ambient-resign-secret"
        os.environ["P12_PASSWORD"] = "ambient-generic-secret"

        def fake_run(argv, **kwargs):
            seen["argv"] = list(argv)
            seen["env"] = kwargs.get("env") or {}
            staged_p12 = argv[argv.index("-k") + 1]
            staged_profile = argv[argv.index("-m") + 1]
            staged_app = argv[-1]
            seen["paths"] = (staged_p12, staged_profile, staged_app)
            seen["profile"] = open(staged_profile, "rb").read()
            seen["app"] = open(staged_app, "rb").read()
            from cryptography.hazmat.primitives.serialization import pkcs12
            key, cert, _ = pkcs12.load_key_and_certificates(
                open(staged_p12, "rb").read(), None)
            seen["passwordless"] = bool(key and cert)
            open(app, "wb").write(b"replaced after snapshot")
            open(p12, "wb").write(b"replaced after snapshot")
            open(profile, "wb").write(b"replaced after snapshot")
            return P()

        R.subprocess.run = fake_run
        ok, detail = R.resign(
            app, p12, "resign-secret", profile, out)
    finally:
        R.subprocess.run, R._validate_staged = real_run, real_validate
        for name, value in old_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    argv = seen.get("argv") or []
    check("zsign receives no p12 password in argv or environment",
          ok and "resign-secret" not in argv and "-p" not in argv
          and "FILAMENT_P12_PASSWORD" not in seen.get("env", {})
          and "P12_PASSWORD" not in seen.get("env", {})
          and seen.get("passwordless") is True,
          "detail=%r seen=%r" % (detail, seen))
    check("zsign receives immutable copies and they are cleaned afterward",
          seen.get("profile") == original_profile
          and seen.get("app") == original_app
          and seen.get("paths")
          and all(source not in argv for source in (app, p12, profile))
          and not any(os.path.exists(path) for path in seen["paths"]),
          repr(seen))


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


# ---------------------------------------------------------------- rcsign

def test_rcsign():
    """rcsign.py exists because of LiveContainer+SideStore on 2026-09-03: zsign
    sealed SideStoreApp.framework before re-signing the frameworks nested inside
    it (0xe8008017), go-ios skipped that framework (0xe800801c), and rcodesign
    only got it right once the entitlements path was RELATIVE - it read the
    "C:" of an absolute Windows path as a scope selector and attached the
    entitlements to nothing (0xe8008015)."""
    import plistlib
    import zipfile
    import rcsign as RC
    section("rcsign - prepare/repack on a fake ipa")
    tmp = tempfile.mkdtemp(prefix="rcs-t-")
    ipa = os.path.join(tmp, "in.ipa")
    with zipfile.ZipFile(ipa, "w") as z:
        z.writestr("Payload/Demo.app/Info.plist", plistlib.dumps(
            {"CFBundleIdentifier": "com.example.demo", "CFBundleExecutable": "Demo"}))
        z.writestr("Payload/Demo.app/Demo", b"\xcf\xfa\xed\xfe fake")
        z.writestr("Payload/Demo.app/PlugIns/X.appex/Info.plist", plistlib.dumps(
            {"CFBundleIdentifier": "com.example.demo.X"}))
    prof = os.path.join(tmp, "p.mobileprovision")
    body = plistlib.dumps({
        "TeamIdentifier": ["TEAM1"],
        "Entitlements": {"application-identifier": "TEAM1.com.example.demo.TEAM1",
                         "get-task-allow": True}})
    open(prof, "wb").write(b"\x30\x82CMSjunk" + body + b"\x00trailer")

    work = os.path.join(tmp, "w1"); os.makedirs(work)
    try:
        RC.prepare(work, ipa, prof)
        check("mismatched app id without --bundle-id is refused", False)
    except ValueError as exc:
        check("mismatched app id without --bundle-id is refused",
              "--bundle-id" in str(exc), str(exc))

    work = os.path.join(tmp, "w2"); os.makedirs(work)
    app, ent_rel = RC.prepare(work, ipa, prof, bundle_id="com.example.demo.TEAM1")
    check("PlugIns are stripped", not os.path.isdir(os.path.join(app, "PlugIns")))
    info = plistlib.load(open(os.path.join(app, "Info.plist"), "rb"))
    check("bundle id is rewritten", info["CFBundleIdentifier"] == "com.example.demo.TEAM1")
    check("profile is embedded", os.path.exists(os.path.join(app, "embedded.mobileprovision")))
    ent = plistlib.load(open(os.path.join(work, ent_rel), "rb"))
    check("entitlements come from the profile and the path is relative",
          ent.get("application-identifier") == "TEAM1.com.example.demo.TEAM1"
          and not os.path.isabs(ent_rel) and ":" not in ent_rel)

    out = os.path.join(tmp, "out.ipa")
    RC.repack(work, out)
    names = zipfile.ZipFile(out).namelist()
    check("repack keeps Payload/ layout, profile in, extensions out",
          all(n.startswith("Payload/") for n in names)
          and "Payload/Demo.app/embedded.mobileprovision" in names
          and not any("/PlugIns/" in n for n in names))

    section("rcsign - rcodesign invocation")
    seen = {}
    key_pem = os.path.join(tmp, "k.pem")
    cert_pem = os.path.join(tmp, "c.pem")
    open(key_pem, "wb").write(b"test key")
    open(cert_pem, "wb").write(b"test cert")
    class P:
        returncode = 0; stdout = "ok"; stderr = ""
    def fake_run(argv, **kw):
        seen["argv"] = argv; seen["cwd"] = kw.get("cwd"); return P()
    real = RC.subprocess.run
    RC.subprocess.run = fake_run
    try:
        ok, _ = RC.sign(work, app, ent_rel,
                        pems=[key_pem, cert_pem],
                        rcodesign="rcodesign.exe")
    finally:
        RC.subprocess.run = real
    argv = seen.get("argv") or []
    i = argv.index("--entitlements-xml-file") if "--entitlements-xml-file" in argv else -1
    check("entitlements are passed by a relative path from the work dir",
          ok and i > 0 and argv[i + 1] == ent_rel and seen.get("cwd") == work
          and not os.path.isabs(argv[-1]))
    pem_args = [argv[i + 1] for i, value in enumerate(argv[:-1])
                if value == "--pem-file"]
    check("rcodesign gets disposable PEM copies, not mutable source paths",
          pem_args and all(path not in (key_pem, cert_pem) for path in pem_args)
          and not any(os.path.exists(path) for path in pem_args),
          repr(argv))

    fixture = _matching_identity_fixture(password="rc-secret")
    if not fixture:
        SKIP.append("rcodesign p12 secret handling")
        print("  [SKIP] rcodesign p12 secret handling - cryptography unavailable")
        return
    _, p12, _profile, _signer, _udid = fixture
    p12_seen = {}
    old_env = {name: os.environ.get(name) for name in
               ("FILAMENT_P12_PASSWORD", "P12_PASSWORD")}

    def fake_p12_run(argv, **kwargs):
        p12_seen["argv"] = list(argv)
        p12_seen["env"] = kwargs.get("env") or {}
        staged_p12 = argv[argv.index("--p12-file") + 1]
        p12_seen["path"] = staged_p12
        from cryptography.hazmat.primitives.serialization import pkcs12
        key, cert, _ = pkcs12.load_key_and_certificates(
            open(staged_p12, "rb").read(), None)
        p12_seen["passwordless"] = bool(key and cert)
        open(p12, "wb").write(b"replaced after staging")
        return P()

    try:
        os.environ["FILAMENT_P12_PASSWORD"] = "ambient-rc-secret"
        os.environ["P12_PASSWORD"] = "ambient-generic-secret"
        RC.subprocess.run = fake_p12_run
        p12_ok, p12_detail = RC.sign(
            work, app, ent_rel, p12=p12, p12password="rc-secret",
            rcodesign="rcodesign.exe")
    finally:
        RC.subprocess.run = real
        for name, value in old_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    p12_argv = p12_seen.get("argv") or []
    check("rcodesign receives no p12 password in argv or environment",
          p12_ok and "rc-secret" not in p12_argv
          and "--p12-password" not in p12_argv
          and "FILAMENT_P12_PASSWORD" not in p12_seen.get("env", {})
          and "P12_PASSWORD" not in p12_seen.get("env", {})
          and p12_seen.get("passwordless") is True,
          "detail=%r seen=%r" % (p12_detail, p12_seen))
    check("rcodesign's disposable p12 is removed after the child returns",
          p12_seen.get("path") and not os.path.exists(p12_seen["path"]),
          repr(p12_seen))


def main(portable=False):
    print("\n  Filament %sregression tests"
          % ("portable " if portable else ""))
    print("  " + "=" * 52)
    tests = (
        (test_stream, test_auth, test_argv, test_ios_write,
         test_image_mounted, test_sideload_signing, test_signing_status,
         test_touch_coordinates, test_resign_secret_handling, test_rcsign)
        if portable else
        (test_stream, test_bringup, test_auth, test_argv,
         test_ios_write, test_image_mounted,
         test_sideload_signing, test_signing_status,
         test_touch_coordinates,
         test_touch_report, test_touch_gate_detection,
         test_resign_secret_handling, test_resign,
         test_rcsign))
    for fn in tests:
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
    unknown = [arg for arg in sys.argv[1:] if arg != "--portable"]
    if unknown:
        print("unknown argument: %s" % unknown[0], file=sys.stderr)
        sys.exit(2)
    sys.exit(main(portable="--portable" in sys.argv[1:]))
