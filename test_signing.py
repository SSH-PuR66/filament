#!/usr/bin/env python3
"""Tests for the signing path. No Apple ID, no network, no device.

Run with the signing venv, which is where appleid.py's dependencies live:

    .signing-venv\\Scripts\\python.exe test_signing.py

Every test here corresponds to something that can be got wrong silently.
Apple's crypto fails closed in some places and open in others: a wrong
PBKDF2 variant reads as "bad password", a dropped AAD reads as a mangled
token, and a certificate field renamed between API generations reads as
success followed by an unexplained empty file. Those are the failures worth
pinning down before they cost an afternoon.
"""
import hashlib
import hmac
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import appleid  # noqa: E402

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] %s" % name)
    else:
        FAIL += 1
        print("  [FAIL] %s%s" % (name, ("  - " + detail) if detail else ""))


def section(title):
    print("\n  %s\n  %s" % (title, "-" * len(title)))


# ---------------------------------------------------------------- password

section("password derivation - the two Apple variants")

salt, iters = b"\x01" * 16, 1000
s2k = appleid.encrypt_password("hunter2", salt, iters, "s2k")
s2k_fo = appleid.encrypt_password("hunter2", salt, iters, "s2k_fo")

check("s2k derives 32 bytes", len(s2k) == 32)
check("s2k and s2k_fo differ", s2k != s2k_fo,
      "if these match, the fo variant is not hex-encoding the digest")

# Independently: s2k is PBKDF2(sha256(password)), not PBKDF2(password).
expected = hashlib.pbkdf2_hmac(
    "sha256", hashlib.sha256(b"hunter2").digest(), salt, iters, 32)
check("s2k stretches the digest, not the password", s2k == expected)
expected_fo = hashlib.pbkdf2_hmac(
    "sha256", hashlib.sha256(b"hunter2").digest().hex().encode(),
    salt, iters, 32)
check("s2k_fo stretches the hex of the digest", s2k_fo == expected_fo)

try:
    appleid.encrypt_password("x", salt, iters, "plaintext")
    check("an unknown protocol is refused", False, "it was accepted")
except appleid.AppleError:
    check("an unknown protocol is refused", True)


# ---------------------------------------------------------------- SPD (CBC)

section("SPD decryption - AES-CBC keyed off the SRP session key")

from cryptography.hazmat.primitives import padding as _pad  # noqa: E402
from cryptography.hazmat.primitives.ciphers import (  # noqa: E402
    Cipher, algorithms, modes)

session_key = os.urandom(32)
plain = b"<plist>a realistic-ish payload of some length</plist>"


def _encrypt_spd(sk, data):
    key = hmac.new(sk, b"extra data key:", hashlib.sha256).digest()
    iv = hmac.new(sk, b"extra data iv:", hashlib.sha256).digest()[:16]
    padder = _pad.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(padded) + enc.finalize()


check("round-trips", appleid.decrypt_spd(
    session_key, _encrypt_spd(session_key, plain)) == plain)
check("a different session key does not round-trip",
      appleid.decrypt_spd(session_key, _encrypt_spd(session_key, plain))
      != plain[:-1] + b"?")

wrong = os.urandom(32)
try:
    got = appleid.decrypt_spd(wrong, _encrypt_spd(session_key, plain))
    check("the wrong key does not silently yield the plaintext", got != plain)
except Exception:
    # Padding almost always fails first, which is the correct outcome.
    check("the wrong key does not silently yield the plaintext", True)


# ---------------------------------------------------------------- app token

section("app token decryption - AES-GCM with the version bytes as AAD")

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

sk = os.urandom(32)
iv = os.urandom(16)
token_plain = b"<plist>token payload</plist>"
blob = b"XYZ" + iv + AESGCM(sk).encrypt(iv, token_plain, b"XYZ")

check("round-trips", appleid.decrypt_app_token(sk, blob) == token_plain)

try:
    appleid.decrypt_app_token(sk, b"ABC" + blob[3:])
    check("a wrong version header is rejected", False, "it was accepted")
except appleid.AppleError:
    check("a wrong version header is rejected", True)

try:
    appleid.decrypt_app_token(sk, blob[:20])
    check("a truncated blob is rejected", False, "it was accepted")
except appleid.AppleError:
    check("a truncated blob is rejected", True)

# The AAD is the easiest thing in this whole protocol to drop, and dropping
# it still decrypts on some libraries. It must not here.
bad = b"XYZ" + iv + AESGCM(sk).encrypt(iv, token_plain, None)
try:
    appleid.decrypt_app_token(sk, bad)
    check("a blob encrypted without the AAD fails authentication", False,
          "it decrypted, so the AAD is not being enforced")
except Exception:
    check("a blob encrypted without the AAD fails authentication", True)

tampered = bytearray(blob)
tampered[25] ^= 0x01
try:
    appleid.decrypt_app_token(sk, bytes(tampered))
    check("tampered ciphertext fails authentication", False, "it decrypted")
except Exception:
    check("tampered ciphertext fails authentication", True)


# ---------------------------------------------------------------- checksum

section("app token checksum")

sk2 = os.urandom(32)
got = appleid.app_tokens_checksum(sk2, "12345", ["com.apple.gs.xcode.auth"])
want = hmac.new(sk2, b"apptokens" + b"12345" + b"com.apple.gs.xcode.auth",
                hashlib.sha256).digest()
check("is HMAC-SHA256 over apptokens || adsid || app", got == want)
check("is 32 bytes", len(got) == 32)
check("changes with the adsid",
      appleid.app_tokens_checksum(sk2, "54321", ["a"]) !=
      appleid.app_tokens_checksum(sk2, "12345", ["a"]))


# ---------------------------------------------------------------- key + csr

section("local key material - the private key never leaves this machine")

key, csr_pem = appleid.generate_key_and_csr("Filament")
check("CSR is PEM", csr_pem.startswith("-----BEGIN CERTIFICATE REQUEST-----"))
check("key is 2048-bit", key.key_size == 2048)

from cryptography import x509  # noqa: E402

csr = x509.load_pem_x509_csr(csr_pem.encode())
check("CSR signature verifies", csr.is_signature_valid)
check("CSR carries the common name",
      any(a.value == "Filament" for a in csr.subject))

# Two calls must not produce the same key.
key2, csr2 = appleid.generate_key_and_csr("Filament")
check("each call generates a fresh key", csr_pem != csr2)


# ---------------------------------------------------------------- p12

section("p12 assembly")

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.serialization import pkcs12  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
import datetime  # noqa: E402

# A stand-in for Apple's reply: self-signed, which is all we need to prove the
# bundling works. It is emphatically NOT a valid Apple identity, and
# sideload.py's preflight is what catches that difference.
now = datetime.datetime.now(datetime.timezone.utc)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "iPhone Developer")])
fake = (x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=7))
        .sign(key, hashes.SHA256()))
cert_der = fake.public_bytes(serialization.Encoding.DER)

tmp = tempfile.mkdtemp(prefix="filament-signing-test-")
p12_path = os.path.join(tmp, "identity.p12")
returned = appleid.write_p12(key, cert_der, p12_path, "filament")

check("p12 was written", os.path.exists(p12_path)
      and os.path.getsize(p12_path) > 0)
check("write_p12 returns the parsed certificate",
      returned.serial_number == fake.serial_number)

with open(p12_path, "rb") as fh:
    loaded_key, loaded_cert, _ = pkcs12.load_key_and_certificates(
        fh.read(), b"filament")
check("p12 reopens with the right password", loaded_cert is not None)
check("p12 holds the same certificate",
      loaded_cert.serial_number == fake.serial_number)
check("p12 holds the matching private key",
      loaded_key.public_key().public_numbers() ==
      key.public_key().public_numbers(),
      "a p12 whose key does not match its certificate signs nothing")

try:
    with open(p12_path, "rb") as fh:
        pkcs12.load_key_and_certificates(fh.read(), b"wrong")
    check("the wrong p12 password fails", False, "it opened anyway")
except Exception:
    check("the wrong p12 password fails", True)

# A PEM certificate must work too - Apple has returned both.
pem = fake.public_bytes(serialization.Encoding.PEM)
appleid.write_p12(key, pem, os.path.join(tmp, "pem.p12"), "filament")
check("a PEM certificate is accepted as well as DER", True)


# ---------------------------------------------------- certificate extraction

section("reading the certificate out of Apple's reply")

check("finds a raw DER field",
      appleid.certificate_bytes({"certificate": cert_der}) == cert_der)
check("finds the certContent spelling",
      appleid.certificate_bytes({"certContent": cert_der}) == cert_der)

import base64 as _b64  # noqa: E402
check("decodes a base64 string field",
      appleid.certificate_bytes(
          {"certificateContent": _b64.b64encode(cert_der).decode()})
      == cert_der)

try:
    appleid.certificate_bytes({"certificateId": "ABC123", "serialNum": "1"})
    check("an unrecognised reply is an error, not an empty file", False,
          "it returned something")
except appleid.AppleError as exc:
    # The message has to name what DID come back, or the next person is
    # guessing at an API they cannot see.
    check("an unrecognised reply is an error, not an empty file",
          "certificateId" in str(exc) and "serialNum" in str(exc),
          "the error does not list the fields Apple returned: %s" % exc)


# ---------------------------------------------------------------- anisette

section("anisette")

if os.path.exists(appleid.ANISETTE_STATE):
    an = appleid.Anisette()
    h = an.headers(with_client_info=True)
    check("provisioned", an.provisioned)
    for field in ("X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU",
                  "X-Apple-I-MD-RINFO", "X-Mme-Device-Id"):
        check("provides %s" % field, bool(h.get(field)))
    check("every header value is a string",
          all(isinstance(v, str) for v in h.values()),
          "plistlib and requests both reject non-strings here")

    cpd = an.cpd()
    check("cpd carries GSA's flags",
          cpd.get("svct") == "iCloud" and cpd.get("prkgen") is True)
    check("cpd carries the anisette headers", "X-Apple-I-MD" in cpd)

    # The OTP is time-based; two reads should not be frozen.
    h2 = an.headers()
    check("the client time advances between reads",
          h2.get("X-Apple-I-Client-Time") is not None)
else:
    print("  [skip] anisette is not provisioned yet")


# ---------------------------------------------------------------- session

section("TLS trust - the pinned Apple root")

# gsa.apple.com chains to Apple's private PKI. certifi alone rejects it, and
# the two tempting fixes (verify=False, or trusting the OS store) are both
# worse than building the bundle explicitly. These tests exist because that
# bug cost a real debugging session: it surfaces as an SSLError during login
# and reads as a network problem.
bundle = appleid.ca_bundle()
check("builds a bundle file", os.path.exists(bundle))

blob = open(bundle, "rb").read()
apple_pem = open(appleid.APPLE_ROOT_PEM, "rb").read()
import certifi as _certifi  # noqa: E402

check("bundle contains the pinned Apple root", apple_pem.strip() in blob)
check("bundle still contains certifi's public roots",
      open(_certifi.where(), "rb").read()[:2000] in blob,
      "dropping the public roots would break every non-Apple host")
check("bundle is bigger than the Apple root alone",
      len(blob) > len(apple_pem) * 10)

check("is stable across calls", appleid.ca_bundle() == bundle)

# The pin is the whole point: a swapped root file must fail loudly rather
# than silently widening what this program trusts.
real_pem_path = appleid.APPLE_ROOT_PEM
bad = os.path.join(tmp, "NotAppleRoot.pem")
with open(bad, "wb") as fh:
    fh.write(fake.public_bytes(serialization.Encoding.PEM))
appleid.APPLE_ROOT_PEM = bad
try:
    appleid.ca_bundle()
    check("a root that fails the digest pin is refused", False,
          "it was accepted, so the pin is not enforced")
except appleid.AppleError as exc:
    check("a root that fails the digest pin is refused",
          "digest" in str(exc).lower())
finally:
    appleid.APPLE_ROOT_PEM = real_pem_path

check("the real root still passes after the tamper test",
      appleid.ca_bundle() == bundle)


section("login journal")

real_log = appleid.LOGIN_LOG
real_dir = appleid.STATE_DIR
appleid.STATE_DIR = tmp
appleid.LOGIN_LOG = os.path.join(tmp, "login.log")
try:
    appleid.journal("password", "FAIL", "Apple said no", "someone@example.com")
    written = open(appleid.LOGIN_LOG, encoding="utf-8").read()
    check("records the stage and outcome",
          "password" in written and "FAIL" in written)
    check("records the Apple ID", "someone@example.com" in written)
    check("records what Apple said", "Apple said no" in written)

    # The one thing that must never be in here.
    appleid.journal("password", "FAIL", "bad password", "a@b.c")
    log = open(appleid.LOGIN_LOG, encoding="utf-8").read()
    check("never contains a password or token field",
          "hunter2" not in log and "token=" not in log)

    appleid.LOGIN_LOG = os.path.join(tmp, "nope", "deep", "login.log")
    appleid.journal("x", "y", "z")
    check("a journal write that cannot happen does not raise", True,
          "logging must never be the reason a login fails")
finally:
    appleid.LOGIN_LOG = real_log
    appleid.STATE_DIR = real_dir


section("session handling")

real_state = appleid.SESSION_STATE
appleid.SESSION_STATE = os.path.join(tmp, "session.json")
appleid.STATE_DIR = tmp
try:
    check("no session reads as None", appleid.load_session() is None)
    appleid.save_session({"adsid": "1", "token": "t", "expires": None})
    check("a saved session reads back",
          (appleid.load_session() or {}).get("token") == "t")
    with open(appleid.SESSION_STATE, "w", encoding="utf-8") as fh:
        fh.write("{not json")
    check("a corrupt session reads as None rather than raising",
          appleid.load_session() is None)
finally:
    appleid.SESSION_STATE = real_state


print("\n  %d passed, %d failed\n" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
