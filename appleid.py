#!/usr/bin/env python3
"""Mint a real development signing identity from a free Apple ID, on Windows.

This closes the one gap Filament had. Reading the screen, launching apps and
capturing frames need no signing identity. Tapping inside an app does, because
perform_press only reaches processes carrying task_for_pid-allow - that is,
development-signed builds. No amount of cleverness in flow.py could change
that, because it is enforced by the OS.

What this does NOT do, and will not: defeat code signing. iOS verifies a
provisioning profile against Apple's certificate authority. That is
cryptography, not configuration. What it does instead is the legitimate thing
Xcode has always done - ask Apple for a genuine certificate using the account's
own Apple ID. A free Apple ID is enough. The certificate it issues lasts 7 days
and covers 3 apps, which makes renewal a feature to own rather than an
afterthought.

The protocol, in order, since Apple documents none of it:

  1. Anisette. Apple will not authenticate a device it cannot identify. The
     identifying headers - X-Apple-I-MD (a one-time password) and
     X-Apple-I-MD-M (a machine ID) - come from Apple's own ADI library.
     The copy shipped on Windows in Apple Application Support
     (CoreADI64.dll) exports only two FairPlay-obfuscated entry points that
     nobody has publicly reversed, so this uses the `anisette` package, which
     drives the Apple Music for Android build of the same Apple library.
     Provisioning happens once and is saved: re-provisioning every run would
     present a brand new machine to Apple every time, which is exactly the
     pattern that earns a 2FA prompt on every login.

  2. GSA / SRP-6a. Apple's "Grand Slam" authentication. Standard SRP with two
     twists: the password fed into SRP is PBKDF2(SHA-256(password)), not the
     password; and the useful half of the response is an AES-CBC blob keyed
     off the SRP session key.

  3. Two-factor. Nearly every Apple ID has it. A code is pushed to the
     account's trusted devices and validated back to GSA, after which the SRP
     login is repeated and succeeds cleanly.

  4. App token. The decrypted SPD blob yields `sk` and `c`. Those, plus an
     HMAC checksum over "apptokens" + adsid + the app name, buy a token scoped
     to com.apple.gs.xcode.auth - the same scope Xcode itself uses.

  5. The developer portal, developerservices2.apple.com, which speaks XML
     plists and wants that token.

Credential handling, stated plainly because it matters:
  - The password is never stored. It is read, used for the SRP exchange, and
    dropped when the process exits.
  - The session token IS stored, because the alternative is re-authenticating
    and re-2FA-ing on every command. Treat .signing/session.json as a
    credential: it authenticates as you to Apple's developer portal until it
    expires.
  - The private key is generated locally and never leaves this machine. Apple
    only ever sees the certificate signing request.

Usage:
    python appleid.py login --apple-id you@example.com
    python appleid.py teams
    python appleid.py identity --udid <40-hex-or-25-with-dash> --bundle-id com.you.app
    python appleid.py status
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import plistlib
import sys
import time
import uuid

# Sibling tools live next to this directory (<tools>/filament, <tools>/go-ios,
# <tools>/zsign), so their location is derived rather than hardcoded. Every
# path below can still be overridden by its environment variable.
_TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HERE = os.path.dirname(os.path.abspath(__file__))
IOS = os.environ.get("FILAMENT_IOS_EXE", os.path.join(_TOOLS, "go-ios", "ios.exe"))
NO_WINDOW = 0x08000000 if os.name == "nt" else 0
STATE_DIR = os.path.join(HERE, ".signing")
ANISETTE_STATE = os.path.join(STATE_DIR, "anisette.bin")
SESSION_STATE = os.path.join(STATE_DIR, "session.json")

GSA_URL = "https://gsa.apple.com/grandslam/GsService2"
GSA_VALIDATE_URL = "https://gsa.apple.com/grandslam/GsService2/validate"
GSA_TRUSTED_DEVICE_URL = "https://gsa.apple.com/auth/verify/trusteddevice"

# Xcode's own identifiers. The portal rejects requests that do not look like a
# client it knows, and these are the values AltStore has used for years.
CLIENT_ID = "XABBG36SBA"
PROTOCOL_VERSION = "QH65B2"
XCODE_APP = "com.apple.gs.xcode.auth"
XCODE_VERSION = "11.2 (11B41)"

PORTAL_BASE = "https://developerservices2.apple.com/services/%s/" % PROTOCOL_VERSION
PORTAL_SERVICES = "https://developerservices2.apple.com/services/v1/"


class AppleError(Exception):
    """A failure Apple explained. The message is Apple's, not ours."""


# --------------------------------------------------------------------------
# TLS trust
# --------------------------------------------------------------------------

APPLE_ROOT_PEM = os.path.join(HERE, "certs", "AppleRootCA.pem")
# Apple Root CA, as published at
# https://www.apple.com/appleca/AppleIncRootCertificate.cer
APPLE_ROOT_SHA256 = ("B0B1730ECBC7FF4505142C49F1295E6EDA6BCAED7E2C68C5BE91B5A"
                     "11001F024")
CA_BUNDLE = os.path.join(STATE_DIR, "apple-ca-bundle.pem")


def ca_bundle():
    """certifi's public roots plus Apple's own, pinned by digest.

    This is not optional plumbing. `gsa.apple.com` chains to Apple's PRIVATE
    PKI, which certifi does not carry and never will, so requests rejects it
    with "self-signed certificate in certificate chain" - while a browser, or
    anything using the Windows store (where this project already installed
    Apple Root CA for the TSS endpoint), accepts it without complaint. The
    failure surfaces as an SSLError during login and looks like a network
    problem, which it is not.

    The two wrong ways to fix this are verify=False, which turns off the
    check that makes TLS worth having, and trusting whatever the OS store
    happens to contain, which is a moving target. Instead the bundle is built
    explicitly and the added certificate's SHA-256 is verified before use, so
    a swapped root file fails loudly rather than silently widening trust.
    """
    import ssl
    import certifi

    pem = open(APPLE_ROOT_PEM, "rb").read()
    der = ssl.PEM_cert_to_DER_cert(pem.decode())
    got = hashlib.sha256(der).hexdigest().upper()
    if got != APPLE_ROOT_SHA256:
        raise AppleError(
            "the pinned Apple Root CA at %s does not match its expected "
            "digest - refusing to trust it (expected %s, got %s)"
            % (APPLE_ROOT_PEM, APPLE_ROOT_SHA256[:16] + "...", got[:16] + "..."))

    base = open(certifi.where(), "rb").read()
    blob = base + b"\n" + pem
    os.makedirs(STATE_DIR, exist_ok=True)
    # Rewrite only when it actually changed - certifi updates with pip.
    if (not os.path.exists(CA_BUNDLE)
            or open(CA_BUNDLE, "rb").read() != blob):
        with open(CA_BUNDLE, "wb") as fh:
            fh.write(blob)
    return CA_BUNDLE


# --------------------------------------------------------------------------
# anisette
# --------------------------------------------------------------------------

class Anisette(object):
    """Apple's device-identification headers, generated locally.

    The provisioning state is persisted. Losing it is not fatal - the next run
    re-provisions - but it does mean Apple sees an unfamiliar machine and will
    very likely demand 2FA again.
    """

    def __init__(self, state_path=ANISETTE_STATE):
        import anisette as _anisette
        self.path = state_path
        os.makedirs(os.path.dirname(state_path), exist_ok=True)
        if os.path.exists(state_path):
            self._a = _anisette.Anisette.load(state_path)
        else:
            self._a = _anisette.Anisette.init()
        self._cached = None

    @property
    def provisioned(self):
        return bool(self._a.is_provisioned)

    def save(self):
        self._a.save_all(self.path)

    def headers(self, with_client_info=False):
        """The X-Apple-* identification headers, as strings."""
        data = {k: str(v) for k, v in self._a.get_data().items()}
        # The OTP is time-based, so the state is worth re-saving after each
        # generation - the library advances its counters.
        self.save()
        if not with_client_info:
            data.pop("X-MMe-Client-Info", None)
        return data

    @property
    def client_info(self):
        return str(self._a.get_data().get("X-MMe-Client-Info", ""))

    def cpd(self):
        """"Client provided data" - the anisette headers plus GSA's flags."""
        cpd = {
            "bootstrap": True,
            "icscrec": True,
            "pbe": False,
            "prkgen": True,
            "svct": "iCloud",
        }
        cpd.update(self.headers(with_client_info=True))
        return cpd


# --------------------------------------------------------------------------
# crypto helpers - Apple's variants, not the textbook ones
# --------------------------------------------------------------------------

def encrypt_password(password, salt, iterations, protocol):
    """What Apple feeds into SRP in place of the password.

    s2k hashes the password once; s2k_fo hashes it and then hex-encodes the
    digest before stretching. Getting this wrong fails as "bad password",
    which is a maddening thing to debug, so both are implemented.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    if protocol not in ("s2k", "s2k_fo"):
        raise AppleError("unsupported password protocol %r" % protocol)
    p = hashlib.sha256(password.encode("utf-8")).digest()
    if protocol == "s2k_fo":
        p = p.hex().encode("utf-8")
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                      iterations=iterations).derive(p)


def decrypt_spd(session_key, blob):
    """AES-CBC, with key and IV both HMAC'd out of the SRP session key."""
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = hmac.new(session_key, b"extra data key:", hashlib.sha256).digest()
    iv = hmac.new(session_key, b"extra data iv:", hashlib.sha256).digest()[:16]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    plain = dec.update(blob) + dec.finalize()
    unpad = padding.PKCS7(128).unpadder()
    return unpad.update(plain) + unpad.finalize()


def decrypt_app_token(sk, blob):
    """AES-GCM over a small framed blob: "XYZ" || iv(16) || ct || tag(16).

    The three version bytes are also the additional authenticated data, which
    is easy to miss and produces an authentication failure rather than
    garbage - so at least it fails honestly.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(blob) < 35:
        raise AppleError("app token blob is too short to be valid")
    if blob[:3] != b"XYZ":
        raise AppleError("app token blob has an unexpected version header %r"
                         % blob[:3])
    iv, ct_and_tag = blob[3:19], blob[19:]
    return AESGCM(sk).decrypt(iv, ct_and_tag, blob[:3])


def app_tokens_checksum(sk, adsid, apps):
    """HMAC-SHA256(sk, "apptokens" || adsid || each app name)."""
    h = hmac.new(sk, digestmod=hashlib.sha256)
    h.update(b"apptokens")
    h.update(adsid.encode("utf-8"))
    for app in apps:
        h.update(app.encode("utf-8"))
    return h.digest()


# --------------------------------------------------------------------------
# GSA authentication
# --------------------------------------------------------------------------

class AppleID(object):
    """A GSA login. Ends holding an adsid and an Xcode-scoped auth token."""

    def __init__(self, anisette, verbose=False):
        import requests
        self.an = anisette
        self.http = requests.Session()
        self.http.verify = ca_bundle()
        self.verbose = verbose
        self.adsid = None
        self.token = None
        self.account_name = None

    def _say(self, msg):
        if self.verbose:
            print("  .. %s" % msg, flush=True)

    def _gsa(self, params):
        body = {"Header": {"Version": "1.0.1"},
                "Request": dict(params, cpd=self.an.cpd())}
        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
            "X-MMe-Client-Info": self.an.client_info,
        }
        r = self.http.post(GSA_URL, headers=headers,
                           data=plistlib.dumps(body), timeout=60)
        if r.status_code != 200:
            raise AppleError("GSA returned HTTP %d" % r.status_code)
        return plistlib.loads(r.content)["Response"]

    @staticmethod
    def _check(resp, what):
        st = resp.get("Status") or {}
        if st.get("ec") not in (0, None):
            raise AppleError("%s: %s" % (what, st.get("em") or st.get("ec")))
        return resp

    def login(self, username, password):
        """Full SRP login. Returns the decrypted SPD dictionary.

        Raises if Apple rejects the credentials. Two-factor is NOT handled
        here - the caller sees it in Status.au and drives it, because a
        library that silently blocks on a console prompt is a library that
        cannot be used from a daemon.
        """
        import srp._pysrp as srp
        srp.rfc5054_enable()
        srp.no_username_in_x()

        usr = srp.User(username, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        _, a2k = usr.start_authentication()

        self._say("SRP init")
        r = self._check(self._gsa({"A2k": a2k, "u": username,
                                   "ps": ["s2k", "s2k_fo"], "o": "init"}),
                        "Apple rejected the Apple ID")

        sp = r.get("sp")
        if sp not in ("s2k", "s2k_fo"):
            raise AppleError("unsupported password protocol from Apple: %r" % sp)

        self._say("SRP challenge (%s, %d iterations)" % (sp, r["i"]))
        usr.p = encrypt_password(password, r["s"], r["i"], sp)
        m1 = usr.process_challenge(r["s"], r["B"])
        if m1 is None:
            raise AppleError("SRP challenge failed before it reached Apple")

        r = self._check(self._gsa({"c": r["c"], "M1": m1, "u": username,
                                   "o": "complete"}),
                        "Apple rejected the password")

        usr.verify_session(r.get("M2"))
        if not usr.authenticated():
            # Apple answered, but not with a value that proves it knows the
            # password. Never treat this as success.
            raise AppleError("Apple's session proof did not verify - "
                             "refusing to continue")

        spd = plistlib.loads(decrypt_spd(usr.get_session_key(), r["spd"]))
        spd["_au"] = (r.get("Status") or {}).get("au")
        self.account_name = spd.get("acname")
        self._say("authenticated as %s" % (spd.get("acname") or username))
        return spd

    # -- two factor --------------------------------------------------------

    def _2fa_headers(self, adsid, idms_token):
        identity = base64.b64encode(
            ("%s:%s" % (adsid, idms_token)).encode("utf-8")).decode()
        h = {
            "Content-Type": "text/x-xml-plist",
            "User-Agent": "Xcode",
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "X-Apple-App-Info": XCODE_APP,
            "X-Xcode-Version": XCODE_VERSION,
            "X-Apple-Identity-Token": identity,
        }
        h.update(self.an.headers(with_client_info=True))
        return h

    def request_2fa_code(self, adsid, idms_token):
        """Ask Apple to push a code to the account's trusted devices."""
        r = self.http.get(GSA_TRUSTED_DEVICE_URL,
                          headers=self._2fa_headers(adsid, idms_token),
                          timeout=60)
        # 200 and 412 both mean "the code is on its way"; 412 is Apple saying
        # the account still needs to complete verification, which is the
        # situation we are in by definition.
        if r.status_code not in (200, 412):
            raise AppleError("could not request a 2FA code: HTTP %d"
                             % r.status_code)

    def submit_2fa_code(self, adsid, idms_token, code):
        headers = self._2fa_headers(adsid, idms_token)
        headers["security-code"] = code
        r = self.http.get(GSA_VALIDATE_URL, headers=headers, timeout=60)
        if r.status_code != 200:
            raise AppleError("2FA validation returned HTTP %d" % r.status_code)
        try:
            resp = plistlib.loads(r.content)
        except Exception:
            raise AppleError("2FA validation returned an unreadable response")
        ec = (resp.get("ec") if "ec" in resp
              else (resp.get("Status") or {}).get("ec"))
        if ec not in (0, None):
            em = (resp.get("em")
                  or (resp.get("Status") or {}).get("em") or ec)
            raise AppleError("Apple rejected the code: %s" % em)

    # -- app token ---------------------------------------------------------

    def fetch_app_token(self, spd):
        """Trade the SPD for a token scoped to Xcode's auth app."""
        sk, c = spd.get("sk"), spd.get("c")
        adsid, idms = spd.get("adsid"), spd.get("GsIdmsToken")
        if not (sk and c and adsid and idms):
            raise AppleError("Apple's response is missing the fields needed "
                             "to request a token (sk/c/adsid/GsIdmsToken)")

        apps = [XCODE_APP]
        self._say("requesting an %s token" % XCODE_APP)
        r = self._check(self._gsa({
            "u": adsid, "app": apps, "c": c, "t": idms,
            "checksum": app_tokens_checksum(sk, adsid, apps),
            "o": "apptokens",
        }), "Apple refused to issue a developer token")

        blob = r.get("et")
        if not blob:
            raise AppleError("Apple returned no token payload")
        tokens = plistlib.loads(decrypt_app_token(sk, blob))
        entry = (tokens.get("t") or {}).get(XCODE_APP) or {}
        token = entry.get("token")
        if not token:
            raise AppleError("Apple's token payload had no %s token" % XCODE_APP)

        self.adsid, self.token = adsid, token
        expiry = entry.get("expiry")
        return {"adsid": adsid, "token": token,
                "expires": (int(expiry) / 1000.0) if expiry else None,
                "account_name": self.account_name}


# --------------------------------------------------------------------------
# the developer portal
# --------------------------------------------------------------------------

class Portal(object):
    """developerservices2.apple.com. XML plists in, XML plists out."""

    def __init__(self, adsid, token, anisette, verbose=False):
        import requests
        self.adsid, self.token = adsid, token
        self.an = anisette
        self.http = requests.Session()
        self.http.verify = ca_bundle()
        self.verbose = verbose

    def _headers(self):
        h = {
            "Content-Type": "text/x-xml-plist",
            "User-Agent": "Xcode",
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "X-Apple-App-Info": XCODE_APP,
            "X-Xcode-Version": XCODE_VERSION,
            "X-Apple-I-Identity-Id": self.adsid,
            "X-Apple-GS-Token": self.token,
        }
        an = self.an.headers(with_client_info=True)
        h.update(an)
        # The portal wants the locale under both spellings.
        if "X-Apple-Locale" in an:
            h["X-Apple-I-Locale"] = an["X-Apple-Locale"]
        return h

    def post(self, action, params=None, team=None):
        body = {"clientId": CLIENT_ID,
                "protocolVersion": PROTOCOL_VERSION,
                "requestId": str(uuid.uuid4()).upper()}
        if team:
            body["teamId"] = team
        body.update(params or {})

        url = PORTAL_BASE + action + "?clientId=" + CLIENT_ID
        if self.verbose:
            print("  .. POST %s" % action, flush=True)
        r = self.http.post(url, headers=self._headers(),
                           data=plistlib.dumps(body), timeout=90)
        if r.status_code != 200:
            raise AppleError("%s returned HTTP %d" % (action, r.status_code))
        try:
            resp = plistlib.loads(r.content)
        except Exception:
            raise AppleError("%s returned a response that is not a plist"
                             % action)
        # The portal reports failure in-band with HTTP 200.
        code = resp.get("resultCode")
        if code not in (0, None):
            raise AppleError(resp.get("userString")
                             or resp.get("resultString")
                             or "%s failed with code %s" % (action, code))
        return resp

    # -- reads -------------------------------------------------------------

    def teams(self):
        return self.post("listTeams.action").get("teams") or []

    def devices(self, team):
        return self.post("ios/listDevices.action", team=team).get("devices") or []

    def app_ids(self, team):
        return self.post("ios/listAppIds.action", team=team).get("appIds") or []

    # -- writes ------------------------------------------------------------

    def add_device(self, team, udid, name):
        """Register a device. Already-registered is success, not failure."""
        try:
            r = self.post("ios/addDevice.action", team=team,
                          params={"deviceNumber": udid, "name": name})
            return r.get("device") or {}
        except AppleError as exc:
            if "already exist" in str(exc).lower():
                for d in self.devices(team):
                    if (d.get("deviceNumber") or "").lower() == udid.lower():
                        return d
            raise

    def submit_csr(self, team, csr_pem, machine_name="Filament"):
        r = self.post("ios/submitDevelopmentCSR.action", team=team,
                      params={"csrContent": csr_pem,
                              "machineId": str(uuid.uuid4()).upper(),
                              "machineName": machine_name})
        return r.get("certRequest") or {}

    def add_app_id(self, team, bundle_id, name):
        # Apple rejects most punctuation in the visible name.
        safe = "".join(ch if (ch.isalnum() or ch == " ") else " "
                       for ch in name).strip() or "Filament App"
        try:
            r = self.post("ios/addAppId.action", team=team,
                          params={"identifier": bundle_id, "name": safe})
            return r.get("appId") or {}
        except AppleError as exc:
            if "already" not in str(exc).lower():
                raise
            for a in self.app_ids(team):
                if a.get("identifier") == bundle_id:
                    return a
            raise

    def team_profile(self, team, app_id_id):
        r = self.post("ios/downloadTeamProvisioningProfile.action", team=team,
                      params={"appIdId": app_id_id})
        prof = r.get("provisioningProfile") or {}
        blob = prof.get("encodedProfile")
        if not blob:
            raise AppleError("Apple returned a profile with no content")
        return blob


# --------------------------------------------------------------------------
# the attached device
# --------------------------------------------------------------------------

def device_udid():
    """The attached iPhone's UDID, via go-ios. -> str or None.

    Asking the device beats making someone read 40 hex characters off a
    screen and retype them - a step that exists only to be got wrong. go-ios
    reports it as a JSON line among its ordinary logging, so the output is
    scanned for that line rather than parsed whole.
    """
    import subprocess
    try:
        p = subprocess.run([IOS, "list"], capture_output=True, text=True,
                           timeout=40, creationflags=NO_WINDOW,
                           encoding="utf-8", errors="replace")
    except Exception:
        return None
    for line in ((p.stdout or "") + "\n" + (p.stderr or "")).splitlines():
        try:
            o = json.loads(line.strip())
        except ValueError:
            continue
        if isinstance(o, dict) and "deviceList" in o:
            lst = o["deviceList"] or []
            return lst[0] if lst else None
    return None


# --------------------------------------------------------------------------
# local key material
# --------------------------------------------------------------------------

def generate_key_and_csr(common_name="Filament"):
    """A 2048-bit RSA key and a CSR for it. The key never leaves this box."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([
               x509.NameAttribute(NameOID.COMMON_NAME, common_name),
               x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
           ]))
           .sign(key, hashes.SHA256()))
    return key, csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def write_p12(key, cert_der, path, password, friendly_name=b"Filament"):
    """Bundle the private key with Apple's certificate into a .p12."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12

    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception:
        cert = x509.load_pem_x509_certificate(cert_der)

    enc = (serialization.BestAvailableEncryption(password.encode("utf-8"))
           if password else serialization.NoEncryption())
    blob = pkcs12.serialize_key_and_certificates(
        name=friendly_name, key=key, cert=cert, cas=None, encryption_algorithm=enc)
    with open(path, "wb") as fh:
        fh.write(blob)
    return cert


def certificate_bytes(cert_request, portal=None, team=None):
    """Dig the issued certificate out of Apple's reply.

    Apple has moved this field between API generations, so every known
    spelling is tried before giving up - and if none match, the keys that
    WERE returned are reported, because a silent empty result here is the
    difference between a five-minute fix and an afternoon.
    """
    for k in ("certificate", "certContent", "certificateContent",
              "certificateData"):
        v = cert_request.get(k)
        if isinstance(v, bytes) and v:
            return v
        if isinstance(v, str) and v:
            try:
                return base64.b64decode(v)
            except Exception:
                return v.encode("ascii")
        if isinstance(v, dict):
            for kk in ("certContent", "certificateContent"):
                if isinstance(v.get(kk), bytes):
                    return v[kk]
    raise AppleError(
        "Apple accepted the CSR but the reply carried no certificate. "
        "Fields returned: %s" % ", ".join(sorted(cert_request)) or "(none)")


# --------------------------------------------------------------------------
# session persistence
# --------------------------------------------------------------------------

def save_session(data):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(SESSION_STATE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    # Best effort on Windows: at least keep it out of a world-readable mode
    # on any filesystem that honours it.
    try:
        os.chmod(SESSION_STATE, 0o600)
    except Exception:
        pass


LOGIN_LOG = os.path.join(STATE_DIR, "login.log")

# The five stages a login passes through. Naming them is the difference
# between "login failed" and a sentence that says what to do next: each one
# fails for entirely different reasons and has an entirely different fix.
STAGES = (
    ("anisette", "generating this machine's Apple device identity"),
    ("srp-init", "asking Apple whether the Apple ID exists"),
    ("password", "proving the password via SRP"),
    ("2fa", "the two-factor code"),
    ("token", "exchanging the session for a developer token"),
)


def journal(stage, outcome, detail="", apple_id=""):
    """Append one line about a login attempt. Never secrets.

    A failed login that scrolls off the screen is a failure you get to have
    twice. What goes in here is deliberately narrow: when, which Apple ID,
    which stage, and what Apple said. No password, no token, no anisette
    material - none of which would help debugging and all of which would be a
    liability sitting in a log file.
    """
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(LOGIN_LOG, "a", encoding="utf-8") as fh:
            fh.write("%s  %-9s %-7s %s%s\n" % (
                time.strftime("%Y-%m-%d %H:%M:%S"), stage, outcome,
                ("<" + apple_id + "> ") if apple_id else "",
                detail.replace("\n", " ")[:300]))
    except Exception:
        # Logging must never be the reason a login fails.
        pass


def load_session():
    if not os.path.exists(SESSION_STATE):
        return None
    try:
        with open(SESSION_STATE, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def session_or_die():
    s = load_session()
    if not s or not s.get("token"):
        print("\n  not signed in - run:  python appleid.py login "
              "--apple-id you@example.com\n")
        raise SystemExit(2)
    exp = s.get("expires")
    if exp and time.time() > exp:
        print("\n  the saved session expired %s - run login again\n"
              % time.strftime("%Y-%m-%d %H:%M", time.localtime(exp)))
        raise SystemExit(2)
    return s


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

STAGE_ADVICE = {
    "anisette": [
        "delete .signing/anisette.bin and let it re-provision",
        "check that this machine can reach Apple at all",
    ],
    "srp-init": [
        "check the Apple ID is spelled correctly",
        "an Apple ID that has never signed in to a developer tool may need "
        "one sign-in at appleid.apple.com first",
    ],
    "password": [
        "check the password - and note that an app-specific password will "
        "NOT work here, Apple wants the real one",
        "check this machine's clock: the anisette OTP is time-based, and a "
        "skew of a few minutes fails as though the password were wrong "
        "(run: appleid.py doctor)",
    ],
    "2fa": [
        "the code expires quickly - request a fresh one",
        "enter the 6 digits only, no spaces",
    ],
    "token": [
        "this usually means the Apple ID has no developer programme access; "
        "accepting the developer agreement once at developer.apple.com "
        "resolves it",
    ],
}


def _prompt_password(args):
    """Read the password, from a prompt that says plainly what it is.

    Worth the extra lines: a bare "Password:" in a terminal is exactly the
    shape of a phishing prompt, and someone who cannot tell which program is
    asking cannot make a good decision about answering.
    """
    if args.password is not None:
        return args.password
    if args.password_stdin:
        return sys.stdin.readline().rstrip("\n")
    print("\n  ------------------------------------------------------------")
    print("  Apple ID sign-in requested by appleid.py")
    print("  running in : %s" % HERE)
    print("  account    : %s" % args.apple_id)
    print("  sent to    : gsa.apple.com (Apple), over TLS, and nowhere else")
    print("  stored     : never - it is used for the SRP exchange and dropped")
    print("  ------------------------------------------------------------")
    print("  If you did not just start this command, do not type anything.")
    return getpass.getpass("  Apple ID password: ")


def cmd_login(args):
    stage = "anisette"
    try:
        an = Anisette()
        print("\n  anisette: %s" % ("provisioned" if an.provisioned
                                    else "provisioning on first use"))
        api = AppleID(an, verbose=args.verbose)
    except Exception as exc:
        journal("anisette", "FAIL", str(exc), args.apple_id)
        _explain("anisette", "%s: %s" % (type(exc).__name__, exc))
        return 1

    password = _prompt_password(args)
    if not password:
        print("\n  no password given - nothing was sent to Apple\n")
        return 2

    try:
        stage = "srp-init"
        journal(stage, "start", "", args.apple_id)
        spd = api.login(args.apple_id, password)
        # login() covers srp-init and password in one call; reaching here
        # means both succeeded.
        journal("password", "ok", "", args.apple_id)

        if spd.get("_au") in ("secondaryAuth", "trustedDeviceSecondaryAuth"):
            stage = "2fa"
            print("  two-factor required - Apple is sending a code to your "
                  "trusted devices")
            api.request_2fa_code(spd["adsid"], spd["GsIdmsToken"])
            code = (args.code or "").strip() or input("  code: ").strip()
            if not code:
                journal(stage, "FAIL", "no code entered", args.apple_id)
                print("\n  no code entered\n")
                return 2
            api.submit_2fa_code(spd["adsid"], spd["GsIdmsToken"], code)
            journal(stage, "ok", "", args.apple_id)
            print("  code accepted - re-authenticating")
            # The second login is not optional: the first one only ever
            # yields a 2FA-gated SPD, and the token request needs a clean one.
            spd = api.login(args.apple_id, password)
            if spd.get("_au"):
                raise AppleError("Apple still wants two-factor after the code "
                                 "was accepted")

        stage = "token"
        session = api.fetch_app_token(spd)
        journal(stage, "ok", "", args.apple_id)
    except AppleError as exc:
        journal(stage, "FAIL", str(exc), args.apple_id)
        _explain(stage, str(exc))
        return 1
    except Exception as exc:
        journal(stage, "FAIL", "%s: %s" % (type(exc).__name__, exc),
                args.apple_id)
        _explain(stage, "%s: %s" % (type(exc).__name__, exc))
        return 1
    finally:
        del password

    session["apple_id"] = args.apple_id
    save_session(session)
    exp = session.get("expires")
    print("\n  signed in as %s" % (session.get("account_name") or args.apple_id))
    if exp:
        print("  token valid until %s"
              % time.strftime("%Y-%m-%d %H:%M", time.localtime(exp)))
    print("  saved to %s  (treat this as a credential)\n" % SESSION_STATE)
    return 0


def _explain(stage, message):
    """Report a failure as the stage it happened in, plus what to try.

    "login failed" is almost useless: five different subsystems can produce
    it, and the fix for each has nothing to do with the fix for the others.
    """
    label = dict(STAGES).get(stage, stage)
    print("\n  login failed at stage: %s" % stage)
    print("  which is: %s" % label)
    print("  Apple said: %s" % message)
    advice = STAGE_ADVICE.get(stage) or []
    if advice:
        print("\n  worth trying:")
        for a in advice:
            print("    - %s" % a)
    print("\n  logged to %s\n" % LOGIN_LOG)


def _portal(args):
    s = session_or_die()
    return s, Portal(s["adsid"], s["token"], Anisette(), verbose=args.verbose)


def cmd_status(args):
    s = load_session()
    an_ok = os.path.exists(ANISETTE_STATE)
    print("\n  anisette state   %s" % ("present" if an_ok else "not provisioned"))
    if not s:
        print("  session          none - run login\n")
        return 0
    exp = s.get("expires")
    fresh = (not exp) or time.time() < exp
    print("  apple id         %s" % s.get("apple_id", "?"))
    print("  account          %s" % (s.get("account_name") or "?"))
    print("  token            %s%s"
          % ("valid" if fresh else "EXPIRED",
             ("  until " + time.strftime("%Y-%m-%d %H:%M", time.localtime(exp)))
             if exp else ""))
    print()
    return 0


def cmd_doctor(args):
    """Check every link in the signing chain, and say which one is broken.

    Ordered so that the first failure is the real one: anisette cannot work
    without its state, and the password stage cannot work if the clock is
    wrong, so reporting those before "login failed" saves chasing the wrong
    thing.
    """
    ok = "  ok  "
    bad = " !!   "
    meh = "  ?   "
    problems = []

    print("\n  signing chain\n  -------------")

    # -- interpreter and dependencies ------------------------------------
    missing = []
    for mod in ("anisette", "srp", "cryptography", "requests"):
        try:
            __import__(mod)
        except Exception:
            missing.append(mod)
    if missing:
        print("%sdependencies   missing: %s" % (bad, ", ".join(missing)))
        problems.append("install the missing packages into .signing-venv")
    else:
        print("%sdependencies   anisette, srp, cryptography, requests" % ok)

    # -- clock -----------------------------------------------------------
    # The anisette OTP is time-based. A few minutes of skew fails at the
    # password stage, which is a deeply misleading place for it to surface.
    skew = why_no_skew = None
    if args.offline:
        why_no_skew = "not checked (--offline)"
    else:
        try:
            import email.utils
            import requests
            r = requests.head("https://gsa.apple.com/", timeout=15,
                              verify=ca_bundle())
            served = r.headers.get("Date")
            if served:
                theirs = email.utils.parsedate_to_datetime(served).timestamp()
                skew = theirs - time.time()
            else:
                why_no_skew = "Apple returned no Date header to compare"
        except Exception as exc:
            why_no_skew = "could not reach Apple (%s)" % type(exc).__name__

    if skew is None:
        print("%sclock          %s" % (meh, why_no_skew))
    elif abs(skew) < 90:
        print("%sclock          within %ds of Apple's" % (ok, abs(int(skew))))
    else:
        print("%sclock          off by %d seconds vs Apple"
              % (bad, int(skew)))
        problems.append("fix the system clock - a time-based OTP with this "
                        "much skew fails as though the password were wrong")

    # -- anisette --------------------------------------------------------
    try:
        an = Anisette()
        h = an.headers(with_client_info=True)
        need = ("X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU",
                "X-Mme-Device-Id")
        absent = [k for k in need if not h.get(k)]
        if absent:
            print("%sanisette       missing headers: %s" % (bad, ", ".join(absent)))
            problems.append("delete .signing/anisette.bin to re-provision")
        else:
            print("%sanisette       provisioned, emitting a live OTP" % ok)
            print("               device %s" % h.get("X-Mme-Device-Id"))
    except Exception as exc:
        print("%sanisette       %s: %s" % (bad, type(exc).__name__, exc))
        problems.append("delete .signing/anisette.bin to re-provision")

    # -- device ----------------------------------------------------------
    udid = device_udid()
    if udid:
        print("%sdevice         %s" % (ok, udid))
    else:
        print("%sdevice         none attached (only needed for `identity`)" % meh)

    # -- session ---------------------------------------------------------
    s = load_session()
    if not s:
        print("%ssession        none - run login" % meh)
    else:
        exp = s.get("expires")
        if exp and time.time() > exp:
            print("%ssession        EXPIRED %s"
                  % (bad, time.strftime("%Y-%m-%d %H:%M", time.localtime(exp))))
            problems.append("run login again")
        else:
            print("%ssession        %s%s"
                  % (ok, s.get("account_name") or s.get("apple_id") or "?",
                     ("  until " + time.strftime("%Y-%m-%d %H:%M",
                                                 time.localtime(exp)))
                     if exp else ""))

    # -- recent attempts -------------------------------------------------
    if os.path.exists(LOGIN_LOG):
        try:
            with open(LOGIN_LOG, encoding="utf-8") as fh:
                lines = [l.rstrip() for l in fh if l.strip()][-6:]
        except Exception:
            lines = []
        if lines:
            print("\n  recent login attempts\n  ---------------------")
            for l in lines:
                print("  %s" % l)
    else:
        print("\n  no login has ever been attempted from this directory")

    if problems:
        print("\n  what to fix\n  -----------")
        for p in problems:
            print("    - %s" % p)
    print()
    return 1 if problems else 0


def cmd_teams(args):
    _, portal = _portal(args)
    try:
        teams = portal.teams()
    except AppleError as exc:
        print("\n  %s\n" % exc)
        return 1
    if args.json:
        print(json.dumps(teams, indent=2, default=str))
        return 0
    print("\n  %d team(s)\n" % len(teams))
    for t in teams:
        print("    %-12s %-28s %s" % (t.get("teamId", "?"),
                                      (t.get("name") or "")[:28],
                                      t.get("type") or ""))
    print()
    return 0


def cmd_identity(args):
    """The whole path: device -> CSR -> certificate -> app id -> profile."""
    s, portal = _portal(args)
    out_dir = args.out or os.path.join(STATE_DIR, "identity")
    os.makedirs(out_dir, exist_ok=True)

    udid = args.udid or device_udid()
    if not udid:
        print("\n  no device attached and no --udid given. A development "
              "certificate is\n  issued against a specific device, so one or "
              "the other is required.\n")
        return 2

    try:
        teams = portal.teams()
        if not teams:
            print("\n  this Apple ID has no development teams\n")
            return 1
        team = args.team or teams[0].get("teamId")
        print("\n  team          %s (%s)"
              % (team, (teams[0].get("name") or "")[:40]))

        print("  device        registering %s" % udid)
        dev = portal.add_device(team, udid, args.device_name)
        print("                %s" % (dev.get("name") or "registered"))

        print("  key + csr     generating locally (2048-bit RSA)")
        key, csr_pem = generate_key_and_csr()

        print("  certificate   asking Apple to sign it")
        cert_req = portal.submit_csr(team, csr_pem, args.device_name)
        cert_der = certificate_bytes(cert_req)

        p12_path = os.path.join(out_dir, "identity.p12")
        cert = write_p12(key, cert_der, p12_path, args.p12_password)
        print("                issued, expires %s"
              % cert.not_valid_after_utc.strftime("%Y-%m-%d"))

        print("  app id        %s" % args.bundle_id)
        app = portal.add_app_id(team, args.bundle_id, args.device_name)

        print("  profile       downloading team provisioning profile")
        profile = portal.team_profile(team, app.get("appIdId") or app.get("appIdentifierId"))
        prof_path = os.path.join(out_dir, "identity.mobileprovision")
        with open(prof_path, "wb") as fh:
            fh.write(profile)

    except AppleError as exc:
        print("\n  failed: %s\n" % exc)
        return 1
    except Exception as exc:
        print("\n  failed: %s: %s\n" % (type(exc).__name__, exc))
        return 1

    print("\n  identity written:")
    print("    %s" % p12_path)
    print("    %s" % prof_path)
    print("\n  verify it before trusting it:")
    print("    python sideload.py check <app> --p12 %s --profile %s\n"
          % (p12_path, prof_path))
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Mint a development signing identity from a free Apple ID.")
    ap.add_argument("--verbose", "-v", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("login", help="authenticate an Apple ID")
    p.add_argument("--apple-id", required=True)
    p.add_argument("--password", help="NOT recommended - it lands in your "
                                      "shell history")
    p.add_argument("--password-stdin", action="store_true",
                   help="read the password from stdin")
    p.add_argument("--code", help="2FA code, if you already have one")
    p.set_defaults(fn=cmd_login)

    p = sub.add_parser("status", help="what is signed in, and for how long")
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("doctor", help="check every link in the signing chain")
    p.add_argument("--offline", action="store_true",
                   help="skip the checks that contact Apple")
    p.set_defaults(fn=cmd_doctor)

    p = sub.add_parser("teams", help="list development teams")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_teams)

    p = sub.add_parser("identity", help="mint a certificate and profile")
    p.add_argument("--udid", help="the iPhone's UDID (default: ask the "
                                  "attached device)")
    p.add_argument("--bundle-id", required=True)
    p.add_argument("--team", help="team id (default: the first one)")
    p.add_argument("--device-name", default="Filament")
    p.add_argument("--p12-password", default="filament")
    p.add_argument("--out", help="output directory")
    p.set_defaults(fn=cmd_identity)

    args = ap.parse_args()
    if not getattr(args, "fn", None):
        ap.print_help()
        return 0
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    return args.fn(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
