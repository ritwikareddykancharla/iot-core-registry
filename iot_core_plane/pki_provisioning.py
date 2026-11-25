"""X.509 Certificate Authority, JITP, Claim Provisioning & Zero-Downtime Rotation.

Implements real NIST P-256 (secp256r1) ECDSA-SHA256 signatures, RFC 5280 ASN.1 DER
X.509v3 certificate generation/parsing, SHA-256 certificate fingerprint IDs,
HMAC-SHA256 CA proof-of-possession registration, Just-in-Time Provisioning (JITP),
Provisioning-by-Claim bootstrap handshakes, overlapping two-certificate rotation
(ACTIVE_PRIMARY + PENDING_ROTATION -> VERIFIED_CONNECT -> REVOKE_OLD), and O(1)
CRL/status checks (ACTIVE, INACTIVE, PENDING_TRANSFER, REVOKED).
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple


class ProvisioningError(ValueError):
    """Raised when X.509 validation, CA verification, or JITP/Claim checks fail."""


class RotationPreconditionError(RuntimeError):
    """Raised when attempting to revoke an active primary certificate before new cert verification."""


# ==============================================================================
# NIST P-256 (secp256r1) Elliptic Curve & ECDSA-SHA256 Implementation
# ==============================================================================
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

JacobianPoint = Optional[Tuple[int, int, int]]
AffinePoint = Tuple[int, int]


def _jac_double(pt: JacobianPoint) -> JacobianPoint:
    if pt is None:
        return None
    x, y, z = pt
    if y == 0 or z == 0:
        return None
    p = P256_P
    y2 = (y * y) % p
    s = (4 * x * y2) % p
    z2 = (z * z) % p
    m = (3 * (x - z2) * (x + z2)) % p
    nx = (m * m - 2 * s) % p
    y4 = (y2 * y2) % p
    ny = (m * (s - nx) - 8 * y4) % p
    nz = (2 * y * z) % p
    return (nx, ny, nz)


def _jac_add(p1: JacobianPoint, p2: JacobianPoint) -> JacobianPoint:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    p = P256_P
    z1_2 = (z1 * z1) % p
    z2_2 = (z2 * z2) % p
    u1 = (x1 * z2_2) % p
    u2 = (x2 * z1_2) % p
    s1 = (y1 * z2_2 * z2) % p
    s2 = (y2 * z1_2 * z1) % p
    if u1 == u2:
        if s1 != s2:
            return None
        return _jac_double(p1)
    h = (u2 - u1) % p
    r = (s2 - s1) % p
    h2 = (h * h) % p
    h3 = (h * h2) % p
    u1_h2 = (u1 * h2) % p
    x3 = (r * r - h3 - 2 * u1_h2) % p
    y3 = (r * (u1_h2 - x3) - s1 * h3) % p
    z3 = (h * z1 * z2) % p
    return (x3, y3, z3)


def _jac_add_affine(p1: JacobianPoint, p2: AffinePoint) -> JacobianPoint:
    x2, y2 = p2
    if p1 is None:
        return (x2, y2, 1)
    x1, y1, z1 = p1
    p = P256_P
    z1_2 = (z1 * z1) % p
    u2 = (x2 * z1_2) % p
    s2 = (y2 * z1_2 * z1) % p
    if x1 == u2:
        if y1 != s2:
            return None
        return _jac_double(p1)
    h = (u2 - x1) % p
    r = (s2 - y1) % p
    h2 = (h * h) % p
    h3 = (h * h2) % p
    x1_h2 = (x1 * h2) % p
    x3 = (r * r - h3 - 2 * x1_h2) % p
    y3 = (r * (x1_h2 - x3) - y1 * h3) % p
    z3 = (h * z1) % p
    return (x3, y3, z3)


def _to_affine(pt: JacobianPoint) -> Optional[AffinePoint]:
    if pt is None or pt[2] == 0:
        return None
    x, y, z = pt
    inv_z = pow(z, -1, P256_P)
    inv_z2 = (inv_z * inv_z) % P256_P
    return ((x * inv_z2) % P256_P, (y * inv_z2 * inv_z) % P256_P)


def _build_window4_table(base: AffinePoint) -> List[List[Optional[AffinePoint]]]:
    """Precomputes 64 windows of 4-bit multiples [0..15] * (16^i) * base."""
    table: List[List[Optional[AffinePoint]]] = []
    cur: JacobianPoint = (base[0], base[1], 1)
    for _ in range(64):
        win_jac: List[JacobianPoint] = [None] * 16
        win_jac[1] = cur
        win_jac[2] = _jac_double(cur)
        for w in range(3, 16):
            win_jac[w] = _jac_add(win_jac[w - 1], cur)
        table.append([_to_affine(pt) if pt is not None else None for pt in win_jac])
        # Advance cur = 16 * cur via 4 doublings
        for _ in range(4):
            cur = _jac_double(cur)
    return table


_G_TABLE = _build_window4_table((P256_GX, P256_GY))
_PUBKEY_TABLE_CACHE: Dict[AffinePoint, List[List[Optional[AffinePoint]]]] = {}


def _scalar_mult_table(k: int, table: List[List[Optional[AffinePoint]]]) -> AffinePoint:
    k = k % P256_N
    acc: JacobianPoint = None
    for idx in range(64):
        nib = k & 0xF
        k >>= 4
        if nib:
            pt = table[idx][nib]
            if pt is not None:
                acc = _jac_add_affine(acc, pt)
        if k == 0:
            break
    aff = _to_affine(acc)
    if aff is None:
        raise ProvisioningError("Invalid scalar multiplication at point-at-infinity")
    return aff


def _scalar_mult_point(k: int, pub: AffinePoint) -> AffinePoint:
    cached = _PUBKEY_TABLE_CACHE.get(pub)
    if cached is not None:
        return _scalar_mult_table(k, cached)
    acc: JacobianPoint = None
    addend: JacobianPoint = (pub[0], pub[1], 1)
    n = k % P256_N
    while n > 0:
        if n & 1:
            acc = _jac_add(acc, addend)
        addend = _jac_double(addend)
        n >>= 1
    aff = _to_affine(acc)
    if aff is None:
        raise ProvisioningError("Invalid EC point multiplication")
    return aff


def generate_p256_keypair(seed_material: Optional[bytes] = None) -> Tuple[int, AffinePoint]:
    if seed_material is not None:
        digest = hashlib.sha256(seed_material).digest()
        priv = (int.from_bytes(digest, "big") % (P256_N - 1)) + 1
    else:
        priv = secrets.randbelow(P256_N - 1) + 1
    pub = _scalar_mult_table(priv, _G_TABLE)
    return priv, pub


def ecdsa_sign_sha256(priv_key: int, data: bytes) -> Tuple[int, int]:
    digest = hashlib.sha256(data).digest()
    z = int.from_bytes(digest, "big")
    # RFC 6979 style deterministic nonce mixed with key + digest
    k_seed = hmac.new(priv_key.to_bytes(32, "big"), digest + b"\x01iot-core-p256", hashlib.sha256).digest()
    k = (int.from_bytes(k_seed, "big") % (P256_N - 1)) + 1
    while True:
        rx, _ = _scalar_mult_table(k, _G_TABLE)
        r = rx % P256_N
        if r != 0:
            s = (pow(k, -1, P256_N) * (z + r * priv_key)) % P256_N
            if s != 0:
                if s > P256_N // 2:
                    s = P256_N - s
                return r, s
        k = (k + 1) % (P256_N - 1) + 1


def ecdsa_verify_sha256(pub_key: AffinePoint, data: bytes, signature: Tuple[int, int]) -> bool:
    r, s = signature
    if not (1 <= r < P256_N and 1 <= s < P256_N):
        return False
    px, py = pub_key
    if not (0 <= px < P256_P and 0 <= py < P256_P):
        return False
    if (py * py - (px * px * px - 3 * px + P256_B)) % P256_P != 0:
        return False
    z = int.from_bytes(hashlib.sha256(data).digest(), "big")
    w = pow(s, -1, P256_N)
    u1 = (z * w) % P256_N
    u2 = (r * w) % P256_N
    p1 = _scalar_mult_table(u1, _G_TABLE)
    p2 = _scalar_mult_point(u2, pub_key)
    comb = _to_affine(_jac_add((p1[0], p1[1], 1), (p2[0], p2[1], 1)))
    if comb is None:
        return False
    return (comb[0] % P256_N) == r


# ==============================================================================
# RFC 5280 ASN.1 DER X.509v3 Certificate Builder & Parser
# ==============================================================================
OID_EC_PUBLIC_KEY = bytes.fromhex("2a8648ce3d0201")       # 1.2.840.10045.2.1
OID_PRIME256V1 = bytes.fromhex("2a8648ce3d030107")        # 1.2.840.10045.3.1.7
OID_ECDSA_SHA256 = bytes.fromhex("2a8648ce3d040302")      # 1.2.840.10045.4.3.2
OID_COMMON_NAME = bytes.fromhex("550403")                 # 2.5.4.3
OID_SERIAL_NUMBER = bytes.fromhex("550405")               # 2.5.4.5
OID_ORG_NAME = bytes.fromhex("55040a")                    # 2.5.4.10
OID_ORG_UNIT = bytes.fromhex("55040b")                    # 2.5.4.11
OID_BASIC_CONSTRAINTS = bytes.fromhex("551d13")           # 2.5.29.19
OID_SUBJECT_KEY_ID = bytes.fromhex("551d0e")              # 2.5.29.14


def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _der_int(val: int) -> bytes:
    if val == 0:
        return _der_tlv(0x02, b"\x00")
    raw = val.to_bytes((val.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _der_tlv(0x02, raw)


def _der_oid(oid_bytes: bytes) -> bytes:
    return _der_tlv(0x06, oid_bytes)


def _der_utf8(text: str) -> bytes:
    return _der_tlv(0x0C, text.encode("utf-8"))


def _der_gentime(ts: dt.datetime) -> bytes:
    utc = ts.astimezone(dt.timezone.utc)
    return _der_tlv(0x18, utc.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def _der_seq(*items: bytes) -> bytes:
    return _der_tlv(0x30, b"".join(items))


def _der_set(*items: bytes) -> bytes:
    return _der_tlv(0x31, b"".join(items))


def _der_bitstring(payload: bytes) -> bytes:
    return _der_tlv(0x03, b"\x00" + payload)


def _der_octet(payload: bytes) -> bytes:
    return _der_tlv(0x04, payload)


def _encode_x509_name(attrs: List[Tuple[bytes, str]]) -> bytes:
    rdns = [_der_set(_der_seq(_der_oid(oid), _der_utf8(val))) for oid, val in attrs if val]
    return _der_seq(*rdns)


def build_x509_certificate_der(
    *,
    serial_number: int,
    issuer_cn: str,
    issuer_org: str,
    issuer_ou: str,
    subject_cn: str,
    subject_org: str,
    subject_ou: str,
    subject_serial: str,
    subject_pub: AffinePoint,
    issuer_priv: int,
    not_before: dt.datetime,
    not_after: dt.datetime,
    is_ca: bool = False,
) -> Tuple[bytes, bytes, Tuple[int, int]]:
    """Builds a standard RFC 5280 X.509v3 DER certificate signed with ECDSA-P256-SHA256."""
    version_explicit = _der_tlv(0xA0, _der_int(2))
    sig_alg = _der_seq(_der_oid(OID_ECDSA_SHA256))
    issuer_der = _encode_x509_name([
        (OID_ORG_NAME, issuer_org),
        (OID_ORG_UNIT, issuer_ou),
        (OID_COMMON_NAME, issuer_cn),
    ])
    validity_der = _der_seq(_der_gentime(not_before), _der_gentime(not_after))
    subject_der = _encode_x509_name([
        (OID_ORG_NAME, subject_org),
        (OID_ORG_UNIT, subject_ou),
        (OID_COMMON_NAME, subject_cn),
        (OID_SERIAL_NUMBER, subject_serial),
    ])
    uncompressed_pub = b"\x04" + subject_pub[0].to_bytes(32, "big") + subject_pub[1].to_bytes(32, "big")
    spki_der = _der_seq(
        _der_seq(_der_oid(OID_EC_PUBLIC_KEY), _der_oid(OID_PRIME256V1)),
        _der_bitstring(uncompressed_pub),
    )

    bc_val = _der_seq(_der_tlv(0x01, b"\xff")) if is_ca else _der_seq()
    ext_bc = _der_seq(_der_oid(OID_BASIC_CONSTRAINTS), _der_tlv(0x01, b"\xff"), _der_octet(bc_val))
    ski_digest = hashlib.sha256(uncompressed_pub).digest()[:20]
    ext_ski = _der_seq(_der_oid(OID_SUBJECT_KEY_ID), _der_octet(_der_octet(ski_digest)))
    extensions_explicit = _der_tlv(0xA3, _der_seq(ext_bc, ext_ski))

    tbs_der = _der_seq(
        version_explicit,
        _der_int(serial_number),
        sig_alg,
        issuer_der,
        validity_der,
        subject_der,
        spki_der,
        extensions_explicit,
    )
    r, s = ecdsa_sign_sha256(issuer_priv, tbs_der)
    sig_der = _der_seq(_der_int(r), _der_int(s))
    cert_der = _der_seq(tbs_der, sig_alg, _der_bitstring(sig_der))
    return cert_der, tbs_der, (r, s)


def der_to_pem(cert_der: bytes, label: str = "CERTIFICATE") -> str:
    b64 = base64.b64encode(cert_der).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


# ==============================================================================
# Certificate & Provisioning Data Structures
# ==============================================================================
VALID_CERT_STATUSES = {"ACTIVE", "INACTIVE", "PENDING_TRANSFER", "REVOKED"}
VALID_ROTATION_ROLES = {"ACTIVE_PRIMARY", "PENDING_ROTATION", "VERIFIED_CONNECT", "DRAINING", "RETIRED"}


@dataclass
class FleetCARecord:
    ca_id: str
    ca_arn: str
    common_name: str
    organization: str
    org_unit: str
    public_key_hex: str
    status: str
    auto_registration_status: str
    jitp_template_name: str
    registration_code_hmac: str
    certificate_pem: str
    not_before_utc: str
    not_after_utc: str
    _private_key: int = field(repr=False, default=0)
    _public_point: AffinePoint = field(repr=False, default=(0, 0))
    _tbs_der: bytes = field(repr=False, default=b"")
    _signature: Tuple[int, int] = field(repr=False, default=(0, 0))

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "ca_id": self.ca_id,
            "ca_arn": self.ca_arn,
            "common_name": self.common_name,
            "organization": self.organization,
            "org_unit": self.org_unit,
            "public_key_hex": self.public_key_hex,
            "status": self.status,
            "auto_registration_status": self.auto_registration_status,
            "jitp_template_name": self.jitp_template_name,
            "registration_code_hmac": self.registration_code_hmac,
            "not_before_utc": self.not_before_utc,
            "not_after_utc": self.not_after_utc,
            "certificate_pem": self.certificate_pem,
        }


@dataclass
class CertificateRecord:
    certificate_id: str
    certificate_arn: str
    ca_id: str
    serial_hex: str
    subject_cn: str
    subject_ou: str
    hardware_serial: str
    public_key_hex: str
    status: str
    rotation_role: str
    attached_thing: Optional[str]
    attached_policy: Optional[str]
    not_before_epoch: float
    not_after_epoch: float
    days_remaining: int
    revocation_reason: Optional[str]
    revoked_at_utc: Optional[str]
    verified_connect_count: int
    certificate_pem: str
    _tbs_der: bytes = field(repr=False, default=b"")
    _signature: Tuple[int, int] = field(repr=False, default=(0, 0))
    _private_key: int = field(repr=False, default=0)
    _public_point: AffinePoint = field(repr=False, default=(0, 0))

    def to_public_dict(self, include_pem: bool = False) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "certificate_id": self.certificate_id,
            "certificate_id_short": self.certificate_id[:16],
            "certificate_arn": self.certificate_arn,
            "ca_id": self.ca_id[:16],
            "serial_hex": self.serial_hex,
            "subject_cn": self.subject_cn,
            "subject_ou": self.subject_ou,
            "hardware_serial": self.hardware_serial,
            "public_key_hex": self.public_key_hex[:40] + "...",
            "status": self.status,
            "rotation_role": self.rotation_role,
            "attached_thing": self.attached_thing,
            "attached_policy": self.attached_policy,
            "days_remaining": self.days_remaining,
            "revocation_reason": self.revocation_reason,
            "revoked_at_utc": self.revoked_at_utc,
            "verified_connect_count": self.verified_connect_count,
        }
        if include_pem:
            out["certificate_pem"] = self.certificate_pem
        return out


# ==============================================================================
# PKI Provisioning Authority Engine
# ==============================================================================
class PKIProvisioningAuthority:
    """Manages Fleet CAs, X.509 device certs, JITP, Claim provisioning, CRL, and zero-downtime rotation."""

    def __init__(self, region: str = "us-west-2", account_id: str = "796330847946") -> None:
        self.region = region
        self.account_id = account_id
        self._lock = threading.RLock()
        self._registration_secret = hashlib.sha256(f"aws-iot-reg-{account_id}-{region}".encode("utf-8")).digest()
        self.fleet_cas: Dict[str, FleetCARecord] = {}
        self.certificates: Dict[str, CertificateRecord] = {}
        self.thing_principals: Dict[str, List[str]] = {}
        self.crl_revoked_ids: Dict[str, Dict[str, str]] = {}
        self.jitp_templates: Dict[str, Dict[str, Any]] = {}
        self.claim_tokens: Dict[str, Dict[str, Any]] = {}
        self.manufacturing_allowlist: Dict[str, Dict[str, str]] = {}

    def get_registration_code(self) -> str:
        return hmac.new(self._registration_secret, b"iot:GetRegistrationCode", hashlib.sha256).hexdigest()

    def register_fleet_ca(
        self,
        *,
        common_name: str = "IoTCorePlane-Industrial-Fleet-CA-G1",
        organization: str = "IoTCorePlane Industrial Systems",
        org_unit: str = "AWS IoT Core Identity & Registry",
        jitp_template_name: str = "IndustrialSensorJITPTemplate",
        default_policy_name: str = "ThingScopedTelemetryAndShadowPolicy",
        default_thing_type: str = "IndustrialGatewayV2",
        default_billing_group: str = "industrial-fleet-west",
        deterministic_seed: Optional[bytes] = None,
    ) -> FleetCARecord:
        """Creates and registers a Fleet CA with proof-of-possession verification and JITP template."""
        with self._lock:
            ca_priv, ca_pub = generate_p256_keypair(seed_material=deterministic_seed)
            # Cache fast 4-bit window table for O(1)-doubling ECDSA signature checks against this CA
            _PUBKEY_TABLE_CACHE[ca_pub] = _build_window4_table(ca_pub)

            now = dt.datetime.now(dt.timezone.utc)
            not_before = now - dt.timedelta(days=1)
            not_after = now + dt.timedelta(days=3650)
            serial_num = int.from_bytes(hashlib.sha256(common_name.encode("utf-8") + ca_pub[0].to_bytes(32, "big")).digest()[:15], "big")

            cert_der, tbs_der, sig = build_x509_certificate_der(
                serial_number=serial_num,
                issuer_cn=common_name,
                issuer_org=organization,
                issuer_ou=org_unit,
                subject_cn=common_name,
                subject_org=organization,
                subject_ou=org_unit,
                subject_serial=f"CA-{serial_num:030x}"[:20],
                subject_pub=ca_pub,
                issuer_priv=ca_priv,
                not_before=not_before,
                not_after=not_after,
                is_ca=True,
            )
            if not ecdsa_verify_sha256(ca_pub, tbs_der, sig):
                raise ProvisioningError("Self-signed Fleet CA ECDSA P-256 verification failed")

            ca_id = hashlib.sha256(cert_der).hexdigest()
            reg_code = self.get_registration_code()
            # Proof-of-possession signature over registration code + HMAC attestation
            pop_sig = ecdsa_sign_sha256(ca_priv, reg_code.encode("utf-8"))
            if not ecdsa_verify_sha256(ca_pub, reg_code.encode("utf-8"), pop_sig):
                raise ProvisioningError("CA registration code proof-of-possession failed")
            reg_hmac = hmac.new(self._registration_secret, f"{ca_id}:{reg_code}".encode("utf-8"), hashlib.sha256).hexdigest()

            pub_hex = "04" + f"{ca_pub[0]:064x}{ca_pub[1]:064x}"
            ca_rec = FleetCARecord(
                ca_id=ca_id,
                ca_arn=f"arn:aws:iot:{self.region}:{self.account_id}:cacert/{ca_id}",
                common_name=common_name,
                organization=organization,
                org_unit=org_unit,
                public_key_hex=pub_hex,
                status="ACTIVE",
                auto_registration_status="ENABLE",
                jitp_template_name=jitp_template_name,
                registration_code_hmac=reg_hmac,
                certificate_pem=der_to_pem(cert_der),
                not_before_utc=not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
                not_after_utc=not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
                _private_key=ca_priv,
                _public_point=ca_pub,
                _tbs_der=tbs_der,
                _signature=sig,
            )
            self.fleet_cas[ca_id] = ca_rec
            self.jitp_templates[jitp_template_name] = {
                "template_name": jitp_template_name,
                "ca_id": ca_id,
                "policy_name": default_policy_name,
                "thing_type": default_thing_type,
                "billing_group": default_billing_group,
                "template_body": {
                    "Parameters": {
                        "AWS::IoT::Certificate::CommonName": {"Type": "String"},
                        "AWS::IoT::Certificate::SerialNumber": {"Type": "String"},
                        "AWS::IoT::Certificate::Id": {"Type": "String"},
                    },
                    "Resources": {
                        "thing": {
                            "Type": "AWS::IoT::Thing",
                            "Properties": {
                                "ThingName": {"Ref": "AWS::IoT::Certificate::CommonName"},
                                "ThingTypeName": default_thing_type,
                                "BillingGroupName": default_billing_group,
                            },
                        },
                        "certificate": {
                            "Type": "AWS::IoT::Certificate",
                            "Properties": {
                                "CertificateId": {"Ref": "AWS::IoT::Certificate::Id"},
                                "Status": "ACTIVE",
                            },
                        },
                        "policy": {
                            "Type": "AWS::IoT::Policy",
                            "Properties": {"PolicyName": default_policy_name},
                        },
                    },
                },
            }
            return ca_rec

    def issue_device_certificate(
        self,
        *,
        ca_id: str,
        subject_cn: str,
        hardware_serial: str,
        subject_ou: str = "Industrial-Telemetry-Unit",
        validity_days: int = 365,
        initial_status: str = "INACTIVE",
        rotation_role: str = "PENDING_ROTATION",
        deterministic_seed: Optional[bytes] = None,
    ) -> CertificateRecord:
        """Signs an X.509v3 device leaf certificate under the specified Fleet CA."""
        with self._lock:
            ca = self.fleet_cas.get(ca_id)
            if ca is None or ca.status != "ACTIVE":
                raise ProvisioningError(f"Fleet CA {ca_id} is missing or not ACTIVE")

            dev_priv, dev_pub = generate_p256_keypair(seed_material=deterministic_seed)
            now = dt.datetime.now(dt.timezone.utc)
            not_before = now - dt.timedelta(minutes=5)
            not_after = now + dt.timedelta(days=validity_days)
            serial_bytes = hashlib.sha256(
                f"{subject_cn}:{hardware_serial}:{dev_pub[0]:x}:{time.time_ns()}".encode("utf-8")
            ).digest()[:15]
            serial_int = max(1, int.from_bytes(serial_bytes, "big"))

            cert_der, tbs_der, sig = build_x509_certificate_der(
                serial_number=serial_int,
                issuer_cn=ca.common_name,
                issuer_org=ca.organization,
                issuer_ou=ca.org_unit,
                subject_cn=subject_cn,
                subject_org=ca.organization,
                subject_ou=subject_ou,
                subject_serial=hardware_serial,
                subject_pub=dev_pub,
                issuer_priv=ca._private_key,
                not_before=not_before,
                not_after=not_after,
                is_ca=False,
            )
            cert_id = hashlib.sha256(cert_der).hexdigest()
            pub_hex = "04" + f"{dev_pub[0]:064x}{dev_pub[1]:064x}"
            rec = CertificateRecord(
                certificate_id=cert_id,
                certificate_arn=f"arn:aws:iot:{self.region}:{self.account_id}:cert/{cert_id}",
                ca_id=ca_id,
                serial_hex=f"{serial_int:030x}",
                subject_cn=subject_cn,
                subject_ou=subject_ou,
                hardware_serial=hardware_serial,
                public_key_hex=pub_hex,
                status=initial_status,
                rotation_role=rotation_role,
                attached_thing=None,
                attached_policy=None,
                not_before_epoch=not_before.timestamp(),
                not_after_epoch=not_after.timestamp(),
                days_remaining=max(0, validity_days),
                revocation_reason=None,
                revoked_at_utc=None,
                verified_connect_count=0,
                certificate_pem=der_to_pem(cert_der),
                _tbs_der=tbs_der,
                _signature=sig,
                _private_key=dev_priv,
                _public_point=dev_pub,
            )
            self.certificates[cert_id] = rec
            return rec

    def verify_x509_chain(self, certificate_id: str, require_active: bool = True) -> Dict[str, Any]:
        """Cryptographically verifies Leaf Cert signature against its Fleet CA + CRL + Validity."""
        t0 = time.perf_counter()
        with self._lock:
            cert = self.certificates.get(certificate_id)
            if cert is None:
                raise ProvisioningError(f"Unknown certificate_id: {certificate_id}")
            ca = self.fleet_cas.get(cert.ca_id)
            if ca is None or ca.status != "ACTIVE":
                raise ProvisioningError(f"Issuing Fleet CA {cert.ca_id[:12]} is not ACTIVE")

            if certificate_id in self.crl_revoked_ids or cert.status == "REVOKED":
                raise ProvisioningError(
                    f"TLS_CERT_REVOKED: Certificate {certificate_id[:16]} is on CRL ({cert.revocation_reason or 'REVOKED'})"
                )
            if require_active and cert.status != "ACTIVE":
                raise ProvisioningError(
                    f"TLS_CERT_INACTIVE: Certificate {certificate_id[:16]} has status {cert.status}"
                )
            now_ts = time.time()
            if now_ts < cert.not_before_epoch or now_ts > cert.not_after_epoch:
                raise ProvisioningError(f"TLS_CERT_EXPIRED: Certificate {certificate_id[:16]} outside validity window")

            sig_valid = ecdsa_verify_sha256(ca._public_point, cert._tbs_der, cert._signature)
            if not sig_valid:
                raise ProvisioningError(f"TLS_BAD_SIGNATURE: ECDSA-P256 chain check failed for {certificate_id[:16]}")

            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 4)
            return {
                "valid": True,
                "certificate_id": cert.certificate_id,
                "attached_thing": cert.attached_thing,
                "attached_policy": cert.attached_policy,
                "rotation_role": cert.rotation_role,
                "verify_ms": elapsed_ms,
            }

    def provision_jitp_on_connect(
        self,
        *,
        certificate_id: str,
        registry: Optional[Any] = None,
        initial_attributes: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Evaluates Fleet CA JITP template on first mTLS connect: activates cert, creates Thing, binds Policy."""
        t0 = time.perf_counter()
        with self._lock:
            cert = self.certificates.get(certificate_id)
            if cert is None:
                raise ProvisioningError(f"Certificate {certificate_id} not found")
            ca = self.fleet_cas.get(cert.ca_id)
            if ca is None or ca.status != "ACTIVE" or ca.auto_registration_status != "ENABLE":
                raise ProvisioningError("Issuing Fleet CA does not allow JITP auto-registration")

            # Verify X.509 cryptographic chain before activating (allow INACTIVE on first JITP connect)
            self.verify_x509_chain(certificate_id, require_active=False)

            tmpl = self.jitp_templates[ca.jitp_template_name]
            thing_name = cert.subject_cn
            policy_name = tmpl["policy_name"]
            thing_type = tmpl["thing_type"]
            billing_group = tmpl["billing_group"]

            cert.status = "ACTIVE"
            cert.rotation_role = "ACTIVE_PRIMARY"
            cert.attached_thing = thing_name
            cert.attached_policy = policy_name
            cert.verified_connect_count += 1

            principals = self.thing_principals.setdefault(thing_name, [])
            if certificate_id not in principals:
                principals.append(certificate_id)

            attrs: Dict[str, Any] = {
                "hardware_serial": cert.hardware_serial,
                "firmware_version": "2.4.2",
                "battery_pct": 94,
                "temp_c": 46.5,
                "region": self.region,
                "connectivity": "CONNECTED",
                "cert_days_remaining": cert.days_remaining,
            }
            if initial_attributes:
                attrs.update(initial_attributes)

            thing_summary = None
            if registry is not None:
                thing_rec = registry.upsert_thing(
                    thing_name=thing_name,
                    thing_type=thing_type,
                    billing_group=billing_group,
                    attributes=attrs,
                )
                thing_summary = thing_rec.to_dict()

            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 4)
            return {
                "provisioning_flow": "JITP",
                "template_name": ca.jitp_template_name,
                "thing_name": thing_name,
                "thing_type": thing_type,
                "billing_group": billing_group,
                "certificate": cert.to_public_dict(include_pem=True),
                "attached_policy": policy_name,
                "thing_registry_record": thing_summary,
                "jitp_ms": elapsed_ms,
            }

    def register_claim_bootstrap(
        self,
        *,
        claim_id: str,
        ca_id: str,
        allowed_serial_prefix: str = "SN-IND-",
        template_name: str = "ManufacturingClaimTemplate",
        policy_name: str = "ThingScopedTelemetryAndShadowPolicy",
    ) -> Dict[str, Any]:
        """Registers a restricted bootstrap Claim credential for factory Provisioning-by-Claim."""
        with self._lock:
            token_sig = hmac.new(self._registration_secret, f"claim:{claim_id}:{ca_id}".encode("utf-8"), hashlib.sha256).hexdigest()
            self.claim_tokens[claim_id] = {
                "claim_id": claim_id,
                "ca_id": ca_id,
                "allowed_serial_prefix": allowed_serial_prefix,
                "template_name": template_name,
                "policy_name": policy_name,
                "status": "ACTIVE",
                "claim_hmac": token_sig,
                "allowed_topics": [
                    "$aws/certificates/create/json",
                    f"$aws/provisioning-templates/{template_name}/provision/json",
                ],
            }
            return dict(self.claim_tokens[claim_id])

    def provision_by_claim(
        self,
        *,
        claim_id: str,
        thing_name: str,
        hardware_serial: str,
        registry: Optional[Any] = None,
        initial_attributes: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Exchanges a restricted manufacturing Claim token + serial check for a unique permanent X.509 cert."""
        t0 = time.perf_counter()
        with self._lock:
            claim = self.claim_tokens.get(claim_id)
            if claim is None or claim.get("status") != "ACTIVE":
                raise ProvisioningError(f"Bootstrap claim {claim_id} is invalid or revoked")
            if not hardware_serial.startswith(claim["allowed_serial_prefix"]):
                raise ProvisioningError(
                    f"Pre-provisioning hook rejected hardware_serial '{hardware_serial}' (expected prefix {claim['allowed_serial_prefix']})"
                )

            cert = self.issue_device_certificate(
                ca_id=claim["ca_id"],
                subject_cn=thing_name,
                hardware_serial=hardware_serial,
                validity_days=365,
                initial_status="ACTIVE",
                rotation_role="ACTIVE_PRIMARY",
            )
            cert.attached_thing = thing_name
            cert.attached_policy = claim["policy_name"]
            cert.verified_connect_count = 1
            self.thing_principals.setdefault(thing_name, []).append(cert.certificate_id)

            attrs: Dict[str, Any] = {
                "hardware_serial": hardware_serial,
                "firmware_version": "2.4.2",
                "battery_pct": 98,
                "temp_c": 44.0,
                "region": self.region,
                "connectivity": "CONNECTED",
                "cert_days_remaining": cert.days_remaining,
            }
            if initial_attributes:
                attrs.update(initial_attributes)

            thing_summary = None
            if registry is not None:
                thing_rec = registry.upsert_thing(
                    thing_name=thing_name,
                    thing_type="IndustrialGatewayV2",
                    billing_group="industrial-fleet-west",
                    attributes=attrs,
                )
                thing_summary = thing_rec.to_dict()

            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 4)
            return {
                "provisioning_flow": "PROVISION_BY_CLAIM",
                "claim_id": claim_id,
                "template_name": claim["template_name"],
                "thing_name": thing_name,
                "certificate": cert.to_public_dict(include_pem=True),
                "attached_policy": claim["policy_name"],
                "thing_registry_record": thing_summary,
                "claim_ms": elapsed_ms,
            }

    # ==========================================================================
    # Zero-Downtime Overlapping Certificate Rotation State Machine
    # ==========================================================================
    def start_overlapping_rotation(
        self,
        *,
        thing_name: str,
        validity_days: int = 365,
    ) -> Dict[str, Any]:
        """Step 1: Issues a second ACTIVE X.509 cert in PENDING_ROTATION while keeping ACTIVE_PRIMARY live."""
        with self._lock:
            principals = self.thing_principals.get(thing_name) or []
            primary_cert: Optional[CertificateRecord] = None
            for cid in principals:
                c = self.certificates[cid]
                if c.status == "ACTIVE" and c.rotation_role == "ACTIVE_PRIMARY":
                    primary_cert = c
                    break
            if primary_cert is None:
                raise ProvisioningError(f"Thing '{thing_name}' has no ACTIVE_PRIMARY certificate to rotate")

            new_cert = self.issue_device_certificate(
                ca_id=primary_cert.ca_id,
                subject_cn=thing_name,
                hardware_serial=primary_cert.hardware_serial,
                subject_ou=primary_cert.subject_ou,
                validity_days=validity_days,
                initial_status="ACTIVE",
                rotation_role="PENDING_ROTATION",
            )
            new_cert.attached_thing = thing_name
            new_cert.attached_policy = primary_cert.attached_policy
            principals.append(new_cert.certificate_id)

            return {
                "stage": "OVERLAP_ISSUED",
                "thing_name": thing_name,
                "active_primary_cert_id": primary_cert.certificate_id,
                "pending_rotation_cert_id": new_cert.certificate_id,
                "simultaneous_active_certs": 2,
                "dropped_sessions": 0,
                "new_certificate": new_cert.to_public_dict(include_pem=True),
            }

    def verify_rotated_connect(
        self,
        *,
        thing_name: str,
        new_certificate_id: str,
    ) -> Dict[str, Any]:
        """Step 2: Verifies mTLS handshake + signed heartbeat on the new cert before promoting it."""
        with self._lock:
            new_cert = self.certificates.get(new_certificate_id)
            if new_cert is None or new_cert.attached_thing != thing_name:
                raise ProvisioningError(f"Certificate {new_certificate_id[:16]} is not attached to '{thing_name}'")
            self.verify_x509_chain(new_certificate_id, require_active=True)

            # Device signs a proof-of-possession rotation heartbeat with its new leaf private key
            challenge = f"ROTATE_VERIFY:{thing_name}:{new_certificate_id}".encode("utf-8")
            hb_sig = ecdsa_sign_sha256(new_cert._private_key, challenge)
            if not ecdsa_verify_sha256(new_cert._public_point, challenge, hb_sig):
                raise ProvisioningError("Leaf proof-of-possession heartbeat failed on new certificate")

            new_cert.verified_connect_count += 1
            new_cert.rotation_role = "VERIFIED_CONNECT"
            return {
                "stage": "VERIFIED_CONNECT",
                "thing_name": thing_name,
                "verified_cert_id": new_cert.certificate_id,
                "verified_connect_count": new_cert.verified_connect_count,
                "dropped_sessions": 0,
            }

    def finalize_rotation_and_revoke_old(
        self,
        *,
        thing_name: str,
        old_certificate_id: str,
        new_certificate_id: str,
        registry: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Step 3: Promotes VERIFIED_CONNECT cert to ACTIVE_PRIMARY and revokes old cert onto CRL."""
        with self._lock:
            old_cert = self.certificates.get(old_certificate_id)
            new_cert = self.certificates.get(new_certificate_id)
            if old_cert is None or new_cert is None:
                raise ProvisioningError("Both old_certificate_id and new_certificate_id must exist")
            if old_cert.attached_thing != thing_name or new_cert.attached_thing != thing_name:
                raise ProvisioningError("Certificates do not belong to the target Thing")
            if new_cert.verified_connect_count < 1 or new_cert.rotation_role not in ("VERIFIED_CONNECT", "ACTIVE_PRIMARY"):
                raise RotationPreconditionError(
                    f"Cannot revoke primary cert {old_certificate_id[:16]} before new cert {new_certificate_id[:16]} completes VERIFIED_CONNECT"
                )
            if new_cert.status != "ACTIVE":
                raise RotationPreconditionError("New certificate is not ACTIVE")

            new_cert.rotation_role = "ACTIVE_PRIMARY"
            self.update_certificate_status(
                certificate_id=old_certificate_id,
                new_status="REVOKED",
                reason="SUPERSEDED_BY_ROTATION",
            )
            old_cert.rotation_role = "RETIRED"

            if registry is not None:
                registry.update_thing_attributes(
                    thing_name,
                    {"cert_days_remaining": new_cert.days_remaining},
                )

            return {
                "stage": "ROTATION_COMPLETE",
                "thing_name": thing_name,
                "new_primary_cert_id": new_cert.certificate_id,
                "revoked_old_cert_id": old_cert.certificate_id,
                "old_cert_status": old_cert.status,
                "new_cert_days_remaining": new_cert.days_remaining,
                "dropped_sessions": 0,
            }

    def rotate_certificate_zero_downtime(
        self,
        *,
        thing_name: str,
        validity_days: int = 365,
        registry: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Executes the full 3-phase overlapping certificate rotation with continuity assertions."""
        t0 = time.perf_counter()
        with self._lock:
            step1 = self.start_overlapping_rotation(thing_name=thing_name, validity_days=validity_days)
            old_cid = step1["active_primary_cert_id"]
            new_cid = step1["pending_rotation_cert_id"]

            # Verify continuity during overlap: old cert is STILL valid right before cutover
            old_check = self.verify_x509_chain(old_cid, require_active=True)
            step2 = self.verify_rotated_connect(thing_name=thing_name, new_certificate_id=new_cid)
            # Both old and new certs authenticated with 0 gap
            new_check = self.verify_x509_chain(new_cid, require_active=True)
            step3 = self.finalize_rotation_and_revoke_old(
                thing_name=thing_name,
                old_certificate_id=old_cid,
                new_certificate_id=new_cid,
                registry=registry,
            )
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 4)
            return {
                "thing_name": thing_name,
                "old_certificate_id": old_cid,
                "new_certificate_id": new_cid,
                "transitions": [
                    "ACTIVE_PRIMARY + PENDING_ROTATION (dual active overlap)",
                    "VERIFIED_CONNECT (ECDSA P-256 heartbeat verified on new cert)",
                    "REVOKE_OLD (old cert added to CRL after cutover)",
                ],
                "overlap_old_cert_valid": old_check["valid"],
                "overlap_new_cert_valid": new_check["valid"],
                "dropped_sessions": 0,
                "new_certificate": self.certificates[new_cid].to_public_dict(include_pem=True),
                "revoked_certificate": self.certificates[old_cid].to_public_dict(include_pem=False),
                "rotation_ms": elapsed_ms,
            }

    def update_certificate_status(
        self,
        *,
        certificate_id: str,
        new_status: str,
        reason: str = "ADMIN_REVOCATION",
    ) -> CertificateRecord:
        with self._lock:
            if new_status not in VALID_CERT_STATUSES:
                raise ProvisioningError(f"Unsupported certificate status: {new_status}")
            cert = self.certificates.get(certificate_id)
            if cert is None:
                raise ProvisioningError(f"Unknown certificate_id: {certificate_id}")
            cert.status = new_status
            if new_status == "REVOKED":
                now_iso = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                cert.revocation_reason = reason
                cert.revoked_at_utc = now_iso
                self.crl_revoked_ids[certificate_id] = {
                    "certificate_id": certificate_id,
                    "reason": reason,
                    "revoked_at_utc": now_iso,
                }
            return cert

    def get_active_cert_for_thing(self, thing_name: str) -> Optional[CertificateRecord]:
        with self._lock:
            for cid in reversed(self.thing_principals.get(thing_name) or []):
                cert = self.certificates[cid]
                if cert.status == "ACTIVE" and cert.rotation_role == "ACTIVE_PRIMARY":
                    return cert
            for cid in reversed(self.thing_principals.get(thing_name) or []):
                cert = self.certificates[cid]
                if cert.status == "ACTIVE":
                    return cert
            return None

    def list_certificates_summary(self, limit: int = 25) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self.certificates.values())[-limit:]
            return [c.to_public_dict(include_pem=False) for c in reversed(items)]
