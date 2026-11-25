"""Local HTTP Server & AWS CloudFront `/api/*` Lambda Origin Handler for IoTCorePlane."""
from __future__ import annotations

import base64
import json
import mimetypes
import os
import platform
import shutil
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .device_shadow import BedrockFleetCopilot, DeviceShadowEngine, VersionConflictError
from .pki_provisioning import (
    PKIProvisioningAuthority,
    ProvisioningError,
    RotationPreconditionError,
)
from .policy_gate import IoTPolicyGate
from .registry_groups import ThingRegistry

ROOT_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT_DIR / "web"
DOCS_DIR = ROOT_DIR / "docs"
BENCHMARKS_FILE = ROOT_DIR / "benchmarks" / "latest_results.json"

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}


class IoTCoreControlPlane:
    """Coordinates PKI JITP/Rotation, Policy Gate, Thing Registry, Device Shadow & Bedrock Copilot."""

    def __init__(self, runtime_dir: Optional[Path] = None) -> None:
        self.runtime_dir = Path(runtime_dir or os.environ.get("IOTCOREPLANE_RUNTIME_DIR", "/tmp/iotcoreplane-runtime"))
        self.region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-west-2"
        self.account_id = "796330847946"
        self._lock = threading.RLock()
        self.audit_feed: List[Dict[str, Any]] = []
        self.copilot = BedrockFleetCopilot(region=self.region)
        self._init_seeded_fleet(clean_disk=True)

    def _record_event(self, category: str, target: str, verdict: str, latency_ms: float, detail: str) -> None:
        entry = {
            "event_id": f"IOT-{len(self.audit_feed) + 1:04d}",
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "category": category,
            "target": target,
            "verdict": verdict,
            "latency_ms": round(latency_ms, 3),
            "detail": detail,
        }
        self.audit_feed.append(entry)
        if len(self.audit_feed) > 60:
            self.audit_feed = self.audit_feed[-60:]

    def _init_seeded_fleet(self, clean_disk: bool = False) -> None:
        with self._lock:
            if clean_disk and self.runtime_dir.exists():
                shutil.rmtree(self.runtime_dir, ignore_errors=True)
            self.runtime_dir.mkdir(parents=True, exist_ok=True)
            self.audit_feed = []

            self.pki = PKIProvisioningAuthority(region=self.region, account_id=self.account_id)
            self.registry = ThingRegistry(
                db_path=self.runtime_dir / "iot_registry.db",
                region=self.region,
                account_id=self.account_id,
            )
            self.policy_gate = IoTPolicyGate(pki=self.pki, region=self.region, account_id=self.account_id)
            self.shadows = DeviceShadowEngine(
                db_path=self.runtime_dir / "iot_shadows.db",
                registry=self.registry,
            )

            # 1. Register Fleet CA + Bootstrap Claim Token
            ca = self.pki.register_fleet_ca(
                common_name="IoTCorePlane-Industrial-Fleet-CA-G1",
                deterministic_seed=b"iotcoreplane-demo-fleet-ca-v1",
            )
            self.default_ca_id = ca.ca_id
            self.pki.register_claim_bootstrap(
                claim_id="claim-factory-line-01",
                ca_id=ca.ca_id,
                allowed_serial_prefix="SN-IND-",
            )

            # 2. Register 4 AWS IoT Dynamic Thing Groups backed by inverted index
            self.registry.create_dynamic_thing_group(
                group_name="overheating-legacy-fw",
                query_string="firmware_version < 2.4.0 AND temp_c > 75",
                description="Devices on legacy firmware (< 2.4.0) running above 75 C thermal threshold",
            )
            self.registry.create_dynamic_thing_group(
                group_name="cert-rotation-due-14d",
                query_string="cert_days_remaining <= 14 AND connectivity = CONNECTED",
                description="Connected devices with X.509 leaf certificates expiring within 14 days",
            )
            self.registry.create_dynamic_thing_group(
                group_name="low-battery-offline",
                query_string="battery_pct < 20 AND connectivity = DISCONNECTED",
                description="Disconnected field sensors reporting critical battery below 20%",
            )
            self.registry.create_dynamic_thing_group(
                group_name="healthy-production-v24",
                query_string="firmware_version >= 2.4.0 AND connectivity = CONNECTED",
                description="Production gateways on current 2.4.x+ firmware with active mTLS sessions",
            )

            # 3. Seed representative industrial Thing fleet via JITP + Device Shadows
            seed_specs = [
                ("turbine-gw-001", "SN-IND-1001", 9, {"firmware_version": "2.3.1", "temp_c": 82.4, "battery_pct": 88, "connectivity": "CONNECTED"}, {"sampling_hz": 50, "valve_state": "CLOSED", "firmware_target": "2.4.2"}, {"sampling_hz": 10, "valve_state": "OPEN", "firmware_target": "2.3.1", "temp_c": 82.4}),
                ("turbine-gw-002", "SN-IND-1002", 11, {"firmware_version": "2.4.2", "temp_c": 51.0, "battery_pct": 95, "connectivity": "CONNECTED"}, {"sampling_hz": 25, "valve_state": "OPEN"}, {"sampling_hz": 25, "valve_state": "OPEN", "temp_c": 51.0}),
                ("coldchain-sensor-042", "SN-IND-1042", 180, {"firmware_version": "2.4.2", "temp_c": 4.2, "battery_pct": 91, "connectivity": "CONNECTED"}, {"target_temp_c": 4.0, "alarm_armed": True}, {"target_temp_c": 4.0, "alarm_armed": True, "temp_c": 4.2}),
                ("coldchain-sensor-099", "SN-IND-1099", 5, {"firmware_version": "2.2.8", "temp_c": 79.6, "battery_pct": 64, "connectivity": "CONNECTED"}, {"target_temp_c": 4.0, "firmware_target": "2.4.2"}, {"target_temp_c": 12.5, "firmware_target": "2.2.8", "temp_c": 79.6}),
                ("field-valve-017", "SN-IND-1017", 120, {"firmware_version": "2.3.5", "temp_c": 41.0, "battery_pct": 14, "connectivity": "DISCONNECTED"}, {"sleep_interval_sec": 300, "valve_state": "CLOSED"}, {"sleep_interval_sec": 60, "valve_state": "OPEN", "battery_pct": 14}),
                ("substation-mtr-008", "SN-IND-1008", 290, {"firmware_version": "2.4.5", "temp_c": 48.2, "battery_pct": 99, "connectivity": "CONNECTED"}, {"grid_relay": "ENGAGED", "telemetry_sec": 15}, {"grid_relay": "ENGAGED", "telemetry_sec": 15, "temp_c": 48.2}),
            ]

            for t_name, serial, valid_days, attrs, des, rep in seed_specs:
                leaf = self.pki.issue_device_certificate(
                    ca_id=ca.ca_id,
                    subject_cn=t_name,
                    hardware_serial=serial,
                    validity_days=valid_days,
                    deterministic_seed=f"seed-leaf-{t_name}".encode("utf-8"),
                )
                res = self.pki.provision_jitp_on_connect(
                    certificate_id=leaf.certificate_id,
                    registry=self.registry,
                    initial_attributes=attrs,
                )
                self.shadows.update_shadow(
                    thing_name=t_name,
                    desired=des,
                    reported=rep,
                    sync_registry=False,
                )
                self._record_event(
                    "JITP_PROVISION",
                    t_name,
                    "ACTIVE_PRIMARY",
                    res["jitp_ms"],
                    f"JITP registered {t_name} with cert {leaf.certificate_id[:12]} ({valid_days}d validity)",
                )

    def reset(self) -> Dict[str, Any]:
        self._init_seeded_fleet(clean_disk=True)
        return self.get_state_snapshot()

    def load_benchmarks(self) -> Dict[str, Any]:
        if BENCHMARKS_FILE.is_file():
            try:
                return json.loads(BENCHMARKS_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"status": "pending_run"}

    def get_state_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            things = self.registry.list_things(limit=25)
            things_enriched = []
            for t in things:
                active_cert = self.pki.get_active_cert_for_thing(t["thing_name"])
                sh = self.shadows.get_shadow(t["thing_name"])
                t_copy = dict(t)
                t_copy["active_certificate"] = active_cert.to_public_dict(include_pem=False) if active_cert else None
                t_copy["shadow"] = sh
                things_enriched.append(t_copy)

            return {
                "fleet_ca": self.pki.fleet_cas[self.default_ca_id].to_public_dict(),
                "things": things_enriched,
                "dynamic_groups": self.registry.list_dynamic_groups(),
                "certificates": self.pki.list_certificates_summary(limit=20),
                "crl_revoked_count": len(self.pki.crl_revoked_ids),
                "shadow_conflict_count": self.shadows.conflict_count,
                "default_policy": self.policy_gate.get_policy("ThingScopedTelemetryAndShadowPolicy"),
                "audit_feed": list(reversed(self.audit_feed[-20:])),
                "benchmarks": self.load_benchmarks(),
            }

    def handle_jitp_or_claim(self, body: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            mode = str(body.get("mode") or "jitp").strip().lower()
            thing_name = str(body.get("thing_name") or f"sensor-gw-{len(self.pki.thing_principals) + 101}").strip()
            hardware_serial = str(body.get("hardware_serial") or f"SN-IND-{1200 + len(self.pki.certificates)}").strip()
            validity_days = int(body.get("validity_days") or 365)
            attrs = body.get("attributes") if isinstance(body.get("attributes"), dict) else {}

            if mode == "claim":
                claim_id = str(body.get("claim_id") or "claim-factory-line-01").strip()
                out = self.pki.provision_by_claim(
                    claim_id=claim_id,
                    thing_name=thing_name,
                    hardware_serial=hardware_serial,
                    registry=self.registry,
                    initial_attributes=attrs,
                )
                self.shadows.update_shadow(
                    thing_name=thing_name,
                    desired={"telemetry_sec": 30, "firmware_target": "2.4.2"},
                    reported={"telemetry_sec": 30, "firmware_target": attrs.get("firmware_version", "2.4.2")},
                    sync_registry=False,
                )
                self._record_event(
                    "CLAIM_PROVISION",
                    thing_name,
                    "ACTIVE_PRIMARY",
                    out["claim_ms"],
                    f"Claim {claim_id} minted X.509 cert {out['certificate']['certificate_id_short']}",
                )
                out["dynamic_groups"] = self.registry.list_dynamic_groups()
                return out

            leaf = self.pki.issue_device_certificate(
                ca_id=self.default_ca_id,
                subject_cn=thing_name,
                hardware_serial=hardware_serial,
                validity_days=validity_days,
            )
            out = self.pki.provision_jitp_on_connect(
                certificate_id=leaf.certificate_id,
                registry=self.registry,
                initial_attributes=attrs,
            )
            self.shadows.update_shadow(
                thing_name=thing_name,
                desired={"sampling_hz": 25, "firmware_target": "2.4.2"},
                reported={"sampling_hz": 25, "firmware_target": attrs.get("firmware_version", "2.4.2")},
                sync_registry=False,
            )
            self._record_event(
                "JITP_PROVISION",
                thing_name,
                "ACTIVE_PRIMARY",
                out["jitp_ms"],
                f"First-connect JITP bound {leaf.certificate_id[:12]} -> {thing_name}",
            )
            out["dynamic_groups"] = self.registry.list_dynamic_groups()
            return out

    def handle_cert_rotate(self, body: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            action = str(body.get("action") or "rotate_zero_downtime").strip().lower()
            thing_name = str(body.get("thing_name") or "turbine-gw-001").strip()
            validity_days = int(body.get("validity_days") or 365)

            if action == "revoke":
                cert_id = str(body.get("certificate_id") or "").strip()
                if not cert_id:
                    active = self.pki.get_active_cert_for_thing(thing_name)
                    if not active:
                        raise ProvisioningError(f"No active certificate found for {thing_name}")
                    cert_id = active.certificate_id
                rec = self.pki.update_certificate_status(
                    certificate_id=cert_id,
                    new_status="REVOKED",
                    reason=str(body.get("reason") or "COMPROMISED_KEY_EMERGENCY_CRL"),
                )
                self._record_event(
                    "CERT_CRL_REVOKE",
                    thing_name,
                    "REVOKED",
                    0.05,
                    f"Added cert {cert_id[:12]} to CRL ({rec.revocation_reason})",
                )
                return {
                    "action": "revoke",
                    "thing_name": thing_name,
                    "certificate": rec.to_public_dict(include_pem=False),
                    "crl_revoked_count": len(self.pki.crl_revoked_ids),
                }

            out = self.pki.rotate_certificate_zero_downtime(
                thing_name=thing_name,
                validity_days=validity_days,
                registry=self.registry,
            )
            self._record_event(
                "ZERO_DOWNTIME_ROTATE",
                thing_name,
                "ROTATION_COMPLETE",
                out["rotation_ms"],
                f"Rotated {out['old_certificate_id'][:10]} -> {out['new_certificate_id'][:10]} (0 dropped sessions)",
            )
            out["dynamic_groups"] = self.registry.list_dynamic_groups()
            return out

    def handle_policy_evaluate(self, body: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            thing_name = str(body.get("thing_name") or "coldchain-sensor-042").strip()
            action = str(body.get("action") or "iot:Publish").strip()
            topic_or_client = str(
                body.get("topic") or body.get("resource") or f"$aws/things/{thing_name}/shadow/update"
            ).strip()
            client_id = str(body.get("client_id") or thing_name).strip()
            cert_id = body.get("certificate_id")
            if cert_id is None and body.get("use_attached_cert", True):
                active = self.pki.get_active_cert_for_thing(thing_name)
                if active is not None:
                    cert_id = active.certificate_id

            attrs: Dict[str, Any] = {}
            thing_type = "IndustrialGatewayV2"
            try:
                t_rec = self.registry.get_thing(thing_name)
                attrs = t_rec.attributes
                thing_type = t_rec.thing_type
            except KeyError:
                pass

            decision = self.policy_gate.evaluate(
                thing_name=thing_name,
                action=action,
                topic_or_client=topic_or_client,
                client_id=client_id,
                certificate_id=str(cert_id) if cert_id else None,
                policy_document=body.get("policy_document") if isinstance(body.get("policy_document"), dict) else None,
                thing_type=thing_type,
                attributes=attrs,
            )
            out = decision.to_dict()
            self._record_event(
                "IOT_POLICY_GATE",
                f"{thing_name} -> {action}",
                decision.verdict,
                decision.eval_ms,
                f"{topic_or_client} ({decision.reason_code})",
            )
            return out

    def handle_registry_search_or_mutate(self, body: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            op = str(body.get("operation") or "query").strip().lower()
            if op == "update_attributes":
                thing_name = str(body.get("thing_name") or "turbine-gw-001").strip()
                patch = body.get("attributes") if isinstance(body.get("attributes"), dict) else {}
                res = self.registry.update_thing_attributes(thing_name, patch)
                lin = self.registry.full_linear_scan_all_groups()
                res["linear_scan_baseline_ms"] = lin["linear_scan_ms"]
                res["dynamic_groups"] = self.registry.list_dynamic_groups()
                self._record_event(
                    "REGISTRY_REINDEX",
                    thing_name,
                    "INDEX_UPDATED",
                    res["reindex_ms"],
                    f"Added={res['groups_added']} Removed={res['groups_removed']}",
                )
                return res

            if op == "create_group":
                g_name = str(body.get("group_name") or "custom-fleet-group").strip()
                q_str = str(body.get("query_string") or "temp_c > 70").strip()
                desc = str(body.get("description") or "Custom Fleet Indexing Dynamic Thing Group").strip()
                grp = self.registry.create_dynamic_thing_group(
                    group_name=g_name,
                    query_string=q_str,
                    description=desc,
                )
                return {
                    "created_group": grp.to_dict(),
                    "dynamic_groups": self.registry.list_dynamic_groups(),
                }

            q_str = str(body.get("query_string") or "firmware_version < 2.4.0 AND temp_c > 75").strip()
            inv = self.registry.query_fleet_inverted_index(q_str)
            lin = self.registry.full_linear_scan_all_groups()
            inv["linear_scan_baseline_ms"] = lin["linear_scan_ms"]
            inv["dynamic_groups"] = self.registry.list_dynamic_groups()
            self._record_event(
                "FLEET_INDEX_QUERY",
                q_str[:42],
                f"{inv['matched_count']}_MATCHED",
                inv["query_ms"],
                f"Inverted-index query matched {inv['matched_count']}/{inv['total_fleet_count']} Things",
            )
            return inv

    def handle_shadow_update(self, body: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            thing_name = str(body.get("thing_name") or "turbine-gw-001").strip()
            shadow_name = str(body.get("shadow_name") or "classic").strip()
            desired = body.get("desired") if isinstance(body.get("desired"), dict) else None
            reported = body.get("reported") if isinstance(body.get("reported"), dict) else None
            expected_ver_raw = body.get("expected_version")
            expected_ver = int(expected_ver_raw) if expected_ver_raw is not None and str(expected_ver_raw) != "" else None

            out = self.shadows.update_shadow(
                thing_name=thing_name,
                desired=desired,
                reported=reported,
                expected_version=expected_ver,
                shadow_name=shadow_name,
                sync_registry=True,
            )
            out["dynamic_groups"] = self.registry.list_dynamic_groups()
            self._record_event(
                "SHADOW_CAS_UPDATE",
                f"{thing_name}/{shadow_name}",
                f"v{out['version']} ({'DELTA' if out['has_delta'] else 'IN_SYNC'})",
                out["shadow_cas_ms"],
                f"Delta keys: {list(out['delta'].keys()) or ['none']}",
            )
            return out

    def handle_fleet_diagnose(self, body: Dict[str, Any]) -> Dict[str, Any]:
        prompt = str(
            body.get("prompt")
            or "Diagnose certificates expiring within 14 days, overheating legacy-firmware gateways with active shadow deltas, and author a least-privilege IoT policy."
        ).strip()
        with self._lock:
            snap = {
                "total_things": self.registry.total_things(),
                "dynamic_groups": self.registry.list_dynamic_groups(),
                "crl_revoked_count": len(self.pki.crl_revoked_ids),
                "shadow_version_conflicts": self.shadows.conflict_count,
                "sample_things_and_shadows": [
                    {
                        "thing_name": t["thing_name"],
                        "attributes": t["attributes"],
                        "dynamic_groups": t["dynamic_groups"],
                        "shadow_version": self.shadows.get_shadow(t["thing_name"])["version"],
                        "shadow_delta": self.shadows.get_shadow(t["thing_name"])["delta"],
                    }
                    for t in self.registry.list_things(limit=8)
                ],
                "recent_audit_events": list(reversed(self.audit_feed[-8:])),
            }
        res = self.copilot.diagnose_fleet_incident(incident_prompt=prompt, fleet_snapshot=snap)
        with self._lock:
            self._record_event(
                "BEDROCK_FLEET_DIAGNOSE",
                res["diagnosis"].get("incident_category", "FLEET_DIAGNOSIS"),
                res["diagnosis"].get("severity", "INFO"),
                res["bedrock_latency_ms"],
                f"Amazon Nova Lite ({res['total_tokens']} tokens)",
            )
        return res


CONTROL_PLANE = IoTCoreControlPlane()


def route_api_request(
    method: str,
    path: str,
    query: Dict[str, str],
    body: Dict[str, Any],
    request_id: str = "local",
) -> Tuple[int, Dict[str, Any]]:
    """Shared API router for local HTTP server and AWS Lambda `/api/*` behind CloudFront."""
    try:
        if method == "GET" and path == "/api/health":
            return 200, {
                "status": "ok",
                "service": "iot-core-plane",
                "delivery": os.environ.get("IOTCOREPLANE_DELIVERY", "cloudfront-s3-oac + lambda-api-origin"),
                "aws_region": CONTROL_PLANE.region,
                "bedrock_model": CONTROL_PLANE.copilot.model_id,
                "python_version": platform.python_version(),
                "request_id": request_id,
                "things_registered": CONTROL_PLANE.registry.total_things(),
                "dynamic_groups_count": len(CONTROL_PLANE.registry.list_dynamic_groups()),
                "active_certificates": sum(1 for c in CONTROL_PLANE.pki.certificates.values() if c.status == "ACTIVE"),
                "crl_revoked_certificates": len(CONTROL_PLANE.pki.crl_revoked_ids),
            }

        if method == "GET" and path == "/api/state":
            snap = CONTROL_PLANE.get_state_snapshot()
            snap["request_id"] = request_id
            return 200, snap

        if method == "GET" and path == "/api/benchmarks":
            bench = CONTROL_PLANE.load_benchmarks()
            bench["request_id"] = request_id
            return 200, bench

        if method == "POST" and path in ("/api/provision/jitp", "/api/provision/claim"):
            if path == "/api/provision/claim":
                body = {**body, "mode": "claim"}
            out = CONTROL_PLANE.handle_jitp_or_claim(body)
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/cert/rotate":
            out = CONTROL_PLANE.handle_cert_rotate(body)
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/policy/evaluate":
            out = CONTROL_PLANE.handle_policy_evaluate(body)
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path in ("/api/registry/search", "/api/registry/groups"):
            out = CONTROL_PLANE.handle_registry_search_or_mutate(body)
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/shadow/update":
            try:
                out = CONTROL_PLANE.handle_shadow_update(body)
                out["request_id"] = request_id
                return 200, out
            except VersionConflictError as exc:
                CONTROL_PLANE._record_event(
                    "SHADOW_CAS_CONFLICT",
                    f"{exc.thing_name}/{exc.shadow_name}",
                    "409_VERSION_CONFLICT",
                    0.08,
                    str(exc),
                )
                return 409, {
                    "error": str(exc),
                    "error_code": "VersionConflictException",
                    "thing_name": exc.thing_name,
                    "shadow_name": exc.shadow_name,
                    "expected_version": exc.expected_version,
                    "current_version": exc.current_version,
                    "current_shadow": CONTROL_PLANE.shadows.get_shadow(exc.thing_name, exc.shadow_name),
                    "request_id": request_id,
                }

        if method == "POST" and path == "/api/fleet/diagnose":
            out = CONTROL_PLANE.handle_fleet_diagnose(body)
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/reset":
            snap = CONTROL_PLANE.reset()
            return 200, {
                "status": "reset_complete",
                "service": "iot-core-plane",
                "state": snap,
                "request_id": request_id,
            }

        return 404, {"error": f"Unknown API route: {method} {path}"}
    except (ProvisioningError, ValueError) as exc:
        return 400, {"error": str(exc), "request_id": request_id}
    except RotationPreconditionError as exc:
        return 409, {"error": str(exc), "error_code": "RotationPreconditionFailed", "request_id": request_id}
    except KeyError as exc:
        return 404, {"error": str(exc), "request_id": request_id}
    except Exception as exc:
        return 500, {"error": str(exc), "request_id": request_id}


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """AWS Lambda Function URL handler behind Amazon CloudFront `/api/*`."""
    req_ctx = event.get("requestContext") or {}
    method = ((req_ctx.get("http") or {}).get("method") or event.get("httpMethod") or "GET").upper()
    raw_path = event.get("rawPath") or event.get("path") or "/"
    query_params = {k: str(v) for k, v in (event.get("queryStringParameters") or {}).items() if v is not None}
    req_id = getattr(context, "aws_request_id", "cloudfront-api")

    if method == "OPTIONS":
        return {"statusCode": 204, "headers": CORS_HEADERS, "body": ""}

    if raw_path.startswith("/api/"):
        body: Dict[str, Any] = {}
        raw_body = event.get("body")
        if raw_body:
            if event.get("isBase64Encoded") and isinstance(raw_body, str):
                raw_body = base64.b64decode(raw_body).decode("utf-8")
            body = json.loads(raw_body) if isinstance(raw_body, str) else dict(raw_body)
        status, payload = route_api_request(method, raw_path, query_params, body, request_id=req_id)
        return {
            "statusCode": status,
            "headers": {
                **CORS_HEADERS,
                "Content-Type": "application/json; charset=utf-8",
                "Cache-Control": "no-store",
            },
            "body": json.dumps(payload, default=str),
        }

    target = WEB_DIR / ("index.html" if raw_path in ("/", "") else raw_path.lstrip("/"))
    if not target.is_file() and raw_path.endswith(".svg"):
        target = DOCS_DIR / Path(raw_path).name
    if target.is_file():
        ctype = mimetypes.guess_type(str(target))[0] or "text/html; charset=utf-8"
        return {
            "statusCode": 200,
            "headers": {**CORS_HEADERS, "Content-Type": ctype},
            "body": target.read_text(encoding="utf-8"),
        }
    return {
        "statusCode": 404,
        "headers": {**CORS_HEADERS, "Content-Type": "application/json"},
        "body": json.dumps({"error": "Not found", "path": raw_path}),
    }


class LocalIoTCoreHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}

        if path.startswith("/api/"):
            status, payload = route_api_request("GET", path, query, {}, request_id="local-dev")
            raw = json.dumps(payload, indent=2, default=str).encode("utf-8")
            self.send_response(status)
            for k, v in CORS_HEADERS.items():
                self.send_header(k, v)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        candidate = (WEB_DIR / rel).resolve()
        if not candidate.is_file() and path.endswith(".svg"):
            candidate = (DOCS_DIR / Path(path).name).resolve()
        if not candidate.is_file():
            candidate = WEB_DIR / "index.html"

        data = candidate.read_bytes()
        ctype = mimetypes.guess_type(str(candidate))[0] or "text/html"
        if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
            ctype += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or "0")
        raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        body = json.loads(raw_body) if raw_body.strip() else {}
        status, payload = route_api_request("POST", parsed.path, {}, body, request_id="local-dev")
        raw = json.dumps(payload, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def run_local_server(port: int = 3099) -> None:
    srv = ThreadingHTTPServer(("127.0.0.1", port), LocalIoTCoreHandler)
    print(f"IoTCorePlane Studio running at http://localhost:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    port_num = int(os.environ.get("PORT", "3099"))
    run_local_server(port=port_num)
