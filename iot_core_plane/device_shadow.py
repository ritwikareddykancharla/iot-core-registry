"""Optimistic-Concurrency (`version` CAS) Device Shadow Reconciler & Bedrock Fleet Copilot.

Implements AWS IoT Device Shadow state synchronization for intermittently connected fleets:
  - Recursive JSON state merging (including `null` field tombstones per AWS IoT spec)
  - Exact recursive diff calculation (`delta = desired - reported`)
  - Optimistic Compare-And-Swap (`version` vector) raising `VersionConflictError` (`409 Conflict`)
    on stale out-of-order updates during offline-to-online reconnect storms
  - Per-field `metadata.desired` and `metadata.reported` Unix epoch timestamps
  - Live Amazon Bedrock (`us.amazon.nova-lite-v1:0`) Converse API Copilot for diagnosing
    cert-expiry waves, shadow drift storms, cross-Thing spoofing alerts, and authoring
    least-privilege `${iot:Connection.Thing.ThingName}` policies.
"""
from __future__ import annotations

import copy
import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class VersionConflictError(RuntimeError):
    """Raised (HTTP 409) when expected_version does not match the current Device Shadow version."""

    def __init__(self, thing_name: str, shadow_name: str, expected_version: int, current_version: int) -> None:
        self.thing_name = thing_name
        self.shadow_name = shadow_name
        self.expected_version = expected_version
        self.current_version = current_version
        super().__init__(
            f"409 VersionConflict on shadow '{thing_name}/{shadow_name}': "
            f"expected version {expected_version}, current version is {current_version}"
        )


def _merge_shadow_section(existing: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    """Merges a partial state patch into desired or reported; `None` deletes keys per AWS IoT Shadow spec."""
    result = copy.deepcopy(existing)
    for k, v in patch.items():
        if v is None:
            result.pop(k, None)
        elif isinstance(v, dict) and isinstance(result.get(k), dict):
            nested = _merge_shadow_section(result[k], v)
            result[k] = nested
        else:
            result[k] = copy.deepcopy(v)
    return result


def _build_metadata_timestamps(section: Dict[str, Any], ts: int, prev_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    prev = prev_meta or {}
    for k, v in section.items():
        if isinstance(v, dict):
            meta[k] = _build_metadata_timestamps(v, ts, prev.get(k) if isinstance(prev.get(k), dict) else None)
        else:
            meta[k] = {"timestamp": ts}
    return meta


def compute_shadow_delta(desired: Dict[str, Any], reported: Dict[str, Any]) -> Dict[str, Any]:
    """Computes exact recursive diff `delta = desired - reported` for intermittent IoT devices."""
    delta: Dict[str, Any] = {}
    for key, des_val in desired.items():
        if des_val is None:
            continue
        if key not in reported:
            delta[key] = copy.deepcopy(des_val)
            continue
        rep_val = reported[key]
        if isinstance(des_val, dict) and isinstance(rep_val, dict):
            sub_delta = compute_shadow_delta(des_val, rep_val)
            if sub_delta:
                delta[key] = sub_delta
        elif des_val != rep_val:
            delta[key] = copy.deepcopy(des_val)
    return delta


class DeviceShadowEngine:
    """SQLite WAL-backed Device Shadow store with strict optimistic `version` CAS."""

    def __init__(self, db_path: Path, registry: Optional[Any] = None) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.registry = registry
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._init_schema()
        self.conflict_count = 0

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS device_shadows (
                    thing_name TEXT NOT NULL,
                    shadow_name TEXT NOT NULL DEFAULT 'classic',
                    version INTEGER NOT NULL,
                    desired_json TEXT NOT NULL,
                    reported_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    updated_epoch INTEGER NOT NULL,
                    PRIMARY KEY (thing_name, shadow_name)
                );
                """
            )

    def get_shadow(self, thing_name: str, shadow_name: str = "classic") -> Dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT version, desired_json, reported_json, metadata_json, updated_epoch
                FROM device_shadows
                WHERE thing_name=? AND shadow_name=?
                """,
                (thing_name, shadow_name),
            ).fetchone()
            if row is None:
                return {
                    "thing_name": thing_name,
                    "shadow_name": shadow_name,
                    "version": 0,
                    "state": {"desired": {}, "reported": {}, "delta": {}},
                    "metadata": {"desired": {}, "reported": {}},
                    "has_delta": False,
                    "timestamp": int(time.time()),
                }
            ver, des_raw, rep_raw, meta_raw, ts = row
            desired = json.loads(des_raw)
            reported = json.loads(rep_raw)
            metadata = json.loads(meta_raw)
            delta = compute_shadow_delta(desired, reported)
            state_obj: Dict[str, Any] = {"desired": desired, "reported": reported}
            if delta:
                state_obj["delta"] = delta
            return {
                "thing_name": thing_name,
                "shadow_name": shadow_name,
                "version": int(ver),
                "state": state_obj,
                "delta": delta,
                "has_delta": bool(delta),
                "metadata": metadata,
                "timestamp": int(ts),
            }

    def update_shadow(
        self,
        *,
        thing_name: str,
        desired: Optional[Dict[str, Any]] = None,
        reported: Optional[Dict[str, Any]] = None,
        expected_version: Optional[int] = None,
        shadow_name: str = "classic",
        sync_registry: bool = True,
    ) -> Dict[str, Any]:
        """Applies an optimistic-concurrency CAS update to `desired` and/or `reported` shadow sections."""
        t0 = time.perf_counter()
        now_epoch = int(time.time())

        with self._lock:
            row = self._conn.execute(
                """
                SELECT version, desired_json, reported_json, metadata_json
                FROM device_shadows
                WHERE thing_name=? AND shadow_name=?
                """,
                (thing_name, shadow_name),
            ).fetchone()

            if row is None:
                cur_ver = 0
                cur_des: Dict[str, Any] = {}
                cur_rep: Dict[str, Any] = {}
                cur_meta: Dict[str, Any] = {"desired": {}, "reported": {}}
            else:
                cur_ver = int(row[0])
                cur_des = json.loads(row[1])
                cur_rep = json.loads(row[2])
                cur_meta = json.loads(row[3])

            if expected_version is not None and int(expected_version) != cur_ver:
                self.conflict_count += 1
                raise VersionConflictError(
                    thing_name=thing_name,
                    shadow_name=shadow_name,
                    expected_version=int(expected_version),
                    current_version=cur_ver,
                )

            next_ver = cur_ver + 1
            next_des = _merge_shadow_section(cur_des, desired) if desired is not None else cur_des
            next_rep = _merge_shadow_section(cur_rep, reported) if reported is not None else cur_rep
            next_meta = {
                "desired": _build_metadata_timestamps(next_des, now_epoch, cur_meta.get("desired")),
                "reported": _build_metadata_timestamps(next_rep, now_epoch, cur_meta.get("reported")),
            }
            delta = compute_shadow_delta(next_des, next_rep)

            with self._conn:
                if cur_ver == 0:
                    self._conn.execute(
                        """
                        INSERT INTO device_shadows
                        (thing_name, shadow_name, version, desired_json, reported_json, metadata_json, updated_epoch)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            thing_name,
                            shadow_name,
                            next_ver,
                            json.dumps(next_des, sort_keys=True),
                            json.dumps(next_rep, sort_keys=True),
                            json.dumps(next_meta, sort_keys=True),
                            now_epoch,
                        ),
                    )
                else:
                    cur = self._conn.execute(
                        """
                        UPDATE device_shadows
                        SET version=?, desired_json=?, reported_json=?, metadata_json=?, updated_epoch=?
                        WHERE thing_name=? AND shadow_name=? AND version=?
                        """,
                        (
                            next_ver,
                            json.dumps(next_des, sort_keys=True),
                            json.dumps(next_rep, sort_keys=True),
                            json.dumps(next_meta, sort_keys=True),
                            now_epoch,
                            thing_name,
                            shadow_name,
                            cur_ver,
                        ),
                    )
                    if cur.rowcount != 1:
                        self.conflict_count += 1
                        raise VersionConflictError(thing_name, shadow_name, cur_ver, cur_ver + 1)

            registry_reindex = None
            if sync_registry and reported and self.registry is not None:
                flat_patch = {
                    k: v for k, v in reported.items() if isinstance(v, (str, int, float, bool))
                }
                if flat_patch:
                    registry_reindex = self.registry.update_thing_attributes(thing_name, flat_patch)

            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 4)
            state_obj: Dict[str, Any] = {"desired": next_des, "reported": next_rep}
            if delta:
                state_obj["delta"] = delta
            return {
                "thing_name": thing_name,
                "shadow_name": shadow_name,
                "previous_version": cur_ver,
                "version": next_ver,
                "state": state_obj,
                "delta": delta,
                "has_delta": bool(delta),
                "metadata": next_meta,
                "timestamp": now_epoch,
                "shadow_cas_ms": elapsed_ms,
                "registry_reindex": registry_reindex,
            }

    def list_shadows(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT thing_name, shadow_name FROM device_shadows ORDER BY updated_epoch DESC, thing_name ASC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self.get_shadow(r[0], r[1]) for r in rows]

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass


# ==============================================================================
# Amazon Bedrock (`us.amazon.nova-lite-v1:0`) Fleet Escalation & Policy Copilot
# ==============================================================================
JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


class BedrockFleetCopilot:
    """Uses Amazon Bedrock (`us.amazon.nova-lite-v1:0`) to diagnose IoT fleet incidents & author policies."""

    def __init__(
        self,
        model_id: Optional[str] = None,
        region: Optional[str] = None,
    ) -> None:
        self.model_id = model_id or os.environ.get("IOTCOREPLANE_BEDROCK_MODEL", "us.amazon.nova-lite-v1:0")
        self.region = region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-west-2"
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            import shutil
            import subprocess
            import boto3

            try:
                client = boto3.client("bedrock-runtime", region_name=self.region)
                # Trigger credential resolution check eagerly so local AWS CLI v2 login profiles fall back cleanly
                _ = client._request_signer  # noqa: SLF001
                if os.environ.get("AWS_EXECUTION_ENV"):
                    self._client = client
                    return self._client
                # Verify credentials load without MissingDependencyException
                sess = boto3.Session(region_name=self.region)
                creds = sess.get_credentials()
                if creds is not None:
                    _ = creds.get_frozen_credentials()
                    self._client = sess.client("bedrock-runtime", region_name=self.region)
                    return self._client
            except Exception:
                pass

            aws_bin = shutil.which("aws")
            if aws_bin:
                env = dict(os.environ)
                env.pop("AWS_ACCESS_KEY_ID", None)
                env.pop("AWS_SECRET_ACCESS_KEY", None)
                env.pop("AWS_SESSION_TOKEN", None)
                profile = env.get("AWS_PROFILE") or "portfolio"
                proc = subprocess.run(
                    [aws_bin, "configure", "export-credentials", "--profile", profile, "--format", "process"],
                    capture_output=True,
                    text=True,
                    env=env,
                    check=True,
                )
                exported = json.loads(proc.stdout)
                sess = boto3.Session(
                    aws_access_key_id=exported["AccessKeyId"],
                    aws_secret_access_key=exported["SecretAccessKey"],
                    aws_session_token=exported.get("SessionToken"),
                    region_name=self.region,
                )
                self._client = sess.client("bedrock-runtime", region_name=self.region)
                return self._client

            self._client = boto3.client("bedrock-runtime", region_name=self.region)
        return self._client

    def diagnose_fleet_incident(
        self,
        *,
        incident_prompt: str,
        fleet_snapshot: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Invokes live Amazon Bedrock Nova Lite Converse API on the current IoT fleet snapshot."""
        system_text = (
            "You are an AWS IoT Core Identity, Registry, and Device Shadow principal operations engineer. "
            "Analyze the live fleet telemetry snapshot and operator escalation prompt. "
            "Respond strictly with a single valid JSON object containing these exact keys:\n"
            "  - severity: one of 'SEV-2', 'SEV-3', or 'INFO'\n"
            "  - incident_category: one of 'CERT_EXPIRY_WAVE', 'SHADOW_DRIFT_STORM', 'CROSS_THING_POLICY_BLOCK', or 'LEAST_PRIVILEGE_POLICY'\n"
            "  - root_cause: concise 2-sentence engineering diagnosis referencing exact Thing names, Dynamic Thing Groups, cert IDs, or shadow versions from the snapshot\n"
            "  - remediation_steps: array of 3 actionable AWS IoT Core steps (JITP/cert rotation, Dynamic Thing Group job targeting, or CAS shadow reconciliation)\n"
            "  - least_privilege_policy: valid AWS IoT Core policy JSON object (Version '2012-10-17' and Statement array) using ${iot:Connection.Thing.ThingName} or ${iot:ClientId} variables."
        )
        user_payload = json.dumps(
            {
                "operator_escalation": incident_prompt,
                "live_fleet_snapshot": fleet_snapshot,
            },
            indent=2,
            default=str,
        )

        t0 = time.perf_counter()
        client = self._get_client()
        resp = client.converse(
            modelId=self.model_id,
            system=[{"text": system_text}],
            messages=[{"role": "user", "content": [{"text": user_payload}]}],
            inferenceConfig={"maxTokens": 700, "temperature": 0.1},
        )
        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        blocks = resp.get("output", {}).get("message", {}).get("content", [])
        raw_text = "\n".join(b.get("text", "") for b in blocks if "text" in b).strip()
        usage = resp.get("usage") or {}
        in_tok = int(usage.get("inputTokens", 0))
        out_tok = int(usage.get("outputTokens", 0))
        tot_tok = int(usage.get("totalTokens", in_tok + out_tok))

        parsed = self._extract_json(raw_text)
        return {
            "model_id": self.model_id,
            "aws_region": self.region,
            "bedrock_latency_ms": latency_ms,
            "input_tokens": in_tok,
            "output_tokens": out_tok,
            "total_tokens": tot_tok,
            "diagnosis": parsed,
            "raw_response": raw_text,
        }

    @staticmethod
    def _extract_json(raw_text: str) -> Dict[str, Any]:
        candidate = raw_text.strip()
        m = JSON_FENCE_RE.search(candidate)
        if m:
            candidate = m.group(1)
        else:
            first = candidate.find("{")
            last = candidate.rfind("}")
            if first != -1 and last != -1 and last > first:
                candidate = candidate[first : last + 1]
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
        return {
            "severity": "SEV-3",
            "incident_category": "FLEET_DIAGNOSIS",
            "root_cause": raw_text[:400],
            "remediation_steps": [
                "Rotate expiring certificates via dual-active PENDING_ROTATION overlap before CRL revocation.",
                "Target affected devices via Dynamic Thing Group inverted-index query.",
                "Reconcile Device Shadow delta payloads with expected_version optimistic CAS checks.",
            ],
            "least_privilege_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "ScopedThingConnectAndShadow",
                        "Effect": "Allow",
                        "Action": ["iot:Connect", "iot:Publish"],
                        "Resource": [
                            "arn:aws:iot:us-west-2:796330847946:client/${iot:Connection.Thing.ThingName}",
                            "arn:aws:iot:us-west-2:796330847946:topic/$aws/things/${iot:Connection.Thing.ThingName}/shadow/update",
                        ],
                    }
                ],
            },
        }
