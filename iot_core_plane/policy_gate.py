"""IoT Policy Variable Substitution & Thing-Scoped MQTT Topic Isolation Gate.

Evaluates AWS IoT Core policy documents with runtime variable expansion:
  - ${iot:Connection.Thing.ThingName}
  - ${iot:Connection.Thing.ThingTypeName}
  - ${iot:ClientId}
  - ${iot:Certificate.Subject.CommonName}
  - ${iot:Connection.Thing.Attributes[<key>]}

Enforces Explicit Deny > Explicit Allow > Default Implicit Deny across
`iot:Connect`, `iot:Publish`, `iot:Subscribe`, and `iot:Receive`, blocking lateral
cross-device MQTT spoofing (e.g., `thing-042` publishing to `$aws/things/thing-099/shadow/update`)
and unauthorized wildcard topic subscriptions (`#` or `+`).
"""
from __future__ import annotations

import fnmatch
import re
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from .pki_provisioning import PKIProvisioningAuthority, ProvisioningError

POLICY_VAR_RE = re.compile(r"\$\{iot:([^}]+)\}")

SUPPORTED_ACTIONS = {
    "iot:Connect",
    "iot:Publish",
    "iot:Subscribe",
    "iot:Receive",
}


@dataclass
class PolicyDecision:
    allowed: bool
    verdict: str
    reason_code: str
    explanation: str
    action: str
    target_resource_arn: str
    matched_statement_sid: Optional[str]
    expanded_allow_resources: List[str]
    thing_name: str
    client_id: str
    certificate_id: Optional[str]
    eval_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def build_default_thing_scoped_policy(region: str = "us-west-2", account_id: str = "796330847946") -> Dict[str, Any]:
    """Standard least-privilege AWS IoT Core policy scoped via ${iot:Connection.Thing.ThingName}."""
    base = f"arn:aws:iot:{region}:{account_id}"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowThingScopedClientConnect",
                "Effect": "Allow",
                "Action": ["iot:Connect"],
                "Resource": [f"{base}:client/${{iot:Connection.Thing.ThingName}}"],
            },
            {
                "Sid": "AllowOwnShadowAndTelemetryPublish",
                "Effect": "Allow",
                "Action": ["iot:Publish"],
                "Resource": [
                    f"{base}:topic/$aws/things/${{iot:Connection.Thing.ThingName}}/shadow/update",
                    f"{base}:topic/$aws/things/${{iot:Connection.Thing.ThingName}}/shadow/get",
                    f"{base}:topic/$aws/things/${{iot:Connection.Thing.ThingName}}/shadow/name/*/update",
                    f"{base}:topic/$aws/things/${{iot:Connection.Thing.ThingName}}/shadow/name/*/get",
                    f"{base}:topic/dt/industrial/${{iot:Connection.Thing.ThingName}}/*",
                ],
            },
            {
                "Sid": "AllowOwnShadowDeltaAndCommandSubscribe",
                "Effect": "Allow",
                "Action": ["iot:Subscribe"],
                "Resource": [
                    f"{base}:topicfilter/$aws/things/${{iot:Connection.Thing.ThingName}}/shadow/update/accepted",
                    f"{base}:topicfilter/$aws/things/${{iot:Connection.Thing.ThingName}}/shadow/update/rejected",
                    f"{base}:topicfilter/$aws/things/${{iot:Connection.Thing.ThingName}}/shadow/update/delta",
                    f"{base}:topicfilter/$aws/things/${{iot:Connection.Thing.ThingName}}/shadow/name/*/update/delta",
                    f"{base}:topicfilter/cmd/industrial/${{iot:Connection.Thing.ThingName}}/*",
                ],
            },
            {
                "Sid": "AllowOwnShadowDeltaAndCommandReceive",
                "Effect": "Allow",
                "Action": ["iot:Receive"],
                "Resource": [
                    f"{base}:topic/$aws/things/${{iot:Connection.Thing.ThingName}}/shadow/update/accepted",
                    f"{base}:topic/$aws/things/${{iot:Connection.Thing.ThingName}}/shadow/update/rejected",
                    f"{base}:topic/$aws/things/${{iot:Connection.Thing.ThingName}}/shadow/update/delta",
                    f"{base}:topic/$aws/things/${{iot:Connection.Thing.ThingName}}/shadow/name/*/update/delta",
                    f"{base}:topic/cmd/industrial/${{iot:Connection.Thing.ThingName}}/*",
                ],
            },
            {
                "Sid": "ExplicitDenyFleetBroadcastAndRawSystemTopics",
                "Effect": "Deny",
                "Action": ["iot:Publish", "iot:Subscribe", "iot:Receive"],
                "Resource": [
                    f"{base}:topic/$aws/events/*",
                    f"{base}:topicfilter/$aws/events/*",
                    f"{base}:topic/cmd/fleet-admin/*",
                    f"{base}:topicfilter/cmd/fleet-admin/*",
                ],
            },
        ],
    }


class IoTPolicyGate:
    """Evaluates AWS IoT Core policy documents with certificate principal & variable substitution."""

    def __init__(
        self,
        pki: Optional[PKIProvisioningAuthority] = None,
        region: str = "us-west-2",
        account_id: str = "796330847946",
    ) -> None:
        self.pki = pki
        self.region = region
        self.account_id = account_id
        self.policies: Dict[str, Dict[str, Any]] = {
            "ThingScopedTelemetryAndShadowPolicy": build_default_thing_scoped_policy(region, account_id),
        }

    def put_policy(self, policy_name: str, policy_document: Dict[str, Any]) -> None:
        if "Statement" not in policy_document or not isinstance(policy_document["Statement"], list):
            raise ValueError("IoT policy document must contain a Statement list")
        self.policies[policy_name] = policy_document

    def get_policy(self, policy_name: str) -> Dict[str, Any]:
        doc = self.policies.get(policy_name)
        if doc is None:
            raise KeyError(f"Unknown IoT policy: {policy_name}")
        return doc

    @staticmethod
    def expand_policy_variables(template: str, context: Dict[str, Any]) -> Optional[str]:
        """Substitutes ${iot:...} tokens; returns None if any referenced variable is unresolvable."""
        unresolved = False

        def _replace(match: re.Match[str]) -> str:
            nonlocal unresolved
            expr = match.group(1).strip()
            if expr == "Connection.Thing.ThingName":
                val = context.get("thing_name")
            elif expr == "Connection.Thing.ThingTypeName":
                val = context.get("thing_type")
            elif expr == "ClientId":
                val = context.get("client_id")
            elif expr == "Certificate.Subject.CommonName":
                val = context.get("subject_cn")
            elif expr.startswith("Connection.Thing.Attributes[") and expr.endswith("]"):
                attr_key = expr[len("Connection.Thing.Attributes[") : -1]
                attrs = context.get("attributes") or {}
                val = attrs.get(attr_key)
            else:
                val = None
            if val is None or str(val) == "":
                unresolved = True
                return ""
            return str(val)

        rendered = POLICY_VAR_RE.sub(_replace, template)
        return None if unresolved else rendered

    def _build_resource_arn(self, action: str, topic_or_client: str) -> str:
        base = f"arn:aws:iot:{self.region}:{self.account_id}"
        cleaned = topic_or_client.lstrip("/") if action != "iot:Connect" else topic_or_client
        if topic_or_client.startswith("arn:aws:iot:"):
            return topic_or_client
        if action == "iot:Connect":
            return f"{base}:client/{topic_or_client}"
        if action == "iot:Subscribe":
            return f"{base}:topicfilter/{cleaned}"
        return f"{base}:topic/{cleaned}"

    @staticmethod
    def _action_matches(pattern: str, requested_action: str) -> bool:
        if pattern == "iot:*" or pattern == "*":
            return True
        return fnmatch.fnmatchcase(requested_action, pattern)

    @staticmethod
    def _resource_matches(expanded_pattern: str, target_arn: str, action: str, raw_target: str) -> bool:
        # Block MQTT wildcard injection (+ or #) unless the policy resource explicitly contains that MQTT wildcard
        if action == "iot:Subscribe" and ("+" in raw_target or "#" in raw_target):
            if "+" in raw_target and "+" not in expanded_pattern and expanded_pattern != "*":
                return False
            if "#" in raw_target and "#" not in expanded_pattern and expanded_pattern != "*":
                return False
        if action == "iot:Publish" and ("+" in raw_target or "#" in raw_target):
            # MQTT spec forbids publishing to wildcard topics
            return False
        return fnmatch.fnmatchcase(target_arn, expanded_pattern)

    def evaluate(
        self,
        *,
        thing_name: str,
        action: str,
        topic_or_client: str,
        client_id: Optional[str] = None,
        certificate_id: Optional[str] = None,
        policy_name: str = "ThingScopedTelemetryAndShadowPolicy",
        policy_document: Optional[Dict[str, Any]] = None,
        thing_type: str = "IndustrialGatewayV2",
        attributes: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """Evaluates an MQTT / IoT Core action against the attached certificate and Thing-scoped policy."""
        t0 = time.perf_counter()
        effective_client_id = client_id if client_id is not None else thing_name
        target_arn = self._build_resource_arn(action, topic_or_client)

        if action not in SUPPORTED_ACTIONS:
            elapsed = round((time.perf_counter() - t0) * 1000.0, 4)
            return PolicyDecision(
                allowed=False,
                verdict="DENY_UNSUPPORTED_ACTION",
                reason_code="IOT_UNSUPPORTED_ACTION",
                explanation=f"Action '{action}' is not a valid IoT data-plane operation.",
                action=action,
                target_resource_arn=target_arn,
                matched_statement_sid=None,
                expanded_allow_resources=[],
                thing_name=thing_name,
                client_id=effective_client_id,
                certificate_id=certificate_id,
                eval_ms=elapsed,
            )

        if action == "iot:Publish" and ("+" in topic_or_client or "#" in topic_or_client):
            elapsed = round((time.perf_counter() - t0) * 1000.0, 4)
            return PolicyDecision(
                allowed=False,
                verdict="DENY_INVALID_MQTT_PUBLISH_WILDCARD",
                reason_code="MQTT_PUBLISH_WILDCARD_FORBIDDEN",
                explanation="MQTT protocol forbids '+' or '#' wildcards in PUBLISH topic names.",
                action=action,
                target_resource_arn=target_arn,
                matched_statement_sid=None,
                expanded_allow_resources=[],
                thing_name=thing_name,
                client_id=effective_client_id,
                certificate_id=certificate_id,
                eval_ms=elapsed,
            )

        subject_cn = thing_name
        if certificate_id and self.pki is not None:
            try:
                chain_res = self.pki.verify_x509_chain(certificate_id, require_active=True)
            except ProvisioningError as exc:
                elapsed = round((time.perf_counter() - t0) * 1000.0, 4)
                return PolicyDecision(
                    allowed=False,
                    verdict="DENY_INVALID_CERTIFICATE",
                    reason_code="TLS_PRINCIPAL_REJECTED",
                    explanation=str(exc),
                    action=action,
                    target_resource_arn=target_arn,
                    matched_statement_sid=None,
                    expanded_allow_resources=[],
                    thing_name=thing_name,
                    client_id=effective_client_id,
                    certificate_id=certificate_id,
                    eval_ms=elapsed,
                )
            attached_thing = chain_res.get("attached_thing")
            if attached_thing != thing_name:
                elapsed = round((time.perf_counter() - t0) * 1000.0, 4)
                return PolicyDecision(
                    allowed=False,
                    verdict="DENY_PRINCIPAL_THING_MISMATCH",
                    reason_code="IOT_CERT_THING_MISMATCH",
                    explanation=(
                        f"Certificate {certificate_id[:16]} is bound to Thing '{attached_thing}', "
                        f"blocking impersonation of '{thing_name}'."
                    ),
                    action=action,
                    target_resource_arn=target_arn,
                    matched_statement_sid=None,
                    expanded_allow_resources=[],
                    thing_name=thing_name,
                    client_id=effective_client_id,
                    certificate_id=certificate_id,
                    eval_ms=elapsed,
                )
            cert_obj = self.pki.certificates[certificate_id]
            subject_cn = cert_obj.subject_cn
            if cert_obj.attached_policy and policy_document is None:
                policy_name = cert_obj.attached_policy

        doc = policy_document if policy_document is not None else self.get_policy(policy_name)
        ctx = {
            "thing_name": thing_name,
            "thing_type": thing_type,
            "client_id": effective_client_id,
            "subject_cn": subject_cn,
            "attributes": attributes or {},
        }

        expanded_allows: List[str] = []
        allowing_sid: Optional[str] = None

        # Pass 1: Explicit Deny always wins
        for stmt in doc.get("Statement", []):
            effect = str(stmt.get("Effect", "")).strip()
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            if not any(self._action_matches(a, action) for a in actions):
                continue

            for res_tmpl in resources:
                expanded = self.expand_policy_variables(res_tmpl, ctx)
                if expanded is None:
                    continue
                if effect == "Deny" and self._resource_matches(expanded, target_arn, action, topic_or_client):
                    elapsed = round((time.perf_counter() - t0) * 1000.0, 4)
                    sid = stmt.get("Sid") or "ExplicitDenyStatement"
                    return PolicyDecision(
                        allowed=False,
                        verdict="EXPLICIT_DENY",
                        reason_code="IOT_EXPLICIT_DENY",
                        explanation=f"Blocked by explicit Deny statement '{sid}' on resource '{expanded}'.",
                        action=action,
                        target_resource_arn=target_arn,
                        matched_statement_sid=sid,
                        expanded_allow_resources=expanded_allows,
                        thing_name=thing_name,
                        client_id=effective_client_id,
                        certificate_id=certificate_id,
                        eval_ms=elapsed,
                    )

        # Pass 2: Explicit Allow check
        for stmt in doc.get("Statement", []):
            if str(stmt.get("Effect", "")).strip() != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            if not any(self._action_matches(a, action) for a in actions):
                continue

            for res_tmpl in resources:
                expanded = self.expand_policy_variables(res_tmpl, ctx)
                if expanded is None:
                    continue
                expanded_allows.append(expanded)
                if allowing_sid is None and self._resource_matches(expanded, target_arn, action, topic_or_client):
                    allowing_sid = stmt.get("Sid") or "AllowStatement"

        elapsed = round((time.perf_counter() - t0) * 1000.0, 4)
        if allowing_sid is not None:
            return PolicyDecision(
                allowed=True,
                verdict="ALLOW_THING_SCOPED",
                reason_code="IOT_POLICY_ALLOW",
                explanation=(
                    f"Allowed by '{allowing_sid}' after expanding ${{iot:Connection.Thing.ThingName}} -> '{thing_name}'."
                ),
                action=action,
                target_resource_arn=target_arn,
                matched_statement_sid=allowing_sid,
                expanded_allow_resources=expanded_allows,
                thing_name=thing_name,
                client_id=effective_client_id,
                certificate_id=certificate_id,
                eval_ms=elapsed,
            )

        return PolicyDecision(
            allowed=False,
            verdict="IMPLICIT_DENY_CROSS_THING",
            reason_code="IOT_POLICY_TOPIC_ISOLATION",
            explanation=(
                f"Implicit Deny: '{thing_name}' is scoped to {expanded_allows or ['own Thing namespace']} "
                f"and cannot access '{target_arn}'."
            ),
            action=action,
            target_resource_arn=target_arn,
            matched_statement_sid=None,
            expanded_allow_resources=expanded_allows,
            thing_name=thing_name,
            client_id=effective_client_id,
            certificate_id=certificate_id,
            eval_ms=elapsed,
        )
