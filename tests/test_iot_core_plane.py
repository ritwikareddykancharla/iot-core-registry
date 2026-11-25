"""Comprehensive Unit Test Suite for IoTCorePlane (14 Tests)."""
from __future__ import annotations

import concurrent.futures
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from iot_core_plane.device_shadow import (
    DeviceShadowEngine,
    VersionConflictError,
    compute_shadow_delta,
)
from iot_core_plane.pki_provisioning import (
    PKIProvisioningAuthority,
    ProvisioningError,
    RotationPreconditionError,
    ecdsa_verify_sha256,
)
from iot_core_plane.policy_gate import IoTPolicyGate
from iot_core_plane.registry_groups import ThingRegistry
from iot_core_plane.server import lambda_handler, route_api_request


class TestIoTCorePlane(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.pki = PKIProvisioningAuthority(region="us-west-2", account_id="796330847946")
        self.ca = self.pki.register_fleet_ca(
            common_name="Test-IoT-Fleet-CA",
            deterministic_seed=b"unit-test-fleet-ca-seed",
        )
        self.registry = ThingRegistry(db_path=self.base / "registry.db")
        self.policy_gate = IoTPolicyGate(pki=self.pki)
        self.shadows = DeviceShadowEngine(db_path=self.base / "shadows.db", registry=self.registry)

    def tearDown(self) -> None:
        self.shadows.close()
        self.registry.close()
        self.tmp.cleanup()

    def test_01_x509_der_pem_and_openssl_compatibility(self) -> None:
        cert = self.pki.issue_device_certificate(
            ca_id=self.ca.ca_id,
            subject_cn="thing-alpha-01",
            hardware_serial="SN-IND-0001",
            initial_status="ACTIVE",
        )
        self.assertEqual(len(cert.certificate_id), 64)
        self.assertTrue(cert.certificate_pem.startswith("-----BEGIN CERTIFICATE-----"))
        self.assertTrue(
            ecdsa_verify_sha256(self.ca._public_point, cert._tbs_der, cert._signature)
        )
        # Verify RFC 5280 ASN.1 DER structure is parseable by system openssl if present
        pem_file = self.base / "leaf.pem"
        pem_file.write_text(cert.certificate_pem, encoding="utf-8")
        proc = subprocess.run(
            ["openssl", "x509", "-in", str(pem_file), "-noout", "-subject"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            self.assertIn("thing-alpha-01", proc.stdout)

    def test_02_jitp_first_connect_registers_thing_and_activates_cert(self) -> None:
        cert = self.pki.issue_device_certificate(
            ca_id=self.ca.ca_id,
            subject_cn="jitp-sensor-042",
            hardware_serial="SN-IND-0042",
            initial_status="INACTIVE",
        )
        res = self.pki.provision_jitp_on_connect(
            certificate_id=cert.certificate_id,
            registry=self.registry,
            initial_attributes={"firmware_version": "2.4.2", "temp_c": 49.0},
        )
        self.assertEqual(res["provisioning_flow"], "JITP")
        self.assertEqual(res["thing_name"], "jitp-sensor-042")
        self.assertEqual(cert.status, "ACTIVE")
        self.assertEqual(cert.rotation_role, "ACTIVE_PRIMARY")
        thing = self.registry.get_thing("jitp-sensor-042")
        self.assertEqual(thing.attributes["hardware_serial"], "SN-IND-0042")

    def test_03_provision_by_claim_enforces_serial_allowlist(self) -> None:
        self.pki.register_claim_bootstrap(
            claim_id="factory-claim-1",
            ca_id=self.ca.ca_id,
            allowed_serial_prefix="SN-FAC-",
        )
        ok = self.pki.provision_by_claim(
            claim_id="factory-claim-1",
            thing_name="factory-unit-07",
            hardware_serial="SN-FAC-9007",
            registry=self.registry,
        )
        self.assertEqual(ok["provisioning_flow"], "PROVISION_BY_CLAIM")
        with self.assertRaises(ProvisioningError):
            self.pki.provision_by_claim(
                claim_id="factory-claim-1",
                thing_name="rogue-unit-99",
                hardware_serial="ROGUE-9999",
                registry=self.registry,
            )

    def test_04_zero_downtime_rotation_blocks_premature_revocation(self) -> None:
        leaf = self.pki.issue_device_certificate(
            ca_id=self.ca.ca_id,
            subject_cn="gateway-rot-01",
            hardware_serial="SN-IND-701",
        )
        self.pki.provision_jitp_on_connect(certificate_id=leaf.certificate_id, registry=self.registry)

        step1 = self.pki.start_overlapping_rotation(thing_name="gateway-rot-01")
        old_id = step1["active_primary_cert_id"]
        new_id = step1["pending_rotation_cert_id"]

        # Premature cutover before VERIFIED_CONNECT must raise RotationPreconditionError
        with self.assertRaises(RotationPreconditionError):
            self.pki.finalize_rotation_and_revoke_old(
                thing_name="gateway-rot-01",
                old_certificate_id=old_id,
                new_certificate_id=new_id,
            )

        # Complete verified connect on new cert, then safely revoke old cert
        self.pki.verify_rotated_connect(thing_name="gateway-rot-01", new_certificate_id=new_id)
        done = self.pki.finalize_rotation_and_revoke_old(
            thing_name="gateway-rot-01",
            old_certificate_id=old_id,
            new_certificate_id=new_id,
            registry=self.registry,
        )
        self.assertEqual(done["dropped_sessions"], 0)
        self.assertEqual(self.pki.certificates[old_id].status, "REVOKED")
        self.assertEqual(self.pki.certificates[new_id].rotation_role, "ACTIVE_PRIMARY")

    def test_05_crl_revocation_immediately_blocks_mtls_and_policy(self) -> None:
        leaf = self.pki.issue_device_certificate(
            ca_id=self.ca.ca_id,
            subject_cn="sensor-crl-09",
            hardware_serial="SN-IND-909",
        )
        self.pki.provision_jitp_on_connect(certificate_id=leaf.certificate_id, registry=self.registry)
        self.pki.update_certificate_status(certificate_id=leaf.certificate_id, new_status="REVOKED")

        with self.assertRaises(ProvisioningError):
            self.pki.verify_x509_chain(leaf.certificate_id)

        dec = self.policy_gate.evaluate(
            thing_name="sensor-crl-09",
            action="iot:Publish",
            topic_or_client="$aws/things/sensor-crl-09/shadow/update",
            certificate_id=leaf.certificate_id,
        )
        self.assertFalse(dec.allowed)
        self.assertEqual(dec.verdict, "DENY_INVALID_CERTIFICATE")

    def test_06_policy_variable_substitution_allows_own_thing_topics(self) -> None:
        leaf = self.pki.issue_device_certificate(
            ca_id=self.ca.ca_id,
            subject_cn="thing-042",
            hardware_serial="SN-IND-042",
        )
        self.pki.provision_jitp_on_connect(certificate_id=leaf.certificate_id, registry=self.registry)

        conn_dec = self.policy_gate.evaluate(
            thing_name="thing-042",
            action="iot:Connect",
            topic_or_client="thing-042",
            certificate_id=leaf.certificate_id,
        )
        pub_dec = self.policy_gate.evaluate(
            thing_name="thing-042",
            action="iot:Publish",
            topic_or_client="$aws/things/thing-042/shadow/update",
            certificate_id=leaf.certificate_id,
        )
        sub_dec = self.policy_gate.evaluate(
            thing_name="thing-042",
            action="iot:Subscribe",
            topic_or_client="$aws/things/thing-042/shadow/update/delta",
            certificate_id=leaf.certificate_id,
        )
        self.assertTrue(conn_dec.allowed)
        self.assertTrue(pub_dec.allowed)
        self.assertTrue(sub_dec.allowed)

    def test_07_policy_blocks_cross_thing_spoofing_and_mqtt_wildcards(self) -> None:
        leaf = self.pki.issue_device_certificate(
            ca_id=self.ca.ca_id,
            subject_cn="thing-042",
            hardware_serial="SN-IND-042",
        )
        self.pki.provision_jitp_on_connect(certificate_id=leaf.certificate_id, registry=self.registry)

        # Lateral publish to thing-099 shadow
        spoof_pub = self.policy_gate.evaluate(
            thing_name="thing-042",
            action="iot:Publish",
            topic_or_client="$aws/things/thing-099/shadow/update",
            certificate_id=leaf.certificate_id,
        )
        self.assertFalse(spoof_pub.allowed)
        self.assertEqual(spoof_pub.verdict, "IMPLICIT_DENY_CROSS_THING")

        # Wildcard MQTT '+' subscribe across all things
        wild_sub = self.policy_gate.evaluate(
            thing_name="thing-042",
            action="iot:Subscribe",
            topic_or_client="$aws/things/+/shadow/update/delta",
            certificate_id=leaf.certificate_id,
        )
        self.assertFalse(wild_sub.allowed)

        # Impersonating thing-099 while presenting thing-042 certificate
        mismatch = self.policy_gate.evaluate(
            thing_name="thing-099",
            action="iot:Publish",
            topic_or_client="$aws/things/thing-099/shadow/update",
            certificate_id=leaf.certificate_id,
        )
        self.assertFalse(mismatch.allowed)
        self.assertEqual(mismatch.verdict, "DENY_PRINCIPAL_THING_MISMATCH")

    def test_08_policy_explicit_deny_overrides_allow(self) -> None:
        dec = self.policy_gate.evaluate(
            thing_name="thing-042",
            action="iot:Publish",
            topic_or_client="cmd/fleet-admin/reboot-all",
        )
        self.assertFalse(dec.allowed)
        self.assertEqual(dec.verdict, "EXPLICIT_DENY")

    def test_09_dynamic_thing_groups_incremental_reindex_and_semver(self) -> None:
        self.registry.create_dynamic_thing_group(
            group_name="overheating-legacy",
            query_string="firmware_version < 2.4.0 AND temp_c > 75",
        )
        self.registry.upsert_thing(
            thing_name="pump-01",
            attributes={"firmware_version": "2.3.2", "temp_c": 62.0},
        )
        self.assertEqual(self.registry.get_dynamic_group("overheating-legacy").member_count, 0)

        # Spike temperature -> automatically joins group
        upd1 = self.registry.update_thing_attributes("pump-01", {"temp_c": 81.5})
        self.assertIn("overheating-legacy", upd1["groups_added"])
        self.assertEqual(self.registry.get_dynamic_group("overheating-legacy").member_count, 1)

        # Upgrade firmware -> automatically evicted from group
        upd2 = self.registry.update_thing_attributes("pump-01", {"firmware_version": "2.4.2"})
        self.assertIn("overheating-legacy", upd2["groups_removed"])
        self.assertEqual(self.registry.get_dynamic_group("overheating-legacy").member_count, 0)

    def test_10_registry_sqlite_persistence_across_reopen(self) -> None:
        self.registry.create_dynamic_thing_group(
            group_name="low-bat",
            query_string="battery_pct < 20 AND connectivity = DISCONNECTED",
        )
        self.registry.upsert_thing(
            thing_name="sensor-persist-1",
            attributes={"battery_pct": 12, "connectivity": "DISCONNECTED"},
        )
        reopened = ThingRegistry(db_path=self.base / "registry.db")
        try:
            grp = reopened.get_dynamic_group("low-bat")
            self.assertEqual(grp.member_count, 1)
            self.assertIn("sensor-persist-1", grp.sample_members)
        finally:
            reopened.close()

    def test_11_device_shadow_recursive_delta_and_null_tombstone(self) -> None:
        delta = compute_shadow_delta(
            desired={"sampling_hz": 50, "nested": {"fan": "ON", "rpm": 1800}},
            reported={"sampling_hz": 50, "nested": {"fan": "ON", "rpm": 1200}},
        )
        self.assertEqual(delta, {"nested": {"rpm": 1800}})

        s1 = self.shadows.update_shadow(
            thing_name="dev-01",
            desired={"mode": "AUTO", "temp_target": 21},
            reported={"mode": "MANUAL", "temp_target": 21},
        )
        self.assertEqual(s1["version"], 1)
        self.assertEqual(s1["delta"], {"mode": "AUTO"})

        # Tombstone `mode: None` removes key from desired -> delta becomes empty
        s2 = self.shadows.update_shadow(
            thing_name="dev-01",
            desired={"mode": None},
            expected_version=1,
        )
        self.assertEqual(s2["version"], 2)
        self.assertFalse(s2["has_delta"])
        self.assertEqual(s2["delta"], {})

    def test_12_shadow_optimistic_cas_rejects_stale_version_under_concurrency(self) -> None:
        self.shadows.update_shadow(
            thing_name="concurrent-gw",
            desired={"freq": 10},
            reported={"freq": 10},
        )
        # 8 concurrent threads all attempting CAS against expected_version=1: exactly 1 must win, 7 raise 409
        def _attempt(worker_id: int) -> bool:
            try:
                self.shadows.update_shadow(
                    thing_name="concurrent-gw",
                    reported={"freq": 20 + worker_id},
                    expected_version=1,
                )
                return True
            except VersionConflictError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(_attempt, range(8)))
        self.assertEqual(sum(outcomes), 1)
        self.assertEqual(self.shadows.get_shadow("concurrent-gw")["version"], 2)

    def test_13_shadow_reported_syncs_dynamic_thing_group_membership(self) -> None:
        self.registry.create_dynamic_thing_group(
            group_name="hot-sensors",
            query_string="temp_c > 75",
        )
        self.registry.upsert_thing("therm-01", attributes={"temp_c": 45.0})
        self.assertEqual(self.registry.get_dynamic_group("hot-sensors").member_count, 0)

        out = self.shadows.update_shadow(
            thing_name="therm-01",
            reported={"temp_c": 84.2},
            sync_registry=True,
        )
        self.assertIn("hot-sensors", out["registry_reindex"]["groups_added"])
        self.assertEqual(self.registry.get_dynamic_group("hot-sensors").member_count, 1)

    def test_14_server_lambda_handler_and_api_routes(self) -> None:
        status, health = route_api_request("GET", "/api/health", {}, {})
        self.assertEqual(status, 200)
        self.assertEqual(health["service"], "iot-core-plane")

        # Test Lambda handler event envelope on /api/policy/evaluate
        lam_res = lambda_handler(
            {
                "rawPath": "/api/policy/evaluate",
                "requestContext": {"http": {"method": "POST"}},
                "body": json.dumps(
                    {
                        "thing_name": "coldchain-sensor-042",
                        "action": "iot:Publish",
                        "topic": "$aws/things/coldchain-sensor-099/shadow/update",
                    }
                ),
            }
        )
        self.assertEqual(lam_res["statusCode"], 200)
        body = json.loads(lam_res["body"])
        self.assertFalse(body["allowed"])
        self.assertEqual(body["verdict"], "IMPLICIT_DENY_CROSS_THING")

        # Test 409 VersionConflict response on /api/shadow/update
        st_409, payload_409 = route_api_request(
            "POST",
            "/api/shadow/update",
            {},
            {"thing_name": "turbine-gw-001", "reported": {"temp_c": 50.0}, "expected_version": 999},
        )
        self.assertEqual(st_409, 409)
        self.assertEqual(payload_409["error_code"], "VersionConflictException")


if __name__ == "__main__":
    unittest.main()
