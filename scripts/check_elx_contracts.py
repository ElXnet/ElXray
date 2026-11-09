#!/usr/bin/env python3
"""Stage 1: stdlib-only compatibility contract guard. Does NOT test runtime security."""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import struct
import sys
import unittest
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "contracts/elx/v1/golden.json"
LEGACY_PROTO = ROOT / "app/policy/command/command.proto"
TARGET_PROTO = ROOT / "contracts/elx/v1/managed.proto.txt"
ADR = ROOT / "docs/elx/adr/0001-control-core-managed-contract.md"

IDS = [
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
    "44444444-4444-4444-8444-444444444444",
    "55555555-5555-4555-8555-555555555555",
    "66666666-6666-4666-8666-666666666666",
]
SUB, CH = "entitlement-A", "00112233445566778899aabbccddeeff"
SAMPLES = ("control-lease-v2", "policy-v1", "session-fence-v2",
           "rate-barrier-v1", "usage-v1", "pressure-v1", "lease-accept-v1",
           "control-device-reserve-v1", "managed-grant-v1-target")
PROTO_SHA256 = "270f64af0dc126867aeb2c74c83f50f7956b6d31f45eeb677d7007cc7e9715a7"

def uid(n: int) -> bytes:
    return uuid.UUID(IDS[n]).bytes

def be(*args: int) -> bytes:
    return b"".join(struct.pack(">Q", x) for x in args)

def transcript(name: str) -> bytes:
    if name == "control-lease-v2":
        return (f"elx-control-lease-v2\n{IDS[0]}\n{SUB}\n7\n1700000000\n1700000015\n12500000\n6250000").encode()
    if name == "policy-v1":
        return (f"elx-policy-v1\n{CH.encode().hex()}\n{SUB.encode().hex()}\n9\n12500000\n6250000\nfalse").encode()
    if name == "session-fence-v2":
        return b"elx-session-fence-v2\x00" + uid(0) + be(12) + uid(1) + uid(2) + uid(3)
    if name == "rate-barrier-v1":
        return (f"elx-rate-barrier-v1\n{IDS[0]}\n{IDS[1]}\n{IDS[2]}\n{IDS[3]}\n7\n10\n12500000\n6250000").encode()
    if name == "usage-v1":
        body = uid(2) + be(19, 1700000000000000000, 100, 200)
        return (f"elx-usage-v1\n{CH.encode().hex()}\n{SUB.encode().hex()}\n{body.hex()}").encode()
    if name == "pressure-v1":
        body = uid(2) + be(20, 1700000000000000000, 9, 12500000, 6250000,
                           100, 2, 4000, 0, 200, 3, 5000, 1)
        return (f"elx-pressure-v1\n{CH.encode().hex()}\n{SUB.encode().hex()}\n{body.hex()}").encode()
    if name == "lease-accept-v1":
        body = uid(2) + uid(1) + be(7, 1700000015, 12500000, 6250000,
                                    9, 12500000, 6250000)
        return (f"elx-lease-accept-v1\n{CH.encode().hex()}\n{SUB.encode().hex()}\n{body.hex()}").encode()
    if name == "control-device-reserve-v1":
        return (b"elx-device-reserve-v1\x00" + bytes(range(32))
                + b"".join(uid(i) for i in range(6)) + be(4)
                + bytes([0x22])*32 + bytes([0x33])*32)
    if name == "managed-grant-v1-target":
        return (b"elx-managed-grant-v1\x00"
                + b"".join(uid(i) for i in range(4))
                + be(7, 9, 1700000000, 1700000015, 12500000, 6250000) + b"\x00")
    raise AssertionError(f"unknown transcript {name}")

class Contracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_pinned_legacy_proto_is_unchanged(self):
        # Change requires explicit migration, Control stub update and revised pin.
        self.assertEqual(hashlib.sha256(LEGACY_PROTO.read_bytes()).hexdigest(), PROTO_SHA256)

    def test_golden_bytes_and_sha_independently_reconstructed(self):
        vectors = self.data["vectors"]
        self.assertEqual(tuple(v["id"] for v in vectors), SAMPLES)
        for vector in vectors:
            with self.subTest(vector=vector["id"]):
                actual = transcript(vector["id"])
                self.assertEqual(actual.hex(), vector["transcriptHex"])
                self.assertEqual(hashlib.sha256(actual).hexdigest(), vector["sha256"])

    def test_no_undocumented_capabilities_or_legacy_overwrites(self):
        p = TARGET_PROTO.read_text(encoding="utf-8")
        self.assertIn("package elx.enforcement.v1;", p)
        self.assertIn("DESIGN CONTRACT ONLY", p)
        self.assertIn("service ManagedEnforcement", p)
        self.assertIn("string core_incarnation = 11;", p)
        self.assertIn("uint64 authority_generation = 8;", p)
        self.assertNotIn("service SubscriptionService", p)
        self.assertIn("elx-device-reserve-v1", ADR.read_text(encoding="utf-8"))

    def test_target_proto_numbers_unique_in_each_message(self):
        # Lightweight syntax drift check, not a substitute for protoc validation.
        raw = TARGET_PROTO.read_text(encoding="utf-8")
        for match in re.finditer(r"message\s+(\w+)\s*\{([^{}]*)\}", raw, re.S):
            msg, body = match.groups()
            fields = re.findall(r"=\s*(\d+)\s*;", body)
            self.assertEqual(len(fields), len(set(fields)), f"{msg}: repeated field number")

    def test_required_negative_vectors_and_no_claimed_runtime_pass(self):
        n = self.data["negative"]
        ids = {x["id"] for x in n}
        self.assertGreaterEqual(len(ids), 14)
        for required in ("untrusted-local-caller", "managed-missing-boot-flags",
                         "raise-above-ceiling-between-renewals", "wrong-profile-fence",
                         "wrong-owner-fence", "cloned-profile-detached-flow",
                         "wrong-key-generation", "first-payload-before-admission",
                         "timeout-after-apply", "same-operation-different-payload"):
            self.assertIn(required, ids)
        self.assertTrue(all(x["status"] == "target_negative_test_not_yet_executed" for x in n))


    def test_exact_adversarial_wire_vectors(self):
        # These are exact negative *bytes*; runtime rejection is a later-stage E2E gate.
        cases = self.data["negativeWire"]
        self.assertEqual(len(cases), 7)
        for case in cases:
            with self.subTest(vector=case["id"]):
                source = transcript(case["positive"])
                name = case["id"]
                if name == "wrong-node-lease":
                    altered = source.replace(IDS[0].encode(), IDS[1].encode())
                elif name == "wrong-profile-fence":
                    altered = source[:-16] + uid(4)
                elif name == "wrong-owner-fence":
                    altered = source.replace(uid(0), uid(5))
                elif name == "wrong-node-rate":
                    altered = source.replace(IDS[1].encode(), IDS[5].encode())
                elif name == "wrong-challenge-usage":
                    altered = source.replace(CH.encode().hex().encode(),
                                             bytes.fromhex(CH)[::-1].hex().encode().hex().encode())
                elif name == "wrong-key-generation":
                    altered = source[:-72] + be(5) + source[-64:]
                elif name == "cloned-profile-detached-flow":
                    altered = source[:-32] + bytes([0x44])*32
                else:
                    self.fail("unknown negative vector: " + name)
                self.assertEqual(len(altered), len(source))
                self.assertNotEqual(source, altered)
                self.assertEqual(altered.hex(), case["alteredTranscriptHex"])
                self.assertNotEqual(hashlib.sha256(altered).digest(),
                                    hashlib.sha256(source).digest())

    def test_mutation_invalidates_reference_digest(self):
        # Explicit integrity test: even a one-byte mutation MUST change digest.
        for vector in self.data["vectors"]:
            raw = transcript(vector["id"])
            self.assertNotEqual(hashlib.sha256(raw+b"\x00").hexdigest(), vector["sha256"])
            if raw:
                flipped = bytes([raw[0] ^ 1]) + raw[1:]
                self.assertNotEqual(hashlib.sha256(flipped).hexdigest(), vector["sha256"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
