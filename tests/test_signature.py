"""Signature pipeline tests."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

# Allow `python -m unittest discover -s tests -v` without PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dynata_sig.signer import create_signature, sign_request


class SignatureTests(unittest.TestCase):
    def test_create_signature_matches_confluence_example(self) -> None:
        signing_string = "63278ae51527131c0a5727b27a66a5f71bdf9b74a8289ceae7e1939450594458"
        signature = create_signature(
            signing_string_hash=signing_string,
            expiration="2026-01-01T00:00:00Z",
            access_key="12345",
            secret_key="abcde",
        )
        self.assertEqual(
            "9fb16035ec2018e4755f070a9c6cd323055ce5f0a809db092a0e6fc3fc12763c",
            signature,
        )

    def test_sign_request_matches_java_go_golden_vector(self) -> None:
        signed = sign_request(
            method="POST",
            url="https://example.dynata.com/authorize",
            body="{}",
            expiration="2025-12-31T23:59:59.000Z",
            access_key="Z0122D3555DDF9D8FA6780055C27FB8BE520B13U",
            secret_key="test_secret_key_32_chars_long",
        )
        self.assertEqual(
            "d37681ab72af483fd0fc4013abb26b8e8884022f1a37d2fe97a1c67c5635b02e",
            signed.dynata_signing_string,
        )
        self.assertEqual(
            "74e939fe58af15c9f18ae659b22e0b48fa0519c6338c755a1162c20d702f9492",
            signed.dynata_signature,
        )
        self.assertEqual("2025-12-31T23:59:59.000Z", signed.dynata_expiration)
        self.assertEqual(
            "Z0122D3555DDF9D8FA6780055C27FB8BE520B13U",
            signed.dynata_access_key,
        )

    def test_signature_changes_with_expiration(self) -> None:
        first = sign_request(
            method="POST",
            url="https://example.dynata.com/authorize",
            body="{}",
            expiration="2025-12-31T23:59:59.000Z",
            access_key="Z0122D3555DDF9D8FA6780055C27FB8BE520B13U",
            secret_key="test_secret_key_32_chars_long",
        )
        second = sign_request(
            method="POST",
            url="https://example.dynata.com/authorize",
            body="{}",
            expiration="2026-01-01T00:00:00.000Z",
            access_key="Z0122D3555DDF9D8FA6780055C27FB8BE520B13U",
            secret_key="test_secret_key_32_chars_long",
        )
        self.assertNotEqual(first.dynata_signature, second.dynata_signature)


if __name__ == "__main__":
    unittest.main()
