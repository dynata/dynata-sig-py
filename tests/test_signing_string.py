"""Signing-string and canonicalization tests."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

# Allow `python -m unittest discover -s tests -v` without PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dynata_sig.canonicalize import build_canonical_url
from dynata_sig.signer import generate_signing_string


class CanonicalUrlTests(unittest.TestCase):
    def test_preserves_relative_url(self) -> None:
        self.assertEqual("/path/only?", build_canonical_url("/path/only"))

    def test_sorts_query_keys_and_keeps_last_duplicate_value(self) -> None:
        self.assertEqual(
            "https://example.com?a=9&b=1",
            build_canonical_url("https://example.com?b=2&b=1&a=9"),
        )

    def test_encodes_query_and_keeps_last_duplicate_value(self) -> None:
        self.assertEqual(
            "https://example.com?a%5B%5D=2&b=3&empty=",
            build_canonical_url("https://example.com?a[]=1&a[]=2&b=3&empty=&flag"),
        )

    def test_partner_style_vector(self) -> None:
        raw_url = (
            "https://example.dynata.com/"
            "?ctx=context123&respondent_id=user123&language=en"
            "&expiration=2021-10-19T17:48:36.480Z&access_key=1234"
            "&Zeta=encode €xample~v@lue&dupes=1&doubled=this=two&dupes=2&null=&"
        )
        self.assertEqual(
            "https://example.dynata.com/?Zeta=encode%20%E2%82%ACxample~v%40lue"
            "&access_key=1234&ctx=context123&doubled=this%3Dtwo&dupes=2"
            "&expiration=2021-10-19T17%3A48%3A36.480Z&language=en&null="
            "&respondent_id=user123",
            build_canonical_url(raw_url),
        )

    def test_invalid_percent_encoded_query_raises(self) -> None:
        with self.assertRaisesRegex(ValueError, "not decodable"):
            build_canonical_url(
                "https://api.dynata.com/"
                "?redirect_uri=https%3A%2F%2Fwww.dynata.com%2F%3Fparam%3D%2TRUE%"
            )


class SigningStringTests(unittest.TestCase):
    def test_empty_get_request_matches_confluence_vector(self) -> None:
        self.assertEqual(
            "63278ae51527131c0a5727b27a66a5f71bdf9b74a8289ceae7e1939450594458",
            generate_signing_string("GET", "https://example.dynata.com/", ""),
        )

    def test_post_with_body_matches_confluence_vector(self) -> None:
        body = '{\n  "key": "value"\n}'
        self.assertEqual(
            "e131f5d82af633d4716f59c985e4b22191ebdf297761bdddac01bdc5125330a8",
            generate_signing_string("POST", "https://example.dynata.com/", body),
        )

    def test_signing_string_matches_java_go_vector(self) -> None:
        self.assertEqual(
            "d37681ab72af483fd0fc4013abb26b8e8884022f1a37d2fe97a1c67c5635b02e",
            generate_signing_string(
                "POST",
                "https://example.dynata.com/authorize",
                "{}",
            ),
        )


if __name__ == "__main__":
    unittest.main()
