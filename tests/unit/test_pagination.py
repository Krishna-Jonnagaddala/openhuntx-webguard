from __future__ import annotations

import base64
import json
import unittest
from datetime import timedelta

from webguard_api import (
    PageRequest,
    PaginationError,
    SignedCursorCodec,
    parse_page_request,
)

from tests.unit.service_test_support import NOW, ORG_ID


class PageRequestTests(unittest.TestCase):
    def test_default_request_is_canonical(self) -> None:
        page = PageRequest()
        self.assertEqual(page.limit, 50)
        self.assertIsNone(page.cursor)
        self.assertEqual(page.filter_map, {})

    def test_rejects_limit_outside_bounds(self) -> None:
        for value in (0, 101, True, "10"):
            with self.subTest(value=value):
                with self.assertRaises(PaginationError):
                    PageRequest(limit=value)  # type: ignore[arg-type]

    def test_parse_accepts_filters_and_cursor(self) -> None:
        page = parse_page_request(
            {
                "limit": ("25",),
                "cursor": ("abc",),
                "state": ("running",),
            },
            allowed_filters={"state": frozenset({"queued", "running"})},
        )
        self.assertEqual(page.limit, 25)
        self.assertEqual(page.cursor, "abc")
        self.assertEqual(page.filter_map, {"state": "running"})

    def test_parse_rejects_duplicate_unknown_empty_and_invalid_filters(self) -> None:
        cases = (
            ({"limit": ("10", "20")}, "page_query_parameter_duplicate"),
            ({"unknown": ("x",)}, "page_query_parameter_unknown"),
            ({"cursor": ("",)}, "page_query_parameter_empty"),
            ({"state": ("other",)}, "page_filter_invalid"),
        )
        for query, code in cases:
            with self.subTest(query=query):
                with self.assertRaises(PaginationError) as context:
                    parse_page_request(
                        query,
                        allowed_filters={"state": frozenset({"queued"})},
                    )
                self.assertEqual(context.exception.code, code)


class SignedCursorCodecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.codec = SignedCursorCodec(b"k" * 32, validity_seconds=3600)

    def encode(self, **changes) -> str:
        values = dict(
            organization_id=ORG_ID,
            resource="jobs",
            filters={"state": "queued"},
            ordered_at="2026-08-06T18:00:00.000000Z",
            resource_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            now=NOW,
        )
        values.update(changes)
        return self.codec.encode(**values)

    def decode(self, cursor: str, **changes):
        values = dict(
            organization_id=ORG_ID,
            resource="jobs",
            filters={"state": "queued"},
            now=NOW,
        )
        values.update(changes)
        return self.codec.decode(cursor, **values)

    def test_round_trip_preserves_position(self) -> None:
        position = self.decode(self.encode())
        self.assertEqual(position.ordered_at, "2026-08-06T18:00:00.000000Z")
        self.assertEqual(
            position.resource_id,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )

    def test_cursor_is_opaque_and_deterministically_signed(self) -> None:
        first = self.encode()
        second = self.encode()
        self.assertEqual(first, second)
        self.assertNotIn(ORG_ID, first)
        payload_segment = first.split(".", 1)[0]
        payload = base64.urlsafe_b64decode(
            payload_segment + "=" * (-len(payload_segment) % 4)
        )
        decoded = json.loads(payload)
        self.assertEqual(decoded["organization_id"], ORG_ID)

    def test_modified_payload_and_signature_are_rejected(self) -> None:
        cursor = self.encode()
        payload, signature = cursor.split(".")
        modified_payload = ("A" if payload[0] != "A" else "B") + payload[1:]
        modified_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
        for value in (
            f"{modified_payload}.{signature}",
            f"{payload}.{modified_signature}",
        ):
            with self.subTest(value=value[:20]):
                with self.assertRaises(PaginationError) as context:
                    self.decode(value)
                self.assertIn(
                    context.exception.code,
                    {"page_cursor_signature_invalid", "page_cursor_invalid"},
                )

    def test_scope_resource_and_filter_replay_are_rejected(self) -> None:
        cursor = self.encode()
        cases = (
            ({"organization_id": "99999999-9999-4999-8999-999999999999"}, "page_cursor_scope_mismatch"),
            ({"resource": "schedules"}, "page_cursor_resource_mismatch"),
            ({"filters": {"state": "running"}}, "page_cursor_filter_mismatch"),
        )
        for changes, code in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(PaginationError) as context:
                    self.decode(cursor, **changes)
                self.assertEqual(context.exception.code, code)

    def test_expired_cursor_is_rejected(self) -> None:
        cursor = self.encode()
        with self.assertRaises(PaginationError) as context:
            self.decode(cursor, now=NOW + timedelta(hours=1))
        self.assertEqual(context.exception.code, "page_cursor_expired")

    def test_invalid_key_and_validity_are_rejected(self) -> None:
        with self.assertRaises(PaginationError):
            SignedCursorCodec(b"short")
        with self.assertRaises(PaginationError):
            SignedCursorCodec(b"k" * 32, validity_seconds=10)


if __name__ == "__main__":
    unittest.main()
