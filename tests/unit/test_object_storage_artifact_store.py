"""Slice 17 requirement 7/9/14: ObjectStorageArtifactStore's real S3
logic, against a fake S3ClientProtocol -- no real AWS call, matching
this project's established duck-typed-client test pattern (see
test_secret_provider.py's SecretsManagerClientProtocol fakes)."""

from __future__ import annotations

import hashlib
import io
import unittest

from webguard_api.artifact_store import ArtifactStoreError, ObjectStorageArtifactStore

BUCKET = "webguard-test-artifacts"
KMS_KEY_ID = "arn:aws:kms:eu-west-2:111111111111:key/test-key"


class _ClientError(Exception):
    """Structurally matches botocore.exceptions.ClientError -- a
    `.response["Error"]["Code"]` attribute, nothing else -- without
    this test importing botocore."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class _FakeS3Client:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.put_calls: list[dict] = []

    def put_object(self, *, Bucket, Key, Body, ServerSideEncryption, SSEKMSKeyId, ContentType):
        assert Bucket == BUCKET
        self.put_calls.append(
            {
                "Key": Key,
                "ServerSideEncryption": ServerSideEncryption,
                "SSEKMSKeyId": SSEKMSKeyId,
                "ContentType": ContentType,
            }
        )
        self.objects[Key] = Body
        return {}

    def get_object(self, *, Bucket, Key):
        assert Bucket == BUCKET
        if Key not in self.objects:
            raise _ClientError("NoSuchKey")
        return {"Body": io.BytesIO(self.objects[Key])}

    def head_object(self, *, Bucket, Key):
        assert Bucket == BUCKET
        if Key not in self.objects:
            raise _ClientError("404")
        return {}

    def delete_object(self, *, Bucket, Key):
        assert Bucket == BUCKET
        self.objects.pop(Key, None)
        return {}


class ObjectStorageArtifactStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = _FakeS3Client()
        self.store = ObjectStorageArtifactStore(bucket=BUCKET, client=self.client, kms_key_id=KMS_KEY_ID)

    def test_put_encrypts_with_sse_kms_and_a_specific_key(self) -> None:
        self.store.put("organizations/org-1/jobs/job-1/report.json", b'{"ok": true}')
        self.assertEqual(len(self.client.put_calls), 1)
        call = self.client.put_calls[0]
        self.assertEqual(call["ServerSideEncryption"], "aws:kms")
        self.assertEqual(call["SSEKMSKeyId"], KMS_KEY_ID)

    def test_put_returns_the_sha256_of_the_written_bytes(self) -> None:
        data = b'{"finding_count": 3}'
        checksum = self.store.put("organizations/org-1/jobs/job-1/report.json", data)
        self.assertEqual(checksum, hashlib.sha256(data).hexdigest())

    def test_round_trip_put_then_get_returns_identical_bytes(self) -> None:
        data = b"report body bytes"
        self.store.put("organizations/org-1/jobs/job-1/report.json", data)
        self.assertEqual(self.store.get_reference("organizations/org-1/jobs/job-1/report.json"), data)

    def test_checksum_reads_the_object_back_and_hashes_it_directly(self) -> None:
        data = b"another report body"
        self.store.put("organizations/org-1/jobs/job-1/report.json", data)
        self.assertEqual(
            self.store.checksum("organizations/org-1/jobs/job-1/report.json"), hashlib.sha256(data).hexdigest()
        )

    def test_get_reference_on_a_missing_object_raises_not_found(self) -> None:
        with self.assertRaises(ArtifactStoreError) as caught:
            self.store.get_reference("organizations/org-1/jobs/does-not-exist/report.json")
        self.assertEqual(caught.exception.code, "artifact_not_found")

    def test_exists_is_true_for_a_written_object_and_false_for_a_missing_one(self) -> None:
        self.store.put("organizations/org-1/jobs/job-1/report.json", b"data")
        self.assertTrue(self.store.exists("organizations/org-1/jobs/job-1/report.json"))
        self.assertFalse(self.store.exists("organizations/org-1/jobs/missing/report.json"))

    def test_delete_of_a_missing_object_is_not_an_error(self) -> None:
        # Postcondition-based contract, matching LocalArtifactStore:
        # "this reference is gone" already holds.
        self.store.delete("organizations/org-1/jobs/never-existed/report.json")

    def test_delete_removes_a_written_object(self) -> None:
        self.store.put("organizations/org-1/jobs/job-1/report.json", b"data")
        self.store.delete("organizations/org-1/jobs/job-1/report.json")
        self.assertFalse(self.store.exists("organizations/org-1/jobs/job-1/report.json"))

    def test_path_traversal_reference_is_rejected_before_any_s3_call(self) -> None:
        with self.assertRaises(ArtifactStoreError) as caught:
            self.store.put("../../etc/passwd", b"data")
        self.assertEqual(caught.exception.code, "artifact_reference_invalid")
        self.assertEqual(self.client.put_calls, [])

    def test_absolute_path_reference_is_rejected(self) -> None:
        with self.assertRaises(ArtifactStoreError) as caught:
            self.store.get_reference("/etc/passwd")
        self.assertEqual(caught.exception.code, "artifact_reference_invalid")

    def test_access_denied_is_translated_without_leaking_vendor_detail(self) -> None:
        class _DeniedClient(_FakeS3Client):
            def get_object(self, *, Bucket, Key):
                raise _ClientError("AccessDenied")

        store = ObjectStorageArtifactStore(bucket=BUCKET, client=_DeniedClient(), kms_key_id=KMS_KEY_ID)
        with self.assertRaises(ArtifactStoreError) as caught:
            store.get_reference("organizations/org-1/jobs/job-1/report.json")
        self.assertEqual(caught.exception.code, "artifact_storage_access_denied")

    def test_generic_write_failure_does_not_leak_vendor_exception_text(self) -> None:
        secret_detail = "arn:aws:iam::111111111111:role/leaked-internal-role-name"

        class _FailingClient(_FakeS3Client):
            def put_object(self, **_kwargs):
                raise RuntimeError(secret_detail)

        store = ObjectStorageArtifactStore(bucket=BUCKET, client=_FailingClient(), kms_key_id=KMS_KEY_ID)
        with self.assertRaises(ArtifactStoreError) as caught:
            store.put("organizations/org-1/jobs/job-1/report.json", b"data")
        self.assertNotIn(secret_detail, caught.exception.message)
        self.assertEqual(caught.exception.code, "artifact_write_failed")

    def test_cross_tenant_key_is_a_distinct_object_no_accidental_overwrite(self) -> None:
        self.store.put("organizations/org-a/jobs/job-1/report.json", b"org a data")
        self.store.put("organizations/org-b/jobs/job-1/report.json", b"org b data")
        self.assertEqual(self.store.get_reference("organizations/org-a/jobs/job-1/report.json"), b"org a data")
        self.assertEqual(self.store.get_reference("organizations/org-b/jobs/job-1/report.json"), b"org b data")


if __name__ == "__main__":
    unittest.main()
