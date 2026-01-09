#!/usr/bin/env python3
"""
Test suite for storage_backends.py

Tests all storage backend implementations:
- LocalFileBackend
- DynamoDBBackend (mocked)
- S3Backend (mocked)
- Factory function
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, PropertyMock

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage_backends import (
    StorageBackend,
    LocalFileBackend,
    DynamoDBBackend,
    S3Backend,
    create_storage_backend,
    StorageError,
    ConflictError,
)


class TestLocalFileBackend(unittest.TestCase):
    """Test LocalFileBackend implementation."""

    def setUp(self):
        """Create a temporary file for each test."""
        self.temp_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        )
        self.temp_file.close()
        self.backend = LocalFileBackend(file_path=self.temp_file.name)

    def tearDown(self):
        """Clean up temporary file."""
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)
        # Clean up any .tmp files
        tmp_file = f"{self.temp_file.name}.tmp"
        if os.path.exists(tmp_file):
            os.unlink(tmp_file)

    def test_load_empty_file(self):
        """Test loading from non-existent file returns empty dict."""
        os.unlink(self.temp_file.name)
        result = self.backend.load()
        self.assertEqual(result, {})

    def test_load_valid_data(self):
        """Test loading valid JSON data."""
        test_data = {
            "1.2.3.4": {
                "tier": "high",
                "priority": 3,
                "block_until": "2025-01-20T10:00:00+00:00",
            }
        }
        with open(self.temp_file.name, 'w') as f:
            json.dump(test_data, f)

        result = self.backend.load()
        self.assertEqual(result, test_data)

    def test_load_corrupted_json(self):
        """Test loading corrupted JSON returns empty dict."""
        with open(self.temp_file.name, 'w') as f:
            f.write("{invalid json")

        result = self.backend.load()
        self.assertEqual(result, {})

    def test_load_invalid_structure(self):
        """Test loading non-dict JSON returns empty dict."""
        with open(self.temp_file.name, 'w') as f:
            json.dump(["not", "a", "dict"], f)

        result = self.backend.load()
        self.assertEqual(result, {})

    def test_save_creates_file(self):
        """Test save creates file if it doesn't exist."""
        os.unlink(self.temp_file.name)
        test_data = {"1.2.3.4": {"tier": "low"}}

        self.backend.save(test_data)

        self.assertTrue(os.path.exists(self.temp_file.name))
        with open(self.temp_file.name, 'r') as f:
            saved_data = json.load(f)
        self.assertEqual(saved_data, test_data)

    def test_save_overwrites_existing(self):
        """Test save overwrites existing data."""
        with open(self.temp_file.name, 'w') as f:
            json.dump({"old": "data"}, f)

        new_data = {"new": "data"}
        self.backend.save(new_data)

        with open(self.temp_file.name, 'r') as f:
            saved_data = json.load(f)
        self.assertEqual(saved_data, new_data)

    def test_get_existing_ip(self):
        """Test getting an existing IP."""
        test_data = {
            "1.2.3.4": {"tier": "high"},
            "5.6.7.8": {"tier": "low"},
        }
        with open(self.temp_file.name, 'w') as f:
            json.dump(test_data, f)

        result = self.backend.get("1.2.3.4")
        self.assertEqual(result, {"tier": "high"})

    def test_get_non_existing_ip(self):
        """Test getting a non-existing IP returns None."""
        with open(self.temp_file.name, 'w') as f:
            json.dump({}, f)

        result = self.backend.get("1.2.3.4")
        self.assertIsNone(result)

    def test_put_new_ip(self):
        """Test putting a new IP."""
        with open(self.temp_file.name, 'w') as f:
            json.dump({}, f)

        self.backend.put("1.2.3.4", {"tier": "high"})

        with open(self.temp_file.name, 'r') as f:
            saved_data = json.load(f)
        self.assertEqual(saved_data, {"1.2.3.4": {"tier": "high"}})

    def test_put_updates_existing(self):
        """Test putting updates existing IP."""
        with open(self.temp_file.name, 'w') as f:
            json.dump({"1.2.3.4": {"tier": "low"}}, f)

        self.backend.put("1.2.3.4", {"tier": "high"})

        with open(self.temp_file.name, 'r') as f:
            saved_data = json.load(f)
        self.assertEqual(saved_data, {"1.2.3.4": {"tier": "high"}})

    def test_delete_existing_ip(self):
        """Test deleting an existing IP."""
        with open(self.temp_file.name, 'w') as f:
            json.dump({"1.2.3.4": {"tier": "high"}}, f)

        self.backend.delete("1.2.3.4")

        with open(self.temp_file.name, 'r') as f:
            saved_data = json.load(f)
        self.assertEqual(saved_data, {})

    def test_delete_non_existing_ip(self):
        """Test deleting non-existing IP doesn't raise error."""
        with open(self.temp_file.name, 'w') as f:
            json.dump({}, f)

        # Should not raise
        self.backend.delete("1.2.3.4")

    def test_get_expired(self):
        """Test getting expired IPs."""
        now = datetime.now(timezone.utc)
        test_data = {
            "1.2.3.4": {"block_until": (now - timedelta(hours=1)).isoformat()},  # Expired
            "5.6.7.8": {"block_until": (now + timedelta(hours=1)).isoformat()},  # Active
            "9.10.11.12": {"block_until": (now - timedelta(days=1)).isoformat()},  # Expired
        }
        with open(self.temp_file.name, 'w') as f:
            json.dump(test_data, f)

        expired = self.backend.get_expired(now)
        self.assertEqual(expired, {"1.2.3.4", "9.10.11.12"})

    def test_get_expired_handles_invalid_dates(self):
        """Test get_expired handles invalid date formats gracefully."""
        now = datetime.now(timezone.utc)
        test_data = {
            "1.2.3.4": {"block_until": "invalid-date"},
            "5.6.7.8": {"block_until": (now - timedelta(hours=1)).isoformat()},
        }
        with open(self.temp_file.name, 'w') as f:
            json.dump(test_data, f)

        expired = self.backend.get_expired(now)
        self.assertEqual(expired, {"5.6.7.8"})

    def test_cleanup_old_entries(self):
        """Test cleaning up old entries."""
        now = datetime.now(timezone.utc)
        test_data = {
            "1.2.3.4": {"block_until": (now - timedelta(days=40)).isoformat()},  # Very old
            "5.6.7.8": {"block_until": (now - timedelta(days=10)).isoformat()},  # Recently expired
            "9.10.11.12": {"block_until": (now + timedelta(days=5)).isoformat()},  # Active
        }
        with open(self.temp_file.name, 'w') as f:
            json.dump(test_data, f)

        removed = self.backend.cleanup_old_entries(now, days_old=30)
        self.assertEqual(removed, 1)

        with open(self.temp_file.name, 'r') as f:
            remaining = json.load(f)
        self.assertNotIn("1.2.3.4", remaining)
        self.assertIn("5.6.7.8", remaining)
        self.assertIn("9.10.11.12", remaining)


class TestDynamoDBBackend(unittest.TestCase):
    """Test DynamoDBBackend implementation with mocked AWS calls."""

    @patch('storage_backends.boto3.client')
    @patch('storage_backends.boto3.resource')
    def setUp(self, mock_resource, mock_client):
        """Set up mocked DynamoDB backend."""
        self.mock_dynamodb = MagicMock()
        self.mock_table = MagicMock()
        mock_client.return_value = self.mock_dynamodb
        mock_resource.return_value.Table.return_value = self.mock_table

        self.backend = DynamoDBBackend(
            table_name="test-table",
            region="us-east-1",
        )

    def test_get_existing_item(self):
        """Test getting an existing item from DynamoDB."""
        self.mock_table.get_item.return_value = {
            "Item": {
                "ip": "1.2.3.4",
                "tier": "high",
                "priority": 3,
                "block_until_iso": "2025-01-20T10:00:00+00:00",
                "first_seen": "2025-01-15T10:00:00+00:00",
                "last_seen": "2025-01-15T10:00:00+00:00",
                "total_hits": 1000,
                "block_duration_hours": 72,
                "version": 1,
            }
        }

        result = self.backend.get("1.2.3.4")
        self.assertEqual(result["tier"], "high")
        self.assertEqual(result["priority"], 3)

    def test_get_non_existing_item(self):
        """Test getting a non-existing item returns None."""
        self.mock_table.get_item.return_value = {}

        result = self.backend.get("1.2.3.4")
        self.assertIsNone(result)

    def test_put_new_item(self):
        """Test putting a new item to DynamoDB."""
        entry = {
            "tier": "high",
            "priority": 3,
            "block_until": "2025-01-20T10:00:00+00:00",
            "first_seen": "2025-01-15T10:00:00+00:00",
            "last_seen": "2025-01-15T10:00:00+00:00",
            "total_hits": 1000,
            "block_duration_hours": 72,
        }

        self.backend.put("1.2.3.4", entry)

        self.mock_table.put_item.assert_called_once()
        call_args = self.mock_table.put_item.call_args
        item = call_args[1]["Item"]
        self.assertEqual(item["ip"], "1.2.3.4")
        self.assertEqual(item["tier"], "high")

    def test_delete_item(self):
        """Test deleting an item from DynamoDB."""
        self.backend.delete("1.2.3.4")

        self.mock_table.delete_item.assert_called_once_with(Key={"ip": "1.2.3.4"})


class TestS3Backend(unittest.TestCase):
    """Test S3Backend implementation with mocked AWS calls."""

    @patch('storage_backends.boto3.client')
    def setUp(self, mock_client):
        """Set up mocked S3 backend."""
        self.mock_s3 = MagicMock()
        mock_client.return_value = self.mock_s3

        self.backend = S3Backend(
            bucket="test-bucket",
            key="block_registry.json",
            region="us-east-1",
        )

    def test_load_existing_data(self):
        """Test loading existing data from S3."""
        test_data = {"1.2.3.4": {"tier": "high"}}
        self.mock_s3.get_object.return_value = {
            "Body": MagicMock(read=MagicMock(return_value=json.dumps(test_data).encode())),
            "ETag": '"abc123"',
        }

        result = self.backend.load()
        self.assertEqual(result, test_data)
        self.assertEqual(self.backend._etag, "abc123")

    def test_load_non_existing_key(self):
        """Test loading from non-existing key returns empty dict."""
        from botocore.exceptions import ClientError

        self.mock_s3.get_object.side_effect = ClientError(
            {"Error": {"Code": "NoSuchKey"}}, "GetObject"
        )

        result = self.backend.load()
        self.assertEqual(result, {})

    def test_save_data(self):
        """Test saving data to S3."""
        test_data = {"1.2.3.4": {"tier": "high"}}
        self.mock_s3.put_object.return_value = {"ETag": '"def456"'}

        self.backend.save(test_data)

        self.mock_s3.put_object.assert_called_once()
        call_args = self.mock_s3.put_object.call_args
        self.assertEqual(call_args[1]["Bucket"], "test-bucket")
        self.assertEqual(call_args[1]["Key"], "block_registry.json")

    def test_get_existing_ip(self):
        """Test getting an existing IP from S3."""
        test_data = {"1.2.3.4": {"tier": "high"}, "5.6.7.8": {"tier": "low"}}
        self.mock_s3.get_object.return_value = {
            "Body": MagicMock(read=MagicMock(return_value=json.dumps(test_data).encode())),
            "ETag": '"abc123"',
        }

        result = self.backend.get("1.2.3.4")
        self.assertEqual(result, {"tier": "high"})

    def test_delete_ip(self):
        """Test deleting an IP from S3."""
        test_data = {"1.2.3.4": {"tier": "high"}, "5.6.7.8": {"tier": "low"}}
        self.mock_s3.get_object.return_value = {
            "Body": MagicMock(read=MagicMock(return_value=json.dumps(test_data).encode())),
            "ETag": '"abc123"',
        }
        self.mock_s3.put_object.return_value = {"ETag": '"def456"'}

        self.backend.delete("1.2.3.4")

        # Verify put_object was called with data excluding deleted IP
        call_args = self.mock_s3.put_object.call_args
        saved_body = call_args[1]["Body"].decode()
        saved_data = json.loads(saved_body)
        self.assertNotIn("1.2.3.4", saved_data)
        self.assertIn("5.6.7.8", saved_data)


class TestCreateStorageBackend(unittest.TestCase):
    """Test the factory function."""

    def test_create_local_backend(self):
        """Test creating local file backend."""
        backend = create_storage_backend(
            backend_type="local",
            local_file="/tmp/test_registry.json",
        )
        self.assertIsInstance(backend, LocalFileBackend)

    @patch('storage_backends.boto3.client')
    @patch('storage_backends.boto3.resource')
    def test_create_dynamodb_backend(self, mock_resource, mock_client):
        """Test creating DynamoDB backend."""
        mock_client.return_value = MagicMock()
        mock_resource.return_value.Table.return_value = MagicMock()

        backend = create_storage_backend(
            backend_type="dynamodb",
            dynamodb_table="test-table",
            region="us-east-1",
        )
        self.assertIsInstance(backend, DynamoDBBackend)

    @patch('storage_backends.boto3.client')
    def test_create_s3_backend(self, mock_client):
        """Test creating S3 backend."""
        mock_client.return_value = MagicMock()

        backend = create_storage_backend(
            backend_type="s3",
            s3_bucket="test-bucket",
            s3_key="registry.json",
            region="us-east-1",
        )
        self.assertIsInstance(backend, S3Backend)

    def test_create_invalid_backend_type(self):
        """Test creating backend with invalid type raises ValueError."""
        with self.assertRaises(ValueError) as context:
            create_storage_backend(backend_type="invalid")
        self.assertIn("Unknown backend type", str(context.exception))

    def test_create_dynamodb_without_table(self):
        """Test creating DynamoDB backend without table raises ValueError."""
        with self.assertRaises(ValueError) as context:
            create_storage_backend(backend_type="dynamodb")
        self.assertIn("dynamodb_table is required", str(context.exception))

    def test_create_s3_without_bucket(self):
        """Test creating S3 backend without bucket raises ValueError."""
        with self.assertRaises(ValueError) as context:
            create_storage_backend(backend_type="s3")
        self.assertIn("s3_bucket is required", str(context.exception))


class TestStorageBackendInterface(unittest.TestCase):
    """Test that all backends properly implement the interface."""

    def test_local_backend_is_storage_backend(self):
        """Test LocalFileBackend is a StorageBackend."""
        backend = LocalFileBackend(file_path="/tmp/test.json")
        self.assertIsInstance(backend, StorageBackend)

    @patch('storage_backends.boto3.client')
    @patch('storage_backends.boto3.resource')
    def test_dynamodb_backend_is_storage_backend(self, mock_resource, mock_client):
        """Test DynamoDBBackend is a StorageBackend."""
        mock_client.return_value = MagicMock()
        mock_resource.return_value.Table.return_value = MagicMock()

        backend = DynamoDBBackend(table_name="test", region="us-east-1")
        self.assertIsInstance(backend, StorageBackend)

    @patch('storage_backends.boto3.client')
    def test_s3_backend_is_storage_backend(self, mock_client):
        """Test S3Backend is a StorageBackend."""
        mock_client.return_value = MagicMock()

        backend = S3Backend(bucket="test", region="us-east-1")
        self.assertIsInstance(backend, StorageBackend)


def run_tests():
    """Run all tests and return results."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestLocalFileBackend))
    suite.addTests(loader.loadTestsFromTestCase(TestDynamoDBBackend))
    suite.addTests(loader.loadTestsFromTestCase(TestS3Backend))
    suite.addTests(loader.loadTestsFromTestCase(TestCreateStorageBackend))
    suite.addTests(loader.loadTestsFromTestCase(TestStorageBackendInterface))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
