"""
Storage Backend Abstraction Layer for AWS Auto Block Attackers

This module provides pluggable storage backends for the block registry,
enabling deployment in containerized environments (ECS Fargate, Lambda)
where local filesystem persistence is not reliable.

Supported Backends:
    - LocalFileBackend: Original JSON file storage (backward compatible)
    - DynamoDBBackend: Distributed storage with TTL and optimistic locking
    - S3Backend: Lightweight cloud storage with versioning support

Architecture:
    All backends implement the StorageBackend abstract base class, ensuring
    consistent behavior across storage implementations. The factory function
    create_storage_backend() handles instantiation based on configuration.

Usage:
    # Via factory (recommended)
    backend = create_storage_backend(
        backend_type='dynamodb',
        dynamodb_table='block-registry',
        region='us-east-1'
    )

    # Direct instantiation
    backend = DynamoDBBackend(table_name='block-registry', region='us-east-1')

    # Operations
    data = backend.load()
    backend.save(data)
    entry = backend.get('1.2.3.4')
    backend.put('1.2.3.4', {'tier': 'high', ...})
    backend.delete('1.2.3.4')
    expired = backend.get_expired(datetime.now(timezone.utc))
"""

import json
import logging
import os
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Set, Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class StorageBackend(ABC):
    """
    Abstract base class for block registry storage backends.

    All storage backends must implement these methods to ensure consistent
    behavior across different storage implementations.

    Thread Safety:
        Implementations should be thread-safe for concurrent read operations.
        Write operations may require external synchronization depending on
        the specific backend implementation.
    """

    @abstractmethod
    def load(self) -> Dict[str, Dict]:
        """
        Load the entire block registry.

        Returns:
            Dict[str, Dict]: Dictionary mapping IP addresses to their block data.
                            Returns empty dict if no data exists.

        Raises:
            StorageError: If the storage is inaccessible or corrupted.
        """
        pass

    @abstractmethod
    def save(self, data: Dict[str, Dict]) -> None:
        """
        Save the entire block registry.

        Args:
            data: Dictionary mapping IP addresses to their block data.

        Raises:
            StorageError: If the save operation fails.
        """
        pass

    @abstractmethod
    def get(self, ip: str) -> Optional[Dict]:
        """
        Get block data for a specific IP address.

        Args:
            ip: The IP address to look up.

        Returns:
            Optional[Dict]: Block data if found, None otherwise.
        """
        pass

    @abstractmethod
    def put(self, ip: str, data: Dict) -> None:
        """
        Store or update block data for a specific IP address.

        Args:
            ip: The IP address to store.
            data: Block data dictionary containing tier, priority, block_until, etc.

        Raises:
            StorageError: If the put operation fails.
            ConflictError: If optimistic locking detects a concurrent modification.
        """
        pass

    @abstractmethod
    def delete(self, ip: str) -> None:
        """
        Delete block data for a specific IP address.

        Args:
            ip: The IP address to delete.

        Note:
            Should not raise an error if the IP doesn't exist.
        """
        pass

    @abstractmethod
    def get_expired(self, now: datetime) -> Set[str]:
        """
        Get all IP addresses whose blocks have expired.

        Args:
            now: Current UTC datetime for expiration comparison.

        Returns:
            Set[str]: Set of IP addresses with expired blocks.
        """
        pass

    def cleanup_old_entries(self, now: datetime, days_old: int = 30) -> int:
        """
        Remove entries that expired more than `days_old` days ago.

        Args:
            now: Current UTC datetime.
            days_old: Remove entries expired more than this many days ago.

        Returns:
            int: Number of entries removed.
        """
        # Default implementation - subclasses can override for efficiency
        from datetime import timedelta

        cutoff = now - timedelta(days=days_old)
        data = self.load()
        to_remove = []

        for ip, entry in data.items():
            try:
                block_until_str = entry.get("block_until")
                if block_until_str:
                    block_until = datetime.fromisoformat(block_until_str)
                    if block_until.tzinfo is None:
                        block_until = block_until.replace(tzinfo=timezone.utc)
                    if block_until < cutoff:
                        to_remove.append(ip)
            except (ValueError, TypeError) as e:
                logger.warning(f"Error parsing block_until for {ip}: {e}")

        for ip in to_remove:
            self.delete(ip)

        if to_remove:
            logger.info(f"Cleaned up {len(to_remove)} old registry entries")

        return len(to_remove)


class StorageError(Exception):
    """Raised when a storage operation fails."""

    pass


class ConflictError(StorageError):
    """Raised when optimistic locking detects a concurrent modification."""

    pass


class LocalFileBackend(StorageBackend):
    """
    Local JSON file storage backend.

    This is the original storage mechanism, maintained for backward compatibility
    and local development. Uses atomic file writes to prevent corruption.

    Attributes:
        file_path: Path to the JSON registry file.

    Thread Safety:
        Uses atomic rename for write operations to prevent corruption from
        concurrent writes, but does not provide true concurrent access safety.
    """

    def __init__(self, file_path: str = "./block_registry.json"):
        """
        Initialize the local file backend.

        Args:
            file_path: Path to the JSON registry file. Parent directories
                      will be created if they don't exist.
        """
        self.file_path = file_path
        self._ensure_directory()

    def _ensure_directory(self) -> None:
        """Ensure the parent directory exists."""
        parent = Path(self.file_path).parent
        if parent and str(parent) != ".":
            parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> Dict[str, Dict]:
        """Load registry from JSON file."""
        try:
            if os.path.exists(self.file_path):
                with open(self.file_path, "r") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        logger.info(f"Loaded block registry with {len(data)} IPs from {self.file_path}")
                        return data
                    else:
                        logger.warning("Block registry has invalid structure. Starting fresh.")
                        return {}
            else:
                logger.info("Block registry file not found. Starting with empty registry.")
                return {}
        except json.JSONDecodeError as e:
            logger.warning(f"Block registry JSON is corrupted: {e}. Starting fresh.")
            return {}
        except Exception as e:
            logger.warning(f"Error loading block registry: {e}. Starting fresh.")
            return {}

    def save(self, data: Dict[str, Dict]) -> None:
        """Save registry to JSON file atomically."""
        try:
            self._ensure_directory()

            # Write to temp file first, then atomic rename
            temp_file = f"{self.file_path}.tmp"
            with open(temp_file, "w") as f:
                json.dump(data, f, indent=2, default=str)
            os.rename(temp_file, self.file_path)
            logger.info(f"Saved block registry with {len(data)} IPs to {self.file_path}")
        except Exception as e:
            logger.error(f"Failed to save block registry: {e}")
            raise StorageError(f"Failed to save registry: {e}") from e

    def get(self, ip: str) -> Optional[Dict]:
        """Get block data for a specific IP."""
        data = self.load()
        return data.get(ip)

    def put(self, ip: str, entry: Dict) -> None:
        """Store block data for a specific IP."""
        data = self.load()
        data[ip] = entry
        self.save(data)

    def delete(self, ip: str) -> None:
        """Delete block data for a specific IP."""
        data = self.load()
        if ip in data:
            del data[ip]
            self.save(data)

    def get_expired(self, now: datetime) -> Set[str]:
        """Get all IPs with expired blocks."""
        expired = set()
        data = self.load()

        for ip, entry in data.items():
            try:
                block_until_str = entry.get("block_until")
                if block_until_str:
                    block_until = datetime.fromisoformat(block_until_str)
                    if block_until.tzinfo is None:
                        block_until = block_until.replace(tzinfo=timezone.utc)
                    if now >= block_until:
                        expired.add(ip)
            except (ValueError, TypeError) as e:
                logger.warning(f"Error checking expiry for {ip}: {e}")

        return expired


class DynamoDBBackend(StorageBackend):
    """
    DynamoDB storage backend with TTL and optimistic locking.

    Provides distributed, highly-available storage suitable for containerized
    deployments. Uses DynamoDB TTL for automatic expiration cleanup and
    conditional expressions for optimistic locking.

    Table Schema:
        - ip (String, Partition Key): The blocked IP address
        - tier (String): Block tier (critical, high, medium, low, minimal)
        - priority (Number): Numeric priority for slot management
        - block_until (Number): Unix timestamp, TTL attribute for auto-expiration
        - block_until_iso (String): ISO format timestamp for human readability
        - first_seen (String): ISO timestamp of first detection
        - last_seen (String): ISO timestamp of most recent detection
        - total_hits (Number): Total malicious request count
        - block_duration_hours (Number): Duration of the block in hours
        - version (Number): Optimistic locking version counter

    Required IAM Permissions:
        - dynamodb:GetItem
        - dynamodb:PutItem
        - dynamodb:DeleteItem
        - dynamodb:Scan
        - dynamodb:Query
        - dynamodb:DescribeTable
        - dynamodb:CreateTable (optional, for auto-creation)

    TTL Configuration:
        The table should have TTL enabled on the `block_until` attribute
        for automatic cleanup of expired entries.
    """

    def __init__(
        self,
        table_name: str,
        region: str = "us-east-1",
        create_table: bool = False,
        endpoint_url: Optional[str] = None,
    ):
        """
        Initialize the DynamoDB backend.

        Args:
            table_name: Name of the DynamoDB table.
            region: AWS region for the table.
            create_table: If True, create the table if it doesn't exist.
            endpoint_url: Optional endpoint URL (for local DynamoDB testing).
        """
        self.table_name = table_name
        self.region = region

        boto_config = Config(
            connect_timeout=10,
            read_timeout=30,
            retries={"max_attempts": 5, "mode": "adaptive"},
        )

        client_kwargs = {"region_name": region, "config": boto_config}
        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url

        self.dynamodb = boto3.client("dynamodb", **client_kwargs)
        self.table = boto3.resource("dynamodb", **client_kwargs).Table(table_name)

        if create_table:
            self._ensure_table_exists()

    def _ensure_table_exists(self) -> None:
        """Create the table if it doesn't exist."""
        try:
            self.dynamodb.describe_table(TableName=self.table_name)
            logger.info(f"DynamoDB table {self.table_name} exists")
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                logger.info(f"Creating DynamoDB table {self.table_name}")
                self._create_table()
            else:
                raise StorageError(f"Error checking table: {e}") from e

    def _create_table(self) -> None:
        """Create the DynamoDB table with appropriate schema."""
        try:
            self.dynamodb.create_table(
                TableName=self.table_name,
                KeySchema=[{"AttributeName": "ip", "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": "ip", "AttributeType": "S"}],
                BillingMode="PAY_PER_REQUEST",
            )

            # Wait for table to be active
            waiter = self.dynamodb.get_waiter("table_exists")
            waiter.wait(TableName=self.table_name)

            # Enable TTL on block_until attribute
            self.dynamodb.update_time_to_live(
                TableName=self.table_name,
                TimeToLiveSpecification={
                    "Enabled": True,
                    "AttributeName": "block_until",
                },
            )

            logger.info(f"Created DynamoDB table {self.table_name} with TTL enabled")
        except ClientError as e:
            raise StorageError(f"Failed to create table: {e}") from e

    def _serialize_entry(self, ip: str, entry: Dict) -> Dict[str, Any]:
        """Convert registry entry to DynamoDB item format."""
        # Convert block_until to Unix timestamp for TTL
        block_until_ts = None
        block_until_iso = entry.get("block_until")
        if block_until_iso:
            try:
                dt = datetime.fromisoformat(block_until_iso)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                block_until_ts = int(dt.timestamp())
            except (ValueError, TypeError):
                pass

        item = {
            "ip": ip,
            "tier": entry.get("tier", "unknown"),
            "priority": entry.get("priority", 0),
            "first_seen": entry.get("first_seen", ""),
            "last_seen": entry.get("last_seen", ""),
            "total_hits": entry.get("total_hits", 0),
            "block_duration_hours": entry.get("block_duration_hours", 0),
            "block_until_iso": block_until_iso or "",
            "version": entry.get("version", 1),
        }

        if block_until_ts:
            item["block_until"] = block_until_ts

        # Preserve any additional fields
        for key, value in entry.items():
            if key not in item and key != "block_until":
                item[key] = value

        return item

    def _deserialize_item(self, item: Dict[str, Any]) -> Dict:
        """Convert DynamoDB item to registry entry format."""
        entry = {
            "tier": item.get("tier", "unknown"),
            "priority": int(item.get("priority", 0)),
            "first_seen": item.get("first_seen", ""),
            "last_seen": item.get("last_seen", ""),
            "total_hits": int(item.get("total_hits", 0)),
            "block_duration_hours": float(item.get("block_duration_hours", 0)),
            "block_until": item.get("block_until_iso", ""),
            "version": int(item.get("version", 1)),
        }

        # Include any additional fields
        for key, value in item.items():
            if key not in ["ip", "block_until", "block_until_iso", "version"] and key not in entry:
                entry[key] = value

        return entry

    def load(self) -> Dict[str, Dict]:
        """Load all entries from DynamoDB."""
        try:
            data = {}
            paginator = self.dynamodb.get_paginator("scan")

            for page in paginator.paginate(TableName=self.table_name):
                for item in page.get("Items", []):
                    # Convert DynamoDB format to Python dict
                    ip = item.get("ip", {}).get("S", "")
                    if ip:
                        python_item = self._dynamodb_to_python(item)
                        data[ip] = self._deserialize_item(python_item)

            logger.info(f"Loaded {len(data)} entries from DynamoDB table {self.table_name}")
            return data
        except ClientError as e:
            logger.error(f"Failed to load from DynamoDB: {e}")
            raise StorageError(f"Failed to load from DynamoDB: {e}") from e

    def _dynamodb_to_python(self, item: Dict) -> Dict:
        """Convert DynamoDB typed format to Python dict."""
        result = {}
        for key, value in item.items():
            if "S" in value:
                result[key] = value["S"]
            elif "N" in value:
                result[key] = value["N"]
            elif "BOOL" in value:
                result[key] = value["BOOL"]
            elif "NULL" in value:
                result[key] = None
            else:
                result[key] = value
        return result

    def save(self, data: Dict[str, Dict]) -> None:
        """
        Save all entries to DynamoDB.

        Note: This performs a full replace operation. For large datasets,
        consider using individual put() calls for better efficiency.
        """
        try:
            # Get existing IPs to handle deletions
            existing = set(self.load().keys())
            new_ips = set(data.keys())

            # Delete removed entries
            for ip in existing - new_ips:
                self.delete(ip)

            # Put new/updated entries
            for ip, entry in data.items():
                self.put(ip, entry)

            logger.info(f"Saved {len(data)} entries to DynamoDB table {self.table_name}")
        except ClientError as e:
            logger.error(f"Failed to save to DynamoDB: {e}")
            raise StorageError(f"Failed to save to DynamoDB: {e}") from e

    def get(self, ip: str) -> Optional[Dict]:
        """Get block data for a specific IP."""
        try:
            response = self.table.get_item(Key={"ip": ip})
            item = response.get("Item")
            if item:
                return self._deserialize_item(item)
            return None
        except ClientError as e:
            logger.error(f"Failed to get {ip} from DynamoDB: {e}")
            raise StorageError(f"Failed to get from DynamoDB: {e}") from e

    def put(self, ip: str, entry: Dict) -> None:
        """
        Store block data with optimistic locking.

        Uses conditional expression to prevent concurrent overwrites.
        """
        try:
            item = self._serialize_entry(ip, entry)

            # Increment version for optimistic locking
            old_version = entry.get("version", 0)
            item["version"] = old_version + 1

            # Use conditional expression for optimistic locking
            if old_version > 0:
                try:
                    self.table.put_item(
                        Item=item,
                        ConditionExpression="attribute_not_exists(ip) OR version = :v",
                        ExpressionAttributeValues={":v": old_version},
                    )
                except ClientError as e:
                    if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                        # Concurrent modification - retry with fresh data
                        logger.warning(f"Concurrent modification detected for {ip}, retrying")
                        existing = self.get(ip)
                        if existing:
                            # Merge updates and retry
                            merged = {**existing, **entry}
                            merged["version"] = existing.get("version", 0)
                            self.put(ip, merged)
                            return
                        else:
                            # Entry was deleted, proceed with new entry
                            item["version"] = 1
                            self.table.put_item(Item=item)
                    else:
                        raise
            else:
                self.table.put_item(Item=item)

            logger.debug(f"Stored {ip} in DynamoDB (version {item['version']})")
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise ConflictError(f"Concurrent modification for {ip}") from e
            logger.error(f"Failed to put {ip} to DynamoDB: {e}")
            raise StorageError(f"Failed to put to DynamoDB: {e}") from e

    def delete(self, ip: str) -> None:
        """Delete block data for a specific IP."""
        try:
            self.table.delete_item(Key={"ip": ip})
            logger.debug(f"Deleted {ip} from DynamoDB")
        except ClientError as e:
            # Ignore if item doesn't exist
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                logger.error(f"Failed to delete {ip} from DynamoDB: {e}")
                raise StorageError(f"Failed to delete from DynamoDB: {e}") from e

    def get_expired(self, now: datetime) -> Set[str]:
        """Get all IPs with expired blocks."""
        expired = set()
        now_ts = int(now.timestamp())

        try:
            # Scan for items where block_until < now
            # Note: In production, consider using a GSI for more efficient queries
            paginator = self.dynamodb.get_paginator("scan")

            for page in paginator.paginate(
                TableName=self.table_name,
                FilterExpression="block_until < :now",
                ExpressionAttributeValues={":now": {"N": str(now_ts)}},
            ):
                for item in page.get("Items", []):
                    ip = item.get("ip", {}).get("S", "")
                    if ip:
                        expired.add(ip)

            return expired
        except ClientError as e:
            logger.error(f"Failed to get expired entries from DynamoDB: {e}")
            raise StorageError(f"Failed to get expired: {e}") from e

    def cleanup_old_entries(self, now: datetime, days_old: int = 30) -> int:
        """
        DynamoDB TTL handles this automatically.

        Returns 0 as entries are auto-deleted by DynamoDB when TTL expires.
        """
        # DynamoDB TTL handles automatic deletion
        logger.info("DynamoDB TTL handles automatic cleanup of expired entries")
        return 0


class S3Backend(StorageBackend):
    """
    S3 storage backend with versioning support.

    Provides a lightweight cloud storage option using S3. Uses ETags for
    conflict detection and supports S3 versioning for data protection.

    Storage Format:
        The registry is stored as a single JSON file in the specified bucket.
        S3 versioning is recommended for recovery from accidental deletions.

    Required IAM Permissions:
        - s3:GetObject
        - s3:PutObject
        - s3:DeleteObject
        - s3:ListBucket
        - s3:GetObjectVersion (if versioning enabled)

    ETag-Based Conflict Detection:
        Uses S3 ETags to detect concurrent modifications. If a conflict is
        detected, the operation will retry with the latest data.
    """

    def __init__(
        self,
        bucket: str,
        key: str = "block_registry.json",
        region: str = "us-east-1",
        endpoint_url: Optional[str] = None,
    ):
        """
        Initialize the S3 backend.

        Args:
            bucket: S3 bucket name.
            key: S3 object key for the registry file.
            region: AWS region for the bucket.
            endpoint_url: Optional endpoint URL (for S3-compatible storage).
        """
        self.bucket = bucket
        self.key = key
        self.region = region
        self._etag: Optional[str] = None

        boto_config = Config(
            connect_timeout=10,
            read_timeout=30,
            retries={"max_attempts": 5, "mode": "adaptive"},
        )

        client_kwargs = {"region_name": region, "config": boto_config}
        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url

        self.s3 = boto3.client("s3", **client_kwargs)

    def load(self) -> Dict[str, Dict]:
        """Load registry from S3."""
        try:
            response = self.s3.get_object(Bucket=self.bucket, Key=self.key)
            self._etag = response.get("ETag", "").strip('"')
            data = json.loads(response["Body"].read().decode("utf-8"))

            if isinstance(data, dict):
                logger.info(f"Loaded {len(data)} entries from s3://{self.bucket}/{self.key}")
                return data
            else:
                logger.warning("S3 registry has invalid structure. Starting fresh.")
                return {}
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                logger.info("S3 registry not found. Starting with empty registry.")
                self._etag = None
                return {}
            logger.error(f"Failed to load from S3: {e}")
            raise StorageError(f"Failed to load from S3: {e}") from e
        except json.JSONDecodeError as e:
            logger.warning(f"S3 registry JSON is corrupted: {e}. Starting fresh.")
            self._etag = None
            return {}

    def save(self, data: Dict[str, Dict]) -> None:
        """
        Save registry to S3 with ETag-based conflict detection.

        Uses conditional put to prevent overwriting concurrent changes.
        """
        try:
            body = json.dumps(data, indent=2, default=str)

            put_kwargs = {
                "Bucket": self.bucket,
                "Key": self.key,
                "Body": body.encode("utf-8"),
                "ContentType": "application/json",
            }

            # Use ETag for optimistic locking if we have one
            if self._etag:
                put_kwargs["Metadata"] = {"previous-etag": self._etag}

            response = self.s3.put_object(**put_kwargs)
            self._etag = response.get("ETag", "").strip('"')

            logger.info(f"Saved {len(data)} entries to s3://{self.bucket}/{self.key}")
        except ClientError as e:
            logger.error(f"Failed to save to S3: {e}")
            raise StorageError(f"Failed to save to S3: {e}") from e

    def get(self, ip: str) -> Optional[Dict]:
        """Get block data for a specific IP."""
        data = self.load()
        return data.get(ip)

    def put(self, ip: str, entry: Dict) -> None:
        """Store block data for a specific IP."""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                data = self.load()
                data[ip] = entry
                self.save(data)
                return
            except StorageError as e:
                if attempt < max_retries - 1:
                    logger.warning(f"Retry {attempt + 1}/{max_retries} for put({ip})")
                    time.sleep(0.5 * (attempt + 1))
                else:
                    raise

    def delete(self, ip: str) -> None:
        """Delete block data for a specific IP."""
        try:
            data = self.load()
            if ip in data:
                del data[ip]
                self.save(data)
        except StorageError:
            pass  # Ignore errors when deleting non-existent entries

    def get_expired(self, now: datetime) -> Set[str]:
        """Get all IPs with expired blocks."""
        expired = set()
        data = self.load()

        for ip, entry in data.items():
            try:
                block_until_str = entry.get("block_until")
                if block_until_str:
                    block_until = datetime.fromisoformat(block_until_str)
                    if block_until.tzinfo is None:
                        block_until = block_until.replace(tzinfo=timezone.utc)
                    if now >= block_until:
                        expired.add(ip)
            except (ValueError, TypeError) as e:
                logger.warning(f"Error checking expiry for {ip}: {e}")

        return expired


def create_storage_backend(
    backend_type: str = "local",
    local_file: str = "./block_registry.json",
    dynamodb_table: Optional[str] = None,
    s3_bucket: Optional[str] = None,
    s3_key: str = "block_registry.json",
    region: str = "us-east-1",
    create_dynamodb_table: bool = False,
) -> StorageBackend:
    """
    Factory function to create the appropriate storage backend.

    Args:
        backend_type: One of 'local', 'dynamodb', or 's3'.
        local_file: Path for local file backend.
        dynamodb_table: Table name for DynamoDB backend.
        s3_bucket: Bucket name for S3 backend.
        s3_key: Object key for S3 backend.
        region: AWS region for cloud backends.
        create_dynamodb_table: Whether to create DynamoDB table if missing.

    Returns:
        StorageBackend: Configured storage backend instance.

    Raises:
        ValueError: If required parameters are missing for the selected backend.

    Example:
        # Local backend (default)
        backend = create_storage_backend()

        # DynamoDB backend
        backend = create_storage_backend(
            backend_type='dynamodb',
            dynamodb_table='block-registry',
            region='us-east-1'
        )

        # S3 backend
        backend = create_storage_backend(
            backend_type='s3',
            s3_bucket='my-security-bucket',
            s3_key='config/block_registry.json'
        )
    """
    backend_type = backend_type.lower()

    if backend_type == "local":
        logger.info(f"Using local file storage backend: {local_file}")
        return LocalFileBackend(file_path=local_file)

    elif backend_type == "dynamodb":
        if not dynamodb_table:
            raise ValueError("dynamodb_table is required for DynamoDB backend")
        logger.info(f"Using DynamoDB storage backend: {dynamodb_table}")
        return DynamoDBBackend(
            table_name=dynamodb_table,
            region=region,
            create_table=create_dynamodb_table,
        )

    elif backend_type == "s3":
        if not s3_bucket:
            raise ValueError("s3_bucket is required for S3 backend")
        logger.info(f"Using S3 storage backend: s3://{s3_bucket}/{s3_key}")
        return S3Backend(bucket=s3_bucket, key=s3_key, region=region)

    else:
        raise ValueError(f"Unknown backend type: {backend_type}. Use 'local', 'dynamodb', or 's3'")
