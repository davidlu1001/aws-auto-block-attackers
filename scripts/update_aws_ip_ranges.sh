#!/bin/bash
#
# Update AWS IP Ranges
#
# This script downloads the latest AWS IP ranges and updates the local file.
# Run this script once per day via cron.
#
# Usage:
#   ./update_aws_ip_ranges.sh [output_file]
#
# Cron example (runs daily at 2 AM):
#   0 2 * * * /opt/sre-scripts/security/update_aws_ip_ranges.sh

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_FILE="${1:-${SCRIPT_DIR}/ip-ranges.json}"
TEMP_FILE="${OUTPUT_FILE}.tmp"
BACKUP_FILE="${OUTPUT_FILE}.backup"
AWS_URL="https://ip-ranges.amazonaws.com/ip-ranges.json"
LOG_TAG="aws-ip-update"

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a /var/log/auto-block-attackers.log
    logger -t "${LOG_TAG}" "$*"
}

log "Starting AWS IP ranges update..."

# Download to temp file
if curl -f -s -S -o "${TEMP_FILE}" "${AWS_URL}"; then
    log "Successfully downloaded AWS IP ranges from ${AWS_URL}"

    # Validate JSON
    if python3 -m json.tool "${TEMP_FILE}" > /dev/null 2>&1; then
        log "JSON validation passed"

        # Get metadata
        SYNC_TOKEN=$(python3 -c "import json; print(json.load(open('${TEMP_FILE}'))['syncToken'])" 2>/dev/null || echo "unknown")
        CREATE_DATE=$(python3 -c "import json; print(json.load(open('${TEMP_FILE}'))['createDate'])" 2>/dev/null || echo "unknown")
        PREFIX_COUNT=$(python3 -c "import json; print(len(json.load(open('${TEMP_FILE}'))['prefixes']))" 2>/dev/null || echo "unknown")

        log "New file metadata: syncToken=${SYNC_TOKEN}, createDate=${CREATE_DATE}, prefixes=${PREFIX_COUNT}"

        # Backup old file if it exists
        if [[ -f "${OUTPUT_FILE}" ]]; then
            cp "${OUTPUT_FILE}" "${BACKUP_FILE}"
            log "Backed up old file to ${BACKUP_FILE}"
        fi

        # Move temp file to final location
        mv "${TEMP_FILE}" "${OUTPUT_FILE}"
        chmod 644 "${OUTPUT_FILE}"
        log "Successfully updated ${OUTPUT_FILE}"

        # Show file info
        FILE_SIZE=$(du -h "${OUTPUT_FILE}" | cut -f1)
        log "File size: ${FILE_SIZE}"

        exit 0
    else
        log "ERROR: Downloaded file is not valid JSON"
        rm -f "${TEMP_FILE}"
        exit 1
    fi
else
    log "ERROR: Failed to download from ${AWS_URL}"
    rm -f "${TEMP_FILE}"

    # Check if we have an existing file to fall back on
    if [[ -f "${OUTPUT_FILE}" ]]; then
        log "WARNING: Using existing file ${OUTPUT_FILE}"
        exit 0
    else
        log "CRITICAL: No existing file to fall back on!"
        exit 1
    fi
fi
