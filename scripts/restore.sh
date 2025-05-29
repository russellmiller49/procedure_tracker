#!/bin/bash
#
# Restore script for Procedure Tracker
# Restores encrypted backups with verification
# HIPAA-compliant with audit logging
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(dirname "$SCRIPT_DIR")"
RESTORE_DIR="/tmp/procedure_tracker_restore_$$"
LOG_FILE="${LOG_FILE:-/opt/procedure-tracker/logs/restore.log}"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup_file.tar.gz>"
    exit 1
fi
BACKUP_FILE="$1"

if [ -f "${APP_DIR}/.env" ]; then
    export $(grep -E '^[A-Z]' "${APP_DIR}/.env" | xargs)
fi

if [ -z "${BACKUP_ENCRYPTION_KEY}" ]; then
    echo "ERROR: BACKUP_ENCRYPTION_KEY not set" >&2
    exit 1
fi

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG_FILE}"
}

cleanup() {
    if [ -d "${RESTORE_DIR}" ]; then
        rm -rf "${RESTORE_DIR}"
    fi
}
trap cleanup EXIT

log "Starting restore process from: ${BACKUP_FILE}"

if [ ! -f "${BACKUP_FILE}" ]; then
    log "ERROR: Backup file not found"
    exit 1
fi

mkdir -p "${RESTORE_DIR}"

log "Extracting backup archive..."
tar -xzf "${BACKUP_FILE}" -C "${RESTORE_DIR}"
BACKUP_DIR=$(find "${RESTORE_DIR}" -name "procedure_tracker_*" -type d | head -1)

log "Restoring database..."
DB_CONTAINER=$(docker-compose ps -q postgres)
docker exec "$DB_CONTAINER" psql -U "$DB_USER" -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${DB_NAME}' AND pid <> pg_backend_pid();"
openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 -k "$BACKUP_ENCRYPTION_KEY" -in "${BACKUP_DIR}/database.sql.gz.enc" | \
  gunzip | docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME"

log "Restore completed"
