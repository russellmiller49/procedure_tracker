#!/bin/bash
#
# Automated backup script for Procedure Tracker
# Performs encrypted backups of database and files
# HIPAA-compliant with encryption and audit logging
#

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${BACKUP_DIR:-/opt/procedure-tracker/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-90}"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="procedure_tracker_${DATE}"
LOG_FILE="${LOG_FILE:-/opt/procedure-tracker/logs/backup.log}"

# Load environment variables
if [ -f "${APP_DIR}/.env" ]; then
    export $(grep -E '^[A-Z]' "${APP_DIR}/.env" | xargs)
fi

# Ensure required variables are set
if [ -z "${BACKUP_ENCRYPTION_KEY}" ]; then
    echo "ERROR: BACKUP_ENCRYPTION_KEY not set" >&2
    exit 1
fi

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG_FILE}"
}

# Error handler
error_handler() {
    log "ERROR: Backup failed at line $1"
    if [ -d "${BACKUP_DIR}/${BACKUP_NAME}" ]; then
        rm -rf "${BACKUP_DIR}/${BACKUP_NAME}"
    fi
    if [ -n "${SMTP_HOST}" ] && [ -n "${ALERT_EMAIL}" ]; then
        echo "Backup failed for Procedure Tracker on $(hostname)" | \
        mail -s "CRITICAL: Backup Failure" "${ALERT_EMAIL}"
    fi
    exit 1
}
trap 'error_handler $LINENO' ERR

log "Starting backup process: ${BACKUP_NAME}"

mkdir -p "${BACKUP_DIR}/${BACKUP_NAME}"
chmod 700 "${BACKUP_DIR}/${BACKUP_NAME}"

DB_CONTAINER=$(docker-compose ps -q postgres)
APP_CONTAINER=$(docker-compose ps -q app)
if [ -z "$DB_CONTAINER" ] || [ -z "$APP_CONTAINER" ]; then
    log "ERROR: Required containers not running"
    exit 1
fi

log "Backing up PostgreSQL database..."
docker exec "$DB_CONTAINER" pg_dump -U "$DB_USER" -d "$DB_NAME" \
    --no-owner --clean --if-exists --quote-all-identifiers \
    --exclude-table-data="audit_logs" --exclude-table-data="user_sessions" | \
    gzip -9 | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
    -k "$BACKUP_ENCRYPTION_KEY" \
    -out "${BACKUP_DIR}/${BACKUP_NAME}/database.sql.gz.enc"

log "Backing up audit logs..."
docker exec "$DB_CONTAINER" pg_dump -U "$DB_USER" -d "$DB_NAME" \
    --table="audit_logs" --data-only | \
    gzip -9 | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
    -k "$BACKUP_ENCRYPTION_KEY" \
    -out "${BACKUP_DIR}/${BACKUP_NAME}/audit_logs.sql.gz.enc"

if [ -d "/opt/procedure-tracker/data/uploads" ]; then
    log "Backing up uploaded files..."
    tar -czf - -C /opt/procedure-tracker/data uploads 2>/dev/null | \
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
        -k "$BACKUP_ENCRYPTION_KEY" \
        -out "${BACKUP_DIR}/${BACKUP_NAME}/uploads.tar.gz.enc"
fi

log "Backing up configuration..."
cd "$APP_DIR"
tar -czf - --exclude='.env' --exclude='*.key' --exclude='*.pem' \
    nginx/conf.d config package.json package-lock.json | \
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
    -k "$BACKUP_ENCRYPTION_KEY" \
    -out "${BACKUP_DIR}/${BACKUP_NAME}/config.tar.gz.enc"

log "Creating backup manifest..."
cat > "${BACKUP_DIR}/${BACKUP_NAME}/manifest.json" << MAN
{
  "version": "2.0",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "hostname": "$(hostname)",
  "backup_name": "${BACKUP_NAME}",
  "backup_type": "full",
  "encryption": {"algorithm": "aes-256-cbc", "pbkdf2_iterations": 100000},
  "database": {
    "name": "${DB_NAME}",
    "version": "$(docker exec ${DB_CONTAINER} psql -U ${DB_USER} -d ${DB_NAME} -t -c 'SELECT version()')",
    "size": "$(stat -c%s \"${BACKUP_DIR}/${BACKUP_NAME}/database.sql.gz.enc\" 2>/dev/null || echo 0)"
  }
}
MAN

log "Creating integrity verification..."
cd "${BACKUP_DIR}/${BACKUP_NAME}"
sha256sum * > checksums.sha256

log "Compressing backup archive..."
cd "$BACKUP_DIR"
tar -czf "${BACKUP_NAME}.tar.gz" "${BACKUP_NAME}/"
rm -rf "${BACKUP_NAME}"
sha256sum "${BACKUP_NAME}.tar.gz" > "${BACKUP_NAME}.tar.gz.sha256"
chmod 600 "${BACKUP_NAME}.tar.gz" "${BACKUP_NAME}.tar.gz.sha256"

log "Backup process completed successfully"
exit 0
