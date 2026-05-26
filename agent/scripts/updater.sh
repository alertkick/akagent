#!/bin/bash
#
# AlertKick Agent Updater Script
#
# This script handles safe agent binary updates with automatic rollback.
# It is installed alongside the agent via the .deb package.
#
# Usage:
#   alertkick-agent-updater.sh --package <path_to_deb> [--current-version <version>]
#
# Exit codes:
#   0 - Update successful
#   1 - Update failed, rolled back to previous version
#   2 - Invalid arguments
#   3 - Update failed, rollback also failed (manual intervention needed)

set -euo pipefail

# Configuration
AGENT_SERVICE="alertkick-agent"
AGENT_BINARY="/usr/local/bin/alertkick-agent"
BACKUP_BINARY="/usr/local/bin/alertkick-agent.backup"
LOG_DIR="/var/log/alertkick-agent"
LOG_FILE="${LOG_DIR}/update.log"
HEALTH_CHECK_TIMEOUT=30
HEALTH_CHECK_INTERVAL=2
MIGRATIONS_DIR="/etc/alertkick-agent/migrations"

# Parse arguments
PACKAGE_PATH=""
CURRENT_VERSION=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --package)
            PACKAGE_PATH="$2"
            shift 2
            ;;
        --current-version)
            CURRENT_VERSION="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 --package <path_to_deb> [--current-version <version>]"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            exit 2
            ;;
    esac
done

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" | tee -a "${LOG_FILE}"
}

# Ensure log directory exists
mkdir -p "${LOG_DIR}"

log "INFO" "=========================================="
log "INFO" "AlertKick Agent Update Started"
log "INFO" "=========================================="

# Validate arguments
if [[ -z "${PACKAGE_PATH}" ]]; then
    log "ERROR" "Package path is required. Usage: $0 --package <path_to_deb>"
    exit 2
fi

if [[ ! -f "${PACKAGE_PATH}" ]]; then
    log "ERROR" "Package file not found: ${PACKAGE_PATH}"
    exit 2
fi

log "INFO" "Package: ${PACKAGE_PATH}"
log "INFO" "Current version: ${CURRENT_VERSION:-unknown}"

# Step 1: Backup current binary
log "INFO" "Step 1: Backing up current agent binary"
if [[ -f "${AGENT_BINARY}" ]]; then
    cp "${AGENT_BINARY}" "${BACKUP_BINARY}"
    log "INFO" "Backup created at ${BACKUP_BINARY}"
else
    log "WARN" "Current agent binary not found at ${AGENT_BINARY}, skipping backup"
fi

# Step 2: Backup current config
log "INFO" "Step 2: Backing up configuration"
if [[ -f "/etc/alertkick-agent/alertkick-agent.conf" ]]; then
    cp "/etc/alertkick-agent/alertkick-agent.conf" "/etc/alertkick-agent/alertkick-agent.conf.backup"
    log "INFO" "Config backup created"
fi

# Step 3: Stop agent service
log "INFO" "Step 3: Stopping agent service"
if systemctl is-active --quiet "${AGENT_SERVICE}" 2>/dev/null; then
    systemctl stop "${AGENT_SERVICE}"
    log "INFO" "Agent service stopped"
else
    log "WARN" "Agent service was not running"
fi

# Step 4: Install new package
log "INFO" "Step 4: Installing new package"
if dpkg -i "${PACKAGE_PATH}" 2>&1 | tee -a "${LOG_FILE}"; then
    log "INFO" "Package installed successfully"
else
    log "ERROR" "Package installation failed"
    # Attempt rollback
    if [[ -f "${BACKUP_BINARY}" ]]; then
        log "INFO" "Rolling back to previous binary"
        cp "${BACKUP_BINARY}" "${AGENT_BINARY}"
        chmod +x "${AGENT_BINARY}"
        systemctl start "${AGENT_SERVICE}" 2>/dev/null || true
        log "INFO" "Rollback completed"
        exit 1
    fi
    log "ERROR" "No backup available for rollback"
    exit 3
fi

# Step 5: Run config migrations if any exist
log "INFO" "Step 5: Checking for config migrations"
if [[ -d "${MIGRATIONS_DIR}" ]]; then
    for migration in "${MIGRATIONS_DIR}"/*.sh; do
        if [[ -f "${migration}" && -x "${migration}" ]]; then
            log "INFO" "Running migration: ${migration}"
            if "${migration}" 2>&1 | tee -a "${LOG_FILE}"; then
                log "INFO" "Migration completed: ${migration}"
            else
                log "WARN" "Migration failed: ${migration} (continuing anyway)"
            fi
        fi
    done
else
    log "INFO" "No migrations directory found, skipping"
fi

# Step 6: Start agent service
log "INFO" "Step 6: Starting agent service"
systemctl start "${AGENT_SERVICE}"
log "INFO" "Agent service start command issued"

# Step 7: Health check
log "INFO" "Step 7: Running health check (timeout: ${HEALTH_CHECK_TIMEOUT}s)"
elapsed=0
healthy=false

while [[ ${elapsed} -lt ${HEALTH_CHECK_TIMEOUT} ]]; do
    sleep "${HEALTH_CHECK_INTERVAL}"
    elapsed=$((elapsed + HEALTH_CHECK_INTERVAL))

    if systemctl is-active --quiet "${AGENT_SERVICE}" 2>/dev/null; then
        # Additional check: verify the process is actually running
        if pgrep -f "alertkick-agent" > /dev/null 2>&1; then
            log "INFO" "Health check passed after ${elapsed}s - agent process is running"
            healthy=true
            break
        fi
    fi

    log "INFO" "Waiting for agent to start... (${elapsed}/${HEALTH_CHECK_TIMEOUT}s)"
done

if ${healthy}; then
    # Step 8: Success - clean up
    log "INFO" "Step 8: Update successful, cleaning up"

    # Get new version
    NEW_VERSION=""
    if [[ -x "${AGENT_BINARY}" ]]; then
        NEW_VERSION=$("${AGENT_BINARY}" -version 2>&1 | grep -oP 'Version \K[0-9.]+' || echo "unknown")
    fi

    # Remove backup
    rm -f "${BACKUP_BINARY}"
    rm -f "/etc/alertkick-agent/alertkick-agent.conf.backup"

    # Clean up downloaded package
    rm -f "${PACKAGE_PATH}"

    log "INFO" "=========================================="
    log "INFO" "Update completed successfully"
    log "INFO" "Previous version: ${CURRENT_VERSION:-unknown}"
    log "INFO" "New version: ${NEW_VERSION}"
    log "INFO" "=========================================="
    exit 0
else
    # Step 8: Failed - rollback
    log "ERROR" "Health check failed after ${HEALTH_CHECK_TIMEOUT}s"
    log "INFO" "Step 8: Rolling back to previous version"

    # Stop the failed service
    systemctl stop "${AGENT_SERVICE}" 2>/dev/null || true

    if [[ -f "${BACKUP_BINARY}" ]]; then
        # Restore backup binary
        cp "${BACKUP_BINARY}" "${AGENT_BINARY}"
        chmod +x "${AGENT_BINARY}"

        # Restore config backup if it exists
        if [[ -f "/etc/alertkick-agent/alertkick-agent.conf.backup" ]]; then
            cp "/etc/alertkick-agent/alertkick-agent.conf.backup" "/etc/alertkick-agent/alertkick-agent.conf"
        fi

        # Start with old version
        systemctl start "${AGENT_SERVICE}" 2>/dev/null || true

        # Verify rollback
        sleep 5
        if systemctl is-active --quiet "${AGENT_SERVICE}" 2>/dev/null; then
            log "INFO" "Rollback successful - agent running with previous version"
            rm -f "${BACKUP_BINARY}"
            rm -f "/etc/alertkick-agent/alertkick-agent.conf.backup"
            exit 1
        else
            log "ERROR" "Rollback failed - agent service could not start with previous version"
            log "ERROR" "Manual intervention required"
            exit 3
        fi
    else
        log "ERROR" "No backup binary available for rollback"
        log "ERROR" "Manual intervention required"
        exit 3
    fi
fi
