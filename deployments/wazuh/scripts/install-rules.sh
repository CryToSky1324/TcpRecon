#!/usr/bin/env bash
set -euo pipefail

# Determine script location and search for tcprecon_rules.xml
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SCRIPT_DIR/../rules/tcprecon_rules.xml" ]]; then
    RULE_SRC="$(cd "$SCRIPT_DIR/../rules" && pwd)/tcprecon_rules.xml"
elif [[ -f "$SCRIPT_DIR/../../../deployments/wazuh/rules/tcprecon_rules.xml" ]]; then
    RULE_SRC="$(cd "$SCRIPT_DIR/../../../deployments/wazuh/rules" && pwd)/tcprecon_rules.xml"
elif [[ -f "$HOME/tcprecon_rules.xml" ]]; then
    RULE_SRC="$HOME/tcprecon_rules.xml"
else
    echo "[!] FATAL: Cannot locate tcprecon_rules.xml in ../rules, repo root, or home directory." >&2
    exit 1
fi

RULE_DEST="/var/ossec/etc/rules/tcprecon_rules.xml"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
LOG_DIR="/var/log/tcprecon"
LOG_FILE="$LOG_DIR/events.ndjson"

# Enforce root execution
if [[ $EUID -ne 0 ]]; then
   echo "[!] FATAL: install-rules.sh must be executed as root (sudo)" >&2
   exit 1
fi

if [[ ! -f "$RULE_SRC" ]]; then
    echo "[!] FATAL: Source rule file not found at $RULE_SRC" >&2
    exit 1
fi

echo "[*] Staging tcprecon rules..."
cp "$RULE_SRC" "$RULE_DEST"
chown wazuh:wazuh "$RULE_DEST"
chmod 660 "$RULE_DEST"

echo "[*] Ensuring log sink directories and permissions..."
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chown -R wazuh:wazuh "$LOG_DIR"
chmod 750 "$LOG_DIR"
chmod 640 "$LOG_FILE"

echo "[*] Checking ossec.conf ingestion entry..."
if ! grep -qF "$LOG_FILE" "$OSSEC_CONF"; then
    echo "[*] Injecting <localfile> stanza into $OSSEC_CONF..."
    # Insert cleanly before the final </ossec_config>
    sed -i -e '/<\/ossec_config>/i \
  <localfile>\
    <log_format>json<\/log_format>\
    <location>'"$LOG_FILE"'<\/location>\
  <\/localfile>' "$OSSEC_CONF"
else
    echo "[*] Ingestion stanza already present in $OSSEC_CONF."
fi

echo "[*] Verifying Wazuh rules and configuration syntax..."
if ! /var/ossec/bin/wazuh-analysisd -t; then
    echo "[!] FATAL: wazuh-analysisd syntax validation failed! Reverting..." >&2
    exit 1
fi

echo "[*] Configuration valid. Reloading wazuh-manager..."
systemctl restart wazuh-manager
echo "[+] TcpRecon Wazuh rules and ingestion installed successfully."
