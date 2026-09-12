#!/usr/bin/env bash
set -euo pipefail

RULE_DEST="/var/ossec/etc/rules/tcprecon_rules.xml"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
LOG_FILE="/var/log/tcprecon/events.ndjson"

if [[ $EUID -ne 0 ]]; then
   echo "[!] FATAL: uninstall-rules.sh must be executed as root (sudo)" >&2
   exit 1
fi

echo "[*] Removing tcprecon rules..."
rm -f "$RULE_DEST"

if grep -qF "$LOG_FILE" "$OSSEC_CONF"; then
    echo "[*] Purging <localfile> stanza cleanly from $OSSEC_CONF..."
    python3 - << 'PYEOF'
import xml.etree.ElementTree as ET

conf_file = "/var/ossec/etc/ossec.conf"
target_sink = "/var/log/tcprecon/events.ndjson"

try:
    # Read entire file to handle multiple <ossec_config> blocks
    with open(conf_file, "r", encoding="utf-8") as f:
        content = f.read()

    # Wrap in root to safely parse multiple top-level <ossec_config> stanzas
    wrapped = f"<root>{content}</root>"
    root = ET.fromstring(wrapped)
    removed = False

    for cfg in root.findall("ossec_config"):
        for lf in list(cfg.findall("localfile")):
            loc = lf.find("location")
            if loc is not None and loc.text and target_sink in loc.text.strip():
                cfg.remove(lf)
                removed = True

    if removed:
        # Extract content back without the synthetic <root> wrapper
        new_content = "".join(ET.tostring(child, encoding="unicode") for child in root)
        with open(conf_file, "w", encoding="utf-8") as f:
            f.write(new_content)
        print("[+] Stanza cleanly excised via XML DOM parser.")
    else:
        print("[*] Target location not found in XML tree.")
except Exception as e:
    print(f"[!] DOM parse failed: {e}. Falling back to line-block purge...")
    # Safe multi-line block fallback
    with open(conf_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
    out = []
    skip = False
    for line in lines:
        if "<localfile>" in line:
            buffer = [line]
            skip = True
            continue
        if skip:
            buffer.append(line)
            if "</localfile>" in line:
                block_txt = "".join(buffer)
                if target_sink not in block_txt:
                    out.extend(buffer)
                skip = False
            continue
        out.append(line)
    with open(conf_file, "w", encoding="utf-8") as f:
        f.writelines(out)
PYEOF
fi

echo "[*] Validating manager configuration syntax..."
if ! /var/ossec/bin/wazuh-analysisd -t; then
    echo "[!] FATAL: Syntax check failed! Halting prior to service restart." >&2
    exit 1
fi

echo "[*] Configuration verified. Reloading wazuh-manager..."
systemctl restart wazuh-manager
echo "[+] TcpRecon Wazuh rules and ingestion uninstalled cleanly."
