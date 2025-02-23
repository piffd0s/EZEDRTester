#!/bin/bash
#
# MITRE ATT&CK EDR Testing Script for macOS - Comprehensive Simulation
# ------------------------------------------------------------
# This script simulates a broad set of MITRE ATT&CK techniques using benign commands
# and logs each simulated technique to /tmp/EDRTestLog.txt.
#
# Techniques simulated include (but are not limited to):
#   - T1086: Shell/Script Execution
#   - T1059: Command-Line Interface
#   - T1021: Remote Services (SMB/SSH simulation)
#   - T1003: Credential Dumping Simulation
#   - T1566: Phishing Simulation
#   - T1055: Process Injection Simulation
#   - T1047: System Information Discovery
#   - T1053: Scheduled Task Simulation
#   - T1071: Application Layer Protocol Communication
#   - T1105: Ingress Tool Transfer Simulation
#   - T1027: Obfuscated Files or Information Simulation
#   - T1083: File and Directory Discovery
#   - T1070: Indicator Removal on Host Simulation
#   - T1112: Preferences Modification Simulation
#   - T1204: User Execution Simulation
#   - T1497: Virtualization/Sandbox Evasion Simulation
#   - T1218: Signed Binary Proxy Execution Simulation
#   - T1219: Remote Access Tools Simulation
#   - T1486: Data Encrypted for Impact Simulation
#
# Use only on systems where you have explicit permission.
#

LOGFILE="/tmp/EDRTestLog.txt"
echo "EDR Test Log - $(date)" > "$LOGFILE"

# Function to log test execution
log_test() {
    local technique=$1
    local description=$2
    local message="$(date) - Executing Technique $technique: $description"
    echo "$message" | tee -a "$LOGFILE"
}

# T1086: Shell/Script Execution Simulation (using a benign date command)
invoke_T1086() {
    log_test "T1086" "Shell Execution (running 'date')"
    date >> "$LOGFILE"
}

# T1059: Command-Line Interface Simulation (using echo)
invoke_T1059() {
    log_test "T1059" "Command-Line Execution (echo command)"
    echo "Testing T1059: Command Execution" >> "$LOGFILE"
}

# T1021: Remote Services Simulation (listing available network shares via smbutil)
invoke_T1021() {
    log_test "T1021" "Remote Services Simulation (using 'smbutil statshares' if available)"
    smbutil statshares -a >> "$LOGFILE" 2>&1
}

# T1003: Credential Dumping Simulation (using 'security' to list generic passwords)
invoke_T1003() {
    log_test "T1003" "Credential Dumping Simulation (listing generic keychain items)"
    security find-generic-password -ga dummy 2>&1 | head -n 3 >> "$LOGFILE"
}

# T1566: Phishing Simulation (opening a benign text file in TextEdit)
invoke_T1566() {
    log_test "T1566" "Phishing Simulation (opening a dummy phishing text file in TextEdit)"
    PHISH_FILE="/tmp/phishing_simulation.txt"
    echo "Simulated phishing email content for EDR testing." > "$PHISH_FILE"
    open -a "TextEdit" "$PHISH_FILE"
}

# T1055: Process Injection Simulation (simulate by launching a process)
invoke_T1055() {
    log_test "T1055" "Process Injection Simulation (launching a benign application - Calculator)"
    open -a "Calculator"
}

# T1047: System Information Discovery Simulation (using system_profiler)
invoke_T1047() {
    log_test "T1047" "System Information Discovery (querying system profile)"
    system_profiler SPSoftwareDataType | head -n 10 >> "$LOGFILE"
}

# T1053: Scheduled Task Simulation (simulate by creating a temporary cron job)
invoke_T1053() {
    log_test "T1053" "Scheduled Task Simulation (listing crontab - simulation)"
    crontab -l >> "$LOGFILE" 2>&1
}

# T1071: Application Layer Protocol Communication Simulation (using curl)
invoke_T1071() {
    log_test "T1071" "HTTP Request Simulation (using curl to fetch example.com)"
    curl -s -o /dev/null -w "HTTP Response Code: %{http_code}\n" http://example.com >> "$LOGFILE"
}

# T1105: Ingress Tool Transfer Simulation (downloading a benign file using curl)
invoke_T1105() {
    log_test "T1105" "File Download Simulation (using curl to download a benign file)"
    DEST="/tmp/downloaded_sample.html"
    curl -s -o "$DEST" http://example.com
    if [ -f "$DEST" ]; then
        echo "Downloaded file to $DEST" >> "$LOGFILE"
        rm "$DEST"
    else
        echo "File download failed." >> "$LOGFILE"
    fi
}

# T1027: Obfuscated Files or Information Simulation (Base64 encode/decode)
invoke_T1027() {
    log_test "T1027" "Obfuscated Files Simulation (Base64 encoding and decoding a string)"
    ORIGINAL="Simulated Command"
    ENCODED=$(echo -n "$ORIGINAL" | base64)
    DECODED=$(echo -n "$ENCODED" | base64 --decode)
    echo "Original: $ORIGINAL | Encoded: $ENCODED | Decoded: $DECODED" >> "$LOGFILE"
}

# T1083: File and Directory Discovery Simulation (listing /Applications)
invoke_T1083() {
    log_test "T1083" "File and Directory Discovery (listing /Applications)"
    ls -l /Applications | head -n 10 >> "$LOGFILE"
}

# T1070: Indicator Removal on Host Simulation (simulating log cleanup)
invoke_T1070() {
    log_test "T1070" "Indicator Removal Simulation (simulated log cleanup)"
    echo "Simulated event log cleanup executed." >> "$LOGFILE"
}

# T1112: Preferences Modification Simulation (using defaults to write and delete a key)
invoke_T1112() {
    log_test "T1112" "Preferences Modification Simulation (writing and deleting a dummy preference)"
    DOMAIN="com.edrtest.simulation"
    defaults write "$DOMAIN" TestValue "EDRSimulation"
    echo "Set preference for $DOMAIN" >> "$LOGFILE"
    defaults delete "$DOMAIN" TestValue 2>&1 >> "$LOGFILE"
}

# T1204: User Execution Simulation (launching a benign application)
invoke_T1204() {
    log_test "T1204" "User Execution Simulation (opening Calculator)"
    open -a "Calculator"
}

# T1497: Virtualization/Sandbox Evasion Simulation (checking system uptime)
invoke_T1497() {
    log_test "T1497" "Virtualization/Sandbox Evasion Simulation (checking system uptime)"
    uptime >> "$LOGFILE"
}

# T1218: Signed Binary Proxy Execution Simulation (launching a signed application - Safari)
invoke_T1218() {
    log_test "T1218" "Signed Binary Proxy Execution Simulation (launching Safari)"
    open -a "Safari"
}

# T1219: Remote Access Tools Simulation (simulating an SSH connection attempt)
invoke_T1219() {
    log_test "T1219" "Remote Access Tools Simulation (simulating SSH connectivity)"
    ssh -G localhost >> "$LOGFILE" 2>&1
}

# T1486: Data Encrypted for Impact Simulation (compressing a benign file)
invoke_T1486() {
    log_test "T1486" "Data Encrypted for Impact Simulation (compressing a benign file)"
    FILE_TO_COMPRESS="/tmp/EDRTestLog.txt"
    ZIP_PATH="/tmp/EDRTestLog.zip"
    if [ -f "$FILE_TO_COMPRESS" ]; then
        zip -j "$ZIP_PATH" "$FILE_TO_COMPRESS" >> "$LOGFILE" 2>&1
        echo "Compressed $FILE_TO_COMPRESS to $ZIP_PATH" >> "$LOGFILE"
        rm "$ZIP_PATH"
    else
        echo "File $FILE_TO_COMPRESS not found for compression simulation." >> "$LOGFILE"
    fi
}

# Array of technique function names
technique_functions=(
    invoke_T1086
    invoke_T1059
    invoke_T1021
    invoke_T1003
    invoke_T1566
    invoke_T1055
    invoke_T1047
    invoke_T1053
    invoke_T1071
    invoke_T1105
    invoke_T1027
    invoke_T1083
    invoke_T1070
    invoke_T1112
    invoke_T1204
    invoke_T1497
    invoke_T1218
    invoke_T1219
    invoke_T1486
)

# Execute each simulated technique sequentially
for func in "${technique_functions[@]}"; do
    echo "Executing $func..."
    $func
    sleep 2
done

echo "EDR Test Completed at $(date)" | tee -a "$LOGFILE"
echo "EDR Testing complete. Please review the log file at $LOGFILE"
