#!/usr/bin/env python3
import subprocess
import time
import os
import datetime
import base64
import zipfile

# Set log file location (adjust as needed)
LOGFILE = r"C:\Temp\EDRTestLog.txt"

def init_log():
    log_dir = os.path.dirname(LOGFILE)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    with open(LOGFILE, "w") as f:
        f.write(f"EDR Test Log - {datetime.datetime.now()}\n")

def log_message(technique, description, extra=""):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"{timestamp} - Executing Technique {technique}: {description}"
    if extra:
        message += f" | Output: {extra}"
    print(message)
    with open(LOGFILE, "a") as f:
        f.write(message + "\n")

def run_command(cmd_list, shell=False):
    """Helper function to run a command and capture its output."""
    try:
        result = subprocess.run(cmd_list, capture_output=True, text=True, shell=shell)
        return result.stdout.strip() if result.stdout else ""
    except Exception as e:
        return f"Error: {str(e)}"

# ----------------------------
# Base Techniques (Detection Simulation)
# ----------------------------

# T1086: Shell/Script Execution Simulation (using PowerShell Get-Date)
def technique_T1086():
    technique = "T1086"
    description = "Shell Execution (running PowerShell Get-Date)"
    try:
        output = run_command(["powershell", "-Command", "Get-Date"])
        log_message(technique, description, output)
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# T1059: Command-Line Interface Simulation
def technique_T1059():
    technique = "T1059"
    description = "Command-Line Execution (using cmd echo)"
    try:
        output = run_command(["cmd", "/c", "echo Testing T1059: Command Execution"])
        log_message(technique, description, output)
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# T1021: Remote Services Simulation (using netstat)
def technique_T1021():
    technique = "T1021"
    description = "Remote Services Simulation (using netstat -an)"
    try:
        output = run_command(["netstat", "-an"])
        first_line = output.splitlines()[0] if output else "No output"
        log_message(technique, description, first_line)
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# T1003: Credential Dumping Simulation (reading a dummy file)
def technique_T1003():
    technique = "T1003"
    description = "Credential Dumping Simulation (reading first 3 lines of dummy creds file)"
    dummy_file = r"C:\Temp\dummy_creds.txt"
    try:
        with open(dummy_file, "w") as f:
            f.write("Username: TestUser\nHash: ABC123\nDomain: LAB\n")
        with open(dummy_file, "r") as f:
            lines = "".join([next(f) for _ in range(3)])
        os.remove(dummy_file)
        log_message(technique, description, lines.strip())
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# T1566: Phishing Simulation (opening a dummy file in Notepad)
def technique_T1566():
    technique = "T1566"
    description = "Phishing Simulation (opening a dummy phishing file in Notepad)"
    dummy_file = r"C:\Temp\phishing_simulation.txt"
    try:
        with open(dummy_file, "w") as f:
            f.write("Simulated phishing email content for EDR testing on Windows.")
        subprocess.Popen(["notepad.exe", dummy_file])
        log_message(technique, description, "Opened dummy phishing file in Notepad")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# T1055: Process Injection Simulation (simulated by launching Notepad)
def technique_T1055():
    technique = "T1055"
    description = "Process Injection Simulation (launching Notepad)"
    try:
        subprocess.Popen(["notepad.exe"])
        log_message(technique, description, "Launched notepad.exe")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# T1047: System Information Discovery Simulation (using systeminfo)
def technique_T1047():
    technique = "T1047"
    description = "System Information Discovery (running systeminfo)"
    try:
        output = run_command(["systeminfo"])
        first_line = output.splitlines()[0] if output else "No output"
        log_message(technique, description, first_line)
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# T1053: Scheduled Task Simulation (querying scheduled tasks)
def technique_T1053():
    technique = "T1053"
    description = "Scheduled Task Simulation (querying scheduled tasks with schtasks)"
    try:
        output = run_command(["schtasks", "/Query"])
        first_line = output.splitlines()[0] if output else "No scheduled tasks found"
        log_message(technique, description, first_line)
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# T1071: Application Layer Protocol Communication Simulation (HTTP request via curl)
def technique_T1071():
    technique = "T1071"
    description = "HTTP Request Simulation (using curl to fetch example.com)"
    try:
        output = run_command(["curl", "-s", "-o", "NUL", "-w", "HTTP Code: %{http_code}", "http://example.com"])
        log_message(technique, description, output)
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# T1105: Ingress Tool Transfer Simulation (downloading a benign file)
def technique_T1105():
    technique = "T1105"
    description = "File Download Simulation (using curl to download a benign file)"
    dest = r"C:\Temp\downloaded_sample.html"
    try:
        subprocess.run(["curl", "-s", "-o", dest, "http://example.com"], capture_output=True, text=True)
        if os.path.exists(dest):
            log_message(technique, description, f"Downloaded file to {dest}")
            os.remove(dest)
        else:
            log_message(technique, description, "Download failed")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# T1027: Obfuscated Files or Information Simulation (Base64 encode/decode)
def technique_T1027():
    technique = "T1027"
    description = "Obfuscated Files Simulation (Base64 encoding and decoding a string)"
    try:
        original = "Simulated Command"
        encoded = base64.b64encode(original.encode()).decode()
        decoded = base64.b64decode(encoded).decode()
        log_message(technique, description, f"Original: {original} | Encoded: {encoded} | Decoded: {decoded}")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# T1083: File and Directory Discovery Simulation (listing System32)
def technique_T1083():
    technique = "T1083"
    description = "File and Directory Discovery (listing C:\\Windows\\System32)"
    try:
        output = run_command(["cmd", "/c", "dir", r"C:\Windows\System32"])
        first_line = output.splitlines()[0] if output else "No output"
        log_message(technique, description, first_line)
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# T1070: Indicator Removal Simulation (simulated log cleanup)
def technique_T1070():
    technique = "T1070"
    description = "Indicator Removal Simulation (simulated log cleanup)"
    log_message(technique, description, "Simulated event log cleanup executed")

# T1112: Registry Modification Simulation (add/remove dummy key)
def technique_T1112():
    technique = "T1112"
    description = "Registry Modification Simulation (adding and removing a dummy registry key)"
    key_path = r"HKCU\Software\EDRTestSimulation"
    try:
        add_cmd = ["reg", "add", key_path, "/v", "TestValue", "/t", "REG_SZ", "/d", "EDRSimulation", "/f"]
        subprocess.run(add_cmd, capture_output=True, text=True)
        del_cmd = ["reg", "delete", key_path, "/f"]
        subprocess.run(del_cmd, capture_output=True, text=True)
        log_message(technique, description, "Added and removed dummy registry key")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# T1204: User Execution Simulation (launching Calculator)
def technique_T1204():
    technique = "T1204"
    description = "User Execution Simulation (launching calc.exe)"
    try:
        subprocess.Popen(["calc.exe"])
        log_message(technique, description, "Launched Calculator (calc.exe)")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# T1497: Virtualization/Sandbox Evasion Simulation (querying last boot time)
def technique_T1497():
    technique = "T1497"
    description = "Virtualization/Sandbox Evasion Simulation (querying last boot time with wmic)"
    try:
        output = run_command(["wmic", "os", "get", "LastBootUpTime", "/value"])
        first_line = output.splitlines()[0] if output else "No output"
        log_message(technique, description, first_line)
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# T1218: Signed Binary Proxy Execution Simulation (launching mshta.exe)
def technique_T1218():
    technique = "T1218"
    description = "Signed Binary Proxy Execution Simulation (launching mshta.exe with about:blank)"
    try:
        subprocess.Popen(["mshta.exe", "about:blank"])
        log_message(technique, description, "Launched mshta.exe")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# T1219: Remote Access Tools Simulation (using query user)
def technique_T1219():
    technique = "T1219"
    description = "Remote Access Tools Simulation (using query user to list sessions)"
    try:
        output = run_command(["query", "user"])
        first_line = output.splitlines()[0] if output else "No output"
        log_message(technique, description, first_line)
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# T1486: Data Encrypted for Impact Simulation (compressing the log file)
def technique_T1486():
    technique = "T1486"
    description = "Data Encrypted for Impact Simulation (compressing the log file)"
    zip_path = r"C:\Temp\EDRTestLog.zip"
    try:
        if os.path.exists(LOGFILE):
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(LOGFILE, os.path.basename(LOGFILE))
            if os.path.exists(zip_path):
                log_message(technique, description, f"Compressed {LOGFILE} to {zip_path}")
                os.remove(zip_path)
            else:
                log_message(technique, description, "Compression failed")
        else:
            log_message(technique, description, f"File {LOGFILE} not found")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# ----------------------------
# Additional Persistence Techniques
# ----------------------------

# T1547: Boot or Logon Autostart Execution – Registry Run Key Persistence
def technique_T1547():
    technique = "T1547"
    description = "Persistence via Registry Run Key (adding then removing a dummy Run key)"
    reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        # Add dummy run key
        add_cmd = ["reg", "add", reg_path, "/v", "EDRTestRun", "/t", "REG_SZ", "/d", "notepad.exe", "/f"]
        subprocess.run(add_cmd, capture_output=True, text=True)
        log_message(technique, description, "Added dummy Run key")
        # Remove dummy run key
        del_cmd = ["reg", "delete", reg_path, "/v", "EDRTestRun", "/f"]
        subprocess.run(del_cmd, capture_output=True, text=True)
        log_message(technique, description, "Removed dummy Run key")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# ----------------------------
# Additional Privilege Escalation Techniques
# ----------------------------

# T1136: Create Account – Simulate creating a new local user (and then deleting it)
def technique_T1136():
    technique = "T1136"
    description = "Privilege Escalation Simulation (creating and deleting a local user)"
    username = "EDRTestUser"
    try:
        # Create the user with a dummy password
        create_cmd = ["net", "user", username, "P@ssw0rd!", "/add"]
        subprocess.run(create_cmd, capture_output=True, text=True)
        log_message(technique, description, f"Created user {username}")
        # Delete the user
        del_cmd = ["net", "user", username, "/delete"]
        subprocess.run(del_cmd, capture_output=True, text=True)
        log_message(technique, description, f"Deleted user {username}")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# T1548: Abuse Elevation Control Mechanism – Simulate UAC bypass attempt (benign simulation)
def technique_T1548():
    technique = "T1548"
    description = "Privilege Escalation Simulation (simulated UAC bypass attempt)"
    try:
        # This is only a simulation—launch a benign process with 'runas' without actual credential bypass
        output = run_command(["runas", "/user:dummy", "cmd.exe /c echo UAC simulation"])
        log_message(technique, description, f"Simulated UAC bypass: {output}")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

# ----------------------------
# Main Execution
# ----------------------------

def main():
    init_log()
    techniques = [
        technique_T1086,
        technique_T1059,
        technique_T1021,
        technique_T1003,
        technique_T1566,
        technique_T1055,
        technique_T1047,
        technique_T1053,
        technique_T1071,
        technique_T1105,
        technique_T1027,
        technique_T1083,
        technique_T1070,
        technique_T1112,
        technique_T1204,
        technique_T1497,
        technique_T1218,
        technique_T1219,
        technique_T1486,
        technique_T1547,  # Persistence via Run key
        technique_T1136,  # Create Account simulation
        technique_T1548,  # UAC bypass simulation
    ]
    
    for tech in techniques:
        tech()
        time.sleep(2)
    
    log_message("INFO", "Test Completed", "EDR Testing complete. Please review the log file at " + LOGFILE)

if __name__ == "__main__":
    main()
