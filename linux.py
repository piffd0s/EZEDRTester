#!/usr/bin/env python3
import subprocess
import time
import os
import datetime
import base64

LOGFILE = "/tmp/EDRTestLog.txt"

def log_message(technique, description, extra=""):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"{timestamp} - Executing Technique {technique}: {description}"
    if extra:
        message += f" | Output: {extra}"
    print(message)
    with open(LOGFILE, "a") as f:
        f.write(message + "\n")

def technique_T1086():
    # T1086: Shell/Script Execution Simulation
    technique = "T1086"
    description = "Shell Execution (running 'date')"
    try:
        result = subprocess.run(["date"], capture_output=True, text=True)
        log_message(technique, description, result.stdout.strip())
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def technique_T1059():
    # T1059: Command-Line Interface Simulation
    technique = "T1059"
    description = "Command-Line Execution (using echo)"
    try:
        result = subprocess.run(["echo", "Testing T1059: Command Execution"], capture_output=True, text=True)
        log_message(technique, description, result.stdout.strip())
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def technique_T1021():
    # T1021: Remote Services Simulation (using netstat)
    technique = "T1021"
    description = "Remote Services Simulation (using netstat)"
    try:
        result = subprocess.run(["netstat", "-tuln"], capture_output=True, text=True)
        output = result.stdout.splitlines()[0] if result.stdout else "No output"
        log_message(technique, description, output)
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def technique_T1003():
    # T1003: Credential Dumping Simulation (reading /etc/passwd)
    technique = "T1003"
    description = "Credential Dumping Simulation (reading first 3 lines of /etc/passwd)"
    try:
        with open("/etc/passwd", "r") as f:
            first_lines = "".join([next(f) for _ in range(3)])
        log_message(technique, description, first_lines.strip())
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def technique_T1566():
    # T1566: Phishing Simulation (opening a dummy phishing text file)
    technique = "T1566"
    description = "Phishing Simulation (opening a dummy file with xdg-open)"
    try:
        filepath = "/tmp/phishing_simulation.txt"
        with open(filepath, "w") as f:
            f.write("Simulated phishing email content for EDR testing on Linux.")
        # This will open the file in the default editor
        subprocess.Popen(["xdg-open", filepath])
        log_message(technique, description, "Opened phishing simulation file")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def technique_T1055():
    # T1055: Process Injection Simulation (simulated by launching a benign GUI application)
    technique = "T1055"
    description = "Process Injection Simulation (launching a calculator)"
    try:
        # Attempt to launch gnome-calculator, fallback to xcalc if unavailable
        try:
            subprocess.Popen(["gnome-calculator"])
            proc = "gnome-calculator"
        except Exception:
            subprocess.Popen(["xcalc"])
            proc = "xcalc"
        log_message(technique, description, f"Launched {proc}")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def technique_T1047():
    # T1047: System Information Discovery Simulation (using uname)
    technique = "T1047"
    description = "System Information Discovery (running 'uname -a')"
    try:
        result = subprocess.run(["uname", "-a"], capture_output=True, text=True)
        log_message(technique, description, result.stdout.strip())
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def technique_T1053():
    # T1053: Scheduled Task Simulation (listing current user's crontab)
    technique = "T1053"
    description = "Scheduled Task Simulation (listing crontab entries)"
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        output = result.stdout.strip() if result.stdout else "No crontab entries"
        first_line = output.splitlines()[0] if output.splitlines() else output
        log_message(technique, description, first_line)
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def technique_T1071():
    # T1071: Application Layer Protocol Communication Simulation (using curl)
    technique = "T1071"
    description = "HTTP Request Simulation (using curl to fetch example.com)"
    try:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "HTTP Code: %{http_code}", "http://example.com"],
            capture_output=True, text=True)
        log_message(technique, description, result.stdout.strip())
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def technique_T1105():
    # T1105: Ingress Tool Transfer Simulation (downloading a benign file)
    technique = "T1105"
    description = "File Download Simulation (using curl to download a benign file)"
    try:
        dest = "/tmp/downloaded_sample.html"
        subprocess.run(["curl", "-s", "-o", dest, "http://example.com"])
        if os.path.exists(dest):
            log_message(technique, description, f"Downloaded file to {dest}")
            os.remove(dest)
        else:
            log_message(technique, description, "Download failed")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def technique_T1027():
    # T1027: Obfuscated Files or Information Simulation (Base64 encode/decode)
    technique = "T1027"
    description = "Obfuscated Files Simulation (Base64 encoding and decoding a string)"
    try:
        original = "Simulated Command"
        encoded = base64.b64encode(original.encode()).decode()
        decoded = base64.b64decode(encoded).decode()
        log_message(technique, description, f"Original: {original} | Encoded: {encoded} | Decoded: {decoded}")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def technique_T1083():
    # T1083: File and Directory Discovery Simulation (listing /etc)
    technique = "T1083"
    description = "File and Directory Discovery (listing /etc directory)"
    try:
        result = subprocess.run(["ls", "-l", "/etc"], capture_output=True, text=True)
        first_line = result.stdout.splitlines()[0] if result.stdout else "No output"
        log_message(technique, description, first_line)
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def technique_T1070():
    # T1070: Indicator Removal on Host Simulation (simulate log cleanup)
    technique = "T1070"
    description = "Indicator Removal Simulation (simulated log cleanup)"
    try:
        log_message(technique, description, "Simulated log cleanup executed")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def technique_T1112():
    # T1112: Configuration Modification Simulation (writing and deleting a dummy file)
    technique = "T1112"
    description = "Configuration Modification Simulation (creating and removing a dummy file)"
    try:
        dummy_file = "/tmp/edr_test_dummy.txt"
        with open(dummy_file, "w") as f:
            f.write("EDR Simulation")
        os.remove(dummy_file)
        log_message(technique, description, "Created and removed dummy file")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def technique_T1204():
    # T1204: User Execution Simulation (launching a benign terminal emulator)
    technique = "T1204"
    description = "User Execution Simulation (launching xterm with a simple command)"
    try:
        subprocess.Popen(["xterm", "-e", "bash", "-c", "echo 'EDR Test - T1204'; sleep 5"])
        log_message(technique, description, "Launched xterm")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def technique_T1497():
    # T1497: Virtualization/Sandbox Evasion Simulation (checking system uptime)
    technique = "T1497"
    description = "Virtualization/Sandbox Evasion Simulation (running 'uptime')"
    try:
        result = subprocess.run(["uptime"], capture_output=True, text=True)
        log_message(technique, description, result.stdout.strip())
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def technique_T1218():
    # T1218: Signed Binary Proxy Execution Simulation (launching xdg-open on a benign URL)
    technique = "T1218"
    description = "Signed Binary Proxy Execution Simulation (using xdg-open to open a URL)"
    try:
        subprocess.Popen(["xdg-open", "http://example.com"])
        log_message(technique, description, "Launched xdg-open")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def technique_T1219():
    # T1219: Remote Access Tools Simulation (simulate SSH connectivity)
    technique = "T1219"
    description = "Remote Access Tools Simulation (simulating SSH connectivity to localhost)"
    try:
        result = subprocess.run(["ssh", "-G", "localhost"], capture_output=True, text=True)
        output = result.stdout.splitlines()[0] if result.stdout else "No output"
        log_message(technique, description, output)
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def technique_T1486():
    # T1486: Data Encrypted for Impact Simulation (compressing a benign file)
    technique = "T1486"
    description = "Data Encrypted for Impact Simulation (compressing the log file)"
    try:
        file_to_compress = LOGFILE
        zip_path = "/tmp/EDRTestLog.zip"
        if os.path.exists(file_to_compress):
            subprocess.run(["zip", "-j", zip_path, file_to_compress], capture_output=True, text=True)
            if os.path.exists(zip_path):
                log_message(technique, description, f"Compressed {file_to_compress} to {zip_path}")
                os.remove(zip_path)
            else:
                log_message(technique, description, "Compression failed")
        else:
            log_message(technique, description, f"File {file_to_compress} not found")
    except Exception as e:
        log_message(technique, description, f"Error: {str(e)}")

def main():
    # Create or clear the log file
    with open(LOGFILE, "w") as f:
        f.write(f"EDR Test Log - {datetime.datetime.now()}\n")
    
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
    ]
    
    for tech in techniques:
        tech()
        time.sleep(2)

    log_message("INFO", "Test Completed", "EDR Testing complete. Please review the log file at /tmp/EDRTestLog.txt")

if __name__ == "__main__":
    main()
