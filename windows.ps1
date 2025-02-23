<# 
    MITRE ATT&CK EDR Testing Script - Comprehensive Simulation
    ------------------------------------------------------------
    This script simulates a broad set of MITRE ATT&CK techniques and logs each technique executed.
    Techniques simulated include (but are not limited to):
      - T1086: PowerShell Execution
      - T1059: Command-Line Interface
      - T1021: Remote Services (SMB)
      - T1003: Credential Dumping (Simulation)
      - T1566: Phishing (Simulation)
      - T1055: Process Injection (Simulation)
      - T1047: WMI Execution (Simulation)
      - T1053: Scheduled Task/Job
      - T1071: Application Layer Protocol Communication
      - T1105: Ingress Tool Transfer (File Download Simulation)
      - T1027: Obfuscated Files or Information (Simulation)
      - T1083: File and Directory Discovery
      - T1070: Indicator Removal on Host (Simulation)
      - T1112: Modify Registry (Simulation)
      - T1204: User Execution (Simulation)
      - T1497: Virtualization/Sandbox Evasion (Simulation)
      - T1218: Signed Binary Proxy Execution (Simulation)
      - T1219: Remote Access Tools (Simulation)
      - T1486: Data Encrypted for Impact (Simulation)
      
    Use only on systems where you have explicit permission.
#>

# Set up a log file (ensure the folder exists or adjust the path)
$LogFile = "C:\Temp\EDRTestLog.txt"
if (!(Test-Path "C:\Temp")) {
    New-Item -ItemType Directory -Path "C:\Temp" | Out-Null
}
"EDR Test Log - $(Get-Date)" | Out-File $LogFile

# Function to log test execution
function Log-Test {
    param(
        [string]$Technique,
        [string]$Description
    )
    $logMessage = "$(Get-Date) - Executing Technique $Technique: $Description"
    Write-Host $logMessage -ForegroundColor Cyan
    $logMessage | Out-File $LogFile -Append
}

# T1086: PowerShell Execution
function Invoke-TechniqueT1086 {
    Log-Test -Technique "T1086" -Description "PowerShell Execution (benign Get-Date call)"
    Get-Date | Out-File $LogFile -Append
}

# T1059: Command-Line Interface
function Invoke-TechniqueT1059 {
    Log-Test -Technique "T1059" -Description "Command-Line Execution (using cmd echo)"
    cmd /c "echo Testing T1059: Command Execution" | Out-File $LogFile -Append
}

# T1021: Remote Services (SMB)
function Invoke-TechniqueT1021 {
    Log-Test -Technique "T1021" -Description "Remote Services Simulation (using net view)"
    net view | Out-File $LogFile -Append
}

# T1003: Credential Dumping Simulation
function Invoke-TechniqueT1003 {
    Log-Test -Technique "T1003" -Description "Credential Dumping Simulation (reading dummy data)"
    $dummyCredentials = "Simulated Credential Data: Username=TestUser; Hash=ABC123"
    $dummyCredentials | Out-File $LogFile -Append
}

# T1566: Phishing Simulation
function Invoke-TechniqueT1566 {
    Log-Test -Technique "T1566" -Description "Phishing Simulation (opening notepad with simulated content)"
    $phishFile = "C:\Temp\phishing_simulation.txt"
    "Simulated phishing email content for EDR testing." | Out-File $phishFile
    Start-Process -FilePath "notepad.exe" -ArgumentList $phishFile
}

# T1055: Process Injection Simulation
function Invoke-TechniqueT1055 {
    Log-Test -Technique "T1055" -Description "Process Injection Simulation (launching notepad)"
    Start-Process -FilePath "notepad.exe"
    "Simulated process injection trigger executed." | Out-File $LogFile -Append
}

# T1047: WMI Execution Simulation
function Invoke-TechniqueT1047 {
    Log-Test -Technique "T1047" -Description "WMI Execution Simulation (querying Win32_OperatingSystem)"
    Get-WmiObject -Class Win32_OperatingSystem | Out-File $LogFile -Append
}

# T1053: Scheduled Task/Job Simulation
function Invoke-TechniqueT1053 {
    Log-Test -Technique "T1053" -Description "Scheduled Task Simulation (creating and deleting a task)"
    $taskName = "EDRTestTask"
    schtasks /create /tn $taskName /tr "cmd /c echo EDR Test Task" /sc once /st 00:00 /F | Out-File $LogFile -Append
    schtasks /delete /tn $taskName /f | Out-File $LogFile -Append
}

# T1071: Application Layer Protocol Communication Simulation
function Invoke-TechniqueT1071 {
    Log-Test -Technique "T1071" -Description "Application Layer Protocol (HTTP request to example.com)"
    try {
        $response = Invoke-WebRequest -Uri "http://example.com" -UseBasicParsing
        "HTTP Response Status: $($response.StatusCode)" | Out-File $LogFile -Append
    } catch {
        "HTTP request failed: $_" | Out-File $LogFile -Append
    }
}

# T1105: Ingress Tool Transfer Simulation (File Download)
function Invoke-TechniqueT1105 {
    Log-Test -Technique "T1105" -Description "Ingress Tool Transfer Simulation (downloading a benign file)"
    $url = "http://example.com"
    $destination = "C:\Temp\downloaded_sample.html"
    try {
        Invoke-WebRequest -Uri $url -OutFile $destination -UseBasicParsing
        "Downloaded file from $url" | Out-File $LogFile -Append
        Remove-Item $destination -Force
    } catch {
        "File download failed: $_" | Out-File $LogFile -Append
    }
}

# T1027: Obfuscated Files or Information Simulation
function Invoke-TechniqueT1027 {
    Log-Test -Technique "T1027" -Description "Obfuscated Files Simulation (decoding a Base64 string)"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Simulated Command"))
    $decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
    "Decoded string: $decoded" | Out-File $LogFile -Append
}

# T1083: File and Directory Discovery Simulation
function Invoke-TechniqueT1083 {
    Log-Test -Technique "T1083" -Description "File and Directory Discovery (listing C:\Windows)"
    Get-ChildItem -Path "C:\Windows" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10 | Out-File $LogFile -Append
}

# T1070: Indicator Removal on Host Simulation
function Invoke-TechniqueT1070 {
    Log-Test -Technique "T1070" -Description "Indicator Removal Simulation (simulated log cleanup)"
    "Simulated event log cleanup executed." | Out-File $LogFile -Append
    # Note: This does not actually clear logs.
}

# T1112: Modify Registry Simulation
function Invoke-TechniqueT1112 {
    Log-Test -Technique "T1112" -Description "Registry Modification Simulation (writing and deleting a dummy value)"
    $regPath = "HKCU:\Software\EDRTest"
    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    New-ItemProperty -Path $regPath -Name "TestValue" -Value "EDRSimulation" -PropertyType String -Force | Out-Null
    "Registry key set: $regPath\TestValue" | Out-File $LogFile -Append
    Remove-Item -Path $regPath -Recurse -Force | Out-File $LogFile -Append
}

# T1204: User Execution Simulation
function Invoke-TechniqueT1204 {
    Log-Test -Technique "T1204" -Description "User Execution Simulation (opening Calculator)"
    Start-Process -FilePath "calc.exe"
    "Launched calc.exe" | Out-File $LogFile -Append
}

# T1497: Virtualization/Sandbox Evasion Simulation
function Invoke-TechniqueT1497 {
    Log-Test -Technique "T1497" -Description "Virtualization/Sandbox Evasion Simulation (checking system uptime)"
    $uptime = (Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime
    "System uptime: $uptime" | Out-File $LogFile -Append
}

# T1218: Signed Binary Proxy Execution Simulation
function Invoke-TechniqueT1218 {
    Log-Test -Technique "T1218" -Description "Signed Binary Proxy Execution Simulation (launching mshta.exe)"
    Start-Process -FilePath "mshta.exe" -ArgumentList "about:blank"
    "Launched mshta.exe" | Out-File $LogFile -Append
}

# T1219: Remote Access Tools Simulation
function Invoke-TechniqueT1219 {
    Log-Test -Technique "T1219" -Description "Remote Access Tools Simulation (pinging a remote IP)"
    ping -n 2 8.8.8.8 | Out-File $LogFile -Append
}

# T1486: Data Encrypted for Impact Simulation
function Invoke-TechniqueT1486 {
    Log-Test -Technique "T1486" -Description "Data Encrypted for Impact Simulation (compressing a benign file)"
    $fileToCompress = "C:\Temp\EDRTestLog.txt"
    $zipPath = "C:\Temp\EDRTestLog.zip"
    if (Test-Path $fileToCompress) {
        Compress-Archive -Path $fileToCompress -DestinationPath $zipPath -Force
        "Compressed $fileToCompress to $zipPath" | Out-File $LogFile -Append
        Remove-Item $zipPath -Force
    } else {
        "File $fileToCompress not found for compression simulation" | Out-File $LogFile -Append
    }
}

# Array of technique functions to execute
$techniqueFunctions = @(
    "Invoke-TechniqueT1086",
    "Invoke-TechniqueT1059",
    "Invoke-TechniqueT1021",
    "Invoke-TechniqueT1003",
    "Invoke-TechniqueT1566",
    "Invoke-TechniqueT1055",
    "Invoke-TechniqueT1047",
    "Invoke-TechniqueT1053",
    "Invoke-TechniqueT1071",
    "Invoke-TechniqueT1105",
    "Invoke-TechniqueT1027",
    "Invoke-TechniqueT1083",
    "Invoke-TechniqueT1070",
    "Invoke-TechniqueT1112",
    "Invoke-TechniqueT1204",
    "Invoke-TechniqueT1497",
    "Invoke-TechniqueT1218",
    "Invoke-TechniqueT1219",
    "Invoke-TechniqueT1486"
)

# Execute each technique simulation sequentially
foreach ($func in $techniqueFunctions) {
    Write-Host "Executing $func..." -ForegroundColor Yellow
    try {
        & $func
    } catch {
        Write-Host "Error executing $func: $_" -ForegroundColor Red
    }
    Start-Sleep -Seconds 2
}

"EDR Test Completed at $(Get-Date)" | Out-File $LogFile -Append
Write-Host "EDR Testing complete. Please review the log file at $LogFile" -ForegroundColor Green
