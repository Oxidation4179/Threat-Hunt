# Threat Hunt Report: Virtual Machine Compromise

**Date: June 6, 2026**

## Platforms and Tools Used

Microsoft Sentinel, Microsoft Defender for Endpoint (MDE), Advanced Hunting (KQL), Windows 11 host `Threat-hunt1-kent`

## 🧠 Scenario Overview

Where DeviceName contains *"flare"* and Incident Date *14-September-2025*. Suspicious activity has been detected on one of our cloud virtual machines. As a Security Analyst, you’ve been assigned to investigate this incident and determine the scope and impact of the breach. This is an active investigation. Your objective is to reconstruct the attack timeline, identify key indicators, and answer targeted questions related to the compromise.

## 🎯 Executive Summary

This threat hunt investigated a password spray attack that resulted in a full compromise of a cloud-hosted Windows host `slflarewinsysmo`. The attacker successfully logged in via RDP using the compromised account `slflare`, executed a suspicious payload, established persistence through a scheduled task, modified Microsoft Defender exclusions, performed system discovery, staged data in a ZIP archive, and attempted exfiltration to an external server.

## 📅 Attack Timeline

| Time UTC            | Activity                                        | Evidence            |
| ------------------- | ----------------------------------------------- | ------------------- |
| 2025-09-16 18:36:55 | Multiple failed RDP logons from external IP     | DeviceLogonEvents   |
| 2025-09-16 18:43:46 | Successful RDP login by `slflare`               | DeviceLogonEvents   |
| 2025-09-16 19:38:40 | `msupdate.exe` executed from `C:\Users\Public\` | DeviceProcessEvents |
| 2025-09-16 19:39:45 | Scheduled task `MicrosoftUpdateSync` created    | DeviceEvents        |
| 2025-09-16 19:39:48 | Defender exclusion command executed             | DeviceEvents        |
| 2025-09-16 19:40:28 | `systeminfo` executed                           | DeviceProcessEvents |
| 2025-09-16 19:41:30 | `backup_sync.zip` created in Temp               | DeviceFileEvents    |
| 2025-09-16 19:43:28 | ZIP archive uploaded to external server         | DeviceNetworkEvents |

## 📑 Flag Directory

| Flag    | Objective                               | Answer                                                       |
| ------- | --------------------------------------- | ------------------------------------------------------------ |
| Flag 1  | Attacker IP Address                     | `159.26.106.84`                                              |
| Flag 2  | Compromised Account                     | `slflare`                                                    |
| Flag 3  | Executed Binary Name                    | `msupdate.exe`                                               |
| Flag 4  | Command Line Used to Execute the Binary | `"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1` |
| Flag 5  | Persistence Mechanism Created           | `MicrosoftUpdateSync`                                        |
| Flag 6  | Defender Exclusion Path                 | `MicrosoftUpdateSync`                                        |
| Flag 7  | Discovery Command                       | `"cmd.exe" /c systeminfo`                                    |
| Flag 8  | Archive File Created                    | `backup_sync.zip`                                            |
| Flag 9  | C2 / Tooling Destination                | `185.92.220.87`                                              |
| Flag 10 | Exfiltration Destination                | `185.92.220.87:8081`                                         |

## 🔎 Flag Analysis & Findings

### 🚩 Flag 1: Attacker IP Address

- **MITRE Technique:**
  🔸 T1110.001 – Brute Force: Password Guessing

- **Answer:** `159.26.106.84`
- **Discovery:** From `2025-09-16, 6:36:55.240 p.m`, `159.26.106.84` has multiple failed logon. Then at `2025-09-16, 6:43:46.864 p.m`, the **RemoteInteractive** Logon was successfully triggered.

```KQL
DeviceLogonEvents
| where TimeGenerated > todatetime('2025-09-16T00:00:00.0000000Z')
| where DeviceName contains "flare"
| where RemoteIP !in ("","-")
| project TimeGenerated, DeviceName, AccountName, ActionType, LogonType, RemoteIP, FailureReason
| order by TimeGenerated asc
```

![image-20260603183554539](C:\Users\d5423\AppData\Roaming\Typora\typora-user-images\image-20260603183554539.png)

### 🚩 **Flag 2: Compromised Account**

- **MITRE Technique:**
  🔸 T1078 – Valid Accounts

- **Answer:** `slflare`
- **Discovery:** Account name `slflar` was associated with the successful **RemoteInteractive** Logon at `2025-09-16, 6:43:46.864 p.m.`.

![image-20260603184646997](C:\Users\d5423\AppData\Roaming\Typora\typora-user-images\image-20260603184646997.png)

### 🚩 **Flag 3: Executed Binary Name**

- **MITRE Techniques:**
  🔸 T1059.003 – Command and Scripting Interpreter: Windows Command Shell
  🔸 T1204.002 – User Execution: Malicious File

- **Answer:** `msupdate.exe`
- **Discovery:** At `2025-09-16, 7:38:40.063 p.m.`, `msupdate.exe` was executed from `C:\Users\Public\` by `powershell.exe`. This unusual path and parent process indicate it was likely the attacker’s payload.

```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-09-16 00:00:00) .. datetime(2025-09-17 23:59:59))
| where DeviceName == "slflarewinsysmo" and AccountName contains "slflare"
| where FolderPath has_any ("Public", "Temp", "Downloads")
| where FileName endswith ".exe"
| project TimeGenerated, AccountName,ActionType, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine,InitiatingProcessFileName, InitiatingProcessFolderPath, ProcessCommandLine
| order by TimeGenerated
```

![image-20260603214536651](C:\Users\d5423\AppData\Roaming\Typora\typora-user-images\image-20260603214536651.png)

### 🚩**Flag 4: Command Line Used to Execute the Binary**

- **MITRE Techniques:**
  🔸 T1059.003 – Command and Scripting Interpreter: Windows Command Shell
  🔸 T1204.002 – User Execution: Malicious File

- **Answer:** `"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1`

### 🚩**Flag 5: Persistence Mechanism Created**

- **MITRE Technique:**
  🔸 T1059 – Command and Scripting Interpreter

- **Answer:** `MicrosoftUpdateSync`
- **Discovery:** At `2025-09-16, 7:39:45.461 p.m`, a `ScheduledTaskCreated` event showed that the attacker created the task `\MicrosoftUpdateSync` on `slflarewinsysmo`. The task runs a hidden PowerShell script at system boot, confirming it was used for persistence. **Scheduled task name** is `MicrosoftUpdateSync`

```
DeviceEvents
| where TimeGenerated between (datetime(2025-09-16 00:00:00) .. datetime(2025-09-17 23:59:59))
| where DeviceName == "slflarewinsysmo"
| where ActionType contains "ScheduledTask"
```

![image-20260603234948877](C:\Users\d5423\AppData\Roaming\Typora\typora-user-images\image-20260603234948877.png)

### 🚩 **Flag 6: What Defender Setting Was Modified?**

- **MITRE Technique:**
  🔸 T1562.001 – Impair Defenses: Disable or Modify Windows Defender

- **Answer:** `MicrosoftUpdateSync`
- **Discovery:** At `2025-09-16, 7:39:48.523 p.m. UTC`, a `PowerShellCommand` event showed that the attacker executed `Add-MpPreference -ExclusionPath $exclusionPath -Force` on `slflarewinsysmo`. This command added a Microsoft Defender folder exclusion, helping the attacker prevent the payload directory from being scanned.

```
DeviceEvents
| where TimeGenerated between (datetime(2025-09-16 00:00:00) .. datetime(2025-09-17 23:59:59))
| where DeviceName == "slflarewinsysmo"
| extend Fields = tostring(AdditionalFields)
| where ActionType contains "Antivirus"
    or Fields contains "Exclusion"
    or Fields contains "ExclusionPath"
| order by TimeGenerated asc
```

![image-20260604003600661](C:\Users\d5423\AppData\Roaming\Typora\typora-user-images\image-20260604003600661.png)

check `DeviceRegistryEvents` for details of defender exclusion path

```
DeviceRegistryEvents
| where RegistryKey contains "Exclusion"
| where Timestamp between (datetime(2025-09-16 12:45:00) .. datetime(2025-09-16 23:59:59))
```

### 🚩 **Flag 7: What Discovery Command Did the Attacker Run?** 

- **MITRE Techniques:**
  🔸 T1082 – System Information Discovery

- **Answer:** `"cmd.exe" /c systeminfo`
- **Discovery:** At `2025-09-16, 7:40:28.888 p.m. UTC`, a `ProcessCreated` event showed that the attacker executed `systeminfo.exe` from `C:\Windows\System32\systeminfo.exe` on `slflarewinsysmo`. The process was launched through `"cmd.exe" /c systeminfo`, confirming it was used for system information discovery. **Discovery command** is `C:\Windows\System32\systeminfo.exe`.

```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-09-16 00:00:00) .. datetime(2025-09-17 23:59:59))
| where DeviceName == "slflarewinsysmo"
| where AccountName contains "slflare"
| where FileName =~ "systeminfo.exe"
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

![image-20260604115151068](C:\Users\d5423\AppData\Roaming\Typora\typora-user-images\image-20260604115151068.png)

### 🚩 **Flag 8: Archive File Created by Attacker**

- **MITRE Technique:**
  🔸 T1560.001 – Archive Collected Data: Local Archiving

- **Answer:** `backup_sync.zip`

- **Discovery:** At `2025-09-16, 7:41:30.404 p.m. UTC`, a `FileCreated` event showed that `backup_sync.zip` was created on `slflarewinsysmo` under `C:\Users\SLFlare\AppData\Local\Temp\`. The file type was identified as `Zip`, suggesting the attacker may have archived data in a temporary directory.

  ```
  DeviceFileEvents
  | where TimeGenerated between (datetime(2025-09-16 00:00:00) .. datetime(2025-09-17 23:59:59))
  | where DeviceName == "slflarewinsysmo"
  | where FileName has_any (".zip", ".rar", ".7z")
  | where FolderPath contains @"\Temp\"
      or FolderPath contains @"\AppData\"
      or FolderPath contains @"\ProgramData\"
  | order by TimeGenerated asc
  ```

  ![image-20260604172126055](C:\Users\d5423\AppData\Roaming\Typora\typora-user-images\image-20260604172126055.png)

### 🚩 **Flag 9: C2 Connection Destination**

- **MITRE Techniques:**
  🔸 T1071.001 – Application Layer Protocol: Web Protocols (HTTP/S)
  🔸 T1105 – Ingress Tool Transfer

- **Answer:** `backup_sync.zip`

- **Discovery:** I searched `DeviceProcessEvents` for HTTP-related commands involving `backup_sync.zip`. The results showed that the attacker used PowerShell `Invoke-WebRequest` to send `C:\Users\SLFlare\AppData\Local\Temp\backup_sync.zip` to `http://185.92.220.87:8081/api/upload`.

  I then checked `DeviceNetworkEvents` and confirmed outbound TCP connections from `powershell.exe` to `185.92.220.87` on ports `80` and `8081`.

  --------------------------------------------------------------------------------------------------------------------------------------------------

1. Queried process execution events for `curl`, `Invoke-WebRequest`, `http`, and `https`. And filtered the results for `backup_sync.zip`.

```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-09-16 19:41:00) .. datetime(2025-09-16 23:59:59))
| where DeviceName == "slflarewinsysmo"
| where ProcessCommandLine has_any ("curl", "Invoke-WebRequest", "http", "https")
| search "backup_sync.zip"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

2. Confirmed the external destination using network connection events.

![image-20260604182351370](C:\Users\d5423\AppData\Roaming\Typora\typora-user-images\image-20260604182351370.png)

3. Identified `185.92.220.87` as the attacker-controlled destination.

```
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-09-16 19:38:00) .. datetime(2025-09-16 19:45:00))
| where DeviceName == "slflarewinsysmo"
| where RemoteIP == "185.92.220.87"
    or RemoteUrl contains "185.92.220.87"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          RemoteIP, RemoteUrl, RemotePort, Protocol
| order by TimeGenerated asc
```

![image-20260604182631429](C:\Users\d5423\AppData\Roaming\Typora\typora-user-images\image-20260604182631429.png)

![image-20260604182611284](C:\Users\d5423\AppData\Roaming\Typora\typora-user-images\image-20260604182611284.png)

**### 🚩 Flag 10: Exfiltration Attempt Detected**

- **MITRE Technique:**
  🔸 T1048.003 – Exfiltration Over Unencrypted Protocol

- **Answer:** `185.92.220.87:8081`
- **Discovery:** `DeviceNetworkEvents` then confirmed an outbound TCP connection from `powershell.exe` to external IP `185.92.220.87` on port `8081`.

```
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-09-16 19:38:00) .. datetime(2025-09-16 19:45:00))
| where DeviceName == "slflarewinsysmo"
| where RemoteIP == "185.92.220.87"
    or RemoteUrl contains "185.92.220.87"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          RemoteIP, RemoteUrl, RemotePort, Protocol
| order by TimeGenerated asc
```

![image-20260604182611284](C:\Users\d5423\AppData\Roaming\Typora\typora-user-images\image-20260604182611284.png)
