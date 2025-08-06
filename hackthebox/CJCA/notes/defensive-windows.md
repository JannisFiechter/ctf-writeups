# windows eventlogs

The logs are categorized into different event logs, such as "Application", "System", "Security", and others, to organize events based on their source or purpose. We leverage these logs extensively for analysis and intrusion detection.
<br>
Event logs can be accessed using the Event Viewer application or programmatically using APIs such as the Windows Event Log API.
<br>
Forwarded Events are events from other Hosts.

## Log Types
### Information
Information events provide general usage details about the application, such as its start or stop events.

### Error
Error events highlight specific errors and often offer detailed insights into the encountered issues.

### Fields
| **Field**        | **Description**                                                                 |
|------------------|---------------------------------------------------------------------------------|
| **Log Name**     | The name of the event log (e.g., Application, System, Security, etc.).         |
| **Source**       | The software/component that logged the event.                                  |
| **Event ID**     | A unique identifier for the event type.                                        |
| **Task Category**| Helps understand the purpose/context of the event.                             |
| **Level**        | Severity level (Information, Warning, Error, Critical, Verbose).               |
| **Keywords**     | Flags for categorization (e.g., "Audit Success", "Audit Failure").             |
| **User**         | The user account that triggered or is associated with the event.               |
| **OpCode**       | Indicates the specific operation being reported (e.g., Start, Stop).           |
| **Logged**       | Timestamp when the event was logged.                                           |
| **Computer**     | Hostname of the machine where the event occurred.                              |
| **XML Data**     | Full event info in XML format, including raw and extended data.                |

## Custom XML Queries
- Filter Current Log -> XML -> Edit Query Manually
    - Guide: https://techcommunity.microsoft.com/blog/askds/advanced-xml-filtering-in-the-windows-event-viewer/399761

You can search for example a event, look at the logon id and filter for it like this:

### Events by Logon ID (`0x3E7`) within Specific Time Range
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[TimeCreated[@SystemTime&gt;='2022-08-03T17:23:10.000Z' and @SystemTime&lt;='2022-08-03T18:00:00.999Z']]
      and EventData[Data[@Name='TargetLogonId']='0x3e7']]
    </Select>
  </Query>
</QueryList>
```
### Audit Setting Change on Specific DLL
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[EventID=4907] 
      and EventData[Data[@Name='ObjectName']='C:\Windows\Microsoft.NET\Framework64\v4.0.30319\WPF\wpfgfx_v0400.dll']]
    </Select>
  </Query>
</QueryList>
```

### Audit Setting Changes Made by TiWorker.exe
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[EventID=4907] 
      and EventData[Data[@Name='ProcessName']='C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.19041.1790_none_7df2aec07ca10e81\TiWorker.exe']]
    </Select>
  </Query>
</QueryList>
```


## Privilege Constants
[Privilege Constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)

## Useful Windows Event Logs
### Windows System Logs

| **Event ID** | **Description** |
|--------------|-----------------|
| **1074** | System shutdown/restart – reveals when and why the system was shut down. Unexpected shutdowns may indicate malicious activity. |
| **6005** | "Event Log Service was started" – marks system startup, useful for investigating boot times and incidents. |
| **6006** | "Event Log Service was stopped" – usually during shutdown; unexpected stops may point to tampering. |
| **6013** | Windows uptime (daily) – short uptimes may signal reboots due to compromise or instability. |
| **7040** | Service startup type changed – could indicate tampering with critical service behavior. |

---

### Windows Security Logs

| **Event ID** | **Description** |
|--------------|-----------------|
| **1102** | Audit log was cleared – often a sign of malicious activity attempting to cover tracks. |
| **1116** | Antivirus (Defender) detected malware – high volume can signal an active or spreading threat. |
| **1118** | Antivirus remediation started – Defender began attempting to clean/remove malware. |
| **1119** | Antivirus remediation succeeded – malware cleanup was successful. |
| **1120** | Antivirus remediation failed – threat remains active and must be addressed. |
| **4624** | Successful logon – track user logons to identify abnormal patterns. |
| **4625** | Failed logon – repeated failures may indicate brute-force attack attempts. |
| **4648** | Logon with explicit credentials – often used during lateral movement or scheduled tasks. |
| **4656** | Handle to an object requested – monitor access to sensitive files, registry keys, or processes. |
| **4672** | Special privileges assigned to new logon – indicates high-privilege logon (e.g., SYSTEM, admin). |
| **4698** | Scheduled task created – attackers often use this for persistence mechanisms. |
| **4700 / 4701** | Scheduled task enabled / disabled – may indicate malicious manipulation of task behavior. |
| **4702** | Scheduled task updated – used to modify task behavior, potentially for persistence. |
| **4719** | System audit policy changed – could signal tampering to reduce logging visibility. |
| **4738** | User account was changed – changes in privileges or group memberships can indicate compromise. |
| **4771** | Kerberos pre-authentication failed – could be used to brute-force Kerberos tickets. |
| **4776** | Domain controller validated credentials – success or failure helps detect brute-force attempts. |
| **5001** | Real-time AV protection configuration changed – might indicate attempt to disable protection. |
| **5140** | Network share accessed – useful for detecting lateral movement or data exfiltration. |
| **5142** | Network share created – may be used for unauthorized file hosting or malware spread. |
| **5145** | Network share access checked – frequent attempts might indicate scanning or reconnaissance. |
| **5157** | WFP blocked a connection – may indicate malicious traffic or blocked exploit attempts. |
| **7045** | New service installed – often used by malware to maintain persistence. |

---

# Sysmon (system monitor)
Sysmon's primary components include:

- A Windows service for monitoring system activity.
- A device driver that assists in capturing the system activity data.
- An event log to display captured activity data.

Sysmon's unique capability lies in its ability to log information that typically doesn't appear in the Security Event logs, and this makes it a powerful tool for deep system monitoring and cybersecurity forensic analysis.

[full list of Sysmon event IDs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Install Sysmon
[Download](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

In a Administrator shell type:
```powershell
sysmon.exe -i -accepteula -h md5,sha256,imphash -l -n
```
To utilize a custom Sysmon configuration, execute the following after installing Sysmon
```powershell
sysmon.exe -c filename.xml
```

## Examples
### Detecting DLL Hijacking
To detect a DLL hijack, we need to focus on Event Type 7, which corresponds to module load events. To achieve this, we need to modify the sysmonconfig-export.xml Sysmon configuration file we downloaded from https://github.com/SwiftOnSecurity/sysmon-config.

By examining the modified configuration, we can observe that the "include" comment signifies events that should be included.

In the case of detecting DLL hijacks, we change the "include" to "exclude" to ensure that nothing is excluded, allowing us to capture the necessary data.

With the modified Sysmon configuration, we can start observing image load events. To view these events, navigate to the Event Viewer and access "Applications and Services" -> "Microsoft" -> "Windows" -> "Sysmon." 


### Detecting Credential Dumping

One widely used tool for credential dumping is Mimikatz, offering various methods for extracting Windows credentials. One specific command, "sekurlsa::logonpasswords", enables the dumping of password hashes or plaintext passwords by accessing the Local Security Authority Subsystem Service (LSASS). LSASS is responsible for managing user credentials and is a primary target for credential-dumping tools like Mimikatz.
<br>
attention to process access events. By checking Sysmon event ID 10, which represents "ProcessAccess" events, we can identify any suspicious attempts to access LSASS.


# Event Tracing For Windows (ETW)
## Logman
Logman is a pre-installed utility for managing Event Tracing for Windows (ETW) and Event Tracing Sessions.

<br>

```powershell
logman.exe query -ets
```
The -ets parameter will allow for a direct investigation of the event tracing sessions, providing insights into system-wide tracing sessions.

<br>

```powershell
logman.exe query "EventLog-System" -ets
```
For each provider subscribed to the session, we can acquire critical data:
- Name / Provider GUID: This is the exclusive identifier for the provider.
- Level: This describes the event level, indicating if it's filtering for warning, informational, critical, or all events.
- Keywords Any: Keywords create a filter based on the kind of event generated by the provider.

<br>

```powershell
logman.exe query providers
```
By using the logman query providers command, we can generate a list of all available providers on the system, including their respective GUIDs.

<br>

```powershell
logman.exe query providers | findstr "Winlogon"
```
Due to the high number of providers, it's usually advantageous to filter them using findstr.

<br>

```powershell
logman.exe query providers Microsoft-Windows-Winlogon
```
By specifying a provider with Logman, we gain a deeper understanding of the provider's function. This will inform us about the Keywords we can 
filter on, the available event levels, and which processes are currently utilizing the provider.

<br>

```powershell
C:\Tools> logman.exe query providers Microsoft-Windows-Winlogon

Provider                                 GUID
-------------------------------------------------------------------------------
Microsoft-Windows-Winlogon               {DBE9B383-7CF3-4331-91CC-A3CB16A3B538}

Value               Keyword              Description
-------------------------------------------------------------------------------
0x0000000000010000  PerfInstrumentation
0x0000000000020000  PerfDiagnostics
0x0000000000040000  NotificationEvents
0x0000000000080000  PerfTrackContext
0x0000100000000000  ms:ReservedKeyword44
0x0000200000000000  ms:Telemetry
0x0000400000000000  ms:Measures
0x0000800000000000  ms:CriticalData
0x0001000000000000  win:ResponseTime     Response Time
0x0080000000000000  win:EventlogClassic  Classic
0x8000000000000000  Microsoft-Windows-Winlogon/Diagnostic
0x4000000000000000  Microsoft-Windows-Winlogon/Operational
0x2000000000000000  System               System

Value               Level                Description
-------------------------------------------------------------------------------
0x02                win:Error            Error
0x03                win:Warning          Warning
0x04                win:Informational    Information

PID                 Image
-------------------------------------------------------------------------------
0x00001710
0x0000025c


The command completed successfully.
```

## GUI-based alternatives
- Performance Monitor
- EtwExplorer project

## Useful Providers

| **Provider** | **Purpose / Detection Use** |
|--------------|-----------------------------|
| `Microsoft-Windows-Kernel-Process` | Tracks process events; useful for detecting injection, hollowing, APT behavior. |
| `Microsoft-Windows-Kernel-File` | Monitors file operations; detects unauthorized access, ransomware, exfiltration. |
| `Microsoft-Windows-Kernel-Network` | Captures low-level network activity; useful for spotting C2, data exfiltration. |
| `Microsoft-Windows-SMBClient/SMBServer` | Detects unusual SMB activity; helps track lateral movement and file sharing. |
| `Microsoft-Windows-DotNETRuntime` | Monitors .NET execution; detects malicious assembly loading or abuse. |
| `OpenSSH` | Logs SSH connections; useful for tracking brute-force and remote access. |
| `Microsoft-Windows-VPN-Client` | Monitors VPN usage; detects unauthorized or suspicious connections. |
| `Microsoft-Windows-PowerShell` | Captures PowerShell command activity; detects abuse, obfuscated scripts. |
| `Microsoft-Windows-Kernel-Registry` | Tracks registry changes; helps detect persistence and malware setup. |
| `Microsoft-Windows-CodeIntegrity` | Detects unsigned or tampered drivers/code. |
| `Microsoft-Antimalware-Service` | Flags tampering or evasion of AV services. |
| `WinRM` | Tracks remote management usage; useful for spotting lateral movement. |
| `Microsoft-Windows-TerminalServices-LocalSessionManager` | Monitors RDP sessions; detects suspicious remote access. |
| `Microsoft-Windows-Security-Mitigations` | Detects bypass attempts of security mitigations. |
| `Microsoft-Windows-DNS-Client` | Logs DNS queries; helps detect tunneling or malicious domains. |
| `Microsoft-Antimalware-Protection` | Monitors AV protection status; useful for detecting evasion techniques. |

## Tapping into ETW for Detection

This document details two in-depth detection techniques using Event Tracing for Windows (ETW) and Sysmon to reveal stealthy attacker behaviors: (1) detecting parent-child process spoofing and (2) identifying in-memory .NET assembly execution.

---

### Detection Example 1: Abnormal Parent-Child Relationships

Legitimate Windows processes follow predictable parent-child relationships. Abnormal chains often indicate process injection, privilege escalation, or evasion attempts.

#### Example Scenario: `spoolsv.exe` spawning `cmd.exe`

* `spoolsv.exe` (Print Spooler) typically does not spawn interactive shells like `cmd.exe`.
* An attacker can spoof the parent process using Parent PID Spoofing.

#### Tools & Commands:

* Use Process Hacker to view real-time parent-child relationships.
* Use Sysmon (Event ID 1) to detect process creation metadata.

#### Spoofing with `psgetsys.ps1`:

```powershell
powershell -ep bypass
Import-Module .\psgetsys.ps1
[MyProcess]::CreateProcessFromParent([PID of spoolsv.exe], "C:\Windows\System32\cmd.exe", "")
```

This tricks Sysmon into logging `spoolsv.exe` as the parent of `cmd.exe`, even though PowerShell created it.

#### Real Detection via ETW:

```powershell
SilkETW.exe -t user -pn Microsoft-Windows-Kernel-Process -ot file -p C:\Windows\Temp\etw.json
```

* This command uses SilkETW to capture data from the Kernel-Process provider, which shows real parent process relationships.
* ETW reveals the true creator (`powershell.exe`), not the spoofed one.

---

### Detection Example 2: Malicious .NET Assembly Loading

Attackers now shift from "Living off the Land" (LotL) to Bring Your Own Land (BYOL):

* Instead of using native tools (like PowerShell), they load custom .NET assemblies in memory.
* This allows them to evade detections based on disk activity.

#### What Makes .NET Attractive?

* .NET assemblies can be executed fully in-memory (no disk write).
* DLLs like `clr.dll` and `mscoree.dll` are loaded, indicating .NET activity.
* These DLLs are used by the Common Language Runtime (CLR) to manage memory, JIT compilation, and API calls.

#### Example: Executing Seatbelt

```powershell
.\Seatbelt.exe TokenPrivileges
```

* `Seatbelt.exe` is a popular situational awareness tool written in C#.
* Execution causes the loading of `clr.dll` and `mscoree.dll` into memory.

#### Detecting with Sysmon (Event ID 7)

* Logs every DLL loaded into a process.
* By watching for .NET-related DLLs in non-.NET processes, we catch suspicious behavior.

#### Deeper Inspection with SilkETW:

```powershell
SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\Windows\Temp\etw.json
```

This captures:

* `JitKeyword`: Just-In-Time compilation (runtime method generation).
* `InteropKeyword`: Managed to Unmanaged code interaction.
* `LoaderKeyword`: Assembly load operations.
* `NGenKeyword`: Use of precompiled .NET images.

The resulting JSON includes method names, assembly details, and confirms that .NET code was run in memory.

---

### Key Tools Compared

| Tool             | Role in Detection                                  |
| ---------------- | -------------------------------------------------- |
| Sysmon (EID 1,7) | Logs process creation and DLL loads                |
| SilkETW          | Captures ETW providers for deeper telemetry        |
| Process Hacker   | Visualizes real-time process tree and memory state |

---

### Summary

* Sysmon alone can be spoofed; use ETW (SilkETW) for accurate process lineage.
* Monitor .NET-related DLLs (e.g., `clr.dll`, `mscoree.dll`) to detect BYOL behavior.
* Combine Sysmon, ETW, and visual tools for powerful detection workflows.

Let me know if you want Sigma or YARA rules, or help parsing ETW JSON logs.

## Get-WinEvent
List all logs
```powershell
PS C:\Users\Administrator> Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, IsClassicLog, IsEnabled, LogMode, LogType | Format-Table -AutoSize

LogName                                                                                RecordCount IsClassicLog IsEnabled  LogMode        LogType
-------                                                                                ----------- ------------ ---------  -------        -------
Windows PowerShell                                                                            2916         True      True Circular Administrative
System                                                                                        1786         True      True Circular Administrative
Security                                                                                      8968         True      True Circular Administrative
Key Management Service                                                                           0         True      True Circular Administrative
Internet Explorer                                                                                0         True      True Circular Administrative
HardwareEvents                                                                                   0         True      True Circular Administrative
Application                                                                                   2079         True      True Circular Administrative
Windows Networking Vpn Plugin Platform/OperationalVerbose                                                 False     False Circular    Operational
Windows Networking Vpn Plugin Platform/Operational                                                        False     False Circular    Operational
SMSApi                                                                                           
```

<br>

list providers
```powershell
PS C:\Users\Administrator> Get-WinEvent -ListProvider * | Format-Table -AutoSize

Name                                                                       LogLinks
----                                                                       --------
PowerShell                                                                 {Windows PowerShell}
Workstation                                                                {System}
WMIxWDM                                                                    {System}
WinNat                                                                     {System}
Windows Script Host                                                        {System}
Microsoft-Windows-IME-OEDCompiler                                          {Microsoft-Windows-IME-OEDCompiler/Analytic}
```

<br>

Retrieving events from the System log
```powershell
PS C:\Users\Administrator> Get-WinEvent -LogName 'System' -MaxEvents 50 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

TimeCreated            Id ProviderName                             LevelDisplayName Message
-----------            -- ------------                             ---------------- -------
6/2/2023 9:41:42 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5...
6/2/2023 9:38:32 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.ShellExperien...
6/2/2023 9:38:32 AM 10016 Microsoft-Windows-DistributedCOM         Warning          The machine-default permission settings do not grant Local Activation permission for the COM Server applicat...
6/2/2023 9:37:31 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.WindowsAlarms_8wekyb3...

```

<br>

Retrieving the newest events from Microsoft-Windows-WinRM/Operational, To retrieve the oldest events, instead of manually sorting the results, we can utilize the -Oldest parameter with the Get-WinEvent cmdlet
```powershell
PS C:\Users\Administrator> Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 30 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

TimeCreated            Id ProviderName            LevelDisplayName Message
-----------            -- ------------            ---------------- -------
6/2/2023 9:30:15 AM   132 Microsoft-Windows-WinRM Information      WSMan operation Enumeration completed successfully
6/2/2023 9:30:15 AM   145 Microsoft-Windows-WinRM Information      WSMan operation Enumeration started with resourceUri...

```

<br>

Retrieving events from .evtx Files
```powershell
PS C:\Users\Administrator> Get-WinEvent -Path 'C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\exec_sysmon_1_lolbin_pcalua.evtx' -MaxEvents 5 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

TimeCreated           Id ProviderName             LevelDisplayName Message
-----------           -- ------------             ---------------- -------
5/12/2019 10:01:51 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
5/12/2019 10:01:50 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
5/12/2019 10:01:43 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
```

<br>

Filtering events with FilterHashtable, Microsoft-Windows-Sysmon/Operational for ID 1 & 3
```powershell
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

TimeCreated           Id ProviderName             LevelDisplayName Message
-----------           -- ------------             ---------------- -------
6/2/2023 10:40:09 AM   1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 10:39:01 AM   1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 10:34:12 AM   1 Microsoft-Windows-Sysmon Information      Process Create:...

```

<br>

Filtering events with FilterHashtable & XML
```powershell
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=3} |
`ForEach-Object {
$xml = [xml]$_.ToXml()
$eventData = $xml.Event.EventData.Data
New-Object PSObject -Property @{
    SourceIP = $eventData | Where-Object {$_.Name -eq "SourceIp"} | Select-Object -ExpandProperty '#text'
    DestinationIP = $eventData | Where-Object {$_.Name -eq "DestinationIp"} | Select-Object -ExpandProperty '#text'
    ProcessGuid = $eventData | Where-Object {$_.Name -eq "ProcessGuid"} | Select-Object -ExpandProperty '#text'
    ProcessId = $eventData | Where-Object {$_.Name -eq "ProcessId"} | Select-Object -ExpandProperty '#text'
}
}  | Where-Object {$_.DestinationIP -eq "52.113.194.132"}

DestinationIP  ProcessId SourceIP       ProcessGuid
-------------  --------- --------       -----------
52.113.194.132 9196      10.129.205.123 {52ff3419-51ad-6475-1201-000000000e00}
52.113.194.132 5996      10.129.203.180 {52ff3419-54f3-6474-3d03-000000000c00}

```

<br>

Set a Timerange
```powershell
PS C:\Users\Administrator> $startDate = (Get-Date -Year 2023 -Month 5 -Day 28).Date
PS C:\Users\Administrator> $endDate   = (Get-Date -Year 2023 -Month 6 -Day 3).Date
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3; StartTime=$startDate; EndTime=$endDate} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
```

<br>

Filtering events with FilterXPath
```powershell
PS C:\Users\Administrator> Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[EventData[Data[@Name='Image']='C:\Windows\System32\reg.exe']] and *[EventData[Data[@Name='CommandLine']='`"C:\Windows\system32\reg.exe`" ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f']]" | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

 TimeCreated           Id ProviderName             LevelDisplayName Message
-----------           -- ------------             ---------------- -------
5/29/2023 12:44:46 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
5/29/2023 12:29:53 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
```

<br>

Filtering events based on property values
```powershell
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 1 | Select-Object -Property *


Message            : Process Create:
                   RuleName: -
                   UtcTime: 2023-06-03 01:24:25.104
                   ProcessGuid: {52ff3419-9649-647a-1902-000000001000}
                   ProcessId: 1036
                   Image: C:\Windows\System32\taskhostw.exe
                   FileVersion: 10.0.19041.1806 (WinBuild.160101.0800)
                   Description: Host Process for Windows Tasks
                   Product: Microsoft® Windows® Operating System
                   Company: Microsoft Corporation
                   OriginalFileName: taskhostw.exe
                   CommandLine: taskhostw.exe -RegisterDevice -ProtectionStateChanged -FreeNetworkOnly
                   CurrentDirectory: C:\Windows\system32\
                   User: NT AUTHORITY\SYSTEM
                   LogonGuid: {52ff3419-85d0-647a-e703-000000000000}
                   LogonId: 0x3E7
                   TerminalSessionId: 0
                   IntegrityLevel: System
                   Hashes: MD5=C7B722B96F3969EACAE9FA205FAF7EF0,SHA256=76D3D02B265FA5768294549C938D3D9543CC9FEF6927
                   4728E0A72E3FCC335366,IMPHASH=3A0C6863CDE566AF997DB2DEFFF9D924
                   ParentProcessGuid: {00000000-0000-0000-0000-000000000000}
                   ParentProcessId: 1664
                   ParentImage: -
                   ParentCommandLine: -
                   ParentUser: -
Id                   : 1
Version              : 5
Qualifiers           :
Level                : 4
Task                 : 1
Opcode               : 0
Keywords             : -9223372036854775808
RecordId             : 32836
ProviderName         : Microsoft-Windows-Sysmon
ProviderId           : 5770385f-c22a-43e0-bf4c-06f5698ffbd9
LogName              : Microsoft-Windows-Sysmon/Operational
ProcessId            : 2900
ThreadId             : 2436
MachineName          : DESKTOP-NU10MTO
UserId               : S-1-5-18
TimeCreated          : 6/2/2023 6:24:25 PM
ActivityId           :
RelatedActivityId    :
ContainerLog         : Microsoft-Windows-Sysmon/Operational
MatchedQueryIds      : {}
Bookmark             : 		System.Diagnostics.Eventing.Reader.EventBookmark
LevelDisplayName     : Information
OpcodeDisplayName    : Info
TaskDisplayName      : Process Create (rule: ProcessCreate)
KeywordsDisplayNames : {}
Properties           : {System.Diagnostics.Eventing.Reader.EventProperty,
                   System.Diagnostics.Eventing.Reader.EventProperty,
                   System.Diagnostics.Eventing.Reader.EventProperty,
                   System.Diagnostics.Eventing.Reader.EventProperty...}
```
The -Property * parameter, when used with Select-Object, instructs the command to select all properties of the objects passed to it. In the context of the Get-WinEvent command, these properties will include all available information about the event. Let's see an example that will present us with all properties of Sysmon event ID 1 logs.
<br>
Let's now see an example of a command that retrieves Process Create events from the Microsoft-Windows-Sysmon/Operational log, checks the parent command line of each event for the string -enc, and then displays all properties of any matching events as a list.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} | Where-Object {$_.Properties[21].Value -like "*-enc*"} | Format-List
```
### Breakdown

#### `| Where-Object { $_.Properties[21].Value -like "*-enc*" }`

* The pipe (`|`) sends the output from a previous command (e.g., filtered Sysmon Event 1 logs) into `Where-Object`.
* `$_` refers to each object (event) in the pipeline.
* `.Properties[21].Value`: Accesses the 22nd element in the event's Properties array.

  * For Sysmon Event ID 1, index `21` typically corresponds to the **ParentCommandLine** field, which stores the full command line of the parent process.
* `-like "*-enc*"`: Filters for command lines containing `-enc` (e.g., PowerShell encoded commands), which are often used to obfuscate malicious scripts.

#### `| Format-List`

* Formats each resulting object as a list.
* Makes the command line and other relevant fields easier to inspect manually.

### Purpose

This command is designed to highlight instances where a parent process uses `-enc`, a flag that suggests PowerShell script obfuscation. This is a common technique in post-exploitation and malware operations.

### Use Case Example

Run this after retrieving Sysmon logs from Event ID 1:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -eq 1 } | Where-Object { $_.Properties[21].Value -like "*-enc*" } | Format-List
```

This will return all process creation events where the parent command line contains `-enc`.

Let me know if you want this converted into a detection rule or wrapped in a reusable script.


### Question at the end
Utilize the Get-WinEvent cmdlet to traverse all event logs located within the "C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Lateral Movement" directory and determine when the \\*\PRINT share was added. Enter the time of the identified event in the format HH:MM:SS as your answer.

```powershell
Get-ChildItem -Path 'C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Lateral Movement' -Filter *.evtx -Recurse | 
ForEach-Object {
    Get-WinEvent -Path $_.FullName | 
    Where-Object { $_.Message -match '\\\\\*\\PRINT' }
}

```


# USEFUL COMMANDS:
## Spot DLL injection
```
Get-WinEvent -FilterHashtable @{Path="C:\Logs\DLLHijack\DLLHijack.evtx"; ID=7} |
Where-Object { $_.Message -notmatch 'C:\\Windows' } |
ForEach-Object {
  $msg = $_.Message
  $exeMatch = [regex]::Match($msg, "Image:\s+(.*)")
  $dllMatch = [regex]::Match($msg, "ImageLoaded:\s+(.*)")

  if ($exeMatch.Success -and $dllMatch.Success) {
    "$($exeMatch.Groups[1].Value.Trim()) => $($dllMatch.Groups[1].Value.Trim())"     }
  }
```

## Spot unmanaged Powershell
```
Get-WinEvent -FilterHashtable @{Path="C:\Logs\PowershellExec\PowershellExec.evtx"; ID=7} |
Where-Object {
    $_.Message -match 'clr\.dll|System\.Management\.Automation\.dll|mscoree\.dll|amsi\.dll' -and
    $_.Message -notmatch 'powershell.exe|pwsh.exe|dotnet.exe'
} | Format-List TimeCreated, Message



or


Get-WinEvent -Path "C:\Logs\PowershellExec\*.evtx" | Where-Object {
    $_.Id -eq 8
} | Format-List

```

<br>

find the process that was injected
```
Get-WinEvent -Path "C:\Logs\PowershellExec\*.evtx" | Where-Object {
    $_.Message -like "*calculator.exe*" -and ($_.Id -eq 1 -or $_.Id -eq 8 -or $_.Id -eq 10)
} | Format-List
```


## check which process called lsass.exe
```
Get-WinEvent -Path "C:\Logs\PowershellExec\*.evtx" | Where-Object {
    $_.Message -like "*lsass.exe*"
} | Format-List
```

## Check who logged in
```
Get-ChildItem "C:\Logs\dump\*.evtx" | ForEach-Object {
    Write-Host "Processing $($_.FullName)..."
    Get-WinEvent -Path $_.FullName | Where-Object {
        $_.Id -eq 4624 -and $_.TimeCreated -gt [datetime]"2022-04-27 18:54:50"
    } | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $fields = @{}
        foreach ($d in $xml.Event.EventData.Data) {
            $fields[$d.Name] = $d.'#text'
        }
        [PSCustomObject]@{
            TimeCreated     = $_.TimeCreated
            UserName        = $fields["TargetUserName"]
            Domain          = $fields["TargetDomainName"]
            LogonType       = $fields["LogonType"]
            IPAddress       = $fields["IpAddress"]
            LogonProcess    = $fields["LogonProcessName"]
            AuthPackage     = $fields["AuthenticationPackageName"]
        }
    }
}
```
## check which process run which commands
```
Get-WinEvent -Path "C:\Logs\StrangePPID\*.evtx" | Where-Object {
    $_.Id -eq 1
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $fields = @{}
    foreach ($d in $xml.Event.EventData.Data) {
        $fields[$d.Name] = $d.'#text'
    }
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        ParentImage = $fields["ParentImage"]
        Image       = $fields["Image"]
        CommandLine = $fields["CommandLine"]
    }
} | Sort-Object Time | Format-Table -AutoSize
```