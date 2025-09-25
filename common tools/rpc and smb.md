
> Quick reference for RPC / SMB enumeration against `10.10.10.182` (CASC-DC1). Useful when LDAP is blocked or limited — RPC/SMB often yields users, groups, shares, services, sessions, and more.

---

## Summary

- **Target IP:** `10.10.10.182` (CASC-DC1)
    
- **Services:** SMB / MSRPC over TCP 139/445
    
- **Goal:** Detect whether anonymous/null session or credentialed RPC binds are allowed; enumerate users, groups, shares, sessions, services, local accounts, policies, and rights via RPC/SAMR/LSARPC/srvsvc.
    

---

## Quick checklist (priority)

1. Check SMB port reachability and server OS/fingerprint.
    
2. Test anonymous/null session (SMB) and RPC null bind.
    
3. Enumerate shares, sessions, and users via `smbclient`, `rpcclient`, and `enum4linux`.
    
4. If creds available, run credentialed RPC queries (more info: SAMR, LSA, SRVSVC, Scheduler, Eventlog, WinReg).
    
5. If you get a shell/SMB write, deploy SharpHound or use Impacket/WMI for deeper enumeration.
    

---

## Tools you’ll use (common)

- `nmap` (smb scripts)
    
- `enum4linux` (all-in-one SMB/RPC enumeration)
    
- `smbclient` (list shares, anonymous access)
    
- `rpcclient` (SAMR / LSARPC queries)
    
- `crackmapexec` (fast smb checks / modules)
    
- `smbmap` (map shares & perms)
    
- `impacket` tools: `smbclient.py`, `wmiexec.py`, `psexec.py`, `secretsdump.py`, `rpcdump.py` (if available)
    
- `BloodHound`/`SharpHound` (via SMB/WinRM/LDAP collectors once creds or shell are available)
    

---

## Quick checks (copy/paste)

### 1) Nmap first (discover SMB & RPC capabilities)

```bash
nmap -p 139,445 --script smb-protocols,smb-os-discovery,smb-enum-shares,smb-enum-users -oN nmap_smb_10.10.10.182.txt 10.10.10.182
```

**Why:** finds open ports, OS info, and may enumerate shares/users via SMB scripts.

### 2) Check anonymous SMB share listing (no creds)

```bash
smbclient -L //10.10.10.182 -N
```

If it lists shares, try mounting or connecting:

```bash
smbclient //10.10.10.182/SHARE -N
# or mount with mount.cifs on Linux if needed
```

**Why:** anonymous SMB can expose file shares and sometimes readable files with creds/passwords.

### 3) Run `enum4linux` (fast, comprehensive)

```bash
enum4linux -a 10.10.10.182 | tee enum4linux_10.10.10.182.txt
```

**Why:** runs a suite of SMB/RPC queries (null session checks, users, groups, shares, OS info) and is often the quickest first step when LDAP is unavailable.

### 4) Test RPC null/anonymous bind with `rpcclient`

```bash
rpcclient -U "" -N 10.10.10.182
# then at rpcclient prompt try commands below (querydominfo, enumdomusers, netshareenum ...)
```

Or run non-interactively:

```bash
rpcclient -U "" -N 10.10.10.182 -c "enumdomusers"  # list domain users
rpcclient -U "" -N 10.10.10.182 -c "enumdomgroups"  # list groups
rpcclient -U "" -N 10.10.10.182 -c "querydominfo"   # domain basic info
rpcclient -U "" -N 10.10.10.182 -c "netshareenum"  # list SMB shares
```

**Why:** `rpcclient` speaks SAMR/LSA/SRV endpoints and can enumerate users/groups/shares if the server allows null binds or your creds.

### 5) If anonymous fails — try common creds / service accounts

```bash
# CrackMapExec quick check (see if creds work and get extra info)
crackmapexec smb 10.10.10.182 -u <user> -p <pass> --shares --users --groups
```

**Why:** CME gives quick validation, shows shares, sessions, local admin, and supports many modules.

### 6) Enumerate shares and permissions

```bash
smbmap -H 10.10.10.182 -u '<user>' -p '<pass>'    # credentialed
smbmap -H 10.10.10.182 -u '' -p ''                # anonymous/null (if allowed)
```

**Why:** quickly identifies writable shares where you can drop files or upload a binary/agent.

### 7) Enumerate domain users & groups (credentialed rpcclient)

```bash
rpcclient -U '<domain>\<user>%<pass>' 10.10.10.182 -c 'querydominfo'
rpcclient -U '<domain>\<user>%<pass>' 10.10.10.182 -c 'enumdomusers'
rpcclient -U '<domain>\<user>%<pass>' 10.10.10.182 -c 'enumdomgroups'
rpcclient -U '<domain>\<user>%<pass>' 10.10.10.182 -c 'lookupsids S-1-5-21-...'
```

**Why:** credentialed RPC unlocks SAMR/LSA queries returning user and group data similar to LDAP.

### 8) Query sessions / logged-on users / services

```bash
# via smbclient RPC calls (some via enum4linux output). Example with rpcclient:
rpcclient -U '<domain>\<user>%<pass>' 10.10.10.182 -c 'srvinfo'
rpcclient -U '<domain>\<user>%<pass>' 10.10.10.182 -c 'netshareenum'
```

**Why:** sessions and services can reveal active user sessions, mapped drives, and service accounts.

### 9) Use Impacket tools if you have creds or hashes

```bash
# remote command exec over SMB/RPC
python3 wmiexec.py <domain>/<user>:<pass>@10.10.10.182
python3 psexec.py <domain>/<user>:<pass>@10.10.10.182
# dump secrets once privileged
python3 secretsdump.py <domain>/<user>:<pass>@10.10.10.182
```

**Why:** get shell or dump credentials if you can authenticate and escalate.

---

## `rpcclient` commands cheat-sheet (interactive)

After `rpcclient -U '<domain>\\<user>%<pass>' 10.10.10.182` at the prompt, useful commands:

- `querydominfo` — basic domain info (domain name, controllers)
    
- `enumdomusers` — list domain users (sAMAccountName-like)
    
- `enumdomgroups` — list domain groups
    
- `lookupnames <name>` — resolve name -> SID
    
- `lookupsids <SID>` — resolve SID -> name
    
- `netshareenum` — list SMB shares
    
- `srvinfo` — server info (OS/version)
    
- `enumalsgroups` / `enumalsusers` — (if present) enumerate aliases/groups
    

> Note: exact command availability varies with `rpcclient` versions; run `help` in prompt.

---

## What information you can get via RPC that complements LDAP

- **Users & groups** (SAMR) — similar to LDAP but via RPC (useful if LDAP blocked)
    
- **SMB shares & permissions** (srvsvc) — files and writable locations for lateral movement
    
- **Registered services & service accounts** (services RPC) — identify services running as domain accounts
    
- **Sessions & open files** — find active user sessions / possible credentials in memory
    
- **Local SAM / policy info** (if credentials allow) — local accounts, password policies
    

---

## Roadmap: from enumeration → exploitation

1. Try **null/anonymous** SMB (`smbclient`, `rpcclient`, `enum4linux`). If works, scrape shares and config files.
    
2. If anonymous fails, try **password spraying** / credential stuffing on SMB (careful with lockouts).
    
3. If credentials succeed, run `rpcclient` and `smbmap` to enumerate shares and SAMR data.
    
4. Look for writable shares or services you can replace (service binary manipulation) to get codeexec.
    
5. If you can execute commands (wmiexec, psexec), run SharpHound / BloodHound and collect ACLs for DA paths.
    
6. If you find local admin creds or can escalate, use `secretsdump.py` or `DCSync` to extract domain hashes.
    

---

## Practical tips / gotchas

- Many modern Windows hosts disable anonymous RPC/SMB; credentialed enumeration is more reliable.
    
- Be cautious with password spraying against SMB — account lockouts are common. Use slow rate and multi-account strategies.
    
- `enum4linux -a` is super handy as a first pass — it bundles many RPC/SMB checks.
    
- `rpcclient` help shows all supported commands on the target; use it to discover available RPC interfaces.
    
- If `rpcclient` interactive commands return "STATUS_ACCESS_DENIED", you likely need credentials.
    

---

## Example files to save in your notes

- `nmap_smb_10.10.10.182.txt` (nmap output)
    
- `enum4linux_10.10.10.182.txt` (enum4linux full dump)
    
- `shares.txt` (output of smbclient/smbmap)
    
- `rpcclient_enum.txt` (rpcclient command outputs: enumdomusers, enumdomgroups, netshareenum)
    

---

If you want, I can:

- Convert this into a printable `.md` or `.pdf` for your OSCP notes.
    
- Generate a follow-up canvas doc that injects the exact outputs from your `enum4linux` or `rpcclient` runs (paste the raw output and I’ll annotate).
    

Ready to run any of these and paste outputs and I’ll annotate next steps.