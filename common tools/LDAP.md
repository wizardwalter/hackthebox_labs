
> Quick reference for LDAP enumeration against example `ldap://10.10.10.182` (CASC-DC1).

---

## Summary

- **Domain:** `cascade.local`
    
- **Domain Controller (queried):** `CASC-DC1.cascade.local` (`10.10.10.182`)
    
- **Goal:** Enumerate users, groups, SPNs, computers, LAPS entries, and preauth-disabled accounts; identify Kerberoast / AS-REP / LAPS targets and paths to escalation.
    

---

## Quick checklist (priority)

1. Enumerate groups & Domain Admins
    
2. Find accounts with SPNs (Kerberoast targets)
    
3. Find accounts with Kerberos preauth disabled (AS-REP targets)
    
4. Enumerate computers and check for `ms-Mcs-AdmPwd` (LAPS)
    
5. Identify `adminCount` / Admin-like users
    
6. If creds are obtained: run BloodHound/SharpHound, DCSync checks, `secretsdump` path
    

---

## Useful `ldapsearch` commands (copy/paste)

### 1) Export all user sAMAccountNames

```bash
ldapsearch -x -H ldap://10.10.10.182 -b "DC=cascade,DC=local" -LLL \
  "(&(objectCategory=person)(objectClass=user))" sAMAccountName | \
  awk '/^sAMAccountName: /{print $2}' > users.txt
```

### 2) Users + useful attributes (memberOf, adminCount, SPN, last logon)

```bash
ldapsearch -x -H ldap://10.10.10.182 -b "DC=cascade,DC=local" \
  "(&(objectCategory=person)(objectClass=user))" \
  sAMAccountName memberOf userAccountControl adminCount servicePrincipalName pwdLastSet lastLogonTimestamp msDS-User-Account-Control-Computed -LLL
```

### 3) Find accounts that have SPNs (Kerberoast targets)

```bash
ldapsearch -x -H ldap://10.10.10.182 -b "DC=cascade,DC=local" \
  "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName -LLL
```

### 4) Find possible AS-REP (preauth-disabled) targets

> LDAP queries for this can be finicky. If you prefer tooling, use GetNPUsers (Impacket) or PowerView.

LDAP approach (returns msDS computed field if available):

```bash
ldapsearch -x -H ldap://10.10.10.182 -b "DC=cascade,DC=local" \
  "(msDS-User-Account-Control-Computed=*)" sAMAccountName msDS-User-Account-Control-Computed -LLL
```

### 5) Enumerate computer objects (hostnames, machine SPNs)

```bash
ldapsearch -x -H ldap://10.10.10.182 -b "DC=cascade,DC=local" \
  "(objectCategory=computer)" dNSHostName servicePrincipalName -LLL
```

### 6) Check for LAPS stored local admin passwords

```bash
ldapsearch -x -H ldap://10.10.10.182 -b "DC=cascade,DC=local" \
  "(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))" dNSHostName ms-Mcs-AdmPwd -LLL
```

### 7) List members of Domain Admins

```bash
ldapsearch -x -H ldap://10.10.10.182 -b "CN=Domain Admins,CN=Users,DC=cascade,DC=local" member -LLL
```

### 8) Enumerate groups (quick)

```bash
ldapsearch -x -H ldap://10.10.10.182 -b "DC=cascade,DC=local" "(objectCategory=group)" cn member -LLL
```

---

## Explanation / Notes (why these matter)

- **servicePrincipalName (SPN):** accounts with SPNs can be Kerberoasted. You request a service ticket for the SPN, extract the ticket encrypted part, and crack offline.
    
- **ms-Mcs-AdmPwd (LAPS):** if readable, gives local admin password for a computer object. RDP/SMB with these creds frequently leads to lateral movement.
    
- **adminCount:** set to `1` on objects protected by AdminSDHolder (often indicates privileged account membership or formerly privileged accounts).
    
- **msDS-User-Account-Control-Computed / userAccountControl bits:** can indicate `DONT_REQUIRE_PREAUTH` (AS-REP roastable accounts).
    

---

## Recommended tools & one-liners (after enumeration)

### Without creds (anonymous / low-privilege binds)

- `ldapsearch` — manual enumeration (you’re doing this).
    
- `ldapdomaindump` — automated dump of LDAP/DNS/GPO info.
    
- `GetNPUsers.py` (Impacket) / `Rubeus` — check AS-REP roastable users (if discoverable).
    

### With creds (any domain user)

- **Kerberoast:** `GetUserSPNs.py` (Impacket) to request service tickets, then crack with `hashcat` / `john`.
    
- **AS-REP roast:** `GetNPUsers.py` (Impacket) to request AS-REP data and crack offline.
    
- **BloodHound / SharpHound:** collect data for attack graph analysis (ACLs, group membership, sessions, SPNs). Use BloodHound to find DA paths.
    
- **CrackMapExec:** `crackmapexec ldap <dc-ip> -u <user> -p <pass>` for quick checks and enumeration.
    

### If elevated / DA obtained

- `secretsdump.py` (Impacket) / `DCSync` to pull NTDS or perform full credential dump.
    
- Dump LAPS across machines if ACLs allow.
    

---

## Short escalation roadmap (ordered)

1. **SPN -> Kerberoast**: collect SPNs -> request TGS -> crack offline. If cracked, use creds to pivot.
    
2. **LAPS**: search for `ms-Mcs-AdmPwd` -> RDP/SMB into host -> escalate locally.
    
3. **AS-REP**: identify preauth-disabled users -> GetNPUsers -> crack offline.
    
4. **Group / ACL analysis**: with creds, run SharpHound -> BloodHound -> find DCSync or unconstrained delegation paths.
    
5. **DCSync / secretsdump**: if you find `Replicating Directory Changes` rights or DA creds, extract hashes.
    

---

## Practical tips / gotchas

- LDAP query results can be large — use `-LLL` to clean up formatting and `sed`/`awk` to parse.
    
- `userAccountControl` bit checks are easier with PowerView (PowerShell). If you have Windows/PowerShell, use `Get-NPUsers` or `Get-UserProperty` helpers.
    
- Kerberoast targets may be service accounts with long-running passwords — prioritize those.
    
- LAPS values are often rotated — try immediately after you read them.
    
- Always export raw results (`> filename`) so you can parse offline and feed into tools (e.g., list of SPNs to GetUserSPNs).
    

---

## Example workflow (commands stitched together)

```bash
# get users
ldapsearch -x -H ldap://10.10.10.182 -b "DC=cascade,DC=local" -LLL "(&(objectCategory=person)(objectClass=user))" sAMAccountName > users_raw.txt

# get SPNs
ldapsearch -x -H ldap://10.10.10.182 -b "DC=cascade,DC=local" -LLL "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName > spn_list.txt

# query LAPS (if any)
ldapsearch -x -H ldap://10.10.10.182 -b "DC=cascade,DC=local" -LLL "(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))" dNSHostName ms-Mcs-AdmPwd > laps.txt
```

---

## What to save in your notes

- `users.txt` (all sAMAccountName)
    
- `spn_list.txt` (account + SPN)
    
- `laps.txt` (host + ms-Mcs-AdmPwd)
    
- `groups_membership.txt` (members of Domain Admins, Enterprise Admins, etc.)
    

---

If you want:

- I can convert these into a single printable `.md` or `.pdf` OSCP note file.
    
- Or I can create a separate canvas write-up that replaces the placeholders with the exact outputs you got (copy/paste your results and I’ll inject them).
    

Good luck — paste the output files if you want me to annotate them in-line.