Nice — here’s a tight, lab-ready cheat sheet for **enumerating usernames via SMB, RPC, and SMTP**. Includes quick commands (placeholders), what the responses mean, follow-ups, and detection/mitigation notes. Use these only in authorized labs/engagements.

# SMB (Server Message Block)

When to use: Windows file/print shares, SMB services (ports 139/445).  
Goal: enumerate share info, local users, domain users, machine accounts, groups.

Quick checks

```bash
# List shares + basic info (anonymous/null session)
smbclient -L //<TARGET_IP> -N
# or with an explicit null username
smbclient -L //<TARGET_IP> -U ""% -N
```

What to look for

- Share names (e.g., `C$`, `IPC$`, `SYSVOL`) — `IPC$` often indicates RPC/SMB named-pipe services available.
    
- Any `Domain` or `Workgroup` hints in banner.
    

Common tools / commands

```bash
# Aggressive SMB enumeration (lots of useful output)
enum4linux -a <TARGET_IP>

# SMB map (check accessible shares / list files)
smbmap -H <TARGET_IP> -u '' -p ''     # try null session
smbmap -H <TARGET_IP> -u <USER> -p <PASS>

# Interactive null session to IPC$ with smbclient
smbclient // <TARGET_IP>/IPC$ -U ""% -N
# once connected, you can sometimes use 'srvinfo', 'lsa', or enumerate shares (depends on server)
```

How SMB yields usernames

- `enum4linux` and `rpcclient` often parse and return user lists (users/groups) from accessible RPC interfaces.
    
- Share listings or print spooler info sometimes include usernames (owner fields, file lists).
    
- Anonymous/null sessions historically allowed `netshareenum`, `enumdomusers` on older/weakly configured servers.
    

# RPC (remote procedure calls / SAM/LSA via named pipes)

When to use: Active Directory domain controllers, Windows RPC services; can enumerate domain users/groups via RPC/SAM/LSA if permissions allow.

Quick rpcclient

```bash
# Connect to MS-RPC service (uses Samba's rpcclient)
rpcclient -U "" -N <TARGET_IP>
# Once in rpcclient shell, common commands:
# - enumdomusers     -> list domain users
# - querydominfo     -> domain info
# - enumdomgroups    -> list domain groups
# - lookupnames <RID> (or use 'getusername' variants)
# Example (one-liner):
rpcclient -U "" -N <TARGET_IP> -c "enumdomusers"
```

Windows RPC named-pipe probes

- `smbclient //TARGET_IP/IPC$ -U ""% -N` then use `rpcclient` or `smbclient` to talk to named pipes.
    
- `rpcclient` output lines will often include `User: <name>` or enumerated SIDs, and you can map RIDs to usernames.
    

What successful output looks like

- `enumdomusers` returns a numbered list of usernames and RIDs.
    
- `querydominfo` shows domain name and domain SID — helpful to identify domain prefix and build candidate usernames (e.g., `DOMAIN\alice`).
    

Notes / gotchas

- Newer Windows versions and correctly configured DCs block anonymous access; you may need an authenticated low-privilege account to get domain listings.
    
- `rpcclient` commands vary somewhat across Samba versions — `help` inside rpcclient shows available commands.
    

# SMTP (Simple Mail Transfer Protocol)

When to use: mail servers (port 25, 587, 465). Goal: test for username validity via SMTP commands (VRFY, EXPN, RCPT).

Basic manual probe

```bash
# Plaintext SMTP (no TLS)
nc -nv <TARGET_IP> 25
# After connection, type:
EHLO example.com
VRFY <username>
# or:
MAIL FROM:<test@example.com>
RCPT TO:<username@targetdomain>
```

Using STARTTLS (if server supports TLS)

```bash
openssl s_client -starttls smtp -crlf -connect <TARGET_IP>:25
# Then run EHLO and VRFY / RCPT TO as above
```

Swaks (scripted SMTP tester)

```bash
# Test a specific recipient — good because it handles TLS automatically
swaks --to <username@domain> --server <TARGET_IP>    # looks for 250 / 550 responses
```

How to interpret responses

- `250` or `252` after `VRFY` / `RCPT TO` → server accepted the address (likely valid).
    
- `550` / `User unknown` → likely invalid recipient.
    
- Many modern servers disable `VRFY` and `EXPN`. `RCPT TO` during SMTP session is often still used for probing (postfix/exim responses).
    
- Some servers will accept all recipients (catch-alls) — then follow up with further checks (e.g., attempt login or test mail delivery). Catch-alls produce false positives.
    

Practical tips

- Try common username formats: `firstname`, `first.last`, `f.lastname`, `firstname.lastname`, `firstl`.
    
- Use domain from email addresses gathered (internal web pages, cert SANs from `openssl s_client`).
    
- Be aware of rate limits and logging — many mail servers will log and alert on repeated probes.
    

# Combining & workflow (lab/OSCP style)

1. **Start with SMB**: `enum4linux -a <IP>` → get hostnames, domain names, possible usernames/groups.
    
2. **Probe RPC**: `rpcclient -U "" -N <IP>` → `enumdomusers` if possible. Use collected domain SID to form usernames.
    
3. **Validate via SMTP**: use `swaks` or `nc` to `VRFY`/`RCPT TO` to confirm likely addresses.
    
4. **Cross-check**: match entries with web apps, cert SANs, public profiles, or `ssl-cert` output from `nmap` to build a prioritized username list.
    
5. **Record evidence**: copy and save banners/command output (`-oA` for nmap, save rpcclient output).
    

# False positives & defensive signals

- Null sessions may return partial or obfuscated info — verify with a second vector (SMTP or LDAP).
    
- Services behind proxies or MTA relays can give misleading `250` responses even for unknown users (accept then bounce).
    
- Rate-limiting, tarpitting, honeypots — long delays or throttling are signs of monitoring/defense. Respect rules of engagement.
    

# Detection & Mitigation (useful for reports)

- **Detecting enumeration**:
    
    - Spike in `VRFY/EXPN/RCPT` SMTP commands in mail logs.
        
    - Repeated anonymous SMB/RPC connections, many `enum*` calls from a single source.
        
    - IDS signatures for `enum4linux`, `rpcclient`, `smbclient` patterns or high connection rates to 139/445/135/389.
        
- **Mitigations**:
    
    - Disable anonymous/null sessions; disable `VRFY`/`EXPN`.
        
    - Harden SMB/RPC access to authenticated users; apply least privilege to RPC interfaces.
        
    - Enforce rate limiting / tarpitting on SMTP and logging/alerting on repeated failed `RCPT` attempts.
        
    - Monitor for anomalous enumeration behavior and block/blacklist offending IPs.
        

# Quick copy-paste examples (replace placeholders)

```bash
# SMB banner/shares
smbclient -L //<TARGET_IP> -N

# Full automated SMB enum (best first pass)
enum4linux -a <TARGET_IP>

# RPC domain user enum (null session)
rpcclient -U "" -N <TARGET_IP> -c "enumdomusers"

# SMTP probe (manual)
nc -nv <TARGET_IP> 25
# then: EHLO example.com
# then: VRFY john.doe
# or:
MAIL FROM:<me@example.com>
RCPT TO:<john.doe@targetdomain>
```

# Ethics / legality

Only run these techniques on systems you own, control, or have explicit authorization to test (HTB/OSCP/TryHackMe or a signed engagement). Unauthorized enumeration/scanning is illegal in many jurisdictions.

---

Want me to:

- drop this into a Canvas doc (copyable for your exam notes)?
    
- expand with **example output** snippets for each tool so you can quickly recognise valid results?