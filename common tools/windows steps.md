# High-level Windows post-exploit playbook (exam / lab safe)

## First 60 seconds — immediate situational awareness (do these mentally / note them)

- Who am I? (identity & groups)
    
- What privileges do I have? (is impersonation, debug, backup, restore, take ownership present?)
    
- OS & architecture (Windows version, Server vs Workstation, 32/64 bit)
    
- How was I in? (webshell, service, scheduled task, user shell)
    
- Any obvious creds/configs in current working directory or webroot?
    

> Memorize: _identity → privileges → context → OS/arch → evidence of creds_

---

## Quick enumeration _concepts_ (what to look for and why)

(These are the _questions_ you should answer in a lab — not commands)

1. **Privileges & Tokens** — does my account/process show impersonation or debug rights?  
    _Why:_ impersonation lets you try token abuse; debug lets you read memory (LSASS).
    
2. **Services / Scheduled Tasks** — any auto-start service running as SYSTEM or writable service binary or misconfigured path?  
    _Why:_ writable service binaries or unquoted service paths let you cause code execution on restart.
    
3. **Credentials in Files** — are there config files, web.config, .env, or scripts containing passwords, keys, or database strings?  
    _Why:_ cleartext creds let you authenticate elsewhere.
    
4. **Backup / Volume Access** — can you read system files via backup APIs or shadow copies?  
    _Why:_ getting SYSTEM-level files (SAM/NTDS) yields hashes and secrets.
    
5. **Delegation / SPNs / Kerberos** — are there service accounts with SPNs or delegation settings that can be abused?  
    _Why:_ service tickets or delegation settings are lateral avenues.
    
6. **Network Access** — from this host, what other machines are reachable on common ports (SMB, RDP, WinRM, SQL)?  
    _Why:_ reachable services combined with creds is the core pivot method.
    
7. **Local Exploitable Software** — outdated services, drivers, or unpatched components that are known vulnerable.  
    _Why:_ last resort local exploits if config-based escalation not possible.
    
8. **Persistence / Cleanup** — if you escalate, what evidence will be left and how to document it in the report? (lab exams often expect notes.)
    

---

## Decision tree / flow (memorize this sequence for labs)

1. **Check privileges**
    
    - If impersonation or assign/creation token privileges → _try token impersonation vectors_ (token abuse is high ROI in labs).
        
    - Else if debug privilege → _dump memory_ and extract creds.
        
    - Else if backup/restore present → _access protected files_.
        
    - Else if take ownership present → _change ACLs on service binaries or keys_.
        
    - Else proceed to next steps.
        
2. **Search for credentials**
    
    - Config files, scheduled tasks, service accounts, database connection strings. If found → test them for other hosts.
        
3. **Inspect services/scheduled tasks**
    
    - Writable service path, unquoted paths, auto-start programs, or service accounts with weak permissions → may allow binary replacement or DLL hijacking.
        
4. **Check for reachable targets**
    
    - If creds available: attempt authenticated access (SMB/WinRM/RDP/DB). If successful → pivot.
        
    - If no creds: consider credential harvesting (if permitted in lab) or try other local escalation.
        
5. **If token/impersonation attempts fail**
    
    - Try different token targets or alternative vectors (e.g., Print Spooler vs COM-based).
        
    - If still blocked, move to file/permission-based approaches or local vulnerable services.
        
6. **If you reach dead end**
    
    - Re-run enumeration with different tools / angles (scheduled tasks, local users, ACLs, registry keys) — labs usually hide a misconfiguration or secret.
        

---

## Pivoting concepts (high-level)

- **Use valid credentials** you found to authenticate to other hosts using common services (file shares, remote management, RDP, DB).
    
- **Re-use tokens** if you can impersonate an account that has network access.
    
- **Validate reachability** (is the target reachable from current host?) and prioritize high-value hosts (domain controllers, jump boxes).
    
- **Avoid noisy operations** if the lab penalizes detection — in real engagements use caution and legal authorization.