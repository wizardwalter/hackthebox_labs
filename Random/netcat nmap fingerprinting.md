# Quick: netcat (banner grab / quick fingerprint)

- Basic banner grab (TCP):
    

```bash
nc -nvv <target-ip> <port>
# example: nc -nvv 10.10.11.5 80
```

- Flags explained
    
    - `-n` = no DNS (use numeric IPs, faster/safer on labs)
        
    - `-v` = verbose; `-vv` = extra verbose (shows connection status)
        
- Useful variants
    
    - Timeout (close if no response): `nc -nvv -w 3 <ip> <port>`
        
    - Send a probe then exit: `printf "HEAD / HTTP/1.0\r\n\r\n" | nc -nvv -w 3 <ip> 80`
        
    - Zero-I/O connect scan (just check open): `nc -z -v <ip> <port>` or range `nc -z -v <ip> 20-100`
        
    - Reverse banner: connect and paste crafted payloads (FTP/SMTP/POP/IMAP commands) to elicit a banner
        
- When to use `nc`
    
    - Fast manual banner grabs, interactive probing, manual protocol conversation, quick port check when you already know port is open.
        
- What to look for in banner output
    
    - Service name + version (e.g., `Apache/2.4.18 (Ubuntu)`)
        
    - Protocol hints (HTTP status line, SMTP `220`, FTP `220`, SSH `SSH-2.0-OpenSSH_7.6`)
        
    - Certificates (if TLS), odd strings, debug output
        

# Quick: nmap (automated fingerprinting & deeper)

- Basic scans
    

```bash
# quick ping+top ports
nmap -sS -T4 -p- --min-rate=1000 <ip>

# service & version detection + OS detection + scripts
nmap -sS -sV -O -A -p <port-list> -T4 <ip>

# service detection only (less noisy than -A)
nmap -sV -p <port(s)> <ip>
```

- Flags explained (most-used)
    
    - `-sS` = TCP SYN scan (stealthy)
        
    - `-sT` = TCP connect (use when you lack raw sockets)
        
    - `-sU` = UDP scan (slow; combine carefully)
        
    - `-p` = ports (e.g., `-p 21,22,80` or `-p-` all ports)
        
    - `-sV` = version detection (probes services to get banners/versions)
        
    - `-O` = OS detection
        
    - `-A` = aggressive (equivalent to `-sV -O --script=default,safe`)
        
    - `-T0..T5` = timing template (use `T4` for speed, `T3` default, `T2` or lower for stealth)
        
    - `-Pn` = skip host discovery (treat host as up)
        
    - `--script` = run NSE scripts (e.g., `--script=banner,http-title,ssl-cert`)
        
    - `--version-all` = deeper version probes
        
    - `-oA <basename>` = save all outputs (nmap, xml, grepable)
        
- Useful example commands
    

```bash
# Version + scripts for fingerprinting a specific port
nmap -sV --script=banner,ssl-cert,http-title -p 80,443,22 <ip>

# Full TCP port scan faster
nmap -sS -p- -T4 --min-rate=1000 <ip>

# UDP probe for common UDP services (DNS, SNMP, NTP)
nmap -sU -p 53,161,123 -T3 <ip>

# Save results to XML + grepable + nmap
nmap -sV -O -p 1-65535 -T4 -oA scan-full <ip>
```

# NSE (Nmap Scripting Engine) — common useful scripts

- `banner` — grabs banners
    
- `http-title` — gives HTTP title (good for web-ident)
    
- `ssl-cert` — reads TLS certificate (CN, SANs, issuer, expiration)
    
- `ftp-anon`, `smtp-commands`, `imap-capabilities` — protocol-specific info
    
- `vuln/*` — vulnerability checks (use responsibly in lab only)
    
- Use like: `--script=banner,http-title,ssl-cert`
    

# Follow-up manual probes (after initial fingerprint)

- HTTP: `curl -I http://<ip>:<port>` or `curl -kI https://<ip>:<port>`
    
- TLS: `openssl s_client -connect <ip>:<port> -servername <host>` then `QUIT`
    
- SSH: `ssh -vv -oBatchMode=yes -p <port> user@<ip>` (will show server banner)
    
- SMTP: `nc -nvv <ip> 25` then `EHLO test` → reveals capabilities
    
- FTP: `nc -nvv <ip> 21` → expect `220` and banner
    
- SMB: `smbclient -L //<ip> -N` or `smbclient -L //<ip> -U%`
    
- DNS: `dig @<ip> example.com` or `nmap --script=dns-recursion -p 53 <ip>`
    

# Interpreting nmap `-sV` output

- `product` and `version` fields may be approximate — match against CVE databases once confirmed.
    
- If `nmap` shows `|_` script output, read it — it often gives cert details or banner extensions.
    
- `Service Info:` lines can include `Host:`, `OS:`, `CPE:` — use as leads, not gospel.
    

# UDP fingerprinting tips

- UDP requires retries and patience; many services don’t reply unless you send correct probe.
    
- Use `--script=udp-*` or targeted `--script=snmp-info` etc.
    
- Add `--reason` to see why nmap thinks a port is open/filtered/closed.
    

# Common flags to speed up or stealth scans

- Speed: `-T4 --min-rate=500` (faster but noisier)
    
- Stealth: `-T2`, increase retries/timeouts, `-sS`, `--data-length`, `-f` (fragmentation) — IDS/IPS may detect/ignore
    
- Evade simple IP-based rate limits: `--randomize-hosts` and `--scan-delay 10ms` (but slower)
    

# Output & parsing

- Save everything: `-oA <basename>` (creates `.nmap`, `.xml`, `.gnmap`)
    
- XML is parseable for automation; there are tools to convert to JSON or parse with Python
    
- Use `grep`, `jq` (if convert), or `xsltproc` on Nmap XML
    

# Lab/Exam Checklist (what to do after you see an open port)

1. Banner grab with `nc -nvv -w 3 <ip> <port>` (get immediate info)
    
2. `nmap -sV -p <port> <ip>` for structured version detection
    
3. Run targeted NSE scripts (banner, http-title, ssl-cert, ftp-anon, smtp-commands)
    
4. Manual protocol conversation (`curl`, `openssl s_client`, `smbclient`, `telnet`, `smtp` commands)
    
5. Note any credentials, default pages, exposed directories (use `gobuster`/`ffuf` if web)
    
6. Record evidence: `-oA` and copy banners to your notes
    
7. Only in lab: run deeper vuln scripts / exploit POCs (never on production)
    

# Short examples you can copy-paste (placeholders)

```bash
# 1) Quick banner with nc
nc -nvv -w 3 <target-ip> <port>

# 2) nmap version and banner scripts for a few ports
nmap -sV --script=banner,http-title,ssl-cert -p 22,80,443 <target-ip>

# 3) Full TCP port quick sweep (fast)
nmap -sS -p- -T4 --min-rate=1000 -oA <save-prefix> <target-ip>
```

# Pitfalls & gotchas

- Many services give misleading banners (intentionally or by fronting proxies). Use additional probes.
    
- `sV` might identify a service as `http` when it’s an HTTPS service on a nonstandard port — use `openssl s_client` to check TLS.
    
- Firewalls can drop probes or send RSTs; correlate multiple scans (timing + `-Pn`) before concluding closed.
    
- UDP scans are slow and often unreliable — treat `open|filtered` as ambiguous until manually probed.
    

# Safety / ethics (short)

- Only fingerprint/scan systems you own, have explicit permission to test, or are in a sanctioned lab (HTB/OSCP/TRYHACKME). Unauthorized scanning can be illegal.
    

---

Want me to drop these into a Canvas doc with lab-ready command blocks, or expand to include **service-specific quick probes** (HTTP, SMTP, SMB, MSSQL, MySQL, RDP, etc.) with example probe strings you can paste into `nc`?