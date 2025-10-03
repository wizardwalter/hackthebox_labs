Perfect — here’s a compact, **lab-only** cheat sheet with copy-pasteable commands and quick “what to look for” notes. Replace the placeholders and go.

# Fingerprint first (stack + versions)

```bash
# Fast tech fingerprint (prints CMS hints, server, frameworks)
whatweb -a 3 <URL-or-BASE>            # e.g., http://<target-ip>[:<port>]
whatweb -a 3 -v <URL>                 # verbose to see matches

# TLS / SANs (subdomains, internal names)
sslscan <host>:<port>                 # e.g., sslscan <target-host>:443
openssl s_client -connect <host>:443 -servername <vhost> -showcerts </dev/null
```

Look for: `WordPress/Drupal/Joomla` tags, version leaks, JS libs, SANs with other targets.

---

# WordPress — WPScan

```bash
# Full recon (no creds)
wpscan --url <URL> --enumerate u,ap,at,tt,cb,dbe --plugins-detection aggressive --random-user-agent --disable-tls-checks -o wpscan_<host>.txt

# With login brute (only if allowed in scope)
wpscan --url <URL> --password-attack wp-login --usernames <users.txt> --passwords <pw.txt> --random-user-agent -o wpscan_login_<host>.txt

# Using an API token for vuln DB enrichment (optional)
export WPSCAN_API_TOKEN=<token>
wpscan --url <URL> --api-token $WPSCAN_API_TOKEN --enumerate vp,vt
```

Watch for: `Users found`, `Interesting Finding`, `Vulnerable plugins/themes (CVE…)`, `XML-RPC enabled`, `Backup/config files`.

---

# Drupal — Droopescan

```bash
# Core and modules/themes recon
droopescan scan drupal -u <URL> -t 20 -o droopescan_<host>.json

# If site uses non-standard paths
droopescan scan drupal -u <URL> --wordlist /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt -o droopescan_wl_<host>.json
```

Watch for: `Installed modules`, `Version guesses`, `Vulnerable modules` (map to CVEs), exposed `/CHANGELOG.txt`, `/core/` leaks.

---

# Joomla — JoomScan

```bash
# Recon + report
joomscan -u <URL> -ec -ot joomscan_<host>.txt
```

Watch for: `Joomla version`, `Components/Extensions`, default admin paths (`/administrator/`), known CVEs flagged.

---

# Generic web vulns & misconfig — Nikto (quick pass)

```bash
nikto -h <URL> -timeout 5 -Tuning x  -o nikto_<host>.txt
# Tip: add -port <n> for nonstandard ports, or use -ssl for https if needed
```

Watch for: `Default files`, `phpinfo`, `backup/~ files`, outdated server banners.

---

# Content discovery — Gobuster & FFUF

```bash
# Directories (Gobuster)
gobuster dir -u <URL> -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt -t 50 -x php,txt,zip,bak,old,tar.gz -o gobuster_dir_<host>.txt

# Virtual hosts (if you suspect vhosts and have a domain)
gobuster vhost -u http://<base-domain> -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o gobuster_vhost_<host>.txt

# Files/dirs (FFUF) — great for filtering by size/words
ffuf -u <URL>/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt -mc 200,204,301,302,307,401,403 -of json -o ffuf_<host>.json
```

Watch for: admin panels, backups (`.zip`, `.bak`, `.old`), env files (`.env`), installers, API docs.

---

# Multi-CMS scanner — CMSMap (broad sweep)

```bash
# Auto-detect and scan (be conservative on threads in lab)
cmsmap <URL> -o cmsmap_<host>.txt
```

Watch for: detected CMS, plugin/extension lists, flagged CVEs (confirm manually).

---

# Nmap scripts (CMS-aware flavor)

```bash
# Web-centric NSE bundle on common web ports
nmap -p 80,443,8080,8443 -sV --version-all --script=banner,http-title,http-headers,http-server-header,ssl-cert,ssl-enum-ciphers <host> -oA nmap_web_<host>

# If WordPress suspected
nmap --script http-wordpress-enum,http-wordpress-users -p <port> <host> -oA nmap_wp_<host>

# If Joomla/Drupal suspected (lightweight probes)
nmap --script http-joomla*,http-drupal-enum* -p <port> <host> -oA nmap_cms_<host>
```

Watch for: titles, headers, cert SANs, and any NSE notes pointing to CMS paths.

---

# Quick “manual” web checks

```bash
# Identify quickly
curl -I <URL>                           # headers
curl -sL <URL> | head -n 50             # look for meta generator tags
curl -sL <URL>/robots.txt               # disallowed paths = leads
curl -sL <URL>/.git/HEAD                # accidental git exposure
```

Watch for: `X-Powered-By`, `Server`, `Generator`, robots-disallowed admin paths.

---

# Practical OSCP workflow (fast path)

1. **Fingerprint**: `whatweb` → is it WP/Drupal/Joomla? Note versions if leaked.
    
2. **CMS-specific scan**: WP ⇒ `wpscan`; Drupal ⇒ `droopescan`; Joomla ⇒ `joomscan`. Save outputs.
    
3. **Content discovery**: `gobuster/ffuf` for hidden admin/dev/backup endpoints.
    
4. **TLS/certs**: `sslscan`/`openssl s_client` for SANs (extra hosts) and service intel.
    
5. **Validate**: cross-check scanner claims manually in the browser/with `curl`.
    
6. **Prioritize**: outdated plugins/modules/extensions with known CVEs; exposed backups; default creds pages.
    
7. **Document**: keep `-o/ -oA` outputs. Screenshot key findings.
    

---

# Output triage — what “good” looks like

- **WPScan**: `Found X users: admin, editor…` / `Vulnerability found: Plugin <name> <version> (CVE-YYYY-XXXX)`.
    
- **Droopescan**: `Modules found:` + versions; `possible vulnerabilities` section.
    
- **JoomScan**: `Components:` list + version; warnings with CVE refs.
    
- **Gobuster/FFUF**: 200/301/401/403 on juicy paths (`/wp-admin/`, `/backup.zip`, `/administrator/`, `/sites/default/…`, `/vendor/`, `/phpmyadmin/`).
    
- **Nikto**: `OSVDB/CVE` style items, default files, dangerous options.
    

---

## Handy placeholders to keep ready

- `<URL>` = full scheme + host (e.g., `http://<target-ip>:<port>` or `https://<vhost>`).
    
- `<host>` = hostname or IP (used in filenames).
    
- Wordlists: `/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt`
    
- Users/password lists (for _allowed_ brute): `users.txt`, `pw.txt`
    

---

If you want, I can drop this into a Canvas doc for you with tidy headings and space to paste your outputs underneath each tool section.