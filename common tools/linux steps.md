## Decision tree / flow (memorize this sequence for labs)

1. **Are you root?**
    
    - Yes → collect evidence, creds, and pivot (credentials, keys, local DB files).
        
    - No → continue.
        
2. **Check sudo rights** (can you run anything as root without password?)
    
    - If yes → exploit sudo misconfig to get root.
        
3. **SUID & capabilities**
    
    - Find SUID binaries and files with capabilities. If any match known exploitable patterns, attempt privesc.
        
4. **Writable system files / cron / systemd**
    
    - Check crontab entries owned by root pointing to writable locations, or systemd unit files you can modify; exploit on next service/restart.
        
5. **Credentials**
    
    - Search home dirs, webroot, config files for credentials or keys. If found, use them to SSH/SMB to other hosts.
        
6. **Docker / container escape**
    
    - If Docker socket (`/var/run/docker.sock`) present, use it to spawn a privileged container or access host files.
        
7. **Debug / logs / memory**
    
    - If permitted by lab, inspect processes, logs, and memory for secrets (e.g., process args, environment variables).
        
8. **If all else fails**
    
    - Re-run enumeration with different tooling/paths; check mounted file systems, leftover archives, backups, or world-writable directories; revisit web app for forgotten uploads.
        

---

## Common red-flags / what they indicate

- `sudo` without password for specific binaries → immediate escalation vector.
    
- SUID `nmap`/`vim`/`less`/`find`/`bash` etc. → potential SUID abuse.
    
- `/var/run/docker.sock` present → potential host takeover.
    
- Private SSH keys in home directories → lateral movement.
    
- Writable `/etc/cron.d/*` or `/etc/systemd/system/*.service` → persistence/escalation.
    
- `cap_sys_admin` on a binary → powerful capability-based abuse.
    
- `SSHD` configured to accept publickey and you have a key → direct SSH pivot.