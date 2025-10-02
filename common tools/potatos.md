# SweetPotato quick cheat sheet (exam ready)

## Short summary — what SweetPotato is

- SweetPotato (Juicy/Rotten family) is a local Windows **privilege escalation** helper that abuses COM/DCOM + token impersonation to get **NT AUTHORITY\SYSTEM** from a lower-privileged context.
    
- It needs to _run on the target host_ (local execution) and the environment must allow token interception/impersonation (not patched/mitigated).
    

---

## When to run it (prereqs)

Run SweetPotato **only when**:

1. You have **local code execution** on the Windows target (an interactive shell or command execution).
    
2. The user/context you’re in has **SeImpersonatePrivilege** (or equivalent rights). Often this is a **service account** or other privileged system account.
    
3. The target OS and DCOM services are susceptible (many modern systems are patched — check OS version).
    
4. AV/EDR is not blocking the tool or COM abuse.
    

If any of the above is missing, SweetPotato will likely fail with the message you posted.

# PrintSpoofer — exam notes

- **Different vector:** abuses RPC endpoints in Print Spooler to get SYSTEM impersonation. Can work when COM targets are patched.
    
- **When to use:** Print Spooler service is present and reachable; Juicy/Sweet fail.
    
- **Prereqs & notes:** still often needs SeImpersonatePrivilege; architecture matters; newer Windows may block certain spooler calls—try it in labs.
    
- **Risk:** printing interfaces are noisy and may trigger logging.