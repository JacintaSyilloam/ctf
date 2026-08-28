
## Forensics — Log

Author: **daffainfo**

My website has been hacked. Please help me answer the provided questions using the available logs!

**TL;DR**

- just explore the logs to answer

**FLAG**

`C2C{7H15_15_V3rY_345Y_da62eb54ac37}`

**Exploration**

#1 and #2

looking at the normal traffic vs malicious traffic, we can distinguish the IP addresses

- normal traffic coming from `182.8.97.244`
- aggrsive scans coming from `219.75.27.16`

#3 

login attempts were filtered by looking for post reqs to `wp-login.php` that originates from the attacker ip → there were `7` login attempts

```python
$ grep "219.75.27.16" access.log | grep "POST /wp-login.php"        
219.75.27.16 - - [11/Jan/2026:12:45:37 +0000] "POST /wp-login.php HTTP/1.1" 200 2583 "http://165.22.125.147/wp-login.php?redirect_to=http%3A%2F%2F165.22.125.147%2Fwp-admin%2F&reauth=1" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.56 Safari/537.36"
219.75.27.16 - - [11/Jan/2026:12:50:51 +0000] "POST /wp-login.php HTTP/1.1" 200 2583 "http://165.22.125.147/wp-login.php?redirect_to=http%3A%2F%2F165.22.125.147%2Fwp-admin%2F&reauth=1" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.56 Safari/537.36"
219.75.27.16 - - [11/Jan/2026:12:50:53 +0000] "POST /wp-login.php HTTP/1.1" 200 2583 "http://165.22.125.147/wp-login.php" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.56 Safari/537.36"
219.75.27.16 - - [11/Jan/2026:12:50:57 +0000] "POST /wp-login.php HTTP/1.1" 200 2583 "http://165.22.125.147/wp-login.php" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.56 Safari/537.36"
219.75.27.16 - - [11/Jan/2026:12:51:20 +0000] "POST /wp-login.php HTTP/1.1" 200 2583 "http://165.22.125.147/wp-login.php" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.56 Safari/537.36"
219.75.27.16 - - [11/Jan/2026:12:51:22 +0000] "POST /wp-login.php HTTP/1.1" 200 2583 "http://165.22.125.147/wp-login.php" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.56 Safari/537.36"
219.75.27.16 - - [11/Jan/2026:13:12:49 +0000] "POST /wp-login.php HTTP/1.1" 302 1275 "http://165.22.125.147/wp-login.php?redirect_to=http%3A%2F%2F165.22.125.147%2Fwp-admin%2F&reauth=1" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.56 Safari/537.36"
```

#4, #5, and #6

there were multiple sql injection attempts

by searching for plugin we found the targetted plugin → `easy-quotes`

![image.png](images/image%2017.png)

doing a simple google search led us to the cve → `CVE-2025-26943`

![image.png](images/image%2018.png)

the tool used to automate the sql injection can be found by simply searching for sqlmap → sqlmap/1.10.1.21

![image.png](images/image%2019.png)

#7 

a script was created to analyze the payloads targetting user_email (done by ai agent)

→ `admin@daffainfo.com`

decode.py

```python
import re
import urllib.parse

log_file = "access.log"

extracted_vals = {}

with open(log_file, "r") as f:
    for line in f:
        if "user_email" in line and "layart" in line:
            # Decode URL
            parts = line.split()
            if len(parts) < 7: continue
            url = parts[6]
            decoded = urllib.parse.unquote(url)
            
            # Look for MID(..., POS, 1) != VAL or = VAL
            # Regex for != is !=
            # Regex for = is =
            
            # Pattern for != VAL
            match_neq = re.search(r"MID\(.+?,(\d+),1\)\)!=(?:%21%3D)?(\d+)", decoded)
            if match_neq:
                pos = int(match_neq.group(1))
                val = int(match_neq.group(2))
                extracted_vals[pos] = val
                continue

            # Pattern for = VAL
            match_eq = re.search(r"MID\(.+?,(\d+),1\)\)=(?:%3D)?(\d+)", decoded)
            if match_eq:
                pos = int(match_eq.group(1))
                val = int(match_eq.group(2))
                extracted_vals[pos] = val
                continue
            
            # Additional check: sometimes sqlmap uses `!=` in url encoding which is %21%3D
            # My current regex handles unquoted string, but urllib.parse.unquote handles %21%3D -> !=
            
print("Extracted Values from Verification Checks:")
s = ""
for pos in sorted(extracted_vals.keys()):
    val = extracted_vals[pos]
    print(f"Pos {pos}: {val} ('{chr(val)}')")
    s += chr(val)

print("\nFinal String:")
print(s)
```

output:

```python
$ python3 decode.py 
Extracted Values from Verification Checks:
Pos 1: 97 ('a')
Pos 2: 100 ('d')
Pos 3: 109 ('m')
Pos 4: 105 ('i')
Pos 5: 110 ('n')
Pos 6: 64 ('@')
Pos 7: 100 ('d')
Pos 8: 97 ('a')
Pos 9: 102 ('f')
Pos 10: 102 ('f')
Pos 11: 97 ('a')
Pos 12: 105 ('i')
Pos 13: 110 ('n')
Pos 14: 102 ('f')
Pos 15: 111 ('o')
Pos 16: 46 ('.')
Pos 17: 99 ('c')
Pos 18: 111 ('o')
Pos 19: 109 ('m')

Final String:
admin@daffainfo.com
```

#8

a script was created to analyze the payloads targetting user_pass (done by ai agent)

→ `$2y$10$vMTERqJh2IlhS.NZthNpRu/VWyhLWc0ZmTgbzIUcWxwNwXze44SqW` 

decode_pass.py:

```python

import re
import urllib.parse

log_file = "access.log"

extracted_vals = {}

with open(log_file, "r") as f:
    for line in f:
        if "user_pass" in line and "layart" in line:
            # Decode URL
            parts = line.split()
            if len(parts) < 7: continue
            url = parts[6]
            decoded = urllib.parse.unquote(url)
            
            # Look for MID(..., POS, 1) != VAL or = VAL
            # Regex for != is !=
            # Regex for = is =
            
            # Pattern for != VAL (sqlmap often uses != to verify exact match via inequality check failure)
            # OR pattern for = VAL
            
            # The regex handles the case where url has %21%3D for !=
            # But decoded usually has !=
            
            match_neq = re.search(r"MID\(.+?,(\d+),1\)\)!=(?:%21%3D)?(\d+)", decoded)
            if match_neq:
                pos = int(match_neq.group(1))
                val = int(match_neq.group(2))
                extracted_vals[pos] = val
                continue

            match_eq = re.search(r"MID\(.+?,(\d+),1\)\)=(?:%3D)?(\d+)", decoded)
            if match_eq:
                pos = int(match_eq.group(1))
                val = int(match_eq.group(2))
                extracted_vals[pos] = val
                continue

print("Extracted Values for user_pass:")
s = ""
for pos in sorted(extracted_vals.keys()):
    val = extracted_vals[pos]
    try:
        char = chr(val)
        s += char
    except:
        s += "?"
    print(f"Pos {pos}: {val} ('{char}')")

print("\nFinal String:")
print(s)
```

output:

```python
$ python3 decode_pass.py
Extracted Values for user_pass:
Pos 1: 36 ('$')
Pos 2: 119 ('w')
Pos 3: 112 ('p')
Pos 4: 36 ('$')
Pos 5: 50 ('2')
Pos 6: 121 ('y')
Pos 7: 36 ('$')
Pos 8: 49 ('1')
Pos 9: 48 ('0')
Pos 10: 36 ('$')
Pos 11: 118 ('v')
Pos 12: 77 ('M')
Pos 13: 84 ('T')
Pos 14: 69 ('E')
Pos 15: 82 ('R')
Pos 16: 113 ('q')
Pos 17: 74 ('J')
Pos 18: 104 ('h')
Pos 19: 50 ('2')
Pos 20: 73 ('I')
Pos 21: 108 ('l')
Pos 22: 104 ('h')
Pos 23: 83 ('S')
Pos 24: 46 ('.')
Pos 25: 78 ('N')
Pos 26: 90 ('Z')
Pos 27: 116 ('t')
Pos 28: 104 ('h')
Pos 29: 78 ('N')
Pos 30: 112 ('p')
Pos 31: 82 ('R')
Pos 32: 117 ('u')
Pos 33: 47 ('/')
Pos 34: 86 ('V')
Pos 35: 87 ('W')
Pos 36: 121 ('y')
Pos 37: 104 ('h')
Pos 38: 76 ('L')
Pos 39: 87 ('W')
Pos 40: 99 ('c')
Pos 41: 48 ('0')
Pos 42: 90 ('Z')
Pos 43: 109 ('m')
Pos 44: 84 ('T')
Pos 45: 103 ('g')
Pos 46: 98 ('b')
Pos 47: 122 ('z')
Pos 48: 73 ('I')
Pos 49: 85 ('U')
Pos 50: 99 ('c')
Pos 51: 87 ('W')
Pos 52: 120 ('x')
Pos 53: 119 ('w')
Pos 54: 78 ('N')
Pos 55: 119 ('w')
Pos 56: 88 ('X')
Pos 57: 122 ('z')
Pos 58: 101 ('e')
Pos 59: 52 ('4')
Pos 60: 52 ('4')
Pos 61: 83 ('S')
Pos 62: 113 ('q')
Pos 63: 87 ('W')

Final String:
$wp$2y$10$vMTERqJh2IlhS.NZthNpRu/VWyhLWc0ZmTgbzIUcWxwNwXze44SqW 
```

#9
looked for the `POST /wp-login.php` request from the attacker that resulted in a `302 Found` status code (redirection to dashboard) → `11/01/2026 13:12:49`

```python
219.75.27.16 - - [11/Jan/2026:13:12:49 +0000] "POST /wp-login.php HTTP/1.1" 302 1275 "http://165.22.125.147/wp-login.php?redirect_to=http%3A%2F%2F165.22.125.147%2Fwp-admin%2F&reauth=1" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.56 Safari/537.36"
```

**Exploit script to reproduce**

```python
from pwn import *

r = remote('challenges.1pc.tf', 27723)

print(r.recvuntil(b":").decode())
r.sendline(b"182.8.97.244")

print(r.recvuntil(b":").decode())
r.sendline(b"219.75.27.16")

print(r.recvuntil(b":").decode())
r.sendline(b"6")

print(r.recvuntil(b":").decode())        
r.sendline(b"Easy Quotes")

print(r.recvuntil(b":").decode())        
r.sendline(b"CVE-2025-26943")

print(r.recvuntil(b":").decode())        
r.sendline(b"sqlmap/1.10.1.21")

print(r.recvuntil(b":").decode())        
r.sendline(b"admin@daffainfo.com")

print(r.recvuntil(b":").decode())        
r.sendline(b"$wp$2y$10$vMTERqJh2IlhS.NZthNpRu/VWyhLWc0ZmTgbzIUcWxwNwXze44SqW")

print(r.recvuntil(b":").decode())        
r.sendline(b"11/01/2026 13:12:49")

r.interactive()
```

output:

```python
$ python3 solve.py
[+] Opening connection to challenges.1pc.tf on port 27723: Done     
Please answer the following questions based on your analysis:       

Question #1:

1. What is the Victim's IP address?
Required Format:
 127.0.0.1
Your Answer:
 Status:
 Correct!

Question #2:

2. What is the Attacker's IP address?
Required Format:
 127.0.0.1
Your Answer:
 Status:
[*] Switching to interactive mode
 Correct!

Question #3:
3. How many login attempts were made by the attacker?
Required Format: 1337
Your Answer: Status: Correct!

Question #4:
4. Which plugin was affected (Full Name)?
Required Format: -
Your Answer: Status: Correct!

Question #5:
5. What is the CVE ID?
Required Format: CVE-XXXX-XXXX
Your Answer: Status: Correct!

Question #6:
6. Which tool and version were used to exploit the CVE?
Required Format: tool_name/13.3.7
Your Answer: Status: Correct!

Question #7:
7. What is the email address obtained by the attacker?
Required Format: r00t@localhost.xyz
Your Answer: Status: Correct!

Question #8:
8. What is the password hash obtained by the attacker?
Required Format: -
Your Answer: Status: Correct!

Question #9:
9. When did the attacker successfully log in?
Required Format: DD/MM/YYYY HH:MM:SS
Your Answer: Status: Correct!

========================================
Congratulations!
Flag: C2C{7H15_15_V3rY_345Y_da62eb54ac37}
========================================
[*] Got EOF while reading in interactive
$
```