
## Forensics — Tattletale

Author: **aseng**

Apparently I have just suspected that this `serizawa` binary is a malware .. I was just so convinced that a friend of mine who was super inactive suddenly goes online today and tell me that this binary will help me to boost my Linux performance.

Now that I realized something's wrong.

Note: This is a reverse engineering and forensic combined theme challenge. Don't worry, the malware is not destructive, not like the other challenge. Once you realized what does the malware do, you'll know how the other 2 files are correlated. Enjoy warming up with this easy one!

**TL;DR**

- extract pyc files → decompile into py
- decode keylogger → found password to decrypt
- derypt using openssl → obtain a dump
- reverse the octal dump

**FLAG**

`C2C{it_is_just_4_very_simpl3_linuX_k3ylogger_xixixi_haiyaaaaa_ez}`

**Exploration**

had fun w this chall, the steps r q enjoyable

we were given the following files

```python
┌──(jac㉿kali)-[~/ctf/c2c/tattletale/dist]
└─$ file cron.aseng 
cron.aseng: data

┌──(jac㉿kali)-[~/ctf/c2c/tattletale/dist]
└─$ ls
cron.aseng  serizawa  whatisthis.enc

┌──(jac㉿kali)-[~/ctf/c2c/tattletale/dist]
└─$ file serizawa  
serizawa: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=f5e4eb9bd95f0a14f41d1ef1a6f8ee703c85a059, stripped

┌──(jac㉿kali)-[~/ctf/c2c/tattletale/dist]
└─$ file whatisthis.enc 
whatisthis.enc: openssl enc'd data with salted password
```

i disassemble the serizawa binary using ida 

![image.png](images/image%2015.png)

check main pseudocode

```python
 int __fastcall main(int a1, char **a2, char **a3)

{

  dword_60F300[0] = a1;

  *(_QWORD *)&dword_60F300[2] = a2;

  return sub_404C00(dword_60F300, a2, a3);

} 
```

then I went to check `sub_404C00` , pasted the whole content of it to gemini and it says that its a pyinstaller bootloader, specifically the native wrapper that unpacks and executes a python app bundled into an executable

→ the `cron.aseng` and `whatisthis.enc` files are likely artifacts of the python code running inside this wrapper

so then I decide to just extract the pyc files using `pyinstxtractor.py` 

```python
┌──(jac㉿kali)-[~/…/c2c/tattletale/dist/pyinstxtractor]
└─$ python pyinstxtractor.py ../serizawa
[+] Processing ../serizawa
[+] Pyinstaller version: 2.1+
[+] Python version: 3.11
[+] Length of package: 17011072 bytes
[+] Found 55 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: serizawa.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python 3.11 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: ../serizawa

You can now use a python decompiler on the pyc files within the extracted directory
```

decompiling the pyc file gives us this:

```python
┌──(jac㉿kali)-[~/…/c2c/tattletale/dist/pycdc]
└─$ ./pycdc ~/ctf/c2c/tattletale/dist/serizawa_extracted/serizawa.pyc
# Source Generated with Decompyle++
# File: serizawa.pyc (Python 3.11)

import struct
import sys
import os
streya = '/dev/input/event0'
pvut = '/opt/cron.aseng'
strc = 'QQHHi'
evo = struct.calcsize(strc)

def prm():
    if os.geteuid() != 0:
        sys.exit(1)
    if not os.path.exists(streya):
        sys.exit(1)
        return None

def kst():
Unsupported opcode: BEFORE_WITH (108)
    ec = 0
# WARNING: Decompyle incomplete

def main():
    prm()
    kst()

if __name__ == '__main__':
    main()
    return None
```

from here we know the binary is a keylogger

→ `/dev/input/event0`  is the file path for a linux input device

→ `/opt/cron.aseng` → the keylogger was reading keystrokes and dumping the raw binary events into this file

thus we can create a keylogger decoder script:

```python
┌──(jac㉿kali)-[~/ctf/c2c/tattletale/dist]
└─$ cat decoder.py 
import struct
import sys

# Standard Linux Input Event Codes (partial map for standard keyboard)
# Format: {code: "Key"}
KEY_MAP = {
    1: "ESC", 2: "1", 3: "2", 4: "3", 5: "4", 6: "5", 7: "6", 8: "7", 9: "8", 10: "9", 11: "0",
    12: "-", 13: "=", 14: "BKSP", 15: "TAB", 
    16: "q", 17: "w", 18: "e", 19: "r", 20: "t", 21: "y", 22: "u", 23: "i", 24: "o", 25: "p",
    26: "[", 27: "]", 28: "ENTER", 29: "L_CTRL", 
    30: "a", 31: "s", 32: "d", 33: "f", 34: "g", 35: "h", 36: "j", 37: "k", 38: "l", 39: ";", 40: "'",
    42: "L_SHIFT", 43: "\\", 
    44: "z", 45: "x", 46: "c", 47: "v", 48: "b", 49: "n", 50: "m", 51: ",", 52: ".", 53: "/", 
    54: "R_SHIFT", 56: "L_ALT", 57: "SPACE", 58: "CAPS", 
}

# The struct format from the decompiled code: QQHHi
# Size = 8+8+2+2+4 = 24 bytes
EVENT_FORMAT = 'QQHHi'
EVENT_SIZE = struct.calcsize(EVENT_FORMAT)

def decode_file(filename):
    print(f"[*] Decoding {filename}...")
    
    with open(filename, "rb") as f:
        while True:
            data = f.read(EVENT_SIZE)
            if not data or len(data) < EVENT_SIZE:
                break
            
            # Unpack the binary data
            tv_sec, tv_usec, type_, code, value = struct.unpack(EVENT_FORMAT, data)
            
            # Type 1 is EV_KEY (Keyboard events)
            if type_ == 1:
                # Value 1 is "Key Press" (0 is Release, 2 is Repeat)
                if value == 1:
                    key = KEY_MAP.get(code, f"UNK_{code}")
                    
                    if key == "SPACE":
                        print(" ", end="", flush=True)
                    elif key == "ENTER":
                        print("\n[ENTER]")
                    elif "SHIFT" in key or "CTRL" in key or "ALT" in key:
                        print(f"[{key}]", end="", flush=True)
                    elif key == "BKSP":
                         print("<BACKSPACE>", end="", flush=True)
                    else:
                        print(key, end="", flush=True)

    print("\n\n[*] Done.")

if __name__ == "__main__":
    decode_file("cron.aseng")
```

running the script gave us this output:

```python
┌──(jac㉿kali)-[~/ctf/c2c/tattletale/dist]
└─$ python decoder.py                   
[*] Decoding cron.aseng...
ls
[ENTER]
whoami
[ENTER]
echo [L_SHIFT]'CAPSyCAPSey you finally decrypt me [L_SHIFT];0[L_SHIFT]'
[ENTER]
echo [L_SHIFT]'CAPSjCAPSust a little more steps ok[L_SHIFT]/[L_SHIFT]'
[ENTER]
env [L_SHIFT]. whatisthis
[ENTER]
od whatisthis [L_SHIFT]. whatisthis.baboi
[ENTER]
openssl enc -aes-256-cbc -salt -pass pass[L_SHIFT];letsseethepassword<BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE>hmmm<BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE>thepasswordisjajajaja<BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE><BACKSPACE>4[L_SHIFT]-g00d[L_SHIFT]-fr1en<BACKSPACE><BACKSPACE>3nCAPSdCAPS[L_SHIFT]-in[L_SHIFT]-n33CAPSdCAPS -in whatisthis.baboi -out whatisthis.enc
[ENTER]
echo [L_SHIFT]'CAPSoCAPSk go for it[L_SHIFT]1 CAPStCAPShe flag is in env btw[L_SHIFT]'
[ENTER]
[L_CTRL]c

[*] Done.
```

so he was typing passwords, some fake and a real one → `4_g00d_fr13nD_in_n33D`

the logs show the file whatisthis.enc was created using openssl with -aes-256-cbc, so we can decrypt it like so

```python
┌──(jac㉿kali)-[~/ctf/c2c/tattletale/dist]
└─$ openssl enc -d -aes-256-cbc -md sha256 -in whatisthis.enc -out result.txt -pass pass:4_g00d_fr13nD_in_n33D
*** WARNING : deprecated key derivation used.
Using -iter or -pbkdf2 would be better.
```

this gives us result.txt as so

```python
┌──(jac㉿kali)-[~/ctf/c2c/tattletale/dist]
└─$ cat result.txt             
0000000 047503 047514 052122 051105 036515 071164 062565 067543
0000020 067554 005162 044504 050123 040514 036531 030072 030056
0000040 046012 047101 036507 067145 052537 027123 052125 026506
0000060 005070 040514 043516 040525 042507 005075 040520 044124
```

then i asked gemini to create script to reverse this dump

```python
import sys

def solve():
    print("[*] Reversing octal dump...")
    try:
        with open("result.txt", "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("Error: result.txt not found.")
        return

    recovered_data = bytearray()

    for line in lines:
        parts = line.strip().split()
        if not parts: 
            continue
            
        # Skip the first part (the offset number like 0000000)
        octal_values = parts[1:]
        
        for val_str in octal_values:
            try:
                # Convert Octal string -> Integer
                val = int(val_str, 8)
                
                # Extract Little Endian Bytes
                # 1. Low Byte (The first character)
                low_byte = val & 0xFF
                # 2. High Byte (The second character)
                high_byte = (val >> 8) & 0xFF
                
                # Append them in the correct order
                recovered_data.append(low_byte)
                if high_byte != 0: # Avoid appending null padding at the very end
                    recovered_data.append(high_byte)
            except ValueError:
                continue

    # Write to a file just in case it's binary, but also print to screen
    with open("final_flag.txt", "wb") as f:
        f.write(recovered_data)
        
    print("\n[-] CONTENT RECOVERED BELOW [-]\n")
    # Decode as UTF-8, ignoring errors if there's binary junk
    print(recovered_data.decode('utf-8', errors='ignore'))

if __name__ == "__main__":
    solve()
```

output:

![image.png](images/image%2016.png)

got the flag

**Exploit script to reproduce**

- already all attached above
