## Reverse — bunaken

**TL;DR**

1. notice its a bun runtime via ida
2. catch write syscal → dump core → get obfuscated javascript
3. deobfuscate the javascript → reverse the logic → get secret key
4. reverse the algorithm 

**FLAG**

`C2C{BUN_AwKward_ENcryption_compression_obfuscation}`

**Exploration**

upon unzipping the chall, we got these files:

```python
 (env)─(jac㉿kali)-[~/…/CTF/2025/c2c/bunaken]
└─$ ls
bunaken  flag.txt.bunakencrypted
                                                            
┌──(env)─(jac㉿kali)-[~/…/CTF/2025/c2c/bunaken]
└─$ file bunaken    
bunaken: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=109a021c1b3405d73bd0e95dcad52ec5857f4ed9, not stripped

┌──(env)─(jac㉿kali)-[~/…/CTF/2025/c2c/bunaken]
└─$ file flag.txt.bunakencrypted 
flag.txt.bunakencrypted: ASCII text, with no line terminators 
```

i also was disassembling the binary using ida

![image.png](images/image%2013.png)

looking at pseudocode for `sub_2ACC8F0`, we know the binary is actually a bun runtime

to first solve the chall locally, i added my own flag.txt

flag.txt:

```python
AAAA_BBBB_CCCC_DDDD
```

i then catch the write syscall and generate a core dump using gdb

```python
┌──(jac㉿kali)-[~/…/CTF/2025/c2c/bunaken]
└─$ gdb ./bunaken
GNU gdb (Debian 16.3-5) 16.3
Copyright (C) 2024 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 215 pwndbg commands. Type pwndbg [filter] for a list.
pwndbg: created 13 GDB functions (can be used with print/break). Type help function to see them.
Reading symbols from ./bunaken...
(No debugging symbols found in ./bunaken)
------- tip of the day (disable with set show-tips off) -------
GDB's follow-fork-mode parameter can be used to set whether to trace parent or child after fork() calls. Pwndbg sets it to child by default
pwndbg> catch syscall write
Catchpoint 1 (syscall 'write' [1])
pwndbg> run
Starting program: /home/jac/Documents/cysec/CTF/2025/c2c/bunaken/bunaken 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7fffefbff6c0 (LWP 45286)]
[New Thread 0x7fffef3fe6c0 (LWP 45287)]
[New Thread 0x7fffef37d6c0 (LWP 45288)]
[New Thread 0x7fffef2fc6c0 (LWP 45289)]
[New Thread 0x7fffab1fd6c0 (LWP 45290)]
[New Thread 0x7fffaadfc6c0 (LWP 45291)]
[Switching to Thread 0x7fffab1fd6c0 (LWP 45290)]

Thread 6 "Bun Pool 0" hit Catchpoint 1 (call to syscall write), __syscall_cancel_arch () at ../sysdeps/unix/sysv/linux/x86_64/syscall_cancel.S:56
warning: 56     ../sysdeps/unix/sysv/linux/x86_64/syscall_cancel.S: No such file or directory
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
──────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────
 RAX  0xffffffffffffffda
 RBX  0x7fffab1fd6c0 ◂— 0x7fffab1fd6c0
 RCX  0x7ffff7c9b72e (__syscall_cancel_arch+46) ◂— ret 
 RDX  8
 RDI  6
 RSI  0x7fffab19c5f8 ◂— 1
 R8   0
 R9   0
 R10  0
 R11  0x246
 R12  0x7fffab1ac740 ◂— 0
 R13  0x7fffab19c620 ◂— 'AAAA_BBBB_CCCC_DDDD\n'
 R14  0x2e53c0200b4 ◂— 0
 R15  0x2e53a8d0110 —▸ 0x2e53c0200a0 ◂— 'AAAA_BBBB_CCCC_DDDD\n'
 RBP  0x7fffab19c600 —▸ 0x7fffab1ac7b0 —▸ 0x7fffab1ac900 —▸ 0x7fffab1ada10 —▸ 0x7fffab1ae350 ◂— ...
 RSP  0x7fffab19c588 —▸ 0x7ffff7c902b8 (__internal_syscall_cancel+72) ◂— mov edx, dword ptr [rbx + 0x308]
 RIP  0x7ffff7c9b72e (__syscall_cancel_arch+46) ◂— ret 
───────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────────
 ► 0x7ffff7c9b72e <__syscall_cancel_arch+46>        ret                                <__internal_syscall_cancel+72>
    ↓
   0x7ffff7c902b8 <__internal_syscall_cancel+72>    mov    edx, dword ptr [rbx + 0x308]     EDX, [0x7fffab1fd9c8] => 0
   0x7ffff7c902be <__internal_syscall_cancel+78>    pop    rcx                              RCX => 0x7fffab1fd9c8
   0x7ffff7c902bf <__internal_syscall_cancel+79>    pop    rsi                              RSI => 0
   0x7ffff7c902c0 <__internal_syscall_cancel+80>    cmp    rax, -4                          0xffffffffffffffda - -0x4     EFLAGS => 0x297 [ CF PF AF zf SF IF df of ac ]
   0x7ffff7c902c4 <__internal_syscall_cancel+84>  ✘ je     __internal_syscall_cancel+112 <__internal_syscall_cancel+112>
 
   0x7ffff7c902c6 <__internal_syscall_cancel+86>    pop    rbx         RBX => 0x2e53a8d0000
   0x7ffff7c902c7 <__internal_syscall_cancel+87>    ret                                <__syscall_cancel+13>
    ↓
   0x7ffff7c902fd <__syscall_cancel+13>             pop    rdx              RDX => 1
   0x7ffff7c902fe <__syscall_cancel+14>             pop    rcx              RCX => 0
   0x7ffff7c902ff <__syscall_cancel+15>             cmp    rax, -0x1000     0xffffffffffffffda - -0x1000     EFLAGS => 0x202 [ cf pf af zf sf IF df of ac ]
─────────────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffab19c588 —▸ 0x7ffff7c902b8 (__internal_syscall_cancel+72) ◂— mov edx, dword ptr [rbx + 0x308]
01:0008│-070 0x7fffab19c590 —▸ 0x7fffab1fd9c8 ◂— 0x8000000000
02:0010│-068 0x7fffab19c598 ◂— 0
03:0018│-060 0x7fffab19c5a0 —▸ 0x2e53a8d0000 —▸ 0x7fffee0ccc00 ◂— 0x800000004
04:0020│-058 0x7fffab19c5a8 —▸ 0x7ffff7c902fd (__syscall_cancel+13) ◂— pop rdx /* 'ZYH=' */
05:0028│-050 0x7fffab19c5b0 ◂— 1
06:0030│-048 0x7fffab19c5b8 ◂— 0
07:0038│-040 0x7fffab19c5c0 ◂— 0
───────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────────────────
 ► 0   0x7ffff7c9b72e __syscall_cancel_arch+46
   1   0x7ffff7c902b8 __internal_syscall_cancel+72
   2   0x7ffff7c902fd __syscall_cancel+13
   3   0x7ffff7d05036 write+22
   4        0x40ba31a None
   5    0x2e53a8d0110 None
   6              0x1 None
   7   0x7fffab1ac7b0 None
───────────────────────────────────────────────────────────────────────────────[ THREADS (7 TOTAL) ]───────────────────────────────────────────────────────────────────────────────
  ► 6   "Bun Pool 0" stopped: 0x7ffff7c9b72e <__syscall_cancel_arch+46> 
    1   "bunaken"    stopped: 0x3a9994a
    2   "bunaken"    stopped: 0x7ffff7c9b72e <__syscall_cancel_arch+46> 
    4   "JITWorker"  stopped: 0x7ffff7c9b72e <__syscall_cancel_arch+46> 
Not showing 3 thread(s). Use set context-max-threads <number of threads> to change this.
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> generate-core-file bunaken.dump
Saved corefile bunaken.dump
pwndbg> quit
```

when i look for flag.txt, this is what i got:

```python
┌──(jac㉿kali)-[~/…/CTF/2025/c2c/bunaken]
└─$ strings bunaken.dump | grep -C 5 "flag.txt"
P               :
`               :
p               :
/$bunfs/root/bunaken
// @bun
function w(){let n=["WR0tF8oezmkl","toString","W603xSol","1tlHJnY","1209923ghGtmw","text","13820KCwBPf","byteOffset","40xRjnfn","Cfa9","bNaXh8oEW6OiW5FcIq","alues","lXNdTmoAgqS0pG","D18RtemLWQhcLConW5a","nCknW4vfbtX+","WOZcIKj+WONdMq","FCk1cCk2W7FcM8kdW4y","a8oNWOjkW551fSk2sZVcNa","yqlcTSo9xXNcIY9vW7dcS8ky","from","iSoTxCoMW6/dMSkXW7PSW4xdHaC","c0ZcS2NdK37cM8o+mW","377886jVoqYx","417805ESwrVS","7197AxJyfv","cu7cTX/cMGtdJSowmSk4W5NdVCkl","W7uTCqXDf0ddI8kEFW","write","encrypt","ted","xHxdQ0m","byteLength","6CCilXQ","304OpHfOi","set","263564pSWjjv","subtle","945765JHdYMe","SHA-256","Bu7dQfxcU3K","getRandomV"];return w=function(){return n},w()}function l(n,r){return n=n-367,w()[n]}var y=l,s=c;function c(n,r){n=n-367;let t=w(),x=t[n];if(c.uRqEit===void 0){var b=function(i){let f="",a="";for(let d=0,o,e,p=0;e=i.charAt(p++);~e&&(o=d%4?o*64+e:e,d++%4)?f+=String.fromCharCode(255&o>>(-2*d&6)):0)e="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=".indexOf(e);for(let d=0,o=f.length;d<o;d++)a+="%"+("00"+f.charCodeAt(d).toString(16)).slice(-2);return decodeURIComponent(a)};let U=function(i,B){let f=[],a=0,d,o="";i=b(i);let e;for(e=0;e<256;e++)f[e]=e;for(e=0;e<256;e++)a=(a+f[e]+B.charCodeAt(e%B.length))%256,d=f[e],f[e]=f[a],f[a]=d;e=0,a=0;for(let p=0;p<i.length;p++)e=(e+1)%256,a=(a+f[e])%256,d=f[e],f[e]=f[a],f[a]=d,o+=String.fromCharCode(i.charCodeAt(p)^f[(f[e]+f[a])%256]);return o};c.yUvSwA=U,c.MmZTqk={},c.uRqEit=!0}let u=t[0],I=n+u,A=c.MmZTqk[I];return!A?(c.ftPoNg===void 0&&(c.ftPoNg=!0),x=c.yUvSwA(x,r),c.MmZTqk[I]=x):x=A,x}(function(n,r){let t=c,x=l,b=n();while(!0)try{if(parseInt(x(405))/1*(parseInt(x(383))/2)+-parseInt(x(385))/3*(parseInt(t(382,"9Dnx"))/4)+parseInt(x(384))/5*(-parseInt(x(393))/6)+parseInt(x(396))/7*(parseInt(x(369))/8)+parseInt(t(381,"R69F"))/9+-parseInt(x(367))/10+-parseInt(x(406))/11===r)break;else b.push(b.shift())}catch(u){b.push(b.shift())}})(w,105028);var h=async(n)=>{let r=l,t=c,x=n instanceof ArrayBuffer?new Uint8Array(n):new Uint8Array(n[t(400,"I2yl")],n[r(368)],n.byteLength);if(x.byteLength===16||x.byteLength===24||x.byteLength===32)return x;let b=await crypto.subtle[t(402,"Fw]1")](r(399),x);return new Uint8Array(b).subarray(0,16)},g=(n,r)=>{let t=l,x=new Uint8Array(n.byteLength+r.byteLength);return x.set(n,0),x[t(395)](r,n[t(392)]),x},m=async(n,r)=>{let t=c,x=l,b=crypto[x(401)+x(372)](new Uint8Array(16)),u=await h(n),I=await crypto[x(397)][t(371,"kAmA")](t(370,"CYgn"),u,{name:"AES-CBC"},!1,[x(389)]),A=await crypto.subtle[x(389)]({name:t(375,"dHTh"),iv:b},I,r);return g(b,new Uint8Array(A))},S=Bun[s(391,"9Dnx")](s(377,"R69F")),k=await S[y(407)](),v=await Bun[s(387,"f]pG")+"ss"](k),z=await m(Buffer[y(380)](s(373,"rG]G")),v);Bun[y(388)]("flag.txt.b"+s(374,"CYgn")+y(390),Buffer[s(404,"(Y*]")](z)[y(403)](s(376,"$lpa")));
//# debugId=89BBB7E67C06C2CD64756E2164756E21
```

its a large chunk of javascript, i asked gemini to deobfuscate and look for the hidden key

this is the script generated

get_key.js:

```python
// The array from your dump
var n = ["WR0tF8oezmkl","toString","W603xSol","1tlHJnY","1209923ghGtmw","text","13820KCwBPf","byteOffset","40xRjnfn","Cfa9","bNaXh8oEW6OiW5FcIq","alues","lXNdTmoAgqS0pG","D18RtemLWQhcLConW5a","nCknW4vfbtX+","WOZcIKj+WONdMq","FCk1cCk2W7FcM8kdW4y","a8oNWOjkW551fSk2sZVcNa","yqlcTSo9xXNcIY9vW7dcS8ky","from","iSoTxCoMW6/dMSkXW7PSW4xdHaC","c0ZcS2NdK37cM8o+mW","377886jVoqYx","417805ESwrVS","7197AxJyfv","cu7cTX/cMGtdJSowmSk4W5NdVCkl","W7uTCqXDf0ddI8kEFW","write","encrypt","ted","xHxdQ0m","byteLength","6CCilXQ","304OpHfOi","set","263564pSWjjv","subtle","945765JHdYMe","SHA-256","Bu7dQfxcU3K","getRandomV"];

// The shuffle function
(function(n,r){let t=c,x=l,b=n();while(!0)try{if(parseInt(x(405))/1*(parseInt(x(383))/2)+-parseInt(x(385))/3*(parseInt(t(382,"9Dnx"))/4)+parseInt(x(384))/5*(-parseInt(x(393))/6)+parseInt(x(396))/7*(parseInt(x(369))/8)+parseInt(t(381,"R69F"))/9+-parseInt(x(367))/10+-parseInt(x(406))/11===r)break;else b.push(b.shift())}catch(u){b.push(b.shift())}})(w,105028);

// The helper functions
function w(){return n}
function l(n,r){return n=n-367,w()[n]}
var y=l,s=c;
function c(n,r){n=n-367;let t=w(),x=t[n];if(c.uRqEit===void 0){var b=function(i){let f="",a="";for(let d=0,o,e,p=0;e=i.charAt(p++);~e&&(o=d%4?o*64+e:e,d++%4)?f+=String.fromCharCode(255&o>>(-2*d&6)):0)e="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=".indexOf(e);for(let d=0,o=f.length;d<o;d++)a+="%"+("00"+f.charCodeAt(d).toString(16)).slice(-2);return decodeURIComponent(a)};let U=function(i,B){let f=[],a=0,d,o="";i=b(i);let e;for(e=0;e<256;e++)f[e]=e;for(e=0;e<256;e++)a=(a+f[e]+B.charCodeAt(e%B.length))%256,d=f[e],f[e]=f[a],f[a]=d;e=0,a=0;for(let p=0;p<i.length;p++)e=(e+1)%256,a=(a+f[e])%256,d=f[e],f[e]=f[a],f[a]=d,o+=String.fromCharCode(i.charCodeAt(p)^f[(f[e]+f[a])%256]);return o};c.yUvSwA=U,c.MmZTqk={},c.uRqEit=!0}let u=t[0],I=n+u,A=c.MmZTqk[I];return!A?(c.ftPoNg===void 0&&(c.ftPoNg=!0),x=c.yUvSwA(x,r),c.MmZTqk[I]=x):x=A,x}

// Reveal the secrets!
console.log("HIDDEN KEY STRING (373):", s(373,"rG]G"));
console.log("FUNCTION PREFIX (387):", s(387,"f]pG"));
```

running the script:

```python
┌──(jac㉿kali)-[~/…/CTF/2025/c2c/bunaken]
└─$ node getkey.js 
HIDDEN KEY STRING (373): sulawesi
FUNCTION PREFIX (387): zstdCompre
```

ultimately we can reverse the algorithm which follows these steps:

1. read flag.txt
2. compress the text using Zstandard
3. generate a random 16-byte IV.
4. derive the AES key: SHA-256("sulawesi").slice(0, 16).
5. encrypt: AES-128-CBC(Key, IV, Compressed_Data).
6. output: Base64(IV + Ciphertext).

here’s the reverse final script:

```python
import base64
import hashlib
import zstandard as zstd
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 1. Configuration from your findings
SECRET_STRING = "sulawesi"
ENCRYPTED_B64 = "3o2Gh52pjRk80IPViTp8KUly+kDGXo7qAlPo2Ff1+IOWW1ziNAoboyBZPX6R4JvNXZ4iWwc662Nv/rMPLdwrIb3D4tTbOg/vi0NKaPfToj0="

def solve():
    print(f"[*] Secret: {SECRET_STRING}")
    
    # 2. Derive the AES Key
    # JS: new Uint8Array(SHA-256(secret)).subarray(0,16)
    hasher = hashlib.sha256()
    hasher.update(SECRET_STRING.encode())
    key = hasher.digest()[:16]
    print(f"[*] Derived AES Key: {key.hex()}")

    # 3. Decode Base64
    blob = base64.b64decode(ENCRYPTED_B64)
    
    # 4. Extract IV and Ciphertext
    # JS: [IV (16 bytes)] + [Ciphertext]
    iv = blob[:16]
    ciphertext = blob[16:]
    print(f"[*] IV: {iv.hex()}")

    # 5. Decrypt (AES-CBC)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted_compressed = cipher.decrypt(ciphertext)
        # Note: Depending on how Bun implements it, there might be PKCS7 padding 
        # or it might just end. We'll try to unpad, but if it fails, we'll try raw.
        try:
            decrypted_compressed = unpad(decrypted_compressed, AES.block_size)
        except:
            pass # padding might not be standard, zstd ignores trailing bytes anyway

        print("[*] Decryption successful. Detecting Zstd header...")
        
        # 6. Decompress (Zstd)
        # Zstd magic bytes are usually 28 B5 2F FD
        if decrypted_compressed.startswith(b'\x28\xb5\x2f\xfd'):
            print("[*] Zstd Magic Bytes found!")
            
        dctx = zstd.ZstdDecompressor()
        flag = dctx.decompress(decrypted_compressed)
        
        print(f"\n[+] FLAG: {flag.decode().strip()}")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        # Debug: Save to file to check manually if script fails
        with open("debug.zst", "wb") as f:
            f.write(decrypted_compressed)
        print("[*] Saved decrypted data to 'debug.zst'. Try 'zstd -d debug.zst' if script failed.")

if __name__ == "__main__":
    solve()
```

output:

```python
┌──(jac㉿kali)-[~/…/CTF/2025/c2c/bunaken]
└─$ python solver.py
[*] Secret: sulawesi
[*] Derived AES Key: 7049c447b8379cacc611361b43b0d2c7
[*] IV: de8d86879da98d193cd083d5893a7c29
[*] Decryption successful. Detecting Zstd header...
[*] Zstd Magic Bytes found!

[+] FLAG: C2C{BUN_AwKward_ENcryption_compression_obfuscation}
```

**Exploit script to reproduce**

```python
import base64
import hashlib
import zstandard as zstd
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 1. Configuration from your findings
SECRET_STRING = "sulawesi"
ENCRYPTED_B64 = "3o2Gh52pjRk80IPViTp8KUly+kDGXo7qAlPo2Ff1+IOWW1ziNAoboyBZPX6R4JvNXZ4iWwc662Nv/rMPLdwrIb3D4tTbOg/vi0NKaPfToj0="

def solve():
    print(f"[*] Secret: {SECRET_STRING}")
    
    # 2. Derive the AES Key
    # JS: new Uint8Array(SHA-256(secret)).subarray(0,16)
    hasher = hashlib.sha256()
    hasher.update(SECRET_STRING.encode())
    key = hasher.digest()[:16]
    print(f"[*] Derived AES Key: {key.hex()}")

    # 3. Decode Base64
    blob = base64.b64decode(ENCRYPTED_B64)
    
    # 4. Extract IV and Ciphertext
    # JS: [IV (16 bytes)] + [Ciphertext]
    iv = blob[:16]
    ciphertext = blob[16:]
    print(f"[*] IV: {iv.hex()}")

    # 5. Decrypt (AES-CBC)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted_compressed = cipher.decrypt(ciphertext)
        # Note: Depending on how Bun implements it, there might be PKCS7 padding 
        # or it might just end. We'll try to unpad, but if it fails, we'll try raw.
        try:
            decrypted_compressed = unpad(decrypted_compressed, AES.block_size)
        except:
            pass # padding might not be standard, zstd ignores trailing bytes anyway

        print("[*] Decryption successful. Detecting Zstd header...")
        
        # 6. Decompress (Zstd)
        # Zstd magic bytes are usually 28 B5 2F FD
        if decrypted_compressed.startswith(b'\x28\xb5\x2f\xfd'):
            print("[*] Zstd Magic Bytes found!")
            
        dctx = zstd.ZstdDecompressor()
        flag = dctx.decompress(decrypted_compressed)
        
        print(f"\n[+] FLAG: {flag.decode().strip()}")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        # Debug: Save to file to check manually if script fails
        with open("debug.zst", "wb") as f:
            f.write(decrypted_compressed)
        print("[*] Saved decrypted data to 'debug.zst'. Try 'zstd -d debug.zst' if script failed.")

if __name__ == "__main__":
    solve()
```