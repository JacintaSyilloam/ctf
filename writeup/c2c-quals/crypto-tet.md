
## Crypto — tet

Author: **azuketto**

apparently it's called tet in Vietnam?

**FLAG**

`C2C{edce9fb96aa0}`

**Exploration**

we connect to the service and get 12 rounds of data. each round gives us variables like `n`, `a_b` (which is $a \cdot b^{-1} \pmod n$), `f`, `z`, `g`, and `u2`. looking at the structure 

→  it involves a global secret $m_1$ used across all rounds, and per-round rsa-like parameters

#1: recovering the global secret m1

we observe that $f_i$ values across rounds are related to $m_1$
specifically, $f_i = e_i \cdot m_1 + c_i$ where $c_i$ is "small" noise 
(approx 6000 bits), this is an approximate gcd problem

→ we assume $f_i \approx q_i \cdot m_1$ and build a lattice
→ we construct a matrix with row 0 as `[k, f1, ..., fn]` and other rows blocking the values with `-f0`
→ running lll reduction → we recover the coefficients $q_i$.

once we have the coefficients →  estimate $m_1 \approx f_0 // q_0$.
however, there is an error term $c_0$. we use interval intersection on all rounds to find the exact offset "alpha"
applying the offset → we recover the exact global secret $m_1$.

#2: breaking each round

with $m_1$ recovered, we can decompose $f_i$ for each round to get $e_i$ and $c_i$ ($f_i = e_i \cdot m_1 + c_i$)

analyzing the relationship → $e_i$ helps us recover the private exponent $d$ using wiener's attack.

we perform continued fraction expansion on $e_i / n^3$ → one of the convergents gives us $k/d$.

using the candidate $d$ and $k$ → we compute $\phi' = (e \cdot d - 1) / k$

simultaneously, we recover $a$ and $b$ from the ratio $a/b \pmod n$ using a 2d lattice.

recovering $a, b$ and $\phi'$ → allows us to set up a quadratic equation where the unknown is $p^3$.

solving the quadratic → we find $p$, then $q$, then the private key

#3: decrypting the flag

using the recovered private key for each round → we decrypt the challenge ciphertext `u2` to get `s`.
we submit `s` for all 12 rounds.

running the script `solve.sage` 

1. collects data frames from remote

2. uses lll to find $m_1$

3. solves 12/12 rounds using wiener's + quadratic root finding

4. server responds with flag

**Exploit script to reproduce**

solve.sage:

```python
from pwn import *
from sage.all import *
import sys

# Parameters
R_count = 12

def solve():
    # Connection
    host = 'challenges.1pc.tf'
    port = 20838
    print(f"Connecting to {host}:{port}")
    
    try:
        io = remote(host, port)
    except Exception as e:
        print(f"Could not connect: {e}")
        return

    data = []
    print("Collecting data...")
    
    # Receive until we get rounds
    try:
        # Sometimes there's a banner or proof of work?
        # Just loop until we see Round 1
        io.recvuntil(b"=== Round 1/12 ===")
        io.recvline() # Consume newline
        
        # Parse Round 1
        d = {}
        # N
        line = io.recvline().decode().strip()
        if not line.startswith("N = "): 
            print("Unexpected line:", line)
        d['N'] = int(line.split(' = ')[1], 16)
        
        # a/b
        line = io.recvline().decode().strip()
        d['a_b'] = int(line.split(' = ')[1], 16)
        
        # f
        line = io.recvline().decode().strip()
        d['f'] = int(line.split(' = ')[1], 16)
        
        # z
        line = io.recvline().decode().strip()
        d['z'] = int(line.split(' = ')[1], 16)
        
        # g
        line = io.recvline().decode().strip()
        d['g'] = int(line.split(' = ')[1], 16)
        
        # U2
        line = io.recvline().decode().strip()
        d['U2'] = int(line.split(' = ')[1], 16)
        
        data.append(d)
        print(f" collected round 1")
        
        # Parse remaining rounds
        for i in range(2, R_count + 1):
            io.recvuntil(f"=== Round {i}/{R_count} ===".encode())
            io.recvline() # Consume newline
            d = {}
            d['N'] = int(io.recvline().decode().strip().split(' = ')[1], 16)
            d['a_b'] = int(io.recvline().decode().strip().split(' = ')[1], 16)
            d['f'] = int(io.recvline().decode().strip().split(' = ')[1], 16)
            d['z'] = int(io.recvline().decode().strip().split(' = ')[1], 16)
            d['g'] = int(io.recvline().decode().strip().split(' = ')[1], 16)
            d['U2'] = int(io.recvline().decode().strip().split(' = ')[1], 16)
            data.append(d)
            print(f" collected round {i}")
            
    except Exception as e:
        print(f"Error collecting data: {e}")
        io.close()
        return

    if not data:
        print("No data collected.")
        return

    fs = [d['f'] for d in data]
    
    # --- Step 1: Recover M1 ---
    # Algorithm:
    # 1. Lattice to find q0 and relations (q0*ci - qi*c0)
    # 2. Recover X = q0*M1 + c0
    # 3. Intersect intervals for alpha (high bits of c0)
    # 4. M1 = X//q0 + alpha
    
    print("Building Lattice for M1...")
    dim = len(fs) 
    M = Matrix(ZZ, dim, dim)
    K = 2**6000 # Matches noise size
    
    # Basis:
    # [ K, f1, f2, ..., f_{n-1} ]
    # [ 0, -f0, 0, ..., 0 ]
    # [ 0, 0, -f0, ..., 0 ]
    
    # Row 0
    M[0, 0] = K
    for i in range(1, dim):
        M[0, i] = fs[i]
        
    # Other rows
    for i in range(1, dim):
        M[i, i] = -fs[0]
        
    print("Running LLL...")
    B = M.LLL()
    
    # Analyze vector
    vec = list(B[0])
    # Ensure positive q0
    if vec[0] < 0:
        vec = [-x for x in vec]
        
    q0 = vec[0] // K
    if q0 == 0:
        # Try second vector?
        print("Warning: q0 was 0 in first vector. Trying second.")
        vec = list(B[1])
        if vec[0] < 0: vec = [-x for x in vec]
        q0 = vec[0] // K
    
    print(f"Recovered q0: {q0}")
    if q0 == 0:
        print("Failed to find q0.")
        io.close()
        return
    
    qs = [q0]
    for i in range(1, dim):
        vi = vec[i]
        qi = (q0 * fs[i] - vi) // fs[0]
        qs.append(qi)

    
    M1_base = fs[0] // q0
    low = -10**100
    high = 10**100
    
    
    bound = 2**6000 + 2**5900 
    
    print(f"M1_base: {M1_base}")
    
    for i in range(dim):
        Di = fs[i] - qs[i] * M1_base
        qi = qs[i]
        
        # Di + qi * alpha > 0  =>  alpha > -Di / qi
        min_alpha = ceil((-Di) / qi)
        
        # Di + qi * alpha < bound => alpha < (bound - Di) / qi
        max_alpha = floor((bound - Di) / qi)
        
        print(f"Round {i}: Di={Di}, qi={qi}")
        print(f"  Range: [{min_alpha}, {max_alpha}]")
        
        low = max(low, min_alpha)
        high = min(high, max_alpha)
        
    print(f"Alpha range: [{low}, {high}]")
    if high < low:
        print("Empty alpha range! Relaxing assumption or taking median?")
        
        candidates = [0, 1, -1, 2, -2]
   
        pass
        
    if high < low:
         # Fallback strat:
         # Try alpha = 0.
         print("Falling back to alpha=0")
         alpha = 0
    else:
         alpha = low 
         
    M1 = M1_base - alpha
    print(f"Recovered M1: {M1}")
    
    # --- Step 2: Solve Rounds ---
    s_list = []
    
    for i in range(R_count):
        N = data[i]['N']
        f = data[i]['f']
        U2 = data[i]['U2']
        ab_val = data[i]['a_b'] # a/b % N
        
        print(f"Solving Round {i+1}...")
        
        # c and e
        # f = e*M1 + c
        # c = f % M1. Correct?
        # f = e*M1 + c. c < 2^6000. M1 ~ 2^6561.
        # Yes, c < M1.
        c = f % M1
        e = (f - c) // M1
        
        # 1. Recover d (Wiener)
        target = Integer(e) / Integer(N**3)
        cf = target.continued_fraction()
        
        d_found = 0
        p_found = 0
        
        # 2. Recover a, b (Lattice)
        # a = ab_val * b mod N
        LB = Matrix(ZZ, [[1, ab_val], [0, N]])
        vecs = LB.LLL()
        # Check vectors
        a_rec, b_rec = 0, 0
        
        # Usually row[0] is (b, a) or similar
        # row = (b, ab_val*b) - k(0, N) = (b, a).
        row = vecs[0]
        # Check signs
        c1, c2 = abs(row[0]), abs(row[1])
        # Verify
        if (c2 * inverse_mod(c1, N)) % N == ab_val:
            b_rec, a_rec = c1, c2
        elif (c1 * inverse_mod(c2, N)) % N == ab_val:
            b_rec, a_rec = c2, c1
        else:
            # Try next row
            row = vecs[1]
            c1, c2 = abs(row[0]), abs(row[1])
            if (c2 * inverse_mod(c1, N)) % N == ab_val:
                b_rec, a_rec = c1, c2
            elif (c1 * inverse_mod(c2, N)) % N == ab_val:
                b_rec, a_rec = c2, c1
                
        if a_rec == 0:
            print("Failed to recover a, b")
            s_list.append(0)
            continue
            
        print(f"  Recovered a, b: {a_rec}, {b_rec}")
        
        # Wiener Loop
        for conv in cf.convergents():
            k = conv.numerator()
            d = conv.denominator()
            if k == 0: continue
            if d.nbits() > 1050: break
            
            # Solve for p
            # phi' = (ed - 1)/k
            if (e*d - 1) % k != 0: continue
            phi_p = (e*d - 1) // k
            
            # Quadratic for X=p^3
            # b X^2 + (phi' - N^3 - ab) X + N^3 a = 0
            aa, bb = a_rec, b_rec # Use recovered a,b
            
            A = bb
            B = phi_p - N**3 - aa*bb
            C = N**3 * aa
            
            delta = B*B - 4*A*C
            if delta >= 0 and delta.is_square():
                sq = delta.sqrt()
                
                # Roots
                X1 = (-B + sq) // (2*A)
                
                # Check X1
                try:
                    p = Integer(X1).nth_root(3)
                    if N % p == 0:
                        p_found = p
                        d_found = d
                        break
                except: pass
                
                X2 = (-B - sq) // (2*A)
                try:
                    p = Integer(X2).nth_root(3)
                    if N % p == 0:
                        p_found = p
                        d_found = d
                        break
                except: pass

            if p_found: break
            
        if p_found:
            print(f"  Recovered d: {d_found}")
            # Recover s
            q = N // p_found
            phi = (p_found-1)*(q-1)
            d_inv = inverse_mod(d_found, phi)
            s = power_mod(U2, d_inv, N)
            s_list.append(s)
            print(f"  Recovered s: {s}")
        else:
            print("  Failed to find p, d")
            s_list.append(0)

    # Submit
    print("Submitting guesses...")
    for i in range(1, R_count+1):
        msg = f"Enter guess for round {i}/{R_count} >> "
        try:
            io.recvuntil(msg.encode())
            io.sendline(str(s_list[i-1]).encode())
            res = io.recvline().decode().strip()
            print(res)
            if "Fail" in res:
                print("Failed round.")
                io.close()
                return
        except Exception as e:
            print(f"Error submitting: {e}")
            break
            
    print("Getting flag...")
    try:
        print(io.recvall().decode().strip())
    except:
        pass
    io.close()

solve()
```

output:

```python
<snip>
Submitting guesses...
Nice!
Nice!
Nice!
Nice!
Nice!
Nice!
Nice!
Nice!
Nice!
Nice!
Nice!
Nice!
Getting flag...
[+] Receiving all data: Done (18B)
[*] Closed connection to challenges.1pc.tf port 20838
C2C{edce9fb96aa0}
```