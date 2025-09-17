### [S-1] Misconfiguration DoS via zero-address in critical setters (Root Cause: missing validation; Impact: protocol operations can be bricked)

**Description:**  
`BidderRegistry.setDepositManagerImpl(address)` and `BidderRegistry.setPreconfManager(address)` accept arbitrary addresses with **no zero-address check**. These values are later relied on by access control / liveness checks:

- `openBid(...)` is gated by `depositManagerIsSet`, which reverts if `depositManagerImpl == address(0)`.  
- Many privileged flows are gated by `onlyPreconfManager` (`convertFundsToProviderReward`, `unlockFunds`, `openBid` via caller expectations), which compares `msg.sender` to `preconfManager`.

If the owner (or a compromised owner key / deployment script) sets either value to the zero address (or clears it during an upgrade/rollback), the registry becomes partially or totally unusable.

**Impact:**  
- **Hard DoS of bidding flow:** With `depositManagerImpl == address(0)`, every `openBid(...)` call reverts due to the `depositManagerIsSet` modifier, halting new bids and escrow accounting.  
- **Settlement/Slashing DoS:** With `preconfManager == address(0)`, *all* functions guarded by `onlyPreconfManager` revert forever, blocking reward settlement (`convertFundsToProviderReward`) and unlocks on slash (`unlockFunds`). Funds can become stranded in escrow/accounting buckets.  
- Severity: **Medium/High**, depending on admin model. A single misconfiguration bricks core functionality and can immobilize user funds until another privileged tx fixes it.

**Proof of Concept:**  
1) Owner (accidentally) calls:
```solidity
bidderRegistry.setDepositManagerImpl(address(0));
```
2) Any subsequent call to:
```solidity
bidderRegistry.openBid(commitmentDigest, bidAmt, bidder, provider);
```
reverts at the modifier:
```solidity
modifier depositManagerIsSet() {
    require(depositManagerImpl != address(0), DepositManagerNotSet());
    _;
}
```

Similarly, setting:
```solidity
bidderRegistry.setPreconfManager(address(0));
```
causes every `onlyPreconfManager` function (e.g., `convertFundsToProviderReward`, `unlockFunds`) to revert because `msg.sender` can never equal `address(0)`.

**Recommended Mitigation:**  
- Add explicit zero-address validation and keep existing events:
```solidity
function setDepositManagerImpl(address _impl) external onlyOwner {
    require(_impl != address(0), "DM impl zero");
    depositManagerImpl = _impl;
    depositManagerHash = keccak256(abi.encodePacked(hex"ef0100", _impl));
    emit DepositManagerImplUpdated(_impl);
}

function setPreconfManager(address _preconf) external onlyOwner {
    require(_preconf != address(0), "preconf zero");
    preconfManager = _preconf;
    emit PreconfManagerUpdated(_preconf);
}
```
- Consider a **two-step admin pattern** for critical address changes:
  1) `proposeX(address)` stores a pending value and emits an event.
  2) `acceptX()` finalizes after a delay or a second confirmation.
- Optionally add **pausing/escape hatches** so that, if a bad value is set, an authorized role can still unbrick the contract quickly.
