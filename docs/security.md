---
layout: default
title: Security
---

# Security

This document describes the security model, threat mitigations, and best practices for MobileCoin Intents.

## Security Model

### Trust Assumptions

The bridge operates on a **Proof of Authority (PoA)** model with the following trust assumptions:

1. **Authority Threshold**: At least M of N authorities are honest (default: 3-of-5)
2. **Key Security**: Authority private keys are stored securely and not compromised
3. **MobileCoin Network**: The MobileCoin blockchain operates correctly
4. **NEAR Network**: The NEAR blockchain operates correctly

### Multi-Signature Authority System

All critical operations require multiple authority signatures:

```
┌─────────────────────────────────────────┐
│         Authority Signatures            │
│                                         │
│   Authority 1  ────┐                    │
│   Authority 2  ────┼──► Threshold ──►  │
│   Authority 3  ────┤    (M-of-N)        │
│   Authority 4  ────┤        │          │
│   Authority 5  ────┘        ▼          │
│                        Valid Operation │
└─────────────────────────────────────────┘
```

**Configuration:**
- Minimum threshold: 1 (for testing only)
- Recommended threshold: 3-of-5 or higher
- Maximum authorities: 20

## Threat Mitigations

### Replay Attacks

**Threat**: An attacker replays a valid deposit proof to mint wMOB multiple times.

**Mitigation**: All deposit transaction hashes are stored and checked before processing.

```rust
// Replay protection in deposit()
assert!(
    !self.processed_deposits.contains(&proof.tx_hash),
    "Deposit already processed"
);
self.processed_deposits.insert(&proof.tx_hash);
```

### Double-Spending

**Threat**: A user attempts to spend the same MOB twice by submitting concurrent deposits.

**Mitigation**:
- Unique transaction hash tracking
- MobileCoin's built-in key image system prevents on-chain double-spends
- Bridge waits for sufficient confirmations

### Integer Overflow/Underflow

**Threat**: Arithmetic operations overflow or underflow, leading to incorrect balances.

**Mitigation**: All arithmetic uses checked operations:

```rust
// Safe arithmetic in transfers
let new_balance = current_balance.checked_add(amount)
    .expect("Balance overflow");
let new_supply = total_supply.checked_sub(amount)
    .expect("Supply underflow");
```

### Denial of Service (DoS)

**Threat**: Attacker floods the bridge with transactions to prevent legitimate use.

**Mitigation**: Rate limiting with configurable parameters:

```rust
pub struct RateLimitConfig {
    pub max_deposits_per_hour: u32,      // Default: 100
    pub max_withdrawals_per_hour: u32,   // Default: 100
    pub max_volume_per_hour: Balance,    // Default: 10,000 MOB
}
```

### Amount Manipulation

**Threat**: Attacker submits deposits or withdrawals with extreme amounts.

**Mitigation**: Strict amount bounds:

| Limit | Default Value |
|-------|---------------|
| Minimum Deposit | 0.001 MOB (10^9 picoMOB) |
| Maximum Deposit | 1,000 MOB (10^15 picoMOB) |
| Maximum Volume/Hour | 10,000 MOB |

### Signature Forgery

**Threat**: Attacker creates fake authority signatures.

**Mitigation**:
- Ed25519 signature verification using NEAR's `env::ed25519_verify`
- Signature format validation (64 bytes, canonical S value)
- Public key length validation

```rust
fn ed25519_verify(&self, pubkey: &[u8], message: &[u8], signature: &[u8; 64]) -> bool {
    if pubkey.len() != 32 { return false; }

    // Reject non-canonical S values
    if signature[31] >= 0x80 { return false; }

    env::ed25519_verify(signature, message, pubkey)
}
```

### JSON Injection

**Threat**: Malicious memo or message content breaks JSON event parsing.

**Mitigation**: All user-provided strings are sanitized:

```rust
fn sanitize_memo(s: &str) -> String {
    s.chars()
        .take(256) // Limit length
        .map(|c| match c {
            '"' => "\\\"".to_string(),
            '\\' => "\\\\".to_string(),
            '\n' => "\\n".to_string(),
            // ... other escapes
        })
        .collect()
}
```

### Invalid Address Injection

**Threat**: Attacker provides malformed MobileCoin address for withdrawal.

**Mitigation**: Strict Base58Check validation:

```rust
fn validate_mob_address(&self, address: &str) {
    assert!(address.len() >= 66, "Too short");
    assert!(address.len() <= 200, "Too long");

    // Validate Base58 alphabet (no 0/O/I/l)
    let is_valid = address.chars().all(|c| {
        matches!(c, '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z')
    });
    assert!(is_valid, "Invalid Base58 characters");
}
```

## Emergency Controls

### Pause Mechanism

The bridge can be paused by the owner in case of detected attacks or vulnerabilities:

```rust
// Pause all operations
contract.pause();

// Resume operations
contract.unpause();
```

When paused:
- No deposits can be processed
- No withdrawals can be requested
- No withdrawals can be completed
- View functions remain available

### Authority Rotation

Authorities can be updated without contract redeployment:

```rust
contract.update_authorities(new_authorities, new_threshold);
```

This allows for:
- Key rotation after suspected compromise
- Adding/removing authorities
- Adjusting threshold requirements

## Cryptographic Primitives

| Algorithm | Usage | Library |
|-----------|-------|---------|
| Ed25519 | Authority signatures | `ed25519-dalek 2.1` |
| Curve25519 | Key exchange, stealth addresses | `curve25519-dalek 4.1` |
| SHA-256 | Message hashing | `sha2 0.10` |
| SHA-512 | Ed25519 internal | `sha2 0.10` |
| SHA3 (Keccak) | Additional hashing | `sha3 0.10` |

All cryptographic operations use constant-time implementations where applicable to prevent timing attacks.

## Security Best Practices

### For Operators

1. **Key Management**
   - Use hardware security modules (HSMs) for authority keys
   - Distribute authority keys across multiple geographic locations
   - Implement key rotation schedules

2. **Monitoring**
   - Monitor all deposit and withdrawal events
   - Alert on unusual patterns (volume spikes, failed signatures)
   - Track rate limit approaches

3. **Incident Response**
   - Have a clear pause procedure
   - Maintain communication channels with other authorities
   - Document recovery procedures

### For Users

1. **Address Verification**
   - Always verify MobileCoin addresses before withdrawals
   - Use wallet software that validates addresses

2. **Transaction Confirmation**
   - Wait for sufficient confirmations before considering deposits complete
   - Monitor withdrawal status through the bridge contract

3. **Amount Limits**
   - Be aware of minimum and maximum limits
   - For large transfers, consider multiple smaller transactions

## Audits and Reviews

This codebase is provided as-is for development and testing purposes. Before production deployment:

1. Conduct formal security audits
2. Perform penetration testing
3. Review authority setup procedures
4. Test emergency procedures

## Reporting Vulnerabilities

If you discover a security vulnerability, please:

1. **Do not** disclose publicly
2. Contact the maintainers privately
3. Provide detailed reproduction steps
4. Allow time for patch development

## Known Limitations

1. **PoA Trust Model**: Security depends on authority honesty
2. **Centralized Custody**: Bridge custody address is a potential target
3. **Cross-Chain Finality**: Different confirmation times between chains
4. **Key Recovery**: No mechanism for recovering lost authority keys
