# @eter/oprf

RFC 9497 (2HashDH) Oblivious Pseudorandom Function on P-256, plus Ristretto255 multi-scalar commitments with Schnorr ZK proofs.

Extracted from [Eter](https://eter.app) — an anti-forensic encrypted messenger. Zero Firebase dependencies. Pure cryptography.

## Packages

| Package | Language | Description |
|---------|----------|-------------|
| `@eter/oprf` | TypeScript / Node.js | This package |
| `eter_oprf` | Dart / Flutter | Companion client-side package |

Both packages share the same domain strings and wire format — they are byte-for-byte interoperable.

## Installation

```bash
npm install @eter/oprf
```

Requires Node.js >= 18. The only runtime dependency is [`@noble/curves`](https://github.com/paulmillr/noble-curves).

## Usage

### Basic OPRF (server evaluates a blinded point)

```typescript
import { hashToGroup, evaluateBlindedElement, computeOprfToken } from '@eter/oprf';
import { p256 } from '@noble/curves/p256';

// Server: load your secret key (keep this secret)
const skS: bigint = /* load from secure storage */;

// Client: blind the username
const H = hashToGroup('alice');
const r = BigInt('0x' + Buffer.from(p256.utils.randomPrivateKey()).toString('hex'));
const blindedPoint = H.multiply(r);
const blindedHex = Buffer.from(blindedPoint.toRawBytes(true)).toString('hex');

// Server: evaluate the blinded element (learns nothing about 'alice')
const evaluatedHex = evaluateBlindedElement(blindedHex, skS);

// Client: unblind the response and compute the token
// token = sha256("Eter-OPRF-token|" + username + "|" + hex(r^-1 * evaluatedPoint))
// (unblinding is done in the Dart OprfClient)

// Server: compute token directly (for storage at registration)
const token = computeOprfToken('alice', skS);
// token is a 32-byte hex string stored in oprf_tokens/{token} in Firestore
```

### Threshold OPRF (3-of-3 additive key split)

```typescript
import { computeOprfToken, computeOprfTokenFromShares, evaluateWithShare } from '@eter/oprf';

// Three independent servers each hold one share: s1 + s2 + s3 ≡ skS (mod P-256 ORDER)
const s1: bigint = /* share 1 */;
const s2: bigint = /* share 2 */;
const s3: bigint = /* share 3 */;

// Each server evaluates independently:
const partial1 = evaluateWithShare(blindedHex, s1);
const partial2 = evaluateWithShare(blindedHex, s2);
const partial3 = evaluateWithShare(blindedHex, s3);
// Client combines: finalPoint = partial1 + partial2 + partial3 (elliptic curve addition)

// Or compute the token directly (when all shares are available in one context):
const token = computeOprfTokenFromShares('alice', s1, s2, s3);
// Identical to computeOprfToken('alice', skS) when s1+s2+s3 ≡ skS mod ORDER
```

### Ristretto255 Commitment + Schnorr ZK Proof

```typescript
import {
  computeRistrettoCommitment,
  proveRistrettoCommitment,
  verifyRistrettoProof,
} from '@eter/oprf';
import type { SchnorrProof } from '@eter/oprf';

// Commit to a username — stored publicly in user profiles
const commitment = computeRistrettoCommitment('alice', 'uid-abc123');
// commitment is a 32-byte hex string

// Generate a ZK proof that you know the username behind the commitment
const proof: SchnorrProof = proveRistrettoCommitment('alice', 'uid-abc123');

// Anyone can verify without learning the username
const valid = verifyRistrettoProof(commitment, proof);
console.log(valid); // true
```

## Protocol Constants

These domain strings are part of the public protocol specification. Any compatible implementation must use the same strings to maintain interoperability.

| Constant | Value | Used in |
|----------|-------|---------|
| Hash-to-group prefix | `Eter-OPRF-htg\|` | `hashToGroup` — try-and-increment SHA-256 |
| Token domain | `Eter-OPRF-token\|` | `computeOprfToken` / `computeOprfTokenFromShares` |
| Ristretto255 generator G1 | SHA-512 of `Eter-Ristretto255-G1-v1` | multi-scalar commitment basis |
| Ristretto255 generator G2 | SHA-512 of `Eter-Ristretto255-G2-v1` | multi-scalar commitment basis |
| Ristretto255 generator G3 | SHA-512 of `Eter-Ristretto255-G3-v1` | multi-scalar commitment basis |
| Commitment scalar s1 | SHA-512 of `Eter-comm-s1\|` + username | `computeScalars` |
| Commitment scalar s3 | SHA-512 of `Eter-comm-s3\|` + uid | `computeScalars` |
| Schnorr domain | `Eter-Schnorr-v1\|` | `proveRistrettoCommitment` / `verifyRistrettoProof` |

## Security Properties

**OPRF (RFC 9497 / 2HashDH on P-256):**
- Server learns nothing about the username from a blinded query (pseudorandomness + obliviousness)
- Client cannot compute tokens for usernames without server cooperation
- Threshold 3-of-3 split: no single server holds the full key
- Try-and-increment hash-to-group is constant-time per iteration (no branch on x-coordinate validity in `@noble/curves`)

**Ristretto255 commitment:**
- Binding: computationally infeasible to find two (username, uid) pairs that map to the same commitment (discrete-log hardness)
- Hiding: commitment reveals nothing about the username (multi-scalar randomisation via three independent generators)
- Schnorr ZK proof is honest-verifier zero-knowledge and unforgeable under the discrete-log assumption

**What this package does NOT provide:**
- Key generation or key management utilities (by design — keep env handling in your server code)
- Oblivious PRF blinding on the client side (handled by `eter_oprf` Dart package)
- Network transport or session handling

## References

- [RFC 9497 — Oblivious Pseudorandom Functions (OPRFs)](https://www.rfc-editor.org/rfc/rfc9497)
- [Signal — Username privacy](https://signal.org/blog/phone-number-privacy-usernames/)
- [@noble/curves — audited elliptic curve primitives](https://github.com/paulmillr/noble-curves)
- [Ristretto255 — prime-order group abstraction over Ed25519](https://ristretto.group/)

---

Built by [Eter](https://eter.app) — an anti-forensic encrypted messenger.
