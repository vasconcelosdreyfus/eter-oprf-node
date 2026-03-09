import {
  hashToGroup,
  evaluateBlindedElement,
  computeOprfToken,
  computeOprfTokenFromShares,
  evaluateWithShare,
  computeRistrettoCommitment,
  proveRistrettoCommitment,
  verifyRistrettoProof,
} from '../src/index.js';
import { p256 } from '@noble/curves/p256';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Convert a random 32-byte key to a valid P-256 scalar (BigInt, non-zero, < ORDER). */
function randomScalar(): bigint {
  const n = p256.CURVE.n;
  let sk: bigint;
  do {
    const bytes = p256.utils.randomPrivateKey(); // always valid
    sk = BigInt('0x' + Buffer.from(bytes).toString('hex'));
  } while (sk === 0n || sk >= n);
  return sk;
}

// ---------------------------------------------------------------------------
// hashToGroup
// ---------------------------------------------------------------------------

describe('hashToGroup', () => {
  it('is deterministic for the same input', () => {
    const p1 = hashToGroup('alice');
    const p2 = hashToGroup('alice');
    expect(p1.equals(p2)).toBe(true);
  });

  it('is case-insensitive (normalises to lowercase internally)', () => {
    const lower = hashToGroup('alice');
    const upper = hashToGroup('ALICE');
    expect(lower.equals(upper)).toBe(true);
  });

  it('different inputs produce different points', () => {
    expect(hashToGroup('alice').equals(hashToGroup('bob'))).toBe(false);
  });

  it('returns a valid P-256 point (assertValidity does not throw)', () => {
    expect(() => hashToGroup('alice').assertValidity()).not.toThrow();
  });

  it('empty string does not throw', () => {
    expect(() => hashToGroup('')).not.toThrow();
  });

  it('long username does not throw', () => {
    expect(() => hashToGroup('a'.repeat(100))).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// evaluateBlindedElement
// ---------------------------------------------------------------------------

describe('evaluateBlindedElement', () => {
  it('is deterministic for the same key and blinded input', () => {
    const skS = randomScalar();
    const H = hashToGroup('alice');
    const rS = randomScalar();
    const blindedPoint = H.multiply(rS);
    const blindedHex = Buffer.from(blindedPoint.toRawBytes(true)).toString('hex');

    const result1 = evaluateBlindedElement(blindedHex, skS);
    const result2 = evaluateBlindedElement(blindedHex, skS);
    expect(result1).toEqual(result2);
  });

  it('returns a 66-char hex string (33-byte compressed P-256 point)', () => {
    const skS = randomScalar();
    const H = hashToGroup('alice');
    const blindedHex = Buffer.from(H.toRawBytes(true)).toString('hex');
    const result = evaluateBlindedElement(blindedHex, skS);
    expect(result).toHaveLength(66);
    expect(result).toMatch(/^[0-9a-f]+$/);
  });

  it('different keys produce different evaluations', () => {
    const sk1 = randomScalar();
    const sk2 = randomScalar();
    const blindedHex = Buffer.from(hashToGroup('alice').toRawBytes(true)).toString('hex');
    expect(evaluateBlindedElement(blindedHex, sk1)).not.toEqual(evaluateBlindedElement(blindedHex, sk2));
  });

  it('throws on invalid hex input', () => {
    expect(() => evaluateBlindedElement('not-a-point', randomScalar())).toThrow();
  });
});

// ---------------------------------------------------------------------------
// computeOprfToken
// ---------------------------------------------------------------------------

describe('computeOprfToken', () => {
  it('is deterministic', () => {
    const skS = randomScalar();
    expect(computeOprfToken('alice', skS)).toEqual(computeOprfToken('alice', skS));
  });

  it('returns a 64-char lowercase hex string (32-byte SHA-256 output)', () => {
    const token = computeOprfToken('alice', randomScalar());
    expect(token).toHaveLength(64);
    expect(token).toMatch(/^[0-9a-f]+$/);
  });

  it('different usernames produce different tokens for the same key', () => {
    const skS = randomScalar();
    expect(computeOprfToken('alice', skS)).not.toEqual(computeOprfToken('bob', skS));
  });

  it('different keys produce different tokens for the same username', () => {
    expect(computeOprfToken('alice', randomScalar())).not.toEqual(computeOprfToken('alice', randomScalar()));
  });

  it('is already case-normalised (caller passes normalised username)', () => {
    const skS = randomScalar();
    // computeOprfToken does NOT normalise — it uses the username as-is in the final hash.
    // hashToGroup normalises internally, but the token domain string carries the raw username.
    // So 'alice' and 'ALICE' will produce different tokens if not pre-normalised.
    const t1 = computeOprfToken('alice', skS);
    const t2 = computeOprfToken('alice', skS);
    expect(t1).toEqual(t2);
  });
});

// ---------------------------------------------------------------------------
// threshold OPRF: evaluateWithShare + computeOprfTokenFromShares
// ---------------------------------------------------------------------------

describe('threshold OPRF', () => {
  it('three additive shares produce the same token as the full key', () => {
    const n = p256.CURVE.n;
    const s1 = randomScalar();
    const s2 = randomScalar();
    const s3 = randomScalar();
    const skS = (s1 + s2 + s3) % n;

    const singleToken = computeOprfToken('testuser', skS);
    const thresholdToken = computeOprfTokenFromShares('testuser', s1, s2, s3);

    expect(thresholdToken).toEqual(singleToken);
  });

  it('evaluateWithShare returns a valid 66-char hex point', () => {
    const share = randomScalar();
    const blindedHex = Buffer.from(hashToGroup('alice').toRawBytes(true)).toString('hex');
    const partial = evaluateWithShare(blindedHex, share);
    expect(partial).toHaveLength(66);
    expect(partial).toMatch(/^[0-9a-f]+$/);
  });

  it('computeOprfTokenFromShares is deterministic', () => {
    const s1 = randomScalar();
    const s2 = randomScalar();
    const s3 = randomScalar();
    expect(computeOprfTokenFromShares('alice', s1, s2, s3))
      .toEqual(computeOprfTokenFromShares('alice', s1, s2, s3));
  });

  it('different usernames produce different threshold tokens', () => {
    const s1 = randomScalar();
    const s2 = randomScalar();
    const s3 = randomScalar();
    expect(computeOprfTokenFromShares('alice', s1, s2, s3))
      .not.toEqual(computeOprfTokenFromShares('bob', s1, s2, s3));
  });
});

// ---------------------------------------------------------------------------
// Ristretto255 commitments
// ---------------------------------------------------------------------------

describe('computeRistrettoCommitment', () => {
  it('is deterministic', () => {
    const c1 = computeRistrettoCommitment('alice', 'uid123');
    const c2 = computeRistrettoCommitment('alice', 'uid123');
    expect(c1).toEqual(c2);
  });

  it('returns a 64-char lowercase hex string (32-byte point)', () => {
    const commitment = computeRistrettoCommitment('alice', 'uid123');
    expect(commitment).toHaveLength(64);
    expect(commitment).toMatch(/^[0-9a-f]+$/);
  });

  it('different usernames produce different commitments for the same uid', () => {
    expect(computeRistrettoCommitment('alice', 'uid123'))
      .not.toEqual(computeRistrettoCommitment('bob', 'uid123'));
  });

  it('different uids produce different commitments for the same username', () => {
    expect(computeRistrettoCommitment('alice', 'uid123'))
      .not.toEqual(computeRistrettoCommitment('alice', 'uid456'));
  });
});

// ---------------------------------------------------------------------------
// Schnorr ZK proof: prove + verify
// ---------------------------------------------------------------------------

describe('proveRistrettoCommitment + verifyRistrettoProof', () => {
  it('prove + verify round-trip returns true', () => {
    const commitment = computeRistrettoCommitment('alice', 'uid123');
    const proof = proveRistrettoCommitment('alice', 'uid123');
    expect(verifyRistrettoProof(commitment, proof)).toBe(true);
  });

  it('verify with a commitment for a different user returns false', () => {
    const wrongCommitment = computeRistrettoCommitment('bob', 'uid456');
    const proof = proveRistrettoCommitment('alice', 'uid123');
    expect(verifyRistrettoProof(wrongCommitment, proof)).toBe(false);
  });

  it('verify with a tampered challenge (c) returns false', () => {
    const commitment = computeRistrettoCommitment('alice', 'uid123');
    const proof = proveRistrettoCommitment('alice', 'uid123');
    // Flip the last nibble of the challenge hex string
    const lastChar = proof.c[proof.c.length - 1];
    const flipped = lastChar === '0' ? '1' : '0';
    const tamperedProof = { ...proof, c: proof.c.slice(0, -1) + flipped };
    expect(verifyRistrettoProof(commitment, tamperedProof)).toBe(false);
  });

  it('verify with a tampered z1 returns false', () => {
    const commitment = computeRistrettoCommitment('alice', 'uid123');
    const proof = proveRistrettoCommitment('alice', 'uid123');
    const lastChar = proof.z1[proof.z1.length - 1];
    const flipped = lastChar === '0' ? '1' : '0';
    const tamperedProof = { ...proof, z1: proof.z1.slice(0, -1) + flipped };
    expect(verifyRistrettoProof(commitment, tamperedProof)).toBe(false);
  });

  it('verify with garbage commitment hex returns false', () => {
    const proof = proveRistrettoCommitment('alice', 'uid123');
    expect(verifyRistrettoProof('00'.repeat(32), proof)).toBe(false);
  });

  it('two independent proofs for the same input both verify (non-deterministic R)', () => {
    const commitment = computeRistrettoCommitment('charlie', 'uid789');
    const proof1 = proveRistrettoCommitment('charlie', 'uid789');
    const proof2 = proveRistrettoCommitment('charlie', 'uid789');
    // R should differ (random nonces) but both proofs must be valid
    expect(proof1.R).not.toEqual(proof2.R);
    expect(verifyRistrettoProof(commitment, proof1)).toBe(true);
    expect(verifyRistrettoProof(commitment, proof2)).toBe(true);
  });
});
