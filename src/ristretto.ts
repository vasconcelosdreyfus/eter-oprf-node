import { RistrettoPoint } from '@noble/curves/ed25519';
import { createHash, randomBytes } from 'crypto';

// Ristretto255 group order (same as Ed25519 prime order subgroup)
const ORDER = BigInt('7237005577332262213973186563042994240857116359379907606001950938285454250989');

// Three independent generator points derived via hash-to-curve on well-known domain strings.
// These are the "bases" for the multi-scalar commitment H = s1·G1 + s2·G2 + s3·G3.
// Compatible with Signal's construction (different domain strings = different generators).
// hashToCurve requires exactly 64 bytes — pre-hash domain strings with SHA-512.
//
// Domain strings (public protocol constants):
//   'Eter-Ristretto255-G1-v1'
//   'Eter-Ristretto255-G2-v1'
//   'Eter-Ristretto255-G3-v1'
const G1 = RistrettoPoint.hashToCurve(createHash('sha512').update('Eter-Ristretto255-G1-v1').digest());
const G2 = RistrettoPoint.hashToCurve(createHash('sha512').update('Eter-Ristretto255-G2-v1').digest());
const G3 = RistrettoPoint.hashToCurve(createHash('sha512').update('Eter-Ristretto255-G3-v1').digest());

/** Reduces a 64-byte buffer to a Ristretto255 scalar (mod ORDER). */
function bytesToScalar(bytes: Buffer): bigint {
  return BigInt('0x' + bytes.toString('hex')) % ORDER;
}

/**
 * Encodes a username as a scalar using a modified base-40 scheme.
 * Each character maps to a unique small integer; characters are combined
 * into a single scalar via Horner's method. Compatible with Signal's base-37.
 *
 * Alphabet: _ → 1, a–z → 2–27, 0–9 → 28–37, . → 38, - → 39
 */
function base40Encode(username: string): bigint {
  const map: Record<string, number> = { _: 1, '.': 38, '-': 39 };
  for (let i = 0; i < 26; i++) map[String.fromCharCode(97 + i)] = i + 2;
  for (let i = 0; i < 10; i++) map[String.fromCharCode(48 + i)] = i + 28;

  let result = 0n;
  for (const char of username) {
    result = result * 40n + BigInt(map[char] ?? 0);
  }
  return result % ORDER;
}

/** Generates a random Ristretto255 scalar in [1, ORDER-1]. */
function randomScalar(): bigint {
  let r: bigint;
  do {
    r = BigInt('0x' + randomBytes(64).toString('hex')) % ORDER;
  } while (r === 0n);
  return r;
}

/**
 * Computes the three scalars (s1, s2, s3) from username and uid.
 *
 * s1 = sha512("Eter-comm-s1|" + username) mod ORDER   — deterministic hash of username
 * s2 = base40(username) mod ORDER                      — structural encoding
 * s3 = sha512("Eter-comm-s3|" + uid) mod ORDER         — binds commitment to this account
 *
 * Domain strings (public protocol constants):
 *   'Eter-comm-s1|'
 *   'Eter-comm-s3|'
 */
function computeScalars(usernameNormalized: string, uid: string): [bigint, bigint, bigint] {
  const s1 = bytesToScalar(
    createHash('sha512').update('Eter-comm-s1|' + usernameNormalized).digest()
  );
  const s2 = base40Encode(usernameNormalized);
  const s3 = bytesToScalar(
    createHash('sha512').update('Eter-comm-s3|' + uid).digest()
  );
  return [s1, s2, s3];
}

/**
 * Computes the Ristretto255 multi-scalar commitment.
 *
 *   H = s1·G1 + s2·G2 + s3·G3
 *
 * H is a 32-byte point that commits to the username without revealing it.
 * The construction follows Signal's username commitment scheme.
 *
 * @param usernameNormalized - lowercase username
 * @param uid - user account identifier
 * @returns 32-byte commitment as lowercase hex (64 chars)
 */
export function computeRistrettoCommitment(usernameNormalized: string, uid: string): string {
  const [s1, s2, s3] = computeScalars(usernameNormalized, uid);
  const H = G1.multiply(s1).add(G2.multiply(s2)).add(G3.multiply(s3));
  return Buffer.from(H.toRawBytes()).toString('hex');
}

export interface SchnorrProof {
  /** Random commitment point R = r1·G1 + r2·G2 + r3·G3, 32-byte hex */
  R: string;
  /** Fiat-Shamir challenge c = sha256("Eter-Schnorr-v1|" || H || R) mod ORDER, 32-byte hex */
  c: string;
  /** Response z1 = r1 + c·s1 mod ORDER, 32-byte hex */
  z1: string;
  /** Response z2 = r2 + c·s2 mod ORDER, 32-byte hex */
  z2: string;
  /** Response z3 = r3 + c·s3 mod ORDER, 32-byte hex */
  z3: string;
}

const PAD64 = (n: bigint) => n.toString(16).padStart(64, '0');

/**
 * Generates a Schnorr ZK proof that the prover knows (s1, s2, s3) such that
 * H = s1·G1 + s2·G2 + s3·G3, without revealing any scalar.
 *
 * Protocol (Sigma / Fiat-Shamir):
 *   Prover picks r1, r2, r3 ← Zq randomly
 *   R = r1·G1 + r2·G2 + r3·G3
 *   c = sha256("Eter-Schnorr-v1|" || H || R) mod ORDER
 *   zi = ri + c·si mod ORDER
 *
 * Verifier checks: z1·G1 + z2·G2 + z3·G3 == R + c·H
 *
 * Domain string: `Eter-Schnorr-v1|` (public protocol constant)
 *
 * @param usernameNormalized - lowercase username
 * @param uid - user account identifier
 * @returns Schnorr proof object
 */
export function proveRistrettoCommitment(usernameNormalized: string, uid: string): SchnorrProof {
  const [s1, s2, s3] = computeScalars(usernameNormalized, uid);
  const H = G1.multiply(s1).add(G2.multiply(s2)).add(G3.multiply(s3));

  const r1 = randomScalar();
  const r2 = randomScalar();
  const r3 = randomScalar();
  const R = G1.multiply(r1).add(G2.multiply(r2)).add(G3.multiply(r3));

  const challengeInput = Buffer.concat([
    Buffer.from('Eter-Schnorr-v1|', 'utf8'),
    Buffer.from(H.toRawBytes()),
    Buffer.from(R.toRawBytes()),
  ]);
  const c = BigInt('0x' + createHash('sha256').update(challengeInput).digest('hex')) % ORDER;

  const z1 = (r1 + c * s1) % ORDER;
  const z2 = (r2 + c * s2) % ORDER;
  const z3 = (r3 + c * s3) % ORDER;

  return {
    R: Buffer.from(R.toRawBytes()).toString('hex'),
    c: PAD64(c),
    z1: PAD64(z1),
    z2: PAD64(z2),
    z3: PAD64(z3),
  };
}

/**
 * Verifies a Schnorr proof against commitment H.
 * Can be called by anyone with G1, G2, G3 and the stored proof — fully offline.
 *
 * @param commitmentHex - 32-byte Ristretto255 commitment point as lowercase hex (64 chars)
 * @param proof - Schnorr proof generated by `proveRistrettoCommitment`
 * @returns true if proof is valid (prover knows preimage of H)
 */
export function verifyRistrettoProof(commitmentHex: string, proof: SchnorrProof): boolean {
  try {
    const H = RistrettoPoint.fromHex(commitmentHex);
    const Rpoint = RistrettoPoint.fromHex(proof.R);
    const c = BigInt('0x' + proof.c);
    const z1 = BigInt('0x' + proof.z1);
    const z2 = BigInt('0x' + proof.z2);
    const z3 = BigInt('0x' + proof.z3);

    // Re-derive challenge
    const challengeInput = Buffer.concat([
      Buffer.from('Eter-Schnorr-v1|', 'utf8'),
      Buffer.from(H.toRawBytes()),
      Buffer.from(Rpoint.toRawBytes()),
    ]);
    const expectedC = BigInt('0x' + createHash('sha256').update(challengeInput).digest('hex')) % ORDER;
    if (c !== expectedC) return false;

    // Check: z1·G1 + z2·G2 + z3·G3 == R + c·H
    const lhs = G1.multiply(z1).add(G2.multiply(z2)).add(G3.multiply(z3));
    const rhs = Rpoint.add(H.multiply(c));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}
