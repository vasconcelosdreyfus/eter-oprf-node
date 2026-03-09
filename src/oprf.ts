import { createHash } from 'crypto';
import { p256 } from '@noble/curves/p256';

const HASH_TO_GROUP_PREFIX = Buffer.from('Eter-OPRF-htg|', 'utf8');
const TOKEN_PREFIX = 'Eter-OPRF-token|';

type P256Point = typeof p256.ProjectivePoint.BASE;

/**
 * Hash a username to a P-256 point using try-and-increment.
 *
 * For each counter starting at 0:
 *   hash = sha256("Eter-OPRF-htg|" || username || counter_byte)
 *   try p256.ProjectivePoint.fromHex("02" + hash_hex)  → even y
 *   try p256.ProjectivePoint.fromHex("03" + hash_hex)  → odd y
 *
 * The first valid compressed point is returned. On average ~2 iterations.
 *
 * This implementation is byte-for-byte compatible with the Dart OprfClient.
 *
 * Domain string: `Eter-OPRF-htg|` (public protocol constant)
 */
export function hashToGroup(username: string): P256Point {
  const input = Buffer.from(username.toLowerCase(), 'utf8');
  for (let counter = 0; counter < 256; counter++) {
    const msg = Buffer.concat([HASH_TO_GROUP_PREFIX, input, Buffer.from([counter])]);
    const hash = createHash('sha256').update(msg).digest();
    const hex = hash.toString('hex');
    try {
      return p256.ProjectivePoint.fromHex('02' + hex);
    } catch { /* x not a valid x-coordinate — try odd y */ }
    try {
      return p256.ProjectivePoint.fromHex('03' + hex);
    } catch { /* also invalid — try next counter */ }
  }
  throw new Error('hashToGroup: no valid point found after 256 iterations');
}

/**
 * Computes the OPRF evaluation of a blinded P-256 point.
 *
 * evaluatedElement = secretKey * blindedElement
 *
 * The server never learns the username because the blinded element is
 * r * H(username) for a random client-chosen scalar r — statistically
 * indistinguishable from a uniformly random P-256 point.
 *
 * @param blindedHex - 33-byte compressed P-256 point as lowercase hex (66 chars)
 * @param secretKey  - OPRF server secret key as BigInt
 * @returns 33-byte compressed P-256 point as lowercase hex
 */
export function evaluateBlindedElement(blindedHex: string, secretKey: bigint): string {
  const blindedPoint = p256.ProjectivePoint.fromHex(blindedHex);
  const evaluated = blindedPoint.multiply(secretKey);
  return Buffer.from(evaluated.toRawBytes(true)).toString('hex');
}

/**
 * Computes the OPRF token for a username.
 *
 * token = sha256("Eter-OPRF-token|" + username_normalized + "|" + hex(skS * H(username)))
 *
 * Domain string: `Eter-OPRF-token|` (public protocol constant)
 *
 * Must match the computation in OprfClient.computeToken (Dart).
 *
 * @param usernameNormalized - lowercase username
 * @param secretKey - full OPRF secret key as BigInt
 * @returns 32-byte token as lowercase hex (64 chars)
 */
export function computeOprfToken(usernameNormalized: string, secretKey: bigint): string {
  const inputPoint = hashToGroup(usernameNormalized);
  const N = inputPoint.multiply(secretKey);
  const hexN = Buffer.from(N.toRawBytes(true)).toString('hex');
  const msg = `${TOKEN_PREFIX}${usernameNormalized}|${hexN}`;
  return createHash('sha256').update(msg, 'utf8').digest('hex');
}

/**
 * Computes the OPRF token using the three key shares directly,
 * without requiring the full secret key.
 *
 * N = s1·H(x) + s2·H(x) + s3·H(x) = (s1+s2+s3)·H(x) = skS·H(x)
 *
 * The token is identical to computeOprfToken(username, skS) when
 * s1 + s2 + s3 ≡ skS (mod P-256 ORDER).
 *
 * @param usernameNormalized - lowercase username
 * @param s1 - first key share as BigInt
 * @param s2 - second key share as BigInt
 * @param s3 - third key share as BigInt
 * @returns 32-byte token as lowercase hex (64 chars)
 */
export function computeOprfTokenFromShares(
  usernameNormalized: string,
  s1: bigint,
  s2: bigint,
  s3: bigint
): string {
  const inputPoint = hashToGroup(usernameNormalized);
  const N = inputPoint.multiply(s1)
    .add(inputPoint.multiply(s2))
    .add(inputPoint.multiply(s3));
  const hexN = Buffer.from(N.toRawBytes(true)).toString('hex');
  const msg = `${TOKEN_PREFIX}${usernameNormalized}|${hexN}`;
  return createHash('sha256').update(msg, 'utf8').digest('hex');
}

/**
 * Evaluates a blinded element using a single key share.
 * Returns: share_i * blindedElement (a partial evaluation).
 *
 * The full evaluation requires combining all three partial results:
 *   evaluatedElement = partial1 + partial2 + partial3
 *
 * @param blindedHex - 33-byte compressed P-256 point as lowercase hex (66 chars)
 * @param share - one of the three OPRF key shares as BigInt
 * @returns 33-byte compressed P-256 point as lowercase hex
 */
export function evaluateWithShare(blindedHex: string, share: bigint): string {
  const blindedPoint = p256.ProjectivePoint.fromHex(blindedHex);
  const partial = blindedPoint.multiply(share);
  return Buffer.from(partial.toRawBytes(true)).toString('hex');
}
