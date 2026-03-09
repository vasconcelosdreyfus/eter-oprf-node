// P-256 OPRF (RFC 9497 / 2HashDH)
export {
  hashToGroup,
  evaluateBlindedElement,
  computeOprfToken,
  computeOprfTokenFromShares,
  evaluateWithShare,
} from './oprf.js';

// Ristretto255 multi-scalar commitments + Schnorr ZK proofs
export {
  computeRistrettoCommitment,
  proveRistrettoCommitment,
  verifyRistrettoProof,
} from './ristretto.js';

export type { SchnorrProof } from './ristretto.js';
