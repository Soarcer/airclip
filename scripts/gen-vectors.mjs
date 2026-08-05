// P2 — deterministic test-vector generator. `node scripts/gen-vectors.mjs` overwrites
// packages/protocol/test-vectors.json. Uses libsodium-wrappers; fixed seeds/nonces only.
// Cases required (PHASE1_TASKS P2): 3 keypairs, kx both roles, 5 sealed envelopes covering
// each AAD (POST /v1/clip, GET /v1/clip/latest), 1 tampered-ct, 1 wrong-AAD negative.
console.error("TODO P2 — see docs/PHASE1_TASKS.md");
process.exit(1);
