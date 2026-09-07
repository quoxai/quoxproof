// Parity helper: emit the REAL ward-sdk canonical string + payload hash for each
// value read from stdin (a JSON array), so the Python port can be diffed against
// it byte-for-byte. Run: node ward_canonical_parity.mjs < values.json
import { canonicalize, sha256, payloadHash } from "/home/control/ward-sdk/dist/src/crypto.js";

let raw = "";
process.stdin.on("data", (c) => (raw += c));
process.stdin.on("end", () => {
  const values = JSON.parse(raw);
  const out = values.map((v) => ({
    canonical: canonicalize(v),
    hash: payloadHash(v),
    sha256_of_canonical: sha256(canonicalize(v)),
  }));
  process.stdout.write(JSON.stringify(out));
});
