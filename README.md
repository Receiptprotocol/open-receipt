# Open Receipt v0.1 verifier

`@receiptprotocol/open-receipt` canonicalizes and verifies Receipt Evidence
Specification v0.1 events locally. Verification does not call Receipt's API.

```ts
import { verifyOpenReceipt, verifyOpenReceiptBundle } from "@receiptprotocol/open-receipt";

const result = await verifyOpenReceipt(receipt, { issuerMetadata: cachedMetadata });
if (!result.valid) throw new Error(result.errors.join(", "));
```

An embedded public JWK is sufficient to prove that the document was signed by
the corresponding private key. It is not, by itself, proof of the issuer's
identity. Pass cached issuer metadata obtained through a trusted path to pin the
issuer identity and set `issuer_identity_trusted` to `true`.

The event is canonicalized with RFC 8785 JSON Canonicalization Scheme rules and
signed as a detached compact JWS using Ed25519 (`alg: EdDSA`). Parent event
hashes are SHA-256 digests of complete signed parent envelopes.

Open Receipt v0.1 is an early open specification, not an adopted industry
standard. `validated` means a bound validator ran and passed for that event; it
does not mean a permanent certification or universal guarantee.

## Repository contents

- [`SPECIFICATION.md`](./SPECIFICATION.md): Receipt Evidence Specification v0.1.
- [`schemas`](./schemas): explicit event, bundle, and issuer JSON Schemas.
- [`test-vectors`](./test-vectors): public valid, invalid, and compatibility vectors.
- [`src`](./src): dependency-free TypeScript verifier source.
- [`examples`](./examples): offline verification example.

Run `bun install --frozen-lockfile` and `bun run check` to type-check, test, and
build the package.
