# Open Receipt 0.2

Open Receipt is an open, versioned specification for portable, verifiable
commercial evidence.

Open Receipt 0.2 adds issuer trust resolution, purpose-bound key lifecycle,
historical verification, and issuance attestations while remaining backward
compatible with v0.1.

Install the current verifier:

```sh
npm install @receiptprotocol/open-receipt@0.2.1
```

## Trust-aware verification

```ts
import {
  createHttpsWebPkiResolver,
  verifyOpenReceiptTrust,
} from "@receiptprotocol/open-receipt";

const resolver = createHttpsWebPkiResolver({
  allowedIssuerOrigins: ["https://receiptprotocol.com"],
});

const result = await verifyOpenReceiptTrust(receipt, {
  trustMode: "https_webpki",
  resolver,
});

if (!result.signature.valid || !result.issuer.trusted) {
  throw new Error(result.errors.join(", "));
}
```

Cryptographic signature validity and issuer identity trust are reported
separately. The verifier supports three trust modes:

- `embedded_only` verifies the signature against the embedded public key but
  does not establish a trusted issuer identity.
- `pinned_metadata` verifies against an explicitly trusted signed issuer
  metadata snapshot and hash, including offline use.
- `https_webpki` resolves the exact signed metadata version from an allowlisted
  HTTPS issuer origin and validates its hash chain.

## Issuer trust and key lifecycle

Open Receipt 0.2 issuer metadata is signed, versioned, immutable, and
hash-chained. Public keys are bound to one purpose, including
`open_receipt_evidence`, `issuer_metadata`, and `issuance_log`.

Lifecycle states distinguish preactive, active, retired, revoked, compromised,
and destroyed keys. Historical verification evaluates the key state at the
Receipt's issuance time. Retired public keys remain available for verification;
revocation and compromise are evaluated from their effective timestamps.

## Issuance attestations and checkpoints

An optional issuance attestation binds a Receipt digest, evidence signing key,
issuance time, and append-only sequence under a separate issuance-log key.
Signed checkpoints commit to the current log position and hash. Together they
provide stronger evidence against fraudulent backdating after an evidence-key
compromise without exposing private commercial payloads.

## v0.1 compatibility

The original `verifyOpenReceipt` and `verifyOpenReceiptBundle` APIs, v0.1
schemas, and deterministic vectors remain supported. Existing v0.1 Receipts
are not rewritten or re-signed. A v0.1 Receipt without an issuance attestation
remains cryptographically verifiable with lower trust assurance.

## Repository contents

- [`SPECIFICATION.md`](./SPECIFICATION.md) — Open Receipt 0.2 specification and
  v0.1 compatibility rules.
- [`schemas`](./schemas) — v0.1 and v0.2 JSON Schemas.
- [`test-vectors`](./test-vectors) — preserved v0.1 vectors and the 30-case
  deterministic v0.2 trust catalog.
- [`src`](./src) — dependency-free TypeScript verifier source.
- [`examples`](./examples) — trust-aware verification example.

Run `bun install --frozen-lockfile` and `bun run check` to type-check, test, and
build the package.

Learn more at [receiptprotocol.com/open-receipt](https://receiptprotocol.com/open-receipt)
or view the package on [npm](https://www.npmjs.com/package/@receiptprotocol/open-receipt).
