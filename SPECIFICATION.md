# Open Receipt v0.1

Formal name: **Receipt Evidence Specification v0.1**

Open Receipt defines one portable, signed evidence-event envelope. It does not
standardize Receipt's catalogue, routing, mandates, wallets, payment rails,
remedies, seller contracts, or Receipt Score.

## Event envelope

Every event contains `spec_version`, `event_id`, `event_type`, `issuer`,
`issued_at`, `transaction_id`, `quote_id`, `commercial_facts`, `evidence`,
`provenance`, `assurance`, `parent_event_hashes`, `signing_key_id`, and
`signature`.

The initial event types are:

- `quote.issued`
- `authorization.granted`
- `execution.attempted`
- `validation.completed`
- `settlement.completed`
- `reversal.issued`

The initial assurance values are `delivered` and `validated`. `validated` may
be used only when a bound validator actually ran and passed. `guaranteed` is
reserved for possible future work and is not a v0.1 assurance value.

## Canonicalization and signature

Remove the top-level `signature` property, canonicalize the remaining JSON with
RFC 8785, and UTF-8 encode it. The signature is a detached compact JWS:

```
BASE64URL(protected)..BASE64URL(signature)
```

The protected header is canonical JSON containing `alg: EdDSA`, the matching
`kid`, and `typ: open-receipt+jws`. The JWS signing input is the protected
segment, a period, and the base64url-encoded canonical event bytes. The
signature algorithm is Ed25519.

`parent_event_hashes` contains `sha256:` followed by the lowercase SHA-256 hash
of each complete, signed parent event's canonical JSON. A standalone event can
have a valid signature while reporting a partial chain when its parents are not
present. A bundle permits complete offline chain checking.

## Issuer metadata and trust

Issuer metadata is published at `/.well-known/receipt-issuer`. It contains
current and retained historical public keys. An embedded JWK permits offline
mathematical verification, but verifiers must compare it with metadata obtained
through a trusted path before treating the claimed issuer identity as trusted.

No private key, provider credential, private diagnostic, raw fixture body, or
buyer PII belongs in an Open Receipt.

## Schemas and implementation

- Event schema: `/open-receipt/v0.1/event.schema.json`
- Bundle schema: `/open-receipt/v0.1/bundle.schema.json`
- Issuer schema: `/open-receipt/v0.1/issuer.schema.json`
- TypeScript verifier: `packages/open-receipt`
- CLI: `receipt verify ./receipt.json`

The published vectors include a Delivered v0.1 event, a validation-enabled v0.1
bundle, and all required tamper cases signed by a non-production test key. The
repository also preserves the live homepage's already-completed signed Receipt
as `production-legacy.valid.json` with its published public key. That artifact's
Ed25519 signature is tested entirely offline. It remains explicitly typed as
`com.receiptprotocol.receipt.v1`; it is a production compatibility/provenance
vector and is not misrepresented as a newly signed Open Receipt v0.1 event.

Open Receipt v0.1 is an early open specification, not an adopted industry
standard. It is deliberately narrow and does not imply a universal guarantee.
