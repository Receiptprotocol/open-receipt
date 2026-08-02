# Open Receipt 0.2

Open Receipt is an open, versioned specification for portable, verifiable
commercial evidence. Version 0.2 adds issuer trust resolution, purpose-bound
key lifecycle, historical verification, and issuance attestations. It remains
backward compatible with Open Receipt 0.1.

Open Receipt standardizes the evidence envelope and its verification model. It
does not standardize catalogues, routing, mandates, wallets, payment rails,
seller contracts, remedies, or regulatory conclusions.

## 1. Event envelope

An Open Receipt 0.2 event is a JSON object with these fields:

- `spec_version`: the string `0.2`;
- `event_id`: a stable identifier for this evidence event;
- `event_type`: the commercial event represented;
- `issuer`: the issuer identity, metadata reference, and embedded verification
  key;
- `issued_at`: a normalized RFC 3339 timestamp;
- `transaction_id` and `quote_id`: correlation identifiers;
- `commercial_facts`, `evidence`, and `provenance`: event-specific public
  evidence;
- `assurance`: the issuer's declared assurance level;
- `parent_event_hashes`: immutable references to parent evidence;
- `signing_key_id`: the evidence key identifier;
- `issuer_metadata_version` and `issuer_metadata_hash`: the exact issuer
  metadata snapshot used at issuance;
- `issuance_attestation`: an optional separately signed issuance-log entry;
- `signature`: the evidence signature.

The initial event types remain:

- `quote.issued`
- `authorization.granted`
- `execution.attempted`
- `validation.completed`
- `settlement.completed`
- `reversal.issued`

The JSON Schemas in [`schemas`](./schemas) define the complete structural
requirements. Unknown business fields belong inside the open evidence objects,
not as replacements for protocol fields.

## 2. Canonicalization and evidence signature

To sign an event, remove the top-level `signature` property, normalize supported
timestamps, canonicalize the remaining JSON using RFC 8785 JSON Canonicalization
Scheme rules, and UTF-8 encode the result.

The signature is a detached compact JWS:

```text
BASE64URL(protected)..BASE64URL(signature)
```

The protected header is canonical JSON containing `alg: EdDSA`, the matching
`kid`, and `typ: open-receipt+jws`. The signing input is the protected segment,
a period, and the base64url-encoded canonical event bytes. The signature
algorithm is Ed25519.

The signing key MUST have the `open_receipt_evidence` purpose and MUST be active
at issuance. A matching embedded public key proves signature consistency; it
does not, by itself, establish a trusted issuer identity.

## 3. Parent evidence chains

`parent_event_hashes` links an event to complete, signed parent envelopes. The
canonical reference form is `sha256:` followed by the lowercase SHA-256 digest
of the complete signed parent's canonical JSON.

Version 0.2.1 also accepts immutable early receipts that encoded the same
64-character lowercase SHA-256 digest without the `sha256:` prefix. New events
SHOULD use the prefixed canonical form. Verifiers MUST NOT rewrite or re-sign a
historical event merely to change its parent reference representation.

A standalone event can have a valid signature while reporting an incomplete
chain. A bundle supplies parent events for offline chain verification. A
verifier distinguishes signature validity from chain completeness and rejects
a supplied parent whose digest does not match its reference.

## 4. Issuer metadata references

Every 0.2 event identifies:

- the HTTPS issuer origin;
- the issuer metadata URL;
- an exact `issuer_metadata_version`;
- the canonical `issuer_metadata_hash` for that version;
- the evidence signing key ID and embedded public JWK.

The current issuer snapshot is published at
`/.well-known/receipt-issuer`. Exact historical snapshots are published at
`/.well-known/receipt-issuer/versions/{metadata_version}`.

Each issuer metadata snapshot contains a monotonically increasing version,
issuer, issue and freshness times, previous-version hash, public-purpose keys,
key lifecycle facts, and a metadata-key signature. Snapshots are immutable and
hash-chained. The metadata signature covers the canonical metadata document,
including its signature key ID and algorithm, while excluding only the
signature value.

## 5. Purpose-bound keys

Every registered key has one exact machine-readable purpose:

| Purpose | Authorized use | Public issuer metadata |
| --- | --- | --- |
| `open_receipt_evidence` | Open Receipt evidence | yes |
| `issuer_metadata` | issuer metadata snapshots | yes |
| `issuance_log` | attestations and checkpoints | yes |
| `commerce_quote` | canonical quotes | no |
| `purchase_approval` | purchase approval records | no |
| `oauth_or_authentication` | authentication only | no |

A public-key fingerprint MUST NOT be registered for multiple purposes.
Evidence signatures confer no wallet, purchase, allowance, approval, account,
or authentication authority. Cross-purpose signing and verification attempts
fail closed.

## 6. Key lifecycle

Issuer metadata records lifecycle state and timestamps:

- `preactive`: published for preparation and not authorized to sign;
- `active`: authorized to sign for its exact purpose;
- `retired`: no longer authorized to sign; historical signatures issued before
  `retired_at` and within the validity window remain eligible;
- `revoked`: signatures at or after `revocation_effective_from` are invalid;
  older metadata without a separate effective time uses `revoked_at`;
- `compromised`: signatures at or after `compromise_effective_from` are invalid
  or untrusted; when the effective time is unknown, the verifier does not
  invent a safe period;
- `destroyed`: private material is unavailable while public verification
  metadata remains.

Keys rotate; existing Receipt signatures do not. A Receipt retains its original
signature and `signing_key_id`, and the issuer retains historical public keys.
The metadata can name a replacement key without changing old evidence.

## 7. Trust resolution

`verifyOpenReceiptTrust` supports three trust modes:

- `embedded_only`: validates signature consistency with the embedded key and
  leaves issuer identity untrusted;
- `pinned_metadata`: uses an explicitly trusted signed metadata snapshot and
  hash, including controlled offline verification;
- `https_webpki`: resolves the exact version from an allowlisted HTTPS issuer
  origin and validates the signed hash chain.

The HTTPS resolver rejects arbitrary metadata URLs, non-HTTPS origins,
unallowlisted origins, private or local literal hosts, redirects, invalid
content types, oversized responses, rewritten cached versions, and broken
chains. Implementations use bounded timeouts, ETags, and a maximum chain length.

## 8. Historical verification and freshness

Verification answers separate questions:

1. Does the canonical event match its Ed25519 detached JWS?
2. Which issuer does the event claim?
3. Which configured trust path resolved that issuer?
4. Did the resolved metadata authorize the evidence key at issuance?
5. What key lifecycle state applied at issuance?
6. What newer state was known by the resolved metadata snapshot?
7. Is the snapshot fresh enough for the verifier's policy?
8. Does an independent issuance attestation support the issuance time?

The result reports the metadata snapshot time and freshness separately from
signature validity. An offline verifier cannot discover a revocation or
compromise published after its cached snapshot. Stale metadata therefore does
not invalidate a mathematical signature, but it limits the verifier's claim
about current key state.

Historical conclusions distinguish active or retired validity at issuance,
signing after retirement, signing before or after revocation, signing before or
after compromise, unknown compromise time, validity-window failures, wrong
purpose, unknown key, stale metadata, and untrusted issuer.

## 9. Issuance attestations

An issuance attestation is signed by an independent `issuance_log` key and
binds:

- issuer;
- append-only sequence;
- Receipt digest;
- evidence signing key ID;
- issuance time;
- previous and current entry hashes;
- log signing key ID and signature.

The attestation signature and Receipt digest MUST both validate. The log key
MUST be authorized at issuance. A pre-compromise evidence claim needs stronger
evidence against backdating; a valid independent log attestation can provide
that evidence. Without it, the verifier returns an indeterminate conclusion
instead of inventing certainty.

Public entries contain no transaction input or output, buyer identity, private
commercial payload, provider credential, or private signing material.

## 10. Issuance-log checkpoints

An issuer may publish a signed checkpoint at
`/.well-known/receipt-issuer/checkpoint`. A checkpoint commits to the issuer,
latest sequence, latest entry hash, checkpoint time, metadata version, and log
key signature.

Published entries and checkpoints are immutable. Checkpoints allow a verifier
to compare an attestation with a later trusted commitment to the append-only
log. They strengthen consistency and backdating detection; they do not reveal
the Receipt's private payload and do not replace event or metadata signature
verification.

## 11. Assurance semantics

The event-level assurance values remain `delivered` and `validated`.
`validated` means a bound validator ran and passed for that event. It does not
mean permanent certification, universal correctness, regulatory approval, or a
guarantee.

The trust-aware verifier separately returns:

- `overall_status`: `valid`, `valid_with_warnings`, `invalid`, or
  `indeterminate`;
- mathematical signature validity;
- claimed, resolved, and trusted issuer;
- metadata signature, chain, freshness, and knowledge time;
- key purpose and lifecycle conclusion;
- issuance-attestation status;
- machine-readable warnings and errors.

Consumers MUST apply their own policy to these separate facts. They MUST NOT
collapse an embedded-key signature into an issuer-identity claim.

## 12. Open Receipt 0.1 compatibility

The v0.1 event, bundle, and issuer schemas remain available. The
`verifyOpenReceipt` and `verifyOpenReceiptBundle` APIs retain their established
meaning, and the original deterministic v0.1 vectors remain part of the test
suite.

Existing v0.1 Receipts are not rewritten or re-signed. A v0.1 Receipt without
an issuance attestation remains cryptographically verifiable with lower trust
assurance. Historical v0.1 documentation and source remain permanently
available through the `v0.1.0` tag.

## 13. Conformance and security

Conformance is defined together by this specification, the JSON Schemas, the
deterministic public vectors, and verifier behavior for each supported version.
The v0.2 catalog contains 30 trust and lifecycle cases, including positive,
negative, historical, replay, freshness, and compatibility behavior.

No private key, provider credential, raw private payload, buyer personal data,
or production secret belongs in an Open Receipt, public issuer document, test
vector, or this repository. Private signing material remains in the issuer's
signing provider; only public keys, fingerprints, purposes, and lifecycle facts
are published.
