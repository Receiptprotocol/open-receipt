# Changelog

## 0.2.1 - 2026-08-02

- Accept both canonical `sha256:<digest>` parent references and immutable
  historical bare SHA-256 parent references.

## 0.2.0 - 2026-07-30

- Add issuer trust resolution through embedded, pinned-metadata, and HTTPS
  WebPKI modes.
- Add signed, versioned issuer metadata.
- Add purpose-bound key lifecycle and historical verification.
- Add issuance attestations and signed issuance-log checkpoints.
- Preserve v0.1 APIs, schemas, vectors, and verification behavior.

## 0.1.0 - 2026-07-21

- Publish Receipt Evidence Specification v0.1, explicit JSON Schemas, public
  verification vectors, and the dependency-free TypeScript verifier.
