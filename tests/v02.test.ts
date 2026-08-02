import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  canonicalize,
  createHttpsWebPkiResolver,
  createPinnedMetadataResolver,
  issuerMetadataHash,
  receiptDigestForAttestation,
  signIssuanceAttestation,
  signIssuerMetadata,
  signOpenReceipt,
  signOpenReceiptV02,
  verifyIssuerMetadata,
  verifyIssuerMetadataChain,
  verifyOpenReceipt,
  verifyOpenReceiptTrust,
  type Ed25519PublicJwk,
  type IssuerMetadataKeyV02,
  type IssuerMetadataV02,
  type OpenReceiptEvent,
  type OpenReceiptEventV02,
  type UnsignedIssuerMetadataV02,
} from "../src";

const ISSUER = "https://issuer.example";
const META_URL = `${ISSUER}/.well-known/receipt-issuer`;
// Public RFC 8032 deterministic test material only. Never use these seeds for
// production or any identity-bearing key.
const EVIDENCE_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const EVIDENCE_PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const METADATA_SEED = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const METADATA_PUBLIC = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
const LOG_SEED = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
const LOG_PUBLIC = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
const PKCS8_PREFIX = "302e020100300506032b657004220420";

function hexBytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));
}

function base64Url(hex: string): string {
  return Buffer.from(hexBytes(hex)).toString("base64url");
}

async function privateKey(seed: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "pkcs8",
    hexBytes(PKCS8_PREFIX + seed) as BufferSource,
    { name: "Ed25519" },
    false,
    ["sign"],
  );
}

function jwk(kid: string, publicHex: string): Ed25519PublicJwk {
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: base64Url(publicHex),
    kid,
    use: "sig",
    alg: "EdDSA",
  };
}

const evidenceJwk = jwk("evidence-2026-q3", EVIDENCE_PUBLIC);
const metadataJwk = jwk("metadata-2026-q3", METADATA_PUBLIC);
const logJwk = jwk("log-2026-q3", LOG_PUBLIC);

function metadataKey(
  purpose: IssuerMetadataKeyV02["purpose"],
  key: Ed25519PublicJwk,
  overrides: Partial<IssuerMetadataKeyV02> = {},
): IssuerMetadataKeyV02 {
  return {
    kid: key.kid,
    purpose,
    alg: "EdDSA",
    public_jwk: key,
    status: "active",
    valid_from: "2026-07-01T00:00:00Z",
    valid_until: null,
    activated_at: "2026-07-01T00:00:00Z",
    retired_at: null,
    revoked_at: null,
    revocation_effective_from: null,
    compromised_at: null,
    compromise_effective_from: null,
    destroyed_at: null,
    replaced_by_kid: null,
    reason_code: null,
    ...overrides,
  };
}

async function metadata(
  evidenceOverrides: Partial<IssuerMetadataKeyV02> = {},
  input: Partial<UnsignedIssuerMetadataV02> = {},
): Promise<IssuerMetadataV02> {
  const unsigned: UnsignedIssuerMetadataV02 = {
    schema: "https://receiptprotocol.com/open-receipt/v0.2/issuer-metadata.schema.json",
    issuer: ISSUER,
    metadata_version: 1,
    issued_at: "2026-07-30T12:00:00Z",
    next_update: "2026-07-31T12:00:00Z",
    previous_metadata_hash: null,
    keys: [
      metadataKey("open_receipt_evidence", evidenceJwk, evidenceOverrides),
      metadataKey("issuer_metadata", metadataJwk),
      metadataKey("issuance_log", logJwk),
    ],
    ...input,
  };
  return signIssuerMetadata(unsigned, await privateKey(METADATA_SEED), metadataJwk.kid);
}

async function event(
  issuerMetadata: IssuerMetadataV02,
  issuedAt = "2026-07-30T12:01:00Z",
  options: { kid?: string; attestation?: boolean; key?: CryptoKey } = {},
): Promise<OpenReceiptEventV02> {
  const kid = options.kid ?? evidenceJwk.kid;
  const unsigned: Omit<OpenReceiptEventV02, "signature"> = {
    spec_version: "0.2",
    event_id: "evt_test_1",
    event_type: "settlement.completed",
    issuer: {
      id: ISSUER,
      name: "Test issuer",
      metadata_url: META_URL,
      verification_key: { ...evidenceJwk, kid },
    },
    issued_at: issuedAt,
    transaction_id: "tx_test_1",
    quote_id: "quote_test_1",
    commercial_facts: { buyer_total_cents: 5, currency: "USD" },
    evidence: { delivered: true },
    provenance: { provider: "test" },
    assurance: "validated",
    parent_event_hashes: [],
    signing_key_id: kid,
    issuer_metadata_version: issuerMetadata.metadata_version,
    issuer_metadata_hash: await issuerMetadataHash(issuerMetadata),
  };
  if (options.attestation) {
    const receiptDigest = await receiptDigestForAttestation({ ...unsigned, signature: "" });
    unsigned.issuance_attestation = await signIssuanceAttestation(
      {
        type: "open_receipt_issuance_attestation",
        version: 1,
        issuer: ISSUER,
        sequence: 7,
        receipt_digest: receiptDigest,
        evidence_signing_key_id: kid,
        issued_at: issuedAt,
        previous_entry_hash: `sha256:${"1".repeat(64)}`,
        log_signing_key_id: logJwk.kid,
      },
      await privateKey(LOG_SEED),
    );
  }
  return signOpenReceiptV02(unsigned, options.key ?? (await privateKey(EVIDENCE_SEED)));
}

async function pinned(
  value: OpenReceiptEventV02,
  issuerMetadata: IssuerMetadataV02,
  now = "2026-07-30T12:02:00Z",
) {
  return verifyOpenReceiptTrust(value, {
    trustMode: "pinned_metadata",
    pinnedMetadata: issuerMetadata,
    pinnedMetadataHash: await issuerMetadataHash(issuerMetadata),
    resolvedAt: "2026-07-30T12:01:30Z",
    now,
  });
}

describe("Open Receipt 0.2 public trust vectors", () => {
  it("publishes the complete 30-vector catalog", () => {
    const manifest = JSON.parse(
      readFileSync(
        resolve(import.meta.dir, "../test-vectors/v0.2/manifest.json"),
        "utf8",
      ),
    ) as { vectors: Array<{ id: number }> };
    expect(manifest.vectors.map((vector) => vector.id)).toEqual(
      Array.from({ length: 30 }, (_, index) => index + 1),
    );
  });

  it("01 active evidence key, trusted issuer, fresh metadata", async () => {
    const document = await metadata();
    const result = await pinned(await event(document), document);
    expect(result.overall_status).toBe("valid_with_warnings");
    expect(result.signature.valid).toBe(true);
    expect(result.issuer.trusted).toBe(true);
    expect(result.key.conclusion).toBe("valid_at_issuance");
  });

  it("verifies canonical sha256-prefixed v0.2 parent references", async () => {
    const issuerMetadata = await metadata();
    const base = await event(issuerMetadata);
    const { signature: _signature, ...unsigned } = base;
    const canonical = await signOpenReceiptV02(
      { ...unsigned, parent_event_hashes: [`sha256:${"a".repeat(64)}`] },
      await privateKey(EVIDENCE_SEED),
    );
    const result = await pinned(canonical, issuerMetadata);
    expect(result.signature.valid).toBe(true);
  });

  it("verifies immutable early-v0.2 events that used a bare SHA-256 parent digest", async () => {
    const issuerMetadata = await metadata();
    const base = await event(issuerMetadata);
    const { signature: _signature, ...unsigned } = base;
    const historical = await signOpenReceiptV02(
      { ...unsigned, parent_event_hashes: ["a".repeat(64)] },
      await privateKey(EVIDENCE_SEED),
    );
    const result = await pinned(historical, issuerMetadata);
    expect(result.signature.valid).toBe(true);
  });

  it("02 embedded key is cryptographically valid but issuer is untrusted", async () => {
    const document = await metadata();
    const result = await verifyOpenReceiptTrust(await event(document));
    expect(result.signature.valid).toBe(true);
    expect(result.issuer.trusted).toBe(false);
    expect(result.overall_status).toBe("indeterminate");
  });

  it("03 pinned metadata verification", async () => {
    const document = await metadata(
      {},
      {
        metadata_version: 12,
        previous_metadata_hash: `sha256:${"a".repeat(64)}`,
      },
    );
    const documentHash = await issuerMetadataHash(document);
    const result = await verifyOpenReceiptTrust(await event(document), {
      trustMode: "pinned_metadata",
      resolver: createPinnedMetadataResolver({
        metadata: document,
        metadataHash: documentHash,
        resolvedAt: "2026-07-30T12:01:30Z",
      }),
      now: "2026-07-30T12:02:00Z",
    });
    expect(result.issuer.trust_mode).toBe("pinned_metadata");
    expect(result.issuer.trusted).toBe(true);
    expect(result.metadata.chain_valid).toBe(true);
  });

  it("04 HTTPS-resolved metadata verification", async () => {
    const document = await metadata();
    const signed = await event(document);
    const resolver = createHttpsWebPkiResolver({
      allowedIssuerOrigins: [ISSUER],
      now: () => new Date("2026-07-30T12:01:30Z"),
      fetch: async () =>
        new Response(JSON.stringify(document), {
          headers: { "content-type": "application/open-receipt-issuer+json", etag: '"v1"' },
        }),
    });
    const result = await verifyOpenReceiptTrust(signed, {
      trustMode: "https_webpki",
      resolver,
      now: "2026-07-30T12:02:00Z",
    });
    expect(result.issuer.trusted).toBe(true);
  });

  it("05 retired key remains valid during its issuance window", async () => {
    const document = await metadata({
      status: "retired",
      retired_at: "2026-08-01T00:00:00Z",
      valid_until: "2026-08-01T00:00:00Z",
    });
    expect((await pinned(await event(document), document)).key.historical_result).toBe(
      "retired_key_valid_at_issuance",
    );
  });

  it("06 signing after retirement is invalid", async () => {
    const document = await metadata({
      status: "retired",
      retired_at: "2026-07-29T00:00:00Z",
      valid_until: "2026-08-02T00:00:00Z",
    });
    expect((await pinned(await event(document), document)).key.historical_result).toBe(
      "signed_after_retirement",
    );
  });

  it("07 signing before prospective revocation remains historically valid", async () => {
    const document = await metadata({
      status: "revoked",
      revoked_at: "2026-08-01T00:00:00Z",
    });
    expect((await pinned(await event(document), document)).key.historical_result).toBe(
      "signed_before_revocation",
    );
  });

  it("08 signing at or after revocation is invalid", async () => {
    const document = await metadata({
      status: "revoked",
      revoked_at: "2026-07-30T12:00:00Z",
    });
    const result = await pinned(await event(document), document);
    expect(result.key.conclusion).toBe("signed_after_revocation");
    expect(result.overall_status).toBe("invalid");
  });

  it("09 signing before compromise with a valid issuance attestation", async () => {
    const document = await metadata({
      status: "compromised",
      compromised_at: "2026-08-01T00:00:00Z",
      compromise_effective_from: "2026-08-01T00:00:00Z",
    });
    const result = await pinned(await event(document, undefined, { attestation: true }), document);
    expect(result.issuance_attestation.status).toBe("valid");
    expect(result.key.historical_result).toBe("signed_before_compromise");
  });

  it("10 signing after compromise is invalid", async () => {
    const document = await metadata({
      status: "compromised",
      compromised_at: "2026-07-30T12:00:00Z",
      compromise_effective_from: "2026-07-30T12:00:00Z",
    });
    expect((await pinned(await event(document), document)).key.conclusion).toBe(
      "signed_after_compromise",
    );
  });

  it("11 unknown compromise time is indeterminate", async () => {
    const document = await metadata({
      status: "compromised",
      compromised_at: "2026-08-01T00:00:00Z",
      compromise_effective_from: null,
    });
    expect((await pinned(await event(document), document)).key.historical_result).toBe(
      "compromise_time_unknown",
    );
  });

  it("12 stale offline metadata reports its knowledge boundary", async () => {
    const document = await metadata();
    const result = await pinned(await event(document), document, "2026-08-03T12:00:00Z");
    expect(result.metadata_as_of).toBe("2026-07-30T12:00:00.000Z");
    expect(result.metadata_freshness).toBe("stale");
    expect(result.key_valid_as_of_metadata).toBe(true);
  });

  it("13 tampered metadata signature fails", async () => {
    const document = await metadata();
    document.signature.value = document.signature.value.replace(/.$/, "A");
    expect((await verifyIssuerMetadata(document)).signature_valid).toBe(false);
  });

  it("14 broken metadata hash chain fails", async () => {
    const first = await metadata();
    const second = await metadata(
      {},
      {
        metadata_version: 2,
        issued_at: "2026-07-31T12:00:00Z",
        next_update: "2026-08-01T12:00:00Z",
        previous_metadata_hash: `sha256:${"f".repeat(64)}`,
      },
    );
    expect((await verifyIssuerMetadataChain([first, second])).valid).toBe(false);
  });

  it("15 wrong key purpose cannot validate evidence", async () => {
    const document = await metadata();
    document.keys[0] = metadataKey("issuance_log", evidenceJwk);
    document.signature = (
      await signIssuerMetadata(
        (({ signature: _signature, ...unsigned }) => unsigned)(document),
        await privateKey(METADATA_SEED),
        metadataJwk.kid,
      )
    ).signature;
    const signed = await event(document);
    expect((await pinned(signed, document)).key.historical_result).toBe("key_purpose_mismatch");
  });

  it("16 unknown kid fails closed", async () => {
    const document = await metadata();
    expect(
      (await pinned(await event(document, undefined, { kid: "unknown" }), document)).key
        .historical_result,
    ).toBe("key_unknown");
  });

  it("17 a key not yet valid fails closed", async () => {
    const document = await metadata({ valid_from: "2026-08-01T00:00:00Z" });
    expect((await pinned(await event(document), document)).key.historical_result).toBe(
      "key_not_yet_valid",
    );
  });

  it("18 an expired key fails closed", async () => {
    const document = await metadata({ valid_until: "2026-07-29T00:00:00Z" });
    expect((await pinned(await event(document), document)).key.historical_result).toBe(
      "key_expired",
    );
  });

  it("19 a valid issuance-log attestation verifies", async () => {
    const document = await metadata();
    expect(
      (await pinned(await event(document, undefined, { attestation: true }), document))
        .issuance_attestation.status,
    ).toBe("valid");
  });

  it("20 an invalid issuance-log signature fails", async () => {
    const document = await metadata();
    const signed = await event(document, undefined, { attestation: true });
    signed.issuance_attestation!.signature += "A";
    expect((await pinned(signed, document)).issuance_attestation.status).toBe("invalid");
  });

  it("21 an issuance receipt digest mismatch fails", async () => {
    const document = await metadata();
    const signed = await event(document, undefined, { attestation: true });
    signed.issuance_attestation!.receipt_digest = `sha256:${"0".repeat(64)}`;
    expect((await pinned(signed, document)).errors).toContain(
      "attestation_receipt_digest_mismatch",
    );
  });

  it("22 a v0.1 receipt without issuance attestation still verifies", async () => {
    const unsigned: Omit<OpenReceiptEvent, "signature"> = {
      spec_version: "0.1",
      event_id: "evt_v01",
      event_type: "settlement.completed",
      issuer: { id: ISSUER, metadata_url: META_URL, verification_key: evidenceJwk },
      issued_at: "2026-07-30T12:01:00Z",
      transaction_id: "tx_v01",
      quote_id: null,
      commercial_facts: {},
      evidence: {},
      provenance: {},
      assurance: "validated",
      parent_event_hashes: [],
      signing_key_id: evidenceJwk.kid,
    };
    const signed = await signOpenReceipt(unsigned, await privateKey(EVIDENCE_SEED));
    expect((await verifyOpenReceipt(signed)).valid).toBe(true);
  });

  it("23 cross-purpose signing attempts are blocked", async () => {
    const document = await metadata();
    const signed = await event(document);
    const { signature: _signature, ...unsigned } = signed;
    expect(
      signOpenReceiptV02(unsigned, await privateKey(EVIDENCE_SEED), "commerce_quote"),
    ).rejects.toThrow("key_purpose_mismatch");
  });

  it("24 planned key rotation preserves the old public key", async () => {
    const document = await metadata({
      status: "retired",
      retired_at: "2026-08-01T00:00:00Z",
      replaced_by_kid: "evidence-2026-q4",
    });
    document.keys.push(
      metadataKey("open_receipt_evidence", jwk("evidence-2026-q4", LOG_PUBLIC), {
        status: "preactive",
        activated_at: null,
      }),
    );
    expect(document.keys.map((key) => key.status)).toContain("retired");
    expect(document.keys.map((key) => key.status)).toContain("preactive");
  });

  it("25 emergency compromise can designate a replacement", async () => {
    const document = await metadata({
      status: "compromised",
      compromised_at: "2026-07-30T12:00:00Z",
      compromise_effective_from: "2026-07-30T12:00:00Z",
      replaced_by_kid: "evidence-2026-q4",
      reason_code: "key_material_exposed",
    });
    expect(document.keys[0]!.status).toBe("compromised");
    expect(document.keys[0]!.replaced_by_kid).toBe("evidence-2026-q4");
  });

  it("26 a historical receipt remains verifiable after retirement", async () => {
    const document = await metadata({
      status: "retired",
      retired_at: "2026-08-01T00:00:00Z",
    });
    expect((await pinned(await event(document), document)).signature.valid).toBe(true);
  });

  it("27 a backdated compromised-key receipt without a log attestation is indeterminate", async () => {
    const document = await metadata({
      status: "compromised",
      compromised_at: "2026-08-01T00:00:00Z",
      compromise_effective_from: "2026-08-01T00:00:00Z",
    });
    expect((await pinned(await event(document), document)).overall_status).toBe("indeterminate");
  });

  it("28 equivalent Z and +00:00 timestamps canonicalize identically", async () => {
    const document = await metadata();
    const a = await event(document, "2026-07-30T12:01:00Z");
    const b = await event(document, "2026-07-30T12:01:00+00:00");
    expect(a.signature).toBe(b.signature);
    expect(canonicalize(a)).toBe(canonicalize(b));
  });

  it("29 invalid timestamps fail closed", async () => {
    const document = await metadata();
    expect(event(document, "not-a-time")).rejects.toThrow("invalid_timestamp");
  });

  it("30 metadata version replay or rewrite is rejected by the HTTPS cache", async () => {
    const first = await metadata();
    const rewritten = { ...first, next_update: "2026-08-02T00:00:00.000Z" };
    let calls = 0;
    const resolver = createHttpsWebPkiResolver({
      allowedIssuerOrigins: [ISSUER],
      fetch: async () =>
        new Response(JSON.stringify(calls++ === 0 ? first : rewritten), {
          headers: { "content-type": "application/json" },
        }),
    });
    const firstHash = await issuerMetadataHash(first);
    await resolver.resolve({ issuer: ISSUER, metadataVersion: 1, metadataHash: firstHash });
    await expect(
      resolver.resolve({
        issuer: ISSUER,
        metadataVersion: 1,
        metadataHash: await issuerMetadataHash(rewritten),
      }),
    ).rejects.toThrow("metadata_version_rollback_or_rewrite");
  });

  it("rejects an issuance attestation made by a compromised log key", async () => {
    const document = await metadata(
      {},
      {
        keys: [
          metadataKey("open_receipt_evidence", evidenceJwk),
          metadataKey("issuer_metadata", metadataJwk),
          metadataKey("issuance_log", logJwk, {
            status: "compromised",
            compromised_at: "2026-07-30T12:00:00Z",
            compromise_effective_from: "2026-07-30T12:00:00Z",
          }),
        ],
      },
    );
    const result = await pinned(await event(document, undefined, { attestation: true }), document);
    expect(result.issuance_attestation.status).toBe("invalid");
    expect(result.errors).toContain("attestation_log_key_not_authorized_at_issuance");
  });

  it("rejects private-network issuer origins before fetching metadata", async () => {
    let fetched = false;
    const resolver = createHttpsWebPkiResolver({
      allowedIssuerOrigins: ["https://127.0.0.1"],
      fetch: async () => {
        fetched = true;
        return new Response();
      },
    });
    await expect(
      resolver.resolve({
        issuer: "https://127.0.0.1",
        metadataVersion: 1,
        metadataHash: `sha256:${"0".repeat(64)}`,
      }),
    ).rejects.toThrow("issuer_origin_not_allowed");
    expect(fetched).toBe(false);
  });

  it("rejects issuer metadata redirects without following them", async () => {
    const resolver = createHttpsWebPkiResolver({
      allowedIssuerOrigins: [ISSUER],
      fetch: async () =>
        new Response(null, {
          status: 302,
          headers: { location: "https://attacker.example/metadata" },
        }),
    });
    await expect(
      resolver.resolve({
        issuer: ISSUER,
        metadataVersion: 1,
        metadataHash: `sha256:${"0".repeat(64)}`,
      }),
    ).rejects.toThrow("issuer_redirect_rejected");
  });

  it("preserves historical metadata across metadata-key compromise and replacement", async () => {
    const first = await metadata();
    const replacementMetadataJwk = jwk("metadata-2026-q4", LOG_PUBLIC);
    const second = await signIssuerMetadata(
      {
        schema: "https://receiptprotocol.com/open-receipt/v0.2/issuer-metadata.schema.json",
        issuer: ISSUER,
        metadata_version: 2,
        issued_at: "2026-07-31T12:00:00Z",
        next_update: "2026-08-01T12:00:00Z",
        previous_metadata_hash: await issuerMetadataHash(first),
        keys: [
          metadataKey("open_receipt_evidence", evidenceJwk),
          metadataKey("issuer_metadata", metadataJwk, {
            status: "compromised",
            compromised_at: "2026-07-31T00:00:00Z",
            compromise_effective_from: "2026-07-31T00:00:00Z",
            replaced_by_kid: replacementMetadataJwk.kid,
          }),
          metadataKey("issuer_metadata", replacementMetadataJwk, {
            activated_at: "2026-07-31T00:00:00Z",
          }),
        ],
      },
      await privateKey(LOG_SEED),
      replacementMetadataJwk.kid,
    );
    expect((await verifyIssuerMetadata(first)).valid).toBe(true);
    expect((await verifyIssuerMetadata(second, first)).valid).toBe(true);
    expect(second.keys.find((key) => key.kid === metadataJwk.kid)?.status).toBe("compromised");
  });
});
