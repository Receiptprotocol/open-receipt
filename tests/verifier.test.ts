import { beforeAll, describe, expect, it } from "bun:test";
import {
  OPEN_RECEIPT_MEDIA_TYPE,
  canonicalize,
  eventHash,
  signOpenReceipt,
  verifyOpenReceipt,
  verifyOpenReceiptBundle,
  type Ed25519PublicJwk,
  type IssuerMetadata,
  type OpenReceiptEvent,
} from "../src";

let publicKey: Ed25519PublicJwk;
let privateKey: CryptoKey;
let metadata: IssuerMetadata;

beforeAll(async () => {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
  };
  const exported = await crypto.subtle.exportKey("jwk", pair.publicKey);
  publicKey = {
    kty: "OKP",
    crv: "Ed25519",
    x: exported.x!,
    kid: "open-receipt-test-2026",
    use: "sig",
    alg: "EdDSA",
  };
  privateKey = pair.privateKey;
  metadata = {
    issuer: "https://issuer.example",
    specification: "https://receiptprotocol.com/open-receipt",
    keys: [{ ...publicKey, status: "current" }],
  };
});

function unsigned(
  eventType: OpenReceiptEvent["event_type"] = "settlement.completed",
  parents: string[] = [],
): Omit<OpenReceiptEvent, "signature"> {
  return {
    spec_version: "0.1",
    event_id: `evt_${eventType.replace(".", "_")}`,
    event_type: eventType,
    issuer: {
      id: "https://issuer.example",
      name: "Example issuer",
      metadata_url: "https://issuer.example/.well-known/receipt-issuer",
      verification_key: publicKey,
    },
    issued_at: "2026-07-19T12:00:00.000Z",
    transaction_id: "txn_example_001",
    quote_id: "quote_example_001",
    commercial_facts: {
      currency: "USD",
      authorized_maximum: "0.05",
      final_charge: "0.03",
      seller: { id: "seller_example", display_name: "Example Seller" },
    },
    evidence: { result_sha256: "a".repeat(64), provider_status: 200 },
    provenance: { provider: "Example Provider", execution_id: "exec_001" },
    assurance: eventType === "validation.completed" ? "validated" : "delivered",
    parent_event_hashes: parents,
    signing_key_id: publicKey.kid,
  };
}

describe("Open Receipt v0.1", () => {
  it("canonicalizes JSON deterministically", () => {
    expect(canonicalize({ z: 1, a: { y: true, x: [3, null, "ok"] } })).toBe(
      '{"a":{"x":[3,null,"ok"],"y":true},"z":1}',
    );
    expect(canonicalize({ negativeZero: -0 })).toBe('{"negativeZero":0}');
  });

  it("verifies a valid event offline with cached issuer metadata", async () => {
    const event = await signOpenReceipt(unsigned(), privateKey);
    const result = await verifyOpenReceipt(event, { issuerMetadata: metadata });
    expect(result).toMatchObject({
      valid: true,
      signature_valid: true,
      schema_valid: true,
      chain: "not_applicable",
      key_source: "issuer_metadata",
      issuer_identity_trusted: true,
    });
    expect(result.event_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("can verify offline from the embedded key without overstating issuer trust", async () => {
    const event = await signOpenReceipt(unsigned(), privateKey);
    const result = await verifyOpenReceipt(event);
    expect(result.valid).toBe(true);
    expect(result.key_source).toBe("embedded");
    expect(result.issuer_identity_trusted).toBe(false);
  });

  it.each([
    [
      "amount",
      (event: OpenReceiptEvent) =>
        ((event.commercial_facts as { final_charge: string }).final_charge = "9.99"),
    ],
    [
      "seller",
      (event: OpenReceiptEvent) =>
        ((event.commercial_facts.seller as { display_name: string }).display_name = "Mallory"),
    ],
    ["evidence", (event: OpenReceiptEvent) => (event.evidence.result_sha256 = "b".repeat(64))],
  ])("rejects changed %s", async (_label, tamper) => {
    const event = await signOpenReceipt(unsigned(), privateKey);
    tamper(event);
    const result = await verifyOpenReceipt(event, { issuerMetadata: metadata });
    expect(result.valid).toBe(false);
    expect(result.errors).toContain("bad_signature");
  });

  it("rejects a wrong issuer key", async () => {
    const event = await signOpenReceipt(unsigned(), privateKey);
    delete event.issuer.verification_key;
    const wrongMetadata: IssuerMetadata = {
      ...metadata,
      keys: [{ ...metadata.keys[0]!, x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }],
    };
    const result = await verifyOpenReceipt(event, { issuerMetadata: wrongMetadata });
    expect(result.valid).toBe(false);
    expect(result.errors).toContain("bad_signature");
  });

  it("does not fall back to an embedded key when trusted metadata revokes it", async () => {
    const event = await signOpenReceipt(unsigned(), privateKey);
    const revoked: IssuerMetadata = {
      ...metadata,
      keys: [{ ...metadata.keys[0]!, status: "revoked" }],
    };
    const result = await verifyOpenReceipt(event, { issuerMetadata: revoked });
    expect(result.valid).toBe(false);
    expect(result.key_source).toBe("none");
    expect(result.errors).toContain("verification_key_not_found");
  });

  it("rejects malformed JWS", async () => {
    const event = await signOpenReceipt(unsigned(), privateKey);
    event.signature = "not-a-jws";
    const result = await verifyOpenReceipt(event, { issuerMetadata: metadata });
    expect(result.valid).toBe(false);
    expect(result.errors).toContain("malformed_detached_jws");
  });

  it("rejects undeclared top-level fields instead of silently signing extensions", async () => {
    const event = (await signOpenReceipt(unsigned(), privateKey)) as OpenReceiptEvent & {
      unexpected?: string;
    };
    event.unexpected = "not-in-v0.1";
    const result = await verifyOpenReceipt(event, { issuerMetadata: metadata });
    expect(result.schema_valid).toBe(false);
    expect(result.errors).toContain("unknown_event_field:unexpected");
  });

  it("checks signed parent hashes in an offline bundle", async () => {
    const parent = await signOpenReceipt(unsigned("execution.attempted"), privateKey);
    const event = await signOpenReceipt(
      unsigned("validation.completed", [await eventHash(parent)]),
      privateKey,
    );
    const valid = await verifyOpenReceiptBundle(
      { media_type: OPEN_RECEIPT_MEDIA_TYPE, event, parents: [parent] },
      { issuerMetadata: metadata },
    );
    expect(valid).toMatchObject({ valid: true, chain: "complete" });

    const differentParent = await signOpenReceipt(
      { ...unsigned("execution.attempted"), event_id: "evt_different" },
      privateKey,
    );
    const broken = await verifyOpenReceiptBundle(
      { media_type: OPEN_RECEIPT_MEDIA_TYPE, event, parents: [differentParent] },
      { issuerMetadata: metadata },
    );
    expect(broken.valid).toBe(false);
    expect(broken.chain).toBe("invalid");
    expect(broken.errors).toContain("parent_hash_not_found");
  });
});
