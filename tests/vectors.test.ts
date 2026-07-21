import { describe, expect, it } from "bun:test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  OPEN_RECEIPT_MEDIA_TYPE,
  verifyOpenReceipt,
  verifyOpenReceiptBundle,
  type IssuerMetadata,
  type OpenReceiptBundle,
} from "../src";

const directory = resolve(import.meta.dir, "../test-vectors");

async function load(name: string): Promise<unknown> {
  return JSON.parse(await readFile(resolve(directory, name), "utf8"));
}

async function verify(name: string) {
  const value = await load(name);
  const issuerMetadata = (await load("issuer.json")) as IssuerMetadata;
  return value &&
    typeof value === "object" &&
    (value as { media_type?: unknown }).media_type === OPEN_RECEIPT_MEDIA_TYPE
    ? verifyOpenReceiptBundle(value as OpenReceiptBundle, { issuerMetadata })
    : verifyOpenReceipt(value, { issuerMetadata });
}

describe("published Open Receipt vectors", () => {
  it("verifies both local valid vectors", async () => {
    expect((await verify("delivered-local.valid.json")).valid).toBe(true);
    expect(await verify("validated-local.valid.json")).toMatchObject({
      valid: true,
      chain: "complete",
      issuer_identity_trusted: true,
    });
  });

  for (const name of [
    "changed-amount.invalid.json",
    "changed-seller.invalid.json",
    "changed-evidence.invalid.json",
    "wrong-key.invalid.json",
    "broken-parent.invalid.json",
    "malformed-signature.invalid.json",
  ]) {
    it(`rejects ${name}`, async () => {
      expect((await verify(name)).valid).toBe(false);
    });
  }
});
