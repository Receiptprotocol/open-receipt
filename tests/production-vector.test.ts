import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "bun:test";
import { canonicalize } from "../src";

const vectors = resolve(import.meta.dir, "../test-vectors");
const artifact = JSON.parse(
  readFileSync(resolve(vectors, "production-legacy.valid.json"), "utf8"),
) as Record<string, unknown> & {
  signature: { alg: string; key_id: string; value: string };
};
const metadata = JSON.parse(
  readFileSync(resolve(vectors, "production-legacy-key.json"), "utf8"),
) as { key_id: string; algorithm: string; public_key: string };

function base64Bytes(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function spki(raw: Uint8Array): Uint8Array {
  const prefix = new Uint8Array([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
  ]);
  const value = new Uint8Array(prefix.length + raw.length);
  value.set(prefix);
  value.set(raw, prefix.length);
  return value;
}

describe("completed production Receipt compatibility vector", () => {
  it("verifies the existing Receipt Artifact v1 signature entirely offline", async () => {
    expect(artifact.type).toBe("com.receiptprotocol.receipt.v1");
    expect(artifact.receipt_id).toBe("rcpt_5d3065fb34d542cfb3ff0de383cd5d43");
    expect(artifact.signature.key_id).toBe(metadata.key_id);
    expect(artifact.signature.alg).toBe(metadata.algorithm);
    const key = await crypto.subtle.importKey(
      "spki",
      spki(base64Bytes(metadata.public_key)) as BufferSource,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const { signature, ...unsigned } = artifact;
    const valid = await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      base64Bytes(signature.value) as BufferSource,
      new TextEncoder().encode(canonicalize(unsigned)) as BufferSource,
    );
    expect(valid).toBe(true);
  });

  it("does not relabel the legacy production artifact as Open Receipt v0.1", () => {
    expect(artifact.type).not.toBe("application/open-receipt+json");
    expect(artifact).not.toHaveProperty("spec_version");
  });
});
