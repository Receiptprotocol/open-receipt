import { readFile } from "node:fs/promises";
import { verifyOpenReceiptTrust } from "@receiptprotocol/open-receipt";

const receiptPath = process.argv[2];
const metadataPath = process.argv[3];
const trustedMetadataHash = process.argv[4];

if (!receiptPath || !metadataPath || !trustedMetadataHash) {
  throw new Error("usage: verify <receipt.json> <issuer-metadata.json> <trusted-sha256-hash>");
}

const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
const pinnedMetadata = JSON.parse(await readFile(metadataPath, "utf8"));
const result = await verifyOpenReceiptTrust(receipt, {
  trustMode: "pinned_metadata",
  pinnedMetadata,
  pinnedMetadataHash: trustedMetadataHash,
});

console.log(JSON.stringify(result, null, 2));
process.exitCode = result.overall_status === "invalid" ? 1 : 0;
