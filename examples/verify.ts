import { readFile } from "node:fs/promises";
import { verifyOpenReceiptBundle } from "@receiptprotocol/open-receipt";

const document = JSON.parse(await readFile(process.argv[2]!, "utf8"));
const result = await verifyOpenReceiptBundle(document);

console.log(JSON.stringify(result, null, 2));
process.exitCode = result.valid ? 0 : 1;
