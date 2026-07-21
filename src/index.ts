export const OPEN_RECEIPT_SPEC_VERSION = "0.1" as const;
export const OPEN_RECEIPT_MEDIA_TYPE = "application/open-receipt+json" as const;

export const OPEN_RECEIPT_EVENT_TYPES = [
  "quote.issued",
  "authorization.granted",
  "execution.attempted",
  "validation.completed",
  "settlement.completed",
  "reversal.issued",
] as const;

export const OPEN_RECEIPT_ASSURANCE_VALUES = ["delivered", "validated"] as const;

export type OpenReceiptEventType = (typeof OPEN_RECEIPT_EVENT_TYPES)[number];
export type OpenReceiptAssurance = (typeof OPEN_RECEIPT_ASSURANCE_VALUES)[number];

export type Ed25519PublicJwk = {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  kid: string;
  use?: "sig";
  alg?: "EdDSA";
};

export type OpenReceiptIssuer = {
  id: string;
  name?: string;
  metadata_url: string;
  /** Enables mathematical verification offline. Trust the identity only after
   * comparing this key with issuer metadata obtained through a trusted path. */
  verification_key?: Ed25519PublicJwk;
};

export type OpenReceiptEvent = {
  spec_version: "0.1";
  event_id: string;
  event_type: OpenReceiptEventType;
  issuer: OpenReceiptIssuer;
  issued_at: string;
  transaction_id: string;
  quote_id: string | null;
  commercial_facts: Record<string, unknown>;
  evidence: Record<string, unknown>;
  provenance: Record<string, unknown>;
  assurance: OpenReceiptAssurance;
  parent_event_hashes: string[];
  signing_key_id: string;
  /** Detached compact JWS: BASE64URL(protected)..BASE64URL(signature). */
  signature: string;
};

export type OpenReceiptBundle = {
  media_type: typeof OPEN_RECEIPT_MEDIA_TYPE;
  event: OpenReceiptEvent;
  parents: OpenReceiptEvent[];
};

export type IssuerVerificationKey = Ed25519PublicJwk & {
  status: "current" | "historical" | "revoked";
  valid_from?: string;
  valid_until?: string | null;
};

export type IssuerMetadata = {
  issuer: string;
  specification: "https://receiptprotocol.com/open-receipt";
  keys: IssuerVerificationKey[];
};

export type VerificationResult = {
  valid: boolean;
  signature_valid: boolean;
  schema_valid: boolean;
  chain: "not_applicable" | "complete" | "partial" | "invalid";
  key_id: string | null;
  key_source: "issuer_metadata" | "embedded" | "none";
  issuer_identity_trusted: boolean;
  event_hash: string | null;
  errors: string[];
};

type ProtectedHeader = {
  alg: "EdDSA";
  kid: string;
  typ: "open-receipt+jws";
};

const encoder = new TextEncoder();
const EVENT_TYPE_SET = new Set<string>(OPEN_RECEIPT_EVENT_TYPES);
const ASSURANCE_SET = new Set<string>(OPEN_RECEIPT_ASSURANCE_VALUES);
const EVENT_FIELDS = new Set([
  "spec_version",
  "event_id",
  "event_type",
  "issuer",
  "issued_at",
  "transaction_id",
  "quote_id",
  "commercial_facts",
  "evidence",
  "provenance",
  "assurance",
  "parent_event_hashes",
  "signing_key_id",
  "signature",
]);

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** RFC 8785 JSON Canonicalization Scheme for JSON-parsed values. */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non_finite_number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (!isObject(value)) throw new TypeError("not_json_value");
  const entries = Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`);
  return `{${entries.join(",")}}`;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new TypeError("malformed_base64url");
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - (normalized.length % 4)) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function base64UrlToText(value: string): string {
  return new TextDecoder().decode(base64UrlToBytes(value));
}

async function sha256Bytes(input: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(input)));
}

export async function sha256Hex(value: unknown): Promise<string> {
  const input = typeof value === "string" ? value : canonicalize(value);
  return [...(await sha256Bytes(input))].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function eventHash(event: OpenReceiptEvent): Promise<string> {
  return `sha256:${await sha256Hex(event)}`;
}

function unsignedEvent(event: OpenReceiptEvent): Omit<OpenReceiptEvent, "signature"> {
  const { signature: _signature, ...unsigned } = event;
  void _signature;
  return unsigned;
}

function validateEvent(value: unknown): string[] {
  if (!isObject(value)) return ["event_must_be_object"];
  const errors: string[] = [];
  for (const field of Object.keys(value)) {
    if (!EVENT_FIELDS.has(field)) errors.push(`unknown_event_field:${field}`);
  }
  if (value.spec_version !== OPEN_RECEIPT_SPEC_VERSION) errors.push("unsupported_spec_version");
  if (typeof value.event_id !== "string" || !value.event_id) errors.push("invalid_event_id");
  if (typeof value.event_type !== "string" || !EVENT_TYPE_SET.has(value.event_type)) {
    errors.push("invalid_event_type");
  }
  if (
    !isObject(value.issuer) ||
    typeof value.issuer.id !== "string" ||
    typeof value.issuer.metadata_url !== "string"
  ) {
    errors.push("invalid_issuer");
  }
  if (isObject(value.issuer)) {
    const issuerFields = new Set(["id", "name", "metadata_url", "verification_key"]);
    for (const field of Object.keys(value.issuer)) {
      if (!issuerFields.has(field)) errors.push(`unknown_issuer_field:${field}`);
    }
  }
  if (isObject(value.issuer) && value.issuer.verification_key !== undefined) {
    const key = value.issuer.verification_key;
    if (
      !isObject(key) ||
      key.kty !== "OKP" ||
      key.crv !== "Ed25519" ||
      typeof key.x !== "string" ||
      typeof key.kid !== "string"
    ) {
      errors.push("invalid_embedded_verification_key");
    } else {
      const keyFields = new Set(["kty", "crv", "x", "kid", "use", "alg"]);
      for (const field of Object.keys(key)) {
        if (!keyFields.has(field)) errors.push(`unknown_verification_key_field:${field}`);
      }
    }
  }
  if (typeof value.issued_at !== "string" || Number.isNaN(Date.parse(value.issued_at))) {
    errors.push("invalid_issued_at");
  }
  if (typeof value.transaction_id !== "string" || !value.transaction_id) {
    errors.push("invalid_transaction_id");
  }
  if (value.quote_id !== null && typeof value.quote_id !== "string")
    errors.push("invalid_quote_id");
  if (!isObject(value.commercial_facts)) errors.push("invalid_commercial_facts");
  if (!isObject(value.evidence)) errors.push("invalid_evidence");
  if (!isObject(value.provenance)) errors.push("invalid_provenance");
  if (typeof value.assurance !== "string" || !ASSURANCE_SET.has(value.assurance)) {
    errors.push("invalid_assurance");
  }
  if (
    !Array.isArray(value.parent_event_hashes) ||
    value.parent_event_hashes.some(
      (hash) => typeof hash !== "string" || !/^sha256:[a-f0-9]{64}$/.test(hash),
    )
  ) {
    errors.push("invalid_parent_event_hashes");
  }
  if (typeof value.signing_key_id !== "string" || !value.signing_key_id) {
    errors.push("invalid_signing_key_id");
  }
  if (typeof value.signature !== "string" || !value.signature) errors.push("invalid_signature");
  return errors;
}

function parseDetachedJws(value: string): {
  protectedSegment: string;
  signature: Uint8Array;
  header: ProtectedHeader;
} {
  const segments = value.split(".");
  if (segments.length !== 3 || segments[1] !== "" || !segments[0] || !segments[2]) {
    throw new TypeError("malformed_detached_jws");
  }
  const header = JSON.parse(base64UrlToText(segments[0])) as Partial<ProtectedHeader>;
  if (header.alg !== "EdDSA") throw new TypeError("unsupported_jws_algorithm");
  if (header.typ !== "open-receipt+jws") throw new TypeError("invalid_jws_type");
  if (typeof header.kid !== "string" || !header.kid) throw new TypeError("missing_jws_key_id");
  return {
    protectedSegment: segments[0],
    signature: base64UrlToBytes(segments[2]),
    header: header as ProtectedHeader,
  };
}

function eligibleMetadataKey(metadata: IssuerMetadata, event: OpenReceiptEvent, kid: string) {
  if (metadata.issuer !== event.issuer.id) return undefined;
  const issuedAt = Date.parse(event.issued_at);
  return metadata.keys.find(
    (key) =>
      key.kid === kid &&
      key.kty === "OKP" &&
      key.crv === "Ed25519" &&
      key.status !== "revoked" &&
      (!key.use || key.use === "sig") &&
      (!key.alg || key.alg === "EdDSA") &&
      (!key.valid_from || issuedAt >= Date.parse(key.valid_from)) &&
      (!key.valid_until || issuedAt <= Date.parse(key.valid_until)),
  );
}

async function verifySignature(
  event: OpenReceiptEvent,
  metadata?: IssuerMetadata,
): Promise<{
  valid: boolean;
  keyId: string | null;
  keySource: VerificationResult["key_source"];
  identityTrusted: boolean;
  error?: string;
}> {
  let parsed: ReturnType<typeof parseDetachedJws>;
  try {
    parsed = parseDetachedJws(event.signature);
  } catch (error) {
    return {
      valid: false,
      keyId: null,
      keySource: "none",
      identityTrusted: false,
      error: error instanceof Error ? error.message : "malformed_signature",
    };
  }
  if (parsed.header.kid !== event.signing_key_id) {
    return {
      valid: false,
      keyId: parsed.header.kid,
      keySource: "none",
      identityTrusted: false,
      error: "signing_key_id_mismatch",
    };
  }
  const metadataKey = metadata
    ? eligibleMetadataKey(metadata, event, parsed.header.kid)
    : undefined;
  const embedded = event.issuer.verification_key;
  const metadataIsAuthoritative = metadata?.issuer === event.issuer.id;
  const key = metadataIsAuthoritative
    ? metadataKey
    : embedded?.kid === parsed.header.kid
      ? embedded
      : undefined;
  if (!key) {
    return {
      valid: false,
      keyId: parsed.header.kid,
      keySource: "none",
      identityTrusted: false,
      error: "verification_key_not_found",
    };
  }
  try {
    const cryptoKey = await crypto.subtle.importKey("jwk", key, { name: "Ed25519" }, false, [
      "verify",
    ]);
    const payloadSegment = bytesToBase64Url(encoder.encode(canonicalize(unsignedEvent(event))));
    const signingInput = encoder.encode(`${parsed.protectedSegment}.${payloadSegment}`);
    const valid = await crypto.subtle.verify(
      { name: "Ed25519" },
      cryptoKey,
      parsed.signature as BufferSource,
      signingInput as BufferSource,
    );
    return {
      valid,
      keyId: parsed.header.kid,
      keySource: metadataKey ? "issuer_metadata" : "embedded",
      identityTrusted: Boolean(metadataKey),
      ...(valid ? {} : { error: "bad_signature" }),
    };
  } catch {
    return {
      valid: false,
      keyId: parsed.header.kid,
      keySource: metadataKey ? "issuer_metadata" : "embedded",
      identityTrusted: Boolean(metadataKey),
      error: "invalid_verification_key",
    };
  }
}

export async function verifyOpenReceipt(
  value: unknown,
  options: {
    issuerMetadata?: IssuerMetadata;
    parentEvents?: OpenReceiptEvent[];
    requireCompleteChain?: boolean;
  } = {},
): Promise<VerificationResult> {
  const errors = validateEvent(value);
  if (errors.length > 0) {
    return {
      valid: false,
      signature_valid: false,
      schema_valid: false,
      chain: "invalid",
      key_id: null,
      key_source: "none",
      issuer_identity_trusted: false,
      event_hash: null,
      errors,
    };
  }
  const event = value as OpenReceiptEvent;
  const signature = await verifySignature(event, options.issuerMetadata);
  if (signature.error) errors.push(signature.error);

  let chain: VerificationResult["chain"] = "not_applicable";
  if (event.parent_event_hashes.length > 0) {
    if (!options.parentEvents) {
      chain = options.requireCompleteChain ? "invalid" : "partial";
      if (options.requireCompleteChain) errors.push("parent_events_missing");
    } else {
      const hashes = new Set(await Promise.all(options.parentEvents.map(eventHash)));
      const missing = event.parent_event_hashes.filter((hash) => !hashes.has(hash));
      chain =
        missing.length === 0 ? "complete" : options.requireCompleteChain ? "invalid" : "partial";
      if (missing.length > 0) errors.push("parent_hash_not_found");
    }
  }
  const hash = await eventHash(event);
  return {
    valid: signature.valid && chain !== "invalid",
    signature_valid: signature.valid,
    schema_valid: true,
    chain,
    key_id: signature.keyId,
    key_source: signature.keySource,
    issuer_identity_trusted: signature.identityTrusted,
    event_hash: hash,
    errors,
  };
}

export async function verifyOpenReceiptBundle(
  bundle: OpenReceiptBundle,
  options: { issuerMetadata?: IssuerMetadata; requireCompleteChain?: boolean } = {},
): Promise<VerificationResult> {
  if (!isObject(bundle) || bundle.media_type !== OPEN_RECEIPT_MEDIA_TYPE) {
    return {
      valid: false,
      signature_valid: false,
      schema_valid: false,
      chain: "invalid",
      key_id: null,
      key_source: "none",
      issuer_identity_trusted: false,
      event_hash: null,
      errors: ["invalid_bundle"],
    };
  }
  const parentResults = await Promise.all(
    (bundle.parents ?? []).map((parent) =>
      verifyOpenReceipt(parent, {
        ...(options.issuerMetadata ? { issuerMetadata: options.issuerMetadata } : {}),
      }),
    ),
  );
  const result = await verifyOpenReceipt(bundle.event, {
    ...(options.issuerMetadata ? { issuerMetadata: options.issuerMetadata } : {}),
    parentEvents: bundle.parents ?? [],
    requireCompleteChain: options.requireCompleteChain ?? true,
  });
  if (parentResults.some((parent) => !parent.signature_valid || !parent.schema_valid)) {
    return {
      ...result,
      valid: false,
      chain: "invalid",
      errors: [...result.errors, "invalid_parent_event"],
    };
  }
  return result;
}

export async function signOpenReceipt(
  unsigned: Omit<OpenReceiptEvent, "signature">,
  privateKey: CryptoKey | JsonWebKey,
): Promise<OpenReceiptEvent> {
  const header: ProtectedHeader = {
    alg: "EdDSA",
    kid: unsigned.signing_key_id,
    typ: "open-receipt+jws",
  };
  const protectedSegment = bytesToBase64Url(encoder.encode(canonicalize(header)));
  const payloadSegment = bytesToBase64Url(encoder.encode(canonicalize(unsigned)));
  const key =
    "type" in privateKey
      ? privateKey
      : await crypto.subtle.importKey("jwk", privateKey, { name: "Ed25519" }, false, ["sign"]);
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "Ed25519" },
      key,
      encoder.encode(`${protectedSegment}.${payloadSegment}`),
    ),
  );
  return { ...unsigned, signature: `${protectedSegment}..${bytesToBase64Url(signature)}` };
}
