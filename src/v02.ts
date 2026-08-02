import {
  canonicalize,
  sha256Hex,
  type Ed25519PublicJwk,
  type OpenReceiptAssurance,
  type OpenReceiptEventType,
  type OpenReceiptIssuer,
} from "./index.js";

export const OPEN_RECEIPT_V02_SPEC_VERSION = "0.2" as const;
export const OPEN_RECEIPT_ISSUER_METADATA_SCHEMA =
  "https://receiptprotocol.com/open-receipt/v0.2/issuer-metadata.schema.json" as const;

export const OPEN_RECEIPT_KEY_PURPOSES = [
  "open_receipt_evidence",
  "issuer_metadata",
  "issuance_log",
  "commerce_quote",
  "purchase_approval",
  "oauth_or_authentication",
] as const;

export const OPEN_RECEIPT_PUBLIC_KEY_PURPOSES = [
  "open_receipt_evidence",
  "issuer_metadata",
  "issuance_log",
] as const;

export const OPEN_RECEIPT_KEY_STATUSES = [
  "preactive",
  "active",
  "retired",
  "revoked",
  "compromised",
  "destroyed",
] as const;

export type OpenReceiptKeyPurpose = (typeof OPEN_RECEIPT_KEY_PURPOSES)[number];
export type OpenReceiptPublicKeyPurpose = (typeof OPEN_RECEIPT_PUBLIC_KEY_PURPOSES)[number];
export type OpenReceiptKeyStatus = (typeof OPEN_RECEIPT_KEY_STATUSES)[number];
export type OpenReceiptTrustMode = "embedded_only" | "pinned_metadata" | "https_webpki";
export type MetadataFreshness = "fresh" | "stale" | "unknown";

export type IssuerMetadataKeyV02 = {
  kid: string;
  purpose: OpenReceiptPublicKeyPurpose;
  alg: "EdDSA";
  public_jwk: Ed25519PublicJwk;
  status: OpenReceiptKeyStatus;
  valid_from: string;
  valid_until: string | null;
  activated_at: string | null;
  retired_at: string | null;
  revoked_at: string | null;
  revocation_effective_from: string | null;
  compromised_at: string | null;
  compromise_effective_from: string | null;
  destroyed_at: string | null;
  replaced_by_kid: string | null;
  replacement_kid?: string | null;
  reason_code: string | null;
};

export type IssuerMetadataSignature = {
  kid: string;
  alg: "EdDSA";
  value: string;
};

export type UnsignedIssuerMetadataV02 = {
  schema: typeof OPEN_RECEIPT_ISSUER_METADATA_SCHEMA;
  issuer: string;
  metadata_version: number;
  issued_at: string;
  next_update: string;
  previous_metadata_hash: string | null;
  keys: IssuerMetadataKeyV02[];
};

export type IssuerMetadataV02 = UnsignedIssuerMetadataV02 & {
  signature: IssuerMetadataSignature;
};

export type IssuanceAttestation = {
  type: "open_receipt_issuance_attestation";
  version: 1;
  issuer: string;
  sequence: number;
  receipt_digest: string;
  evidence_signing_key_id: string;
  issued_at: string;
  previous_entry_hash: string | null;
  entry_hash: string;
  log_signing_key_id: string;
  signature: string;
};

export type IssuanceLogCheckpoint = {
  type: "open_receipt_issuance_log_checkpoint";
  version: 1;
  issuer: string;
  latest_sequence: number;
  latest_entry_hash: string;
  issued_at: string;
  signing_key_id: string;
  signature: string;
};

export type OpenReceiptEventV02 = {
  spec_version: "0.2";
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
  issuer_metadata_version: number;
  issuer_metadata_hash: string;
  issuance_attestation?: IssuanceAttestation;
  signature: string;
};

export type IssuerResolution = {
  metadata: IssuerMetadataV02;
  trust_mode: Exclude<OpenReceiptTrustMode, "embedded_only">;
  resolved_at: string;
  trusted: boolean;
  etag?: string;
  previous_metadata?: IssuerMetadataV02[];
};

export interface IssuerResolver {
  readonly trustMode: Exclude<OpenReceiptTrustMode, "embedded_only">;
  resolve(input: {
    issuer: string;
    metadataVersion: number;
    metadataHash: string;
  }): Promise<IssuerResolution>;
}

export type HistoricalKeyResult =
  | "active_key_valid_at_issuance"
  | "retired_key_valid_at_issuance"
  | "signed_after_retirement"
  | "signed_before_revocation"
  | "signed_after_revocation"
  | "signed_before_compromise"
  | "signed_after_compromise"
  | "compromise_time_unknown"
  | "key_not_yet_valid"
  | "key_expired"
  | "key_purpose_mismatch"
  | "key_unknown"
  | "key_status_unknown";

export type HistoricalConclusion =
  | "valid_at_issuance"
  | "valid_but_metadata_stale"
  | "retired_key_valid_at_issuance"
  | "signed_after_revocation"
  | "signed_after_compromise"
  | "key_status_unknown";

export type TrustAwareVerificationResult = {
  overall_status: "valid" | "valid_with_warnings" | "invalid" | "indeterminate";
  signature: {
    valid: boolean;
    algorithm: "EdDSA" | null;
    kid: string | null;
  };
  issuer: {
    claimed: string | null;
    resolved: boolean;
    trusted: boolean;
    trust_mode: OpenReceiptTrustMode;
  };
  metadata: {
    version: number | null;
    hash_valid: boolean | null;
    signature_valid: boolean | null;
    chain_valid: boolean | null;
    issued_at: string | null;
    next_update: string | null;
    resolved_at: string | null;
    age_seconds: number | null;
    freshness: MetadataFreshness;
    as_of: string | null;
    key_valid_as_of_metadata: boolean | null;
  };
  key: {
    purpose: OpenReceiptKeyPurpose | null;
    status_at_issuance: "active" | "inactive" | "unknown";
    current_status: OpenReceiptKeyStatus | "unknown";
    historical_result: HistoricalKeyResult;
    conclusion: HistoricalConclusion;
  };
  issuance_attestation: {
    status: "valid" | "invalid" | "missing";
    sequence: number | null;
  };
  metadata_as_of: string | null;
  metadata_freshness: MetadataFreshness;
  key_valid_as_of_metadata: boolean | null;
  warnings: string[];
  errors: string[];
};

type DetachedHeader = {
  alg: "EdDSA";
  kid: string;
  typ: "open-receipt+jws";
};

const encoder = new TextEncoder();
const PUBLIC_PURPOSES = new Set<string>(OPEN_RECEIPT_PUBLIC_KEY_PURPOSES);

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
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

function timestamp(value: string, field: string): string {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
  ) {
    throw new TypeError(`invalid_timestamp:${field}`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) throw new TypeError(`invalid_timestamp:${field}`);
  return new Date(milliseconds).toISOString();
}

function optionalTimestamp(value: string | null, field: string): string | null {
  return value === null ? null : timestamp(value, field);
}

export function canonicalizeIssuerMetadata(
  metadata: UnsignedIssuerMetadataV02,
): UnsignedIssuerMetadataV02 {
  const metadataFields = new Set([
    "schema",
    "issuer",
    "metadata_version",
    "issued_at",
    "next_update",
    "previous_metadata_hash",
    "keys",
  ]);
  for (const field of Object.keys(metadata)) {
    if (!metadataFields.has(field)) throw new TypeError(`unknown_metadata_field:${field}`);
  }
  if (metadata.schema !== OPEN_RECEIPT_ISSUER_METADATA_SCHEMA) {
    throw new TypeError("unsupported_metadata_schema");
  }
  if (!Array.isArray(metadata.keys)) throw new TypeError("invalid_metadata_keys");
  if (!Number.isSafeInteger(metadata.metadata_version) || metadata.metadata_version < 1) {
    throw new TypeError("invalid_metadata_version");
  }
  const issuer = new URL(metadata.issuer);
  if (issuer.protocol !== "https:" || issuer.origin !== metadata.issuer.replace(/\/$/, "")) {
    throw new TypeError("invalid_issuer_origin");
  }
  if (
    !/^sha256:[a-f0-9]{64}$/.test(metadata.previous_metadata_hash ?? "sha256:" + "0".repeat(64))
  ) {
    throw new TypeError("invalid_previous_metadata_hash");
  }
  const issuedAt = timestamp(metadata.issued_at, "issued_at");
  const nextUpdate = timestamp(metadata.next_update, "next_update");
  if (Date.parse(nextUpdate) <= Date.parse(issuedAt)) throw new TypeError("invalid_next_update");
  const seen = new Set<string>();
  const keys = metadata.keys.map((key) => {
    const keyFields = new Set([
      "kid",
      "purpose",
      "alg",
      "public_jwk",
      "status",
      "valid_from",
      "valid_until",
      "activated_at",
      "retired_at",
      "revoked_at",
      "revocation_effective_from",
      "compromised_at",
      "compromise_effective_from",
      "destroyed_at",
      "replaced_by_kid",
      "replacement_kid",
      "reason_code",
    ]);
    for (const field of Object.keys(key)) {
      if (!keyFields.has(field)) throw new TypeError(`unknown_metadata_key_field:${field}`);
    }
    const jwkFields = new Set(["kty", "crv", "x", "kid", "use", "alg"]);
    for (const field of Object.keys(key.public_jwk ?? {})) {
      if (!jwkFields.has(field)) throw new TypeError(`unknown_public_jwk_field:${field}`);
    }
    if (seen.has(key.kid)) throw new TypeError("duplicate_metadata_kid");
    seen.add(key.kid);
    if (!PUBLIC_PURPOSES.has(key.purpose)) throw new TypeError("non_public_key_purpose");
    if (
      key.alg !== "EdDSA" ||
      key.public_jwk.kty !== "OKP" ||
      key.public_jwk.crv !== "Ed25519" ||
      key.public_jwk.alg !== "EdDSA" ||
      key.public_jwk.kid !== key.kid ||
      "d" in key.public_jwk
    ) {
      throw new TypeError("unsupported_metadata_key");
    }
    if (!/^[A-Za-z0-9_-]{43}$/.test(key.public_jwk.x)) {
      throw new TypeError("invalid_metadata_public_key");
    }
    if (
      key.replacement_kid !== undefined &&
      key.replaced_by_kid !== null &&
      key.replacement_kid !== key.replaced_by_kid
    ) {
      throw new TypeError("conflicting_replacement_kid");
    }
    const validFrom = timestamp(key.valid_from, `keys.${key.kid}.valid_from`);
    const validUntil = optionalTimestamp(key.valid_until, `keys.${key.kid}.valid_until`);
    const retiredAt = optionalTimestamp(key.retired_at, `keys.${key.kid}.retired_at`);
    const revokedAt = optionalTimestamp(key.revoked_at, `keys.${key.kid}.revoked_at`);
    const revocationEffectiveFrom = optionalTimestamp(
      key.revocation_effective_from,
      `keys.${key.kid}.revocation_effective_from`,
    );
    const compromisedAt = optionalTimestamp(key.compromised_at, `keys.${key.kid}.compromised_at`);
    const compromiseEffectiveFrom = optionalTimestamp(
      key.compromise_effective_from,
      `keys.${key.kid}.compromise_effective_from`,
    );
    if (validUntil && Date.parse(validUntil) < Date.parse(validFrom)) {
      throw new TypeError("invalid_key_validity_window");
    }
    if (key.status === "retired" && !retiredAt) throw new TypeError("retired_at_required");
    if (key.status === "revoked" && !revokedAt) throw new TypeError("revoked_at_required");
    if (key.status === "compromised" && !compromisedAt) {
      throw new TypeError("compromised_at_required");
    }
    const destroyedAt = optionalTimestamp(key.destroyed_at, `keys.${key.kid}.destroyed_at`);
    if (key.status === "destroyed" && !destroyedAt) {
      throw new TypeError("destroyed_at_required");
    }
    if (compromiseEffectiveFrom && !compromisedAt) {
      throw new TypeError("compromised_at_required");
    }
    const { replacement_kid: _replacementKidAlias, ...keyWithoutAlias } = key;
    void _replacementKidAlias;
    return {
      ...keyWithoutAlias,
      valid_from: validFrom,
      valid_until: validUntil,
      activated_at: optionalTimestamp(key.activated_at, `keys.${key.kid}.activated_at`),
      retired_at: retiredAt,
      revoked_at: revokedAt,
      revocation_effective_from: revocationEffectiveFrom,
      compromised_at: compromisedAt,
      compromise_effective_from: compromiseEffectiveFrom,
      destroyed_at: destroyedAt,
      replaced_by_kid: key.replaced_by_kid ?? key.replacement_kid ?? null,
      reason_code: key.reason_code ?? null,
    };
  });
  return {
    ...metadata,
    issuer: issuer.origin,
    issued_at: issuedAt,
    next_update: nextUpdate,
    keys,
  };
}

async function importVerificationKey(key: Ed25519PublicJwk): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", key, { name: "Ed25519" }, false, ["verify"]);
}

async function importSigningKey(key: CryptoKey | JsonWebKey): Promise<CryptoKey> {
  return "type" in key
    ? key
    : crypto.subtle.importKey("jwk", key, { name: "Ed25519" }, false, ["sign"]);
}

async function verifyEd25519(
  key: Ed25519PublicJwk,
  signature: string,
  canonicalPayload: string,
): Promise<boolean> {
  try {
    return await crypto.subtle.verify(
      { name: "Ed25519" },
      await importVerificationKey(key),
      base64UrlToBytes(signature) as BufferSource,
      encoder.encode(canonicalPayload) as BufferSource,
    );
  } catch {
    return false;
  }
}

export async function signIssuerMetadata(
  metadata: UnsignedIssuerMetadataV02,
  privateKey: CryptoKey | JsonWebKey,
  metadataSigningKid: string,
): Promise<IssuerMetadataV02> {
  return signIssuerMetadataWith(
    metadata,
    metadataSigningKid,
    async (payload) =>
      new Uint8Array(
        await crypto.subtle.sign(
          { name: "Ed25519" },
          await importSigningKey(privateKey),
          payload as BufferSource,
        ),
      ),
  );
}

export async function signIssuerMetadataWith(
  metadata: UnsignedIssuerMetadataV02,
  metadataSigningKid: string,
  sign: (canonicalPayload: Uint8Array) => Promise<Uint8Array>,
): Promise<IssuerMetadataV02> {
  const canonical = canonicalizeIssuerMetadata(metadata);
  const key = canonical.keys.find(
    (candidate) =>
      candidate.kid === metadataSigningKid &&
      candidate.purpose === "issuer_metadata" &&
      candidate.status === "active",
  );
  if (!key) throw new Error("active_metadata_signing_key_missing");
  const signatureHeader = { kid: metadataSigningKid, alg: "EdDSA" as const };
  const signature = await sign(
    encoder.encode(canonicalize({ ...canonical, signature: signatureHeader })),
  );
  return {
    ...canonical,
    signature: {
      ...signatureHeader,
      value: bytesToBase64Url(signature),
    },
  };
}

export async function issuerMetadataHash(metadata: IssuerMetadataV02): Promise<string> {
  return `sha256:${await sha256Hex(metadata)}`;
}

export async function verifyIssuerMetadata(
  metadata: IssuerMetadataV02,
  previous?: IssuerMetadataV02,
): Promise<{
  valid: boolean;
  signature_valid: boolean;
  hash: string | null;
  chain_valid: boolean;
  errors: string[];
}> {
  const errors: string[] = [];
  if (
    !isObject(metadata.signature) ||
    Object.keys(metadata.signature).some((field) => !["kid", "alg", "value"].includes(field))
  ) {
    return {
      valid: false,
      signature_valid: false,
      hash: null,
      chain_valid: false,
      errors: ["invalid_metadata_signature"],
    };
  }
  let canonical: UnsignedIssuerMetadataV02;
  try {
    const { signature: _signature, ...unsigned } = metadata;
    void _signature;
    canonical = canonicalizeIssuerMetadata(unsigned);
  } catch (error) {
    return {
      valid: false,
      signature_valid: false,
      hash: null,
      chain_valid: false,
      errors: [error instanceof Error ? error.message : "invalid_metadata"],
    };
  }
  const signingKey = canonical.keys.find(
    (key) => key.kid === metadata.signature?.kid && key.purpose === "issuer_metadata",
  );
  if (!signingKey) errors.push("metadata_signing_key_missing_or_wrong_purpose");
  if (signingKey) {
    const signingKeyState = evaluateHistoricalKey(signingKey, Date.parse(canonical.issued_at));
    if (!signingKeyState.valid) errors.push("metadata_signing_key_invalid_at_issuance");
  }
  if (metadata.signature?.alg !== "EdDSA") errors.push("unsupported_metadata_signature_algorithm");
  const signatureValid = Boolean(
    signingKey &&
    (await verifyEd25519(
      signingKey.public_jwk,
      metadata.signature.value,
      canonicalize({
        ...canonical,
        signature: { kid: metadata.signature.kid, alg: metadata.signature.alg },
      }),
    )),
  );
  if (!signatureValid) errors.push("metadata_signature_invalid");
  let chainValid = metadata.metadata_version === 1 && metadata.previous_metadata_hash === null;
  if (previous) {
    const previousHash = await issuerMetadataHash(previous);
    chainValid =
      metadata.metadata_version === previous.metadata_version + 1 &&
      metadata.previous_metadata_hash === previousHash &&
      metadata.issuer === previous.issuer;
  }
  if (!chainValid) errors.push("metadata_hash_chain_invalid");
  return {
    valid: signatureValid && chainValid && errors.length === 0,
    signature_valid: signatureValid,
    hash: await issuerMetadataHash(metadata),
    chain_valid: chainValid,
    errors,
  };
}

export async function verifyIssuerMetadataChain(
  versions: IssuerMetadataV02[],
): Promise<{ valid: boolean; errors: string[] }> {
  const ordered = [...versions].sort((a, b) => a.metadata_version - b.metadata_version);
  const errors: string[] = [];
  for (let index = 0; index < ordered.length; index += 1) {
    const result = await verifyIssuerMetadata(ordered[index]!, ordered[index - 1]);
    if (!result.valid) {
      errors.push(
        ...result.errors.map(
          (error) => `metadata_version_${ordered[index]!.metadata_version}:${error}`,
        ),
      );
    }
  }
  return { valid: errors.length === 0, errors };
}

function unsignedAttestation(
  attestation: IssuanceAttestation,
): Omit<IssuanceAttestation, "signature"> {
  const { signature: _signature, ...unsigned } = attestation;
  void _signature;
  return unsigned;
}

function attestationEntryBody(
  attestation: Omit<IssuanceAttestation, "signature">,
): Omit<IssuanceAttestation, "signature" | "entry_hash"> {
  const { entry_hash: _entryHash, ...body } = attestation;
  void _entryHash;
  return body;
}

export async function issuanceEntryHash(
  attestation: Omit<IssuanceAttestation, "signature" | "entry_hash">,
): Promise<string> {
  const hashInput = [
    "open-receipt-issuance-v1",
    attestation.type,
    String(attestation.version),
    attestation.issuer,
    String(attestation.sequence),
    attestation.receipt_digest,
    attestation.evidence_signing_key_id,
    timestamp(attestation.issued_at, "attestation.issued_at"),
    attestation.previous_entry_hash ?? "",
    attestation.log_signing_key_id,
  ].join("\n");
  return `sha256:${await sha256Hex(hashInput)}`;
}

export async function signIssuanceAttestation(
  input: Omit<IssuanceAttestation, "entry_hash" | "signature">,
  privateKey: CryptoKey | JsonWebKey,
): Promise<IssuanceAttestation> {
  return signIssuanceAttestationWith(
    input,
    async (payload) =>
      new Uint8Array(
        await crypto.subtle.sign(
          { name: "Ed25519" },
          await importSigningKey(privateKey),
          payload as BufferSource,
        ),
      ),
  );
}

export async function signIssuanceAttestationWith(
  input: Omit<IssuanceAttestation, "entry_hash" | "signature">,
  sign: (canonicalPayload: Uint8Array) => Promise<Uint8Array>,
): Promise<IssuanceAttestation> {
  if (!Number.isSafeInteger(input.sequence) || input.sequence < 1) {
    throw new TypeError("invalid_issuance_sequence");
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(input.receipt_digest)) {
    throw new TypeError("invalid_receipt_digest");
  }
  const canonicalInput = {
    ...input,
    issued_at: timestamp(input.issued_at, "attestation.issued_at"),
  };
  const entry_hash = await issuanceEntryHash(canonicalInput);
  const unsigned = { ...canonicalInput, entry_hash };
  const signature = await sign(encoder.encode(canonicalize(unsigned)));
  return { ...unsigned, signature: bytesToBase64Url(signature) };
}

export async function receiptDigestForAttestation(event: OpenReceiptEventV02): Promise<string> {
  const { signature: _signature, issuance_attestation: _attestation, ...core } = event;
  void _signature;
  void _attestation;
  return `sha256:${await sha256Hex({
    ...core,
    issued_at: timestamp(core.issued_at, "issued_at"),
  })}`;
}

export async function verifyIssuanceAttestation(
  event: OpenReceiptEventV02,
  metadata: IssuerMetadataV02,
): Promise<{ status: "valid" | "invalid" | "missing"; sequence: number | null; errors: string[] }> {
  const attestation = event.issuance_attestation;
  if (!attestation) return { status: "missing", sequence: null, errors: [] };
  const errors: string[] = [];
  let attestationIssuedAt: string | null = null;
  try {
    attestationIssuedAt = timestamp(attestation.issued_at, "attestation.issued_at");
  } catch {
    errors.push("attestation_issuance_time_invalid");
  }
  if (attestation.issuer !== event.issuer.id) errors.push("attestation_issuer_mismatch");
  if (attestationIssuedAt !== null && attestationIssuedAt !== event.issued_at) {
    errors.push("attestation_issuance_time_mismatch");
  }
  if (!Number.isSafeInteger(attestation.sequence) || attestation.sequence < 1) {
    errors.push("attestation_sequence_invalid");
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(attestation.receipt_digest)) {
    errors.push("attestation_receipt_digest_invalid");
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(attestation.entry_hash)) {
    errors.push("attestation_entry_hash_invalid");
  }
  if (
    attestation.previous_entry_hash !== null &&
    !/^sha256:[a-f0-9]{64}$/.test(attestation.previous_entry_hash)
  ) {
    errors.push("attestation_previous_entry_hash_invalid");
  }
  if (attestation.evidence_signing_key_id !== event.signing_key_id) {
    errors.push("attestation_evidence_key_mismatch");
  }
  if (attestation.receipt_digest !== (await receiptDigestForAttestation(event))) {
    errors.push("attestation_receipt_digest_mismatch");
  }
  try {
    if (
      (await issuanceEntryHash(attestationEntryBody(unsignedAttestation(attestation)))) !==
      attestation.entry_hash
    ) {
      errors.push("attestation_entry_hash_invalid");
    }
  } catch {
    if (!errors.includes("attestation_entry_hash_invalid")) {
      errors.push("attestation_entry_hash_invalid");
    }
  }
  const logKey = metadata.keys.find(
    (key) => key.kid === attestation.log_signing_key_id && key.purpose === "issuance_log",
  );
  if (!logKey) errors.push("attestation_log_key_missing_or_wrong_purpose");
  if (logKey && attestationIssuedAt) {
    const logKeyState = evaluateHistoricalKey(logKey, Date.parse(attestationIssuedAt));
    if (!logKeyState.valid || logKeyState.needsAttestation) {
      errors.push("attestation_log_key_not_authorized_at_issuance");
    }
  }
  if (
    logKey &&
    !(await verifyEd25519(
      logKey.public_jwk,
      attestation.signature,
      canonicalize(unsignedAttestation(attestation)),
    ))
  ) {
    errors.push("attestation_signature_invalid");
  }
  return {
    status: errors.length === 0 ? "valid" : "invalid",
    sequence: attestation.sequence,
    errors,
  };
}

export async function signIssuanceLogCheckpointWith(
  input: Omit<IssuanceLogCheckpoint, "signature">,
  sign: (canonicalPayload: Uint8Array) => Promise<Uint8Array>,
): Promise<IssuanceLogCheckpoint> {
  if (!Number.isSafeInteger(input.latest_sequence) || input.latest_sequence < 1) {
    throw new TypeError("invalid_checkpoint_sequence");
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(input.latest_entry_hash)) {
    throw new TypeError("invalid_checkpoint_entry_hash");
  }
  const normalized = {
    ...input,
    issued_at: timestamp(input.issued_at, "checkpoint.issued_at"),
  };
  return {
    ...normalized,
    signature: bytesToBase64Url(await sign(encoder.encode(canonicalize(normalized)))),
  };
}

export async function verifyIssuanceLogCheckpoint(
  checkpoint: IssuanceLogCheckpoint,
  metadata: IssuerMetadataV02,
): Promise<boolean> {
  if (
    checkpoint.type !== "open_receipt_issuance_log_checkpoint" ||
    checkpoint.version !== 1 ||
    checkpoint.issuer !== metadata.issuer ||
    !Number.isSafeInteger(checkpoint.latest_sequence) ||
    checkpoint.latest_sequence < 1 ||
    !/^sha256:[a-f0-9]{64}$/.test(checkpoint.latest_entry_hash)
  ) {
    return false;
  }
  const key = metadata.keys.find(
    (candidate) =>
      candidate.kid === checkpoint.signing_key_id && candidate.purpose === "issuance_log",
  );
  if (!key) return false;
  let issuedAt: string;
  try {
    issuedAt = timestamp(checkpoint.issued_at, "checkpoint.issued_at");
  } catch {
    return false;
  }
  const keyState = evaluateHistoricalKey(key, Date.parse(issuedAt));
  if (!keyState.valid || keyState.needsAttestation) return false;
  const { signature: _signature, ...unsigned } = checkpoint;
  void _signature;
  return verifyEd25519(
    key.public_jwk,
    checkpoint.signature,
    canonicalize({ ...unsigned, issued_at: issuedAt }),
  );
}

function parseDetachedJws(value: string): {
  protectedSegment: string;
  signature: Uint8Array;
  header: DetachedHeader;
} {
  const segments = value.split(".");
  if (segments.length !== 3 || segments[1] !== "" || !segments[0] || !segments[2]) {
    throw new TypeError("malformed_detached_jws");
  }
  const header = JSON.parse(base64UrlToText(segments[0])) as Partial<DetachedHeader>;
  if (header.alg !== "EdDSA") throw new TypeError("unsupported_jws_algorithm");
  if (header.typ !== "open-receipt+jws") throw new TypeError("invalid_jws_type");
  if (typeof header.kid !== "string" || !header.kid) throw new TypeError("missing_jws_key_id");
  return {
    protectedSegment: segments[0],
    signature: base64UrlToBytes(segments[2]),
    header: header as DetachedHeader,
  };
}

function unsignedV02(event: OpenReceiptEventV02): Omit<OpenReceiptEventV02, "signature"> {
  const { signature: _signature, ...unsigned } = event;
  void _signature;
  return unsigned;
}

function validateV02Event(value: unknown): string[] {
  if (!isObject(value)) return ["event_must_be_object"];
  const errors: string[] = [];
  const allowed = new Set([
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
    "issuer_metadata_version",
    "issuer_metadata_hash",
    "issuance_attestation",
    "signature",
  ]);
  for (const field of Object.keys(value)) {
    if (!allowed.has(field)) errors.push(`unknown_event_field:${field}`);
  }
  if (value.spec_version !== "0.2") errors.push("unsupported_spec_version");
  if (typeof value.event_id !== "string" || !value.event_id) errors.push("invalid_event_id");
  if (
    typeof value.event_type !== "string" ||
    ![
      "quote.issued",
      "authorization.granted",
      "execution.attempted",
      "validation.completed",
      "settlement.completed",
      "reversal.issued",
    ].includes(value.event_type)
  ) {
    errors.push("invalid_event_type");
  }
  if (
    !isObject(value.issuer) ||
    typeof value.issuer.id !== "string" ||
    typeof value.issuer.metadata_url !== "string"
  ) {
    errors.push("invalid_issuer");
  }
  try {
    timestamp(String(value.issued_at), "issued_at");
  } catch {
    errors.push("invalid_issued_at");
  }
  if (
    !Number.isSafeInteger(value.issuer_metadata_version) ||
    Number(value.issuer_metadata_version) < 1
  ) {
    errors.push("invalid_issuer_metadata_version");
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(String(value.issuer_metadata_hash))) {
    errors.push("invalid_issuer_metadata_hash");
  }
  if (typeof value.signing_key_id !== "string" || !value.signing_key_id) {
    errors.push("invalid_signing_key_id");
  }
  if (typeof value.signature !== "string" || !value.signature) errors.push("invalid_signature");
  for (const field of ["commercial_facts", "evidence", "provenance"]) {
    if (!isObject(value[field])) errors.push(`invalid_${field}`);
  }
  if (typeof value.transaction_id !== "string" || !value.transaction_id) {
    errors.push("invalid_transaction_id");
  }
  if (value.quote_id !== null && typeof value.quote_id !== "string")
    errors.push("invalid_quote_id");
  if (!["delivered", "validated"].includes(String(value.assurance))) {
    errors.push("invalid_assurance");
  }
  if (
    !Array.isArray(value.parent_event_hashes) ||
    value.parent_event_hashes.some(
      // Early Receipt v0.2 evidence-chain artifacts used the same SHA-256
      // digest bytes without the explicit algorithm prefix. Accept those
      // immutable historical signatures; new issuers must emit `sha256:`.
      (hash) => typeof hash !== "string" || !/^(?:sha256:)?[a-f0-9]{64}$/.test(hash),
    )
  ) {
    errors.push("invalid_parent_event_hashes");
  }
  if (value.issuance_attestation !== undefined) {
    const attestation = value.issuance_attestation;
    if (
      !isObject(attestation) ||
      attestation.type !== "open_receipt_issuance_attestation" ||
      attestation.version !== 1 ||
      !Number.isSafeInteger(attestation.sequence) ||
      typeof attestation.signature !== "string"
    ) {
      errors.push("invalid_issuance_attestation");
    }
  }
  return errors;
}

export async function signOpenReceiptV02(
  unsigned: Omit<OpenReceiptEventV02, "signature">,
  privateKey: CryptoKey | JsonWebKey,
  purpose: OpenReceiptKeyPurpose = "open_receipt_evidence",
): Promise<OpenReceiptEventV02> {
  return signOpenReceiptV02With(
    unsigned,
    async (payload) =>
      new Uint8Array(
        await crypto.subtle.sign(
          { name: "Ed25519" },
          await importSigningKey(privateKey),
          payload as BufferSource,
        ),
      ),
    purpose,
  );
}

export async function signOpenReceiptV02With(
  unsigned: Omit<OpenReceiptEventV02, "signature">,
  sign: (signingInput: Uint8Array) => Promise<Uint8Array>,
  purpose: OpenReceiptKeyPurpose = "open_receipt_evidence",
): Promise<OpenReceiptEventV02> {
  if (purpose !== "open_receipt_evidence") throw new Error("key_purpose_mismatch");
  const normalized = { ...unsigned, issued_at: timestamp(unsigned.issued_at, "issued_at") };
  const header: DetachedHeader = {
    alg: "EdDSA",
    kid: normalized.signing_key_id,
    typ: "open-receipt+jws",
  };
  const protectedSegment = bytesToBase64Url(encoder.encode(canonicalize(header)));
  const payloadSegment = bytesToBase64Url(encoder.encode(canonicalize(normalized)));
  const signature = await sign(encoder.encode(`${protectedSegment}.${payloadSegment}`));
  return { ...normalized, signature: `${protectedSegment}..${bytesToBase64Url(signature)}` };
}

type KeyEvaluation = {
  valid: boolean;
  statusAtIssuance: "active" | "inactive" | "unknown";
  result: HistoricalKeyResult;
  conclusion: HistoricalConclusion;
  needsAttestation: boolean;
};

function evaluateHistoricalKey(key: IssuerMetadataKeyV02, issuedAt: number): KeyEvaluation {
  const validFrom = Date.parse(key.valid_from);
  const validUntil = key.valid_until ? Date.parse(key.valid_until) : Number.POSITIVE_INFINITY;
  if (issuedAt < validFrom) {
    return {
      valid: false,
      statusAtIssuance: "inactive",
      result: "key_not_yet_valid",
      conclusion: "key_status_unknown",
      needsAttestation: false,
    };
  }
  if (key.revoked_at) {
    const revocationEffectiveFrom = key.revocation_effective_from ?? key.revoked_at;
    if (issuedAt >= Date.parse(revocationEffectiveFrom)) {
      return {
        valid: false,
        statusAtIssuance: "inactive",
        result: "signed_after_revocation",
        conclusion: "signed_after_revocation",
        needsAttestation: false,
      };
    }
    return {
      valid: true,
      statusAtIssuance: "active",
      result: "signed_before_revocation",
      conclusion: "valid_at_issuance",
      needsAttestation: false,
    };
  }
  if (key.compromised_at) {
    if (!key.compromise_effective_from) {
      return {
        valid: false,
        statusAtIssuance: "unknown",
        result: "compromise_time_unknown",
        conclusion: "key_status_unknown",
        needsAttestation: true,
      };
    }
    if (issuedAt >= Date.parse(key.compromise_effective_from)) {
      return {
        valid: false,
        statusAtIssuance: "inactive",
        result: "signed_after_compromise",
        conclusion: "signed_after_compromise",
        needsAttestation: false,
      };
    }
    return {
      valid: true,
      statusAtIssuance: "active",
      result: "signed_before_compromise",
      conclusion: "valid_at_issuance",
      needsAttestation: true,
    };
  }
  if (key.retired_at || key.status === "retired" || key.status === "destroyed") {
    if (!key.retired_at) {
      return {
        valid: false,
        statusAtIssuance: "unknown",
        result: "key_status_unknown",
        conclusion: "key_status_unknown",
        needsAttestation: false,
      };
    }
    if (key.retired_at && issuedAt >= Date.parse(key.retired_at)) {
      return {
        valid: false,
        statusAtIssuance: "inactive",
        result: "signed_after_retirement",
        conclusion: "key_status_unknown",
        needsAttestation: false,
      };
    }
    return {
      valid: true,
      statusAtIssuance: "active",
      result: "retired_key_valid_at_issuance",
      conclusion: "retired_key_valid_at_issuance",
      needsAttestation: false,
    };
  }
  if (issuedAt > validUntil) {
    return {
      valid: false,
      statusAtIssuance: "inactive",
      result: "key_expired",
      conclusion: "key_status_unknown",
      needsAttestation: false,
    };
  }
  return {
    valid: key.status === "active",
    statusAtIssuance: key.status === "active" ? "active" : "inactive",
    result: key.status === "active" ? "active_key_valid_at_issuance" : "key_status_unknown",
    conclusion: key.status === "active" ? "valid_at_issuance" : "key_status_unknown",
    needsAttestation: false,
  };
}

function emptyTrustResult(
  event: Partial<OpenReceiptEventV02>,
  trustMode: OpenReceiptTrustMode,
): TrustAwareVerificationResult {
  return {
    overall_status: "invalid",
    signature: { valid: false, algorithm: null, kid: null },
    issuer: {
      claimed: event.issuer?.id ?? null,
      resolved: false,
      trusted: false,
      trust_mode: trustMode,
    },
    metadata: {
      version: null,
      hash_valid: null,
      signature_valid: null,
      chain_valid: null,
      issued_at: null,
      next_update: null,
      resolved_at: null,
      age_seconds: null,
      freshness: "unknown",
      as_of: null,
      key_valid_as_of_metadata: null,
    },
    key: {
      purpose: null,
      status_at_issuance: "unknown",
      current_status: "unknown",
      historical_result: "key_status_unknown",
      conclusion: "key_status_unknown",
    },
    issuance_attestation: { status: "missing", sequence: null },
    metadata_as_of: null,
    metadata_freshness: "unknown",
    key_valid_as_of_metadata: null,
    warnings: [],
    errors: [],
  };
}

export async function verifyOpenReceiptTrust(
  value: unknown,
  options: {
    trustMode?: OpenReceiptTrustMode;
    resolver?: IssuerResolver;
    pinnedMetadata?: IssuerMetadataV02;
    pinnedMetadataHash?: string;
    previousMetadata?: IssuerMetadataV02[];
    resolvedAt?: string;
    now?: string;
    maxMetadataAgeSeconds?: number;
  } = {},
): Promise<TrustAwareVerificationResult> {
  const trustMode = options.trustMode ?? "embedded_only";
  const event = (isObject(value) ? value : {}) as unknown as OpenReceiptEventV02;
  const result = emptyTrustResult(event, trustMode);
  const schemaErrors = validateV02Event(value);
  if (schemaErrors.length > 0) {
    result.errors.push(...schemaErrors);
    return result;
  }
  let parsed: ReturnType<typeof parseDetachedJws>;
  try {
    parsed = parseDetachedJws(event.signature);
    result.signature.algorithm = "EdDSA";
    result.signature.kid = parsed.header.kid;
  } catch (error) {
    result.errors.push(error instanceof Error ? error.message : "malformed_signature");
    return result;
  }
  if (parsed.header.kid !== event.signing_key_id) {
    result.errors.push("signing_key_id_mismatch");
    return result;
  }

  let metadata: IssuerMetadataV02 | null = null;
  let metadataTrusted = false;
  let resolvedAt = options.resolvedAt ?? new Date().toISOString();
  let previousMetadata = options.previousMetadata ?? [];
  if (trustMode === "pinned_metadata") {
    metadata = options.pinnedMetadata ?? null;
    if (metadata) {
      const actualHash = await issuerMetadataHash(metadata);
      metadataTrusted =
        typeof options.pinnedMetadataHash === "string" && actualHash === options.pinnedMetadataHash;
      if (!metadataTrusted) result.errors.push("pinned_metadata_hash_mismatch");
    } else if (options.resolver?.trustMode === "pinned_metadata") {
      try {
        const resolution = await options.resolver.resolve({
          issuer: event.issuer.id,
          metadataVersion: event.issuer_metadata_version,
          metadataHash: event.issuer_metadata_hash,
        });
        metadata = resolution.metadata;
        metadataTrusted = resolution.trusted;
        resolvedAt = resolution.resolved_at;
        previousMetadata = resolution.previous_metadata ?? [];
      } catch (error) {
        result.errors.push(
          error instanceof Error ? error.message : "pinned_metadata_resolution_failed",
        );
      }
    } else {
      result.errors.push("pinned_metadata_missing");
    }
  } else if (trustMode === "https_webpki") {
    if (!options.resolver || options.resolver.trustMode !== "https_webpki") {
      result.errors.push("https_resolver_missing");
    } else {
      try {
        const resolution = await options.resolver.resolve({
          issuer: event.issuer.id,
          metadataVersion: event.issuer_metadata_version,
          metadataHash: event.issuer_metadata_hash,
        });
        metadata = resolution.metadata;
        metadataTrusted = resolution.trusted;
        resolvedAt = resolution.resolved_at;
        previousMetadata = resolution.previous_metadata ?? [];
      } catch (error) {
        result.errors.push(error instanceof Error ? error.message : "issuer_resolution_failed");
      }
    }
  }

  let verificationKey: Ed25519PublicJwk | undefined;
  let keyRecord: IssuerMetadataKeyV02 | undefined;
  let keyEvaluation: KeyEvaluation | null = null;
  if (metadata) {
    const metadataVerification = await verifyIssuerMetadata(metadata, previousMetadata.at(-1));
    const pinnedSnapshotAnchor =
      trustMode === "pinned_metadata" && metadataTrusted && previousMetadata.length === 0;
    const actualHash = metadataVerification.hash;
    const hashValid =
      actualHash === event.issuer_metadata_hash &&
      metadata.metadata_version === event.issuer_metadata_version;
    const fullChain =
      previousMetadata.length === 0
        ? pinnedSnapshotAnchor || metadataVerification.chain_valid
        : (await verifyIssuerMetadataChain([...previousMetadata, metadata])).valid;
    result.errors.push(
      ...metadataVerification.errors.filter(
        (error) => !(pinnedSnapshotAnchor && error === "metadata_hash_chain_invalid"),
      ),
    );
    if (!hashValid) result.errors.push("metadata_hash_or_version_mismatch");
    if (!fullChain && !result.errors.includes("metadata_hash_chain_invalid")) {
      result.errors.push("metadata_hash_chain_invalid");
    }
    result.metadata.version = metadata.metadata_version;
    result.metadata.hash_valid = hashValid;
    result.metadata.signature_valid = metadataVerification.signature_valid;
    result.metadata.chain_valid = fullChain;
    result.metadata.issued_at = metadata.issued_at;
    result.metadata.next_update = metadata.next_update;
    result.metadata.resolved_at = resolvedAt;
    result.metadata.as_of = metadata.issued_at;
    result.metadata_as_of = metadata.issued_at;
    result.issuer.resolved = metadata.issuer === event.issuer.id;
    result.issuer.trusted =
      metadataTrusted &&
      result.issuer.resolved &&
      hashValid &&
      metadataVerification.signature_valid &&
      fullChain;
    keyRecord = metadata.keys.find((candidate) => candidate.kid === event.signing_key_id);
    if (!keyRecord) {
      result.errors.push("key_unknown");
      result.key.historical_result = "key_unknown";
    } else if (keyRecord.purpose !== "open_receipt_evidence") {
      result.errors.push("key_purpose_mismatch");
      result.key.purpose = keyRecord.purpose;
      result.key.current_status = keyRecord.status;
      result.key.historical_result = "key_purpose_mismatch";
    } else {
      verificationKey = keyRecord.public_jwk;
      result.key.purpose = keyRecord.purpose;
      result.key.current_status = keyRecord.status;
      keyEvaluation = evaluateHistoricalKey(keyRecord, Date.parse(event.issued_at));
      result.key.status_at_issuance = keyEvaluation.statusAtIssuance;
      result.key.historical_result = keyEvaluation.result;
      result.key.conclusion = keyEvaluation.conclusion;
      result.metadata.key_valid_as_of_metadata = keyEvaluation.valid;
      result.key_valid_as_of_metadata = keyEvaluation.valid;
    }

    const now = Date.parse(options.now ?? new Date().toISOString());
    const issued = Date.parse(metadata.issued_at);
    const resolved = Date.parse(resolvedAt);
    const nextUpdate = Date.parse(metadata.next_update);
    const maxAge = Math.max(0, options.maxMetadataAgeSeconds ?? 86_400);
    result.metadata.age_seconds = Math.max(0, Math.floor((now - issued) / 1000));
    result.metadata.freshness =
      now <= nextUpdate && now - resolved <= maxAge * 1000 ? "fresh" : "stale";
    result.metadata_freshness = result.metadata.freshness;
  } else if (trustMode === "embedded_only") {
    const embedded = event.issuer.verification_key;
    if (embedded?.kid === event.signing_key_id) verificationKey = embedded;
    result.key.historical_result = "key_status_unknown";
    result.key.conclusion = "key_status_unknown";
    result.warnings.push("issuer_untrusted", "key_status_unknown");
  }

  if (verificationKey) {
    const payloadSegment = bytesToBase64Url(encoder.encode(canonicalize(unsignedV02(event))));
    try {
      result.signature.valid = await crypto.subtle.verify(
        { name: "Ed25519" },
        await importVerificationKey(verificationKey),
        parsed.signature as BufferSource,
        encoder.encode(`${parsed.protectedSegment}.${payloadSegment}`) as BufferSource,
      );
    } catch {
      result.signature.valid = false;
    }
    if (!result.signature.valid) result.errors.push("bad_signature");
  } else if (!result.errors.includes("key_unknown")) {
    result.errors.push("verification_key_not_found");
  }

  const attestation = metadata
    ? await verifyIssuanceAttestation(event, metadata)
    : {
        status: event.issuance_attestation ? ("invalid" as const) : ("missing" as const),
        sequence: event.issuance_attestation?.sequence ?? null,
        errors: event.issuance_attestation ? ["attestation_metadata_unavailable"] : [],
      };
  result.issuance_attestation = {
    status: attestation.status,
    sequence: attestation.sequence,
  };
  result.errors.push(...attestation.errors);
  if (attestation.status === "missing") result.warnings.push("issuance_attestation_missing");
  if (attestation.status === "invalid") result.errors.push("issuance_attestation_invalid");

  if (keyEvaluation?.needsAttestation && attestation.status !== "valid") {
    result.warnings.push("backdating_resistance_insufficient");
    if (keyEvaluation.result === "signed_before_compromise") {
      result.key.conclusion = "key_status_unknown";
    }
  }
  if (attestation.status === "valid") result.warnings.push("issuance_attestation_valid");
  if (result.metadata.freshness === "stale") {
    result.warnings.push("metadata_stale");
    if (
      result.key.conclusion === "valid_at_issuance" ||
      result.key.conclusion === "retired_key_valid_at_issuance"
    ) {
      result.key.conclusion = "valid_but_metadata_stale";
    }
  }
  if (!result.issuer.trusted && trustMode !== "embedded_only") {
    result.errors.push("issuer_untrusted");
  }

  const hardInvalid =
    !result.signature.valid ||
    result.errors.some((error) =>
      [
        "bad_signature",
        "key_unknown",
        "key_purpose_mismatch",
        "signed_after_revocation",
        "signed_after_compromise",
        "metadata_signature_invalid",
        "metadata_hash_chain_invalid",
        "metadata_hash_or_version_mismatch",
        "metadata_signing_key_invalid_at_issuance",
        "attestation_signature_invalid",
        "attestation_receipt_digest_mismatch",
        "issuance_attestation_invalid",
      ].includes(error),
    ) ||
    keyEvaluation?.result === "signed_after_revocation" ||
    keyEvaluation?.result === "signed_after_compromise" ||
    keyEvaluation?.result === "signed_after_retirement" ||
    keyEvaluation?.result === "key_expired";
  const indeterminate =
    trustMode === "embedded_only" ||
    !result.issuer.trusted ||
    keyEvaluation?.result === "compromise_time_unknown" ||
    (keyEvaluation?.needsAttestation && attestation.status !== "valid");
  result.overall_status = hardInvalid
    ? "invalid"
    : indeterminate
      ? "indeterminate"
      : result.warnings.length > 0
        ? "valid_with_warnings"
        : "valid";
  return result;
}

export function createPinnedMetadataResolver(input: {
  metadata: IssuerMetadataV02;
  metadataHash: string;
  previousMetadata?: IssuerMetadataV02[];
  resolvedAt?: string;
}): IssuerResolver {
  return {
    trustMode: "pinned_metadata",
    async resolve(request) {
      const actualHash = await issuerMetadataHash(input.metadata);
      if (
        request.issuer !== input.metadata.issuer ||
        request.metadataVersion !== input.metadata.metadata_version ||
        request.metadataHash !== actualHash ||
        input.metadataHash !== actualHash
      ) {
        throw new Error("pinned_metadata_mismatch");
      }
      return {
        metadata: input.metadata,
        trust_mode: "pinned_metadata",
        resolved_at: input.resolvedAt ?? new Date().toISOString(),
        trusted: true,
        ...(input.previousMetadata ? { previous_metadata: input.previousMetadata } : {}),
      };
    },
  };
}

function unsafeIssuerHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  if (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    normalized.endsWith(".local")
  ) {
    return true;
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(normalized)) {
    const octets = normalized.split(".").map(Number);
    return (
      octets[0] === 10 ||
      octets[0] === 127 ||
      (octets[0] === 169 && octets[1] === 254) ||
      (octets[0] === 172 && (octets[1] ?? 0) >= 16 && (octets[1] ?? 0) <= 31) ||
      (octets[0] === 192 && octets[1] === 168)
    );
  }
  return (
    normalized === "::1" ||
    normalized === "[::1]" ||
    normalized.startsWith("[fc") ||
    normalized.startsWith("[fd") ||
    normalized.startsWith("[fe8") ||
    normalized.startsWith("[fe9") ||
    normalized.startsWith("[fea") ||
    normalized.startsWith("[feb")
  );
}

export function createHttpsWebPkiResolver(options: {
  allowedIssuerOrigins: string[];
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
  maximumResponseBytes?: number;
  now?: () => Date;
}): IssuerResolver {
  const fetcher = options.fetch ?? globalThis.fetch;
  const allowed = new Set(
    options.allowedIssuerOrigins.map((origin) => {
      const parsed = new URL(origin);
      if (parsed.protocol !== "https:") throw new TypeError("issuer_allowlist_requires_https");
      return parsed.origin;
    }),
  );
  const cache = new Map<string, { metadata: IssuerMetadataV02; hash: string; etag?: string }>();
  async function fetchVersion(
    issuer: URL,
    metadataVersion: number,
    expectedHash: string,
  ): Promise<{ metadata: IssuerMetadataV02; hash: string; etag?: string }> {
    const key = `${issuer.origin}:${metadataVersion}`;
    const cached = cache.get(key);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 5_000);
    let response: Response;
    try {
      response = await fetcher(
        `${issuer.origin}/.well-known/receipt-issuer/versions/${metadataVersion}`,
        {
          method: "GET",
          redirect: "manual",
          signal: controller.signal,
          headers: cached?.etag ? { "if-none-match": cached.etag } : {},
        },
      );
    } finally {
      clearTimeout(timeout);
    }
    if (response.status === 304 && cached) {
      if (cached.hash !== expectedHash) throw new Error("metadata_hash_mismatch");
      return cached;
    }
    if (response.status >= 300 && response.status < 400) {
      throw new Error("issuer_redirect_rejected");
    }
    if (!response.ok) throw new Error(`issuer_metadata_http_${response.status}`);
    const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
    if (
      !contentType.startsWith("application/json") &&
      !contentType.startsWith("application/open-receipt-issuer+json")
    ) {
      throw new Error("issuer_metadata_content_type_invalid");
    }
    const maximum = options.maximumResponseBytes ?? 262_144;
    const contentLength = Number(response.headers.get("content-length") ?? "0");
    if (contentLength > maximum) throw new Error("issuer_metadata_too_large");
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > maximum) throw new Error("issuer_metadata_too_large");
    const metadata = JSON.parse(new TextDecoder().decode(bytes)) as IssuerMetadataV02;
    const hash = await issuerMetadataHash(metadata);
    if (
      metadata.issuer !== issuer.origin ||
      metadata.metadata_version !== metadataVersion ||
      hash !== expectedHash
    ) {
      throw new Error("metadata_hash_or_version_mismatch");
    }
    if (cached && cached.hash !== hash) throw new Error("metadata_version_rollback_or_rewrite");
    const etag = response.headers.get("etag") ?? undefined;
    const stored = { metadata, hash, ...(etag ? { etag } : {}) };
    cache.set(key, stored);
    return stored;
  }
  return {
    trustMode: "https_webpki",
    async resolve(request) {
      const issuer = new URL(request.issuer);
      if (
        issuer.protocol !== "https:" ||
        issuer.origin !== request.issuer.replace(/\/$/, "") ||
        !allowed.has(issuer.origin) ||
        unsafeIssuerHostname(issuer.hostname)
      ) {
        throw new Error("issuer_origin_not_allowed");
      }
      if (!Number.isSafeInteger(request.metadataVersion) || request.metadataVersion < 1) {
        throw new Error("invalid_metadata_version");
      }
      if (request.metadataVersion > 10_000) throw new Error("metadata_chain_too_long");
      const current = await fetchVersion(issuer, request.metadataVersion, request.metadataHash);
      const previous: IssuerMetadataV02[] = [];
      let expectedPreviousHash = current.metadata.previous_metadata_hash;
      for (let version = request.metadataVersion - 1; version >= 1; version -= 1) {
        if (!expectedPreviousHash) throw new Error("metadata_hash_chain_invalid");
        const resolved = await fetchVersion(issuer, version, expectedPreviousHash);
        previous.unshift(resolved.metadata);
        expectedPreviousHash = resolved.metadata.previous_metadata_hash;
      }
      if (expectedPreviousHash !== null) throw new Error("metadata_hash_chain_invalid");
      return {
        metadata: current.metadata,
        trust_mode: "https_webpki",
        resolved_at: (options.now ?? (() => new Date()))().toISOString(),
        trusted: true,
        ...(current.etag ? { etag: current.etag } : {}),
        ...(previous.length > 0 ? { previous_metadata: previous } : {}),
      };
    },
  };
}
