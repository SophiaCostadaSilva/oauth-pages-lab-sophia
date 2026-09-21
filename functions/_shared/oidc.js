const GOOGLE_DISCOVERY =
  "https://accounts.google.com/.well-known/openid-configuration";

function decodeBase64UrlJson(value) {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padding =
    "=".repeat((4 - (normalized.length % 4)) % 4);

  const binary = atob(normalized + padding);

  const bytes = Uint8Array.from(
    binary,
    char => char.charCodeAt(0)
  );

  return JSON.parse(
    new TextDecoder().decode(bytes)
  );
}

function decodeBase64UrlBytes(value) {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padding =
    "=".repeat((4 - (normalized.length % 4)) % 4);

  const binary = atob(normalized + padding);

  return Uint8Array.from(
    binary,
    char => char.charCodeAt(0)
  );
}

export async function validateGoogleIdToken(
  idToken,
  expectedClientId,
  expectedNonce
) {
  if (typeof idToken !== "string") {
    throw new Error("invalid_id_token");
  }

  const parts = idToken.split(".");

  if (parts.length !== 3) {
    throw new Error("invalid_jwt");
  }

  const [encodedHeader, encodedPayload, encodedSignature] =
    parts;

  const header = decodeBase64UrlJson(encodedHeader);
  const payload = decodeBase64UrlJson(encodedPayload);

  if (header.alg !== "RS256") {
    throw new Error("invalid_algorithm");
  }

  if (!header.kid) {
    throw new Error("missing_kid");
  }

  const discoveryResponse =
    await fetch(GOOGLE_DISCOVERY);

  if (!discoveryResponse.ok) {
    throw new Error("discovery_failed");
  }

  const discovery =
    await discoveryResponse.json();

  if (discovery.issuer !== "https://accounts.google.com") {
    throw new Error("invalid_issuer_configuration");
  }

  const jwksResponse =
    await fetch(discovery.jwks_uri);

  if (!jwksResponse.ok) {
    throw new Error("jwks_failed");
  }

  const jwks =
    await jwksResponse.json();

  const jwk = jwks.keys.find(
    key => key.kid === header.kid
  );

  if (!jwk) {
    throw new Error("unknown_key");
  }

  const publicKey =
    await crypto.subtle.importKey(
      "jwk",
      jwk,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256"
      },
      false,
      ["verify"]
    );

  const signingInput =
    new TextEncoder().encode(
      `${encodedHeader}.${encodedPayload}`
    );

  const signature =
    decodeBase64UrlBytes(encodedSignature);

  const valid =
    await crypto.subtle.verify(
      {
        name: "RSASSA-PKCS1-v1_5"
      },
      publicKey,
      signature,
      signingInput
    );

  if (!valid) {
    throw new Error("invalid_signature");
  }

  const now = Math.floor(Date.now() / 1000);

  if (payload.iss !== "https://accounts.google.com") {
    throw new Error("invalid_issuer");
  }

  if (payload.aud !== expectedClientId) {
    throw new Error("invalid_audience");
  }

  if (
    typeof payload.exp !== "number" ||
    payload.exp <= now
  ) {
    throw new Error("expired_token");
  }

  if (
    typeof payload.iat !== "number" ||
    payload.iat > now + 300
  ) {
    throw new Error("invalid_iat");
  }

  if (payload.nonce !== expectedNonce) {
    throw new Error("invalid_nonce");
  }

  if (!payload.sub) {
    throw new Error("missing_subject");
  }

  return {
    issuer: "https://accounts.google.com",
    subject: String(payload.sub),
    email:
      typeof payload.email === "string"
        ? payload.email
        : null,
    displayName:
      typeof payload.name === "string"
        ? payload.name
        : null
  };
}