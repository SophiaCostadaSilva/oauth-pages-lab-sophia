function base64UrlEncode(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function randomBase64Url(bytesLength = 32) {
  const bytes = new Uint8Array(bytesLength);
  crypto.getRandomValues(bytes);

  return base64UrlEncode(bytes);
}

export async function sha256Base64Url(value) {
  const data = new TextEncoder().encode(value);

  const digest = await crypto.subtle.digest(
    "SHA-256",
    data
  );

  return base64UrlEncode(new Uint8Array(digest));
}

export async function createCodeChallenge(codeVerifier) {
  return sha256Base64Url(codeVerifier);
}