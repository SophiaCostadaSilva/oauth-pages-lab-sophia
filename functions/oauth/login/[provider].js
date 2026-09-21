import {
  randomBase64Url,
  sha256Base64Url,
  createCodeChallenge
} from "../../_shared/crypto.js";

import {
  oauthTransactionCookie
} from "../../_shared/cookies.js";

import {
  PROVIDERS,
  isSupportedProvider
} from "../../_shared/providers.js";

export async function onRequestGet(context) {
  const provider =
    context.params.provider;

  if (!isSupportedProvider(provider)) {
    return new Response("Not Found", {
      status: 404,
      headers: {
        "Cache-Control": "no-store"
      }
    });
  }

  const env = context.env;

  const baseUrl =
    env.PUBLIC_BASE_URL.replace(/\/$/, "");

  const clientId =
    provider === "google"
      ? env.GOOGLE_CLIENT_ID
      : env.GITHUB_CLIENT_ID;

  const redirectUri =
    `${baseUrl}/oauth/callback/${provider}`;

  const transactionId =
    randomBase64Url();

  const state =
    randomBase64Url();

  const codeVerifier =
    randomBase64Url();

  const codeChallenge =
    await createCodeChallenge(
      codeVerifier
    );

  const nonce =
    provider === "google"
      ? randomBase64Url()
      : null;

  const idHash =
    await sha256Base64Url(transactionId);

  const stateHash =
    await sha256Base64Url(state);

  const expiresAt =
    Math.floor(Date.now() / 1000) + 600;

  await env.DB
    .prepare(`
      INSERT INTO oauth_transactions
      (
        id_hash,
        provider,
        state_hash,
        nonce,
        code_verifier,
        expires_at
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `)
    .bind(
      idHash,
      provider,
      stateHash,
      nonce,
      codeVerifier,
      expiresAt
    )
    .run();

  const authorizationUrl =
    new URL(
      PROVIDERS[provider].authorizationEndpoint
    );

  authorizationUrl.searchParams.set(
    "client_id",
    clientId
  );

  authorizationUrl.searchParams.set(
    "redirect_uri",
    redirectUri
  );

  authorizationUrl.searchParams.set(
    "response_type",
    "code"
  );

  authorizationUrl.searchParams.set(
    "state",
    state
  );

  authorizationUrl.searchParams.set(
    "code_challenge",
    codeChallenge
  );

  authorizationUrl.searchParams.set(
    "code_challenge_method",
    "S256"
  );

  if (provider === "google") {
    authorizationUrl.searchParams.set(
      "scope",
      "openid email profile"
    );

    authorizationUrl.searchParams.set(
      "nonce",
      nonce
    );
  }

  return new Response(null, {
    status: 302,

    headers: {
      "Location":
        authorizationUrl.toString(),

      "Set-Cookie":
        oauthTransactionCookie(
          transactionId
        ),

      "Cache-Control":
        "no-store"
    }
  });
}