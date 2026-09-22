import {
  randomBase64Url,
  sha256Base64Url
} from "../../_shared/crypto.js";

import {
  getCookie,
  sessionCookie,
  clearOauthTransactionCookie
} from "../../_shared/cookies.js";

import {
  PROVIDERS,
  isSupportedProvider
} from "../../_shared/providers.js";

import {
  validateGoogleIdToken
} from "../../_shared/oidc.js";

function noStoreHeaders(extra = {}) {
  return {
    "Cache-Control": "no-store",
    ...extra
  };
}

function errorResponse(status = 400, reason = "unknown") {
  return new Response(`Authentication failed: ${reason}`, {
    status,
    headers: noStoreHeaders()
  });

}

export async function onRequestGet(context) {
  const provider =
    context.params.provider;

  if (!isSupportedProvider(provider)) {
    return new Response("Not Found", {
      status: 404,
      headers: noStoreHeaders()
    });
  }

  const request =
    context.request;

  const url =
    new URL(request.url);

  const code =
    url.searchParams.get("code");

  const state =
    url.searchParams.get("state");

  const oauthError =
    url.searchParams.get("error");

  if (
    oauthError ||
    !code ||
    !state
  ) {
    return errorResponse();
  }

  const transactionCookie =
    getCookie(
      request,
      "__Host-oauth-tx"
    );

  if (!transactionCookie) {
    return errorResponse();
  }

  const transactionHash =
    await sha256Base64Url(
      transactionCookie
    );

  const transaction =
    await context.env.DB
      .prepare(`
        SELECT
          id_hash,
          provider,
          state_hash,
          nonce,
          code_verifier,
          expires_at
        FROM oauth_transactions
        WHERE id_hash = ?
      `)
      .bind(transactionHash)
      .first();

  if (!transaction) {
    return errorResponse();
  }

  const now =
    Math.floor(Date.now() / 1000);

  if (
    transaction.expires_at <= now
  ) {
    await context.env.DB
      .prepare(`
        DELETE FROM oauth_transactions
        WHERE id_hash = ?
      `)
      .bind(transactionHash)
      .run();

    return errorResponse();
  }

  if (
    transaction.provider !== provider
  ) {
    return errorResponse();
  }

  const stateHash =
    await sha256Base64Url(state);

  if (
    stateHash !== transaction.state_hash
  ) {
    return errorResponse();
  }
  
  await context.env.DB
    .prepare(`
      DELETE FROM oauth_transactions
      WHERE id_hash = ?
    `)
    .bind(transactionHash)
    .run();

  const baseUrl =
    context.env.PUBLIC_BASE_URL
      .replace(/\/$/, "");

  const clientId =
    provider === "google"
      ? context.env.GOOGLE_CLIENT_ID
      : context.env.GITHUB_CLIENT_ID;

  const clientSecret =
    provider === "google"
      ? context.env.GOOGLE_CLIENT_SECRET
      : context.env.GITHUB_CLIENT_SECRET;

  const redirectUri =
    `${baseUrl}/oauth/callback/${provider}`;

  let identity;

  if (provider === "google") {
    identity =
      await exchangeGoogleCode(
        code,
        transaction.code_verifier,
        clientId,
        clientSecret,
        redirectUri
      );

    identity =
      await validateGoogleIdToken(
        identity.id_token,
        clientId,
        transaction.nonce
      );
  } else {
    identity =
      await exchangeGithubCode(
        code,
        transaction.code_verifier,
        clientId,
        clientSecret,
        redirectUri
      );

    identity =
      await validateGithubIdentity(
        identity,
        clientId,
        clientSecret
      );
  }

  const sessionValue =
    randomBase64Url();

  const sessionHash =
    await sha256Base64Url(
      sessionValue
    );

  const sessionExpiresAt =
    Math.floor(Date.now() / 1000)
    + 28800;

  await context.env.DB
    .prepare(`
      INSERT INTO sessions
      (
        id_hash,
        issuer,
        subject,
        email,
        display_name,
        expires_at,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `)
    .bind(
      sessionHash,
      identity.issuer,
      identity.subject,
      identity.email,
      identity.displayName,
      sessionExpiresAt,
      now
    )
    .run();

  return new Response(null, {
    status: 302,

    headers: noStoreHeaders({
      "Location": baseUrl,

      "Set-Cookie":
        [
          sessionCookie(sessionValue),
          clearOauthTransactionCookie()
        ].join(", ")
    })
  });
}

async function exchangeGoogleCode(
  code,
  codeVerifier,
  clientId,
  clientSecret,
  redirectUri
) {
  const body =
    new URLSearchParams();

  body.set("client_id", clientId);
  body.set("client_secret", clientSecret);
  body.set("code", code);
  body.set("code_verifier", codeVerifier);
  body.set("redirect_uri", redirectUri);
  body.set(
    "grant_type",
    "authorization_code"
  );

  const response =
    await fetch(
      PROVIDERS.google.tokenEndpoint,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },

        body
      }
    );

  if (!response.ok) {
    throw new Error("google_token_exchange_failed");
  }

  const data =
    await response.json();

  if (!data.id_token) {
    throw new Error("missing_google_id_token");
  }

  return data;
}

async function exchangeGithubCode(
  code,
  codeVerifier,
  clientId,
  clientSecret,
  redirectUri
) {
  const body =
    new URLSearchParams();

  body.set("client_id", clientId);
  body.set("client_secret", clientSecret);
  body.set("code", code);
  body.set("code_verifier", codeVerifier);
  body.set("redirect_uri", redirectUri);

  const response =
    await fetch(
      PROVIDERS.github.tokenEndpoint,
      {
        method: "POST",

        headers: {
          "Accept":
            "application/json",

          "Content-Type":
            "application/x-www-form-urlencoded"
        },

        body
      }
    );

  if (!response.ok) {
    throw new Error("github_token_exchange_failed");
  }

  const data =
    await response.json();

  if (
    typeof data.access_token !== "string" ||
    String(data.token_type).toLowerCase()
      !== "bearer"
  ) {
    throw new Error("invalid_github_token");
  }

  return data;
}

async function validateGithubIdentity(
  tokenData,
  clientId,
  clientSecret
) {
  const userResponse =
    await fetch(
      "https://api.github.com/user",
      {
        headers: {
          "Authorization":
            `Bearer ${tokenData.access_token}`,

          "Accept":
            "application/vnd.github+json",

          "X-GitHub-Api-Version":
            "2026-03-10"
        }
      }
    );

  if (!userResponse.ok) {
  throw new Error(
    `github_user_failed_${userResponse.status}`
  );
    }

  const user =
    await userResponse.json();

  if (
    !Number.isInteger(user.id)
  ) {
    throw new Error("invalid_github_user");
  }

  const revokeResponse =
    await fetch(
      `https://api.github.com/applications/${encodeURIComponent(clientId)}/grant`,
      {
        method: "DELETE",

        headers: {
          "Authorization":
            `Basic ${btoa(
              `${clientId}:${clientSecret}`
            )}`,

          "Accept":
            "application/vnd.github+json",

          "X-GitHub-Api-Version":
            "2026-03-10",

          "Content-Type":
            "application/json"
        },

        body: JSON.stringify({
          access_token:
            tokenData.access_token
        })
      }
    );

  if (revokeResponse.status !== 204) {
    throw new Error("github_revoke_failed");
  }

  return {
    issuer: "https://github.com",

    subject:
      String(user.id),

    email:
      typeof user.email === "string"
        ? user.email
        : null,

    displayName:
      typeof user.name === "string"
        ? user.name
        : user.login
  };
}