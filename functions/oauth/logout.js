import {
  getCookie,
  clearSessionCookie
} from "../_shared/cookies.js";

import {
  sha256Base64Url
} from "../_shared/crypto.js";

export async function onRequestPost(context) {
  const request =
    context.request;

  const origin =
    request.headers.get("Origin");

  const baseUrl =
    context.env.PUBLIC_BASE_URL.replace(/\/$/, "");

  if (origin !== baseUrl) {
    return new Response(
      "Forbidden",
      {
        status: 403,
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  }

  const sessionCookie =
    getCookie(
      request,
      "__Host-session"
    );

  if (sessionCookie) {
    const idHash =
      await sha256Base64Url(
        sessionCookie
      );

    await context.env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE id_hash = ?
      `)
      .bind(idHash)
      .run();
  }

  return new Response(null, {
    status: 204,
    headers: {
      "Set-Cookie":
        clearSessionCookie(),

      "Cache-Control":
        "no-store"
    }
  });
}