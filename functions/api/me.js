import {
  sha256Base64Url
} from "../../_shared/crypto.js";

import {
  getCookie
} from "../../_shared/cookies.js";

export async function onRequestGet(context) {
  const cookie =
    getCookie(
      context.request,
      "__Host-session"
    );

  if (!cookie) {
    return new Response(null, {
      status: 401,
      headers: {
        "Cache-Control": "no-store"
      }
    });
  }

  const idHash =
    await sha256Base64Url(cookie);

  const now =
    Math.floor(Date.now() / 1000);

  const session =
    await context.env.DB
      .prepare(`
        SELECT
          issuer,
          subject,
          email,
          display_name,
          expires_at
        FROM sessions
        WHERE id_hash = ?
          AND expires_at > ?
      `)
      .bind(idHash, now)
      .first();

  if (!session) {
    return new Response(null, {
      status: 401,
      headers: {
        "Cache-Control": "no-store"
      }
    });
  }

  return Response.json(
    {
      issuer: session.issuer,
      subject: session.subject,
      email: session.email,
      displayName: session.display_name
    },
    {
      headers: {
        "Cache-Control": "no-store"
      }
    }
  );
}