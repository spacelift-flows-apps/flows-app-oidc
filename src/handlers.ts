import { http, kv } from "@slflows/sdk/v1";
import { CONSTANTS } from "./types.js";

export async function handleConfiguration({ app, request }) {
  const baseUrl = app.http.url;

  await http.respond(request.requestId, {
    statusCode: 200,
    headers: CONSTANTS.DISCOVERY_RESPONSE_HEADERS,
    body: {
      issuer: new URL(baseUrl).origin,
      jwks_uri: `${baseUrl}/jwks`,
      id_token_signing_alg_values_supported: [CONSTANTS.ALGORITHM],
      subject_types_supported: ["public"], // Required by OIDC spec
      response_types_supported: [], // No auth flows supported
      claims_supported: ["sub", "aud", "exp", "iat", "iss", "jti", "nbf"],
      // Note: This is a JWT issuer service, not a full OIDC Provider
      // No authorization_endpoint, token_endpoint, or userinfo_endpoint
    },
  });
}

export async function handleJWKs(requestId: string, app: any) {
  const pubKeys: any[] = [];

  // Only use signal keyring - if no signal, we have no keys to return
  if (!app.signals.keyring) {
    return await http.respond(requestId, {
      statusCode: 200,
      headers: CONSTANTS.JWKS_RESPONSE_HEADERS,
      body: { keys: [] },
    });
  }

  let startingKey: string | undefined;

  // Paginate through all keys and build pubKeys directly
  do {
    const { pairs, nextStartingKey } = await kv.app.list({
      keyPrefix: CONSTANTS.KEY_STORE.getKeyPrefix(app.signals.keyring),
      startingKey,
    });

    // Extract public keys from this page
    (pairs || []).forEach((pair) => {
      pubKeys.push({ ...pair.value, alg: CONSTANTS.ALGORITHM, use: "sig" });
    });

    startingKey = nextStartingKey;
  } while (startingKey);

  return await http.respond(requestId, {
    statusCode: 200,
    headers: CONSTANTS.JWKS_RESPONSE_HEADERS,
    body: { keys: pubKeys },
  });
}
