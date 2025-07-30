import { SignJWT, importJWK, type JWK } from "jose";
import { kv } from "@slflows/sdk/v1";
import { AppConfig, TokenData, CONSTANTS } from "./types.js";

/**
 * Creates a hash of the app configuration for change detection
 */
export function hashConfig(config: AppConfig): string {
  const configStr = JSON.stringify({
    expirationMinutes: config.expirationMinutes,
    audience: config.audience,
    additionalClaims: config.additionalClaims,
    keyring: config.keyring,
  });

  // Simple hash using crypto.subtle would be ideal, but for simplicity use a basic hash
  let hash = 0;
  for (let i = 0; i < configStr.length; i++) {
    const char = configStr.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  return hash.toString();
}

/**
 * Generates a new key and token using TTL-based expiration
 * Keys automatically expire via KV TTL, no manual cleanup needed
 * Returns the new token data for signal updates
 */
export async function generateKeyAndToken(
  config: AppConfig,
  appUrl: string,
): Promise<TokenData> {
  try {
    console.log("Starting key and token generation...");

    // Generate a new key ID and key pair
    const newKeyId = crypto.randomUUID();
    const { privateKey, publicKey } = await generateRsaKeyPair();

    // Generate token with new private key (then discard private key)
    const tokenData = await generateToken(
      config,
      appUrl,
      newKeyId,
      privateKey as JWK,
    );

    // Calculate TTL: grace period + max token lifetime
    const tokenExpirationMinutes = config.expirationMinutes;
    const keyTtlSeconds =
      (CONSTANTS.KEY_GRACE_PERIOD_MINUTES + tokenExpirationMinutes) * 60;

    // Store new key with TTL and current token
    await kv.app.setMany([
      // Store new public key with automatic expiration
      {
        key: `${CONSTANTS.KEY_STORE.getKeyPrefix(config.keyring || "default")}${newKeyId}`,
        value: publicKey as JWK,
        ttl: keyTtlSeconds,
      },
      // Store current token
      {
        key: CONSTANTS.KEY_STORE.CURRENT_TOKEN_KEY,
        value: tokenData,
      },
    ]);

    console.log(
      `Key and token generation completed successfully, new key: ${newKeyId}`,
    );
    return tokenData;
  } catch (error) {
    console.error("Critical error during key and token generation:", error);
    throw error; // Preserve original error for debugging
  }
}

/**
 * Generates an RSA key pair for signing tokens
 */
async function generateRsaKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    CONSTANTS.RSA_KEY_PARAMS,
    true, // extractable: true is critical here
    ["sign", "verify"],
  );

  const [privateKey, publicKey] = await Promise.all([
    crypto.subtle.exportKey("jwk", keyPair.privateKey),
    crypto.subtle.exportKey("jwk", keyPair.publicKey),
  ]);

  return { privateKey, publicKey };
}

/**
 * Generates a JWT token and returns it for signal emission
 */
async function generateToken(
  config: AppConfig,
  appUrl: string,
  kid: string,
  privateKey: JWK,
) {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + config.expirationMinutes * 60;

  return {
    token: await createJWT(kid, privateKey, {
      ...config.additionalClaims, // additional claims overrides go first...
      jti: crypto.randomUUID(), // then standard claims, to prevent tampering
      iss: new URL(appUrl).origin,
      sub: "flows", // subject
      aud: config.audience || new URL(appUrl).hostname, // audience
      exp: expiresAt, // expiration time
      iat: now, // issued at
      nbf: now, // not before
    }),
    expiresAt: expiresAt,
    configHash: hashConfig(config),
  };
}

/**
 * Creates a JWT token using RS256 algorithm via jose library
 */
async function createJWT(
  kid: string,
  privateKey: JWK,
  payload: Record<string, any>,
) {
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: CONSTANTS.ALGORITHM, typ: "JWT", kid })
    .sign(await importJWK(privateKey, CONSTANTS.ALGORITHM));
}
