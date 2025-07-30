// Type definitions
export interface AppConfig {
  expirationMinutes: number;
  audience?: string;
  additionalClaims?: Record<string, unknown>;
  keyring?: string;
}

export interface TokenData {
  token: string;
  expiresAt: number; // Unix timestamp
  configHash: string; // Hash of config when token was generated
}

// Centralized configuration constants
export const CONSTANTS = {
  KEY_STORE: {
    getKeyPrefix: (keyring: string) => `key:${keyring}:`,
    CURRENT_TOKEN_KEY: "current_token",
    ROTATION_TIMER_KEY: "rotation_timer_id",
  },
  // Grace period for key availability after retirement (30 minutes)
  // This should be longer than any reasonable token lifetime to ensure validation works
  KEY_GRACE_PERIOD_MINUTES: 30,
  ALGORITHM: "RS256",
  RSA_KEY_PARAMS: {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
    hash: "SHA-256",
  },
  get DISCOVERY_RESPONSE_HEADERS() {
    return {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": this.CACHE_CONTROL_HEADER,
    };
  },
  get JWKS_RESPONSE_HEADERS() {
    return {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-cache",
    };
  },
};
