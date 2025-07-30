/**
 * OpenID Connect (OIDC) JWT Issuer
 *
 * Provides OIDC-compliant JWT token generation with automatic key rotation
 * and instant token invalidation capabilities via keyring management.
 *
 * Key Features:
 * - Dynamic RSA key rotation based on token lifetime (half of expiration time)
 * - Instant token invalidation via keyring changes
 * - Configuration change detection and automatic token regeneration
 * - Race condition prevention using signal-based keyring tracking
 * - OIDC discovery and JWKS endpoints for standard token validation
 * - Minimum 10-minute token lifetime enforcement for security
 * - Automatic timer management with cancellation on config changes
 */

import { defineApp, kv, http, lifecycle, timers } from "@slflows/sdk/v1";
import { AppConfig, TokenData, CONSTANTS } from "./src/types.js";
import { hashConfig, generateKeyAndToken } from "./src/crypto.js";
import { handleConfiguration, handleJWKs } from "./src/handlers.js";

export const app = defineApp({
  name: "OpenID Connect",
  installationInstructions: `
Generates OIDC-compliant JWT tokens with automatic key rotation. Configure your token settings (minimum 10 minutes expiration), then use the **OIDC Token** and **Issuer URL** signals in your flows. 

For token validation, use:
- Discovery: <copyable>{appEndpointUrl}/.well-known/openid-configuration</copyable>
- JWKS: <copyable>{appEndpointUrl}/jwks</copyable>

**Key rotation** happens automatically at half the token lifetime interval for optimal security.
  `.trim(),

  config: {
    expirationMinutes: {
      name: "Expiration time (minutes)",
      description:
        "How long the token is valid before it expires (minimum: 10 minutes)",
      type: "number",
      required: true,
      default: 120,
    },
    audience: {
      name: "Audience",
      description:
        "The intended recipient of the token. When not specified, the app's URL without the protocol will be used.",
      type: "string",
      required: false,
    },
    additionalClaims: {
      name: "Additional claims",
      description:
        "Any additional claims to include in the token (JSON object)",
      type: { type: "object" },
      required: false,
    },
    keyring: {
      name: "Key Ring ID",
      description:
        "Changing this value will immediately invalidate all existing tokens by making their signing keys inaccessible",
      type: "string",
      required: false,
      default: "default",
    },
  },

  signals: {
    token: {
      name: "OIDC Token",
      description: "Generated OpenID Connect token",
      sensitive: true,
    },
    expiresAt: {
      name: "Token expiration time (Unix timestamp)",
      description: "The time when the token will expire",
    },
    issuer: {
      name: "Issuer URL",
      description:
        "The OIDC issuer URL for this app (used in token validation)",
    },
    keyring: {
      name: "Active Key Ring ID",
      description:
        "The currently active keyring (only updated after successful key generation)",
    },
  },

  blocks: {},

  /**
   * Synchronization Handler - Core State Management
   *
   * Simplified sync logic that delegates to specialized handlers:
   * 1. Configuration validation (minimum 10-minute expiration)
   * 2. Configuration change detection via hashing
   * 3. Token lifecycle management with timer coordination
   * 4. Race condition prevention via signal keyring tracking
   * 5. Signal updates to reflect current state
   *
   * States handled:
   * - Initial setup: Generate first token and start rotation timer
   * - Config change: Regenerate token, cancel old timer, start new timer
   * - No change: Reuse existing token and maintain current keyring
   */
  onSync: async ({ app }) => {
    try {
      const config = app.config as AppConfig;

      // Validate minimum expiration time
      if (config.expirationMinutes < 10) {
        return {
          newStatus: "failed",
          customStatusDescription:
            "Token expiration time must be at least 10 minutes",
        };
      }

      const currentConfigHash = hashConfig(config);
      const configKeyring = config.keyring;
      const currentKeyring = app.signals.keyring || configKeyring;

      // Check if we have a current token stored in KV
      const { value: currentToken } = await kv.app.get(
        CONSTANTS.KEY_STORE.CURRENT_TOKEN_KEY,
      );

      let tokenData: TokenData;
      let activeKeyring: string;

      // Delegate to specialized handlers based on state
      if (!currentToken) {
        ({ tokenData, activeKeyring } = await handleInitialSetup(
          config,
          app.http.url,
          configKeyring,
        ));
      } else if (currentToken.configHash !== currentConfigHash) {
        ({ tokenData, activeKeyring } = await handleConfigChange(
          config,
          app.http.url,
          configKeyring,
        ));
      } else {
        // No changes - reuse existing token and maintain current keyring
        tokenData = currentToken;
        activeKeyring = currentKeyring;
      }

      return {
        newStatus: "ready",
        signalUpdates: createSignalUpdates(
          tokenData,
          app.http.url,
          activeKeyring,
        ),
      };
    } catch (error) {
      console.error("Failed to sync OIDC app: ", error);
      return {
        newStatus: "failed",
        customStatusDescription: "Sync error, see logs",
      };
    }
  },

  /**
   * HTTP Request Handler - OIDC Endpoints
   *
   * Provides standard OIDC endpoints for token validation:
   *
   * /.well-known/openid-configuration:
   *   - OIDC discovery endpoint
   *   - Returns issuer info, JWKS URI, supported algorithms
   *   - Required by OIDC specification
   *
   * /jwks:
   *   - JSON Web Key Set endpoint
   *   - Serves public keys for token verification
   *   - Uses signal keyring to prevent race conditions
   *   - Paginates through all active keys
   */
  http: {
    onRequest: async (input): Promise<void> => {
      try {
        switch (input.request.path) {
          case "/.well-known/openid-configuration":
            return await handleConfiguration(input);
          case "/jwks":
            return await handleJWKs(input.request.requestId, input.app);
          default:
            return await http.respond(input.request.requestId, {
              statusCode: 404,
              body: { error: "not found" },
            });
        }
      } catch (error) {
        console.error("HTTP request failed:", error);
        return await http.respond(input.request.requestId, {
          statusCode: 500,
          body: { error: "internal server error" },
        });
      }
    },
  },

  /**
   * Timer Handler - Dynamic Key Rotation
   *
   * Handles timer events for key rotation with dynamic intervals.
   * Each rotation:
   * 1. Generates new key pair and token
   * 2. Triggers sync to update signals
   * 3. Self-schedules next rotation based on current config
   * 4. Stores new timer ID for future cancellation
   *
   * On failure:
   * - Logs error and schedules retry in 5 minutes
   * - Maintains timer ID tracking for cleanup
   */
  onTimer: async (input) => {
    try {
      console.log("Timer-triggered key rotation...");

      const config = input.app.config as AppConfig;
      await generateKeyAndToken(config, input.app.http.url);

      // Trigger sync to update signals with new token
      await lifecycle.sync();

      // Schedule next rotation with potentially updated interval
      const nextInterval = calculateRotationInterval(config.expirationMinutes);
      console.log(`Next key rotation scheduled in ${nextInterval} minutes`);

      const nextTimerId = await timers.set(nextInterval * 60, {
        description: `Key rotation scheduled for ${nextInterval} minutes`,
      });

      // Store new timer ID for future cancellation
      await kv.app.set({
        key: CONSTANTS.KEY_STORE.ROTATION_TIMER_KEY,
        value: nextTimerId,
      });
    } catch (error) {
      console.error("Failed to rotate key:", error);

      // Schedule retry in 5 minutes on failure
      const retryTimerId = await timers.set(300, {
        description: "Key rotation retry after failure (5 minutes)",
      });

      // Store retry timer ID
      await kv.app.set({
        key: CONSTANTS.KEY_STORE.ROTATION_TIMER_KEY,
        value: retryTimerId,
      });
    }
  },
});

/**
 * Handle Initial Setup - No Existing Token
 *
 * Creates the first token and starts the rotation timer.
 *
 * @param config - App configuration
 * @param appUrl - App's HTTP URL
 * @param configKeyring - Keyring from config
 * @returns Token data and active keyring
 */
async function handleInitialSetup(
  config: AppConfig,
  appUrl: string,
  configKeyring: string,
): Promise<{ tokenData: TokenData; activeKeyring: string }> {
  console.log(
    "No current token found, generating initial key pair and token...",
  );

  const tokenData = await generateKeyAndToken(config, appUrl);
  const rotationInterval = calculateRotationInterval(config.expirationMinutes);

  console.log(
    `Starting initial key rotation timer: ${rotationInterval} minutes`,
  );

  const timerId = await timers.set(rotationInterval * 60, {
    description: `Initial key rotation scheduled for ${rotationInterval} minutes`,
  });

  // Store timer ID for future cancellation
  await kv.app.set({
    key: CONSTANTS.KEY_STORE.ROTATION_TIMER_KEY,
    value: timerId,
  });

  return {
    tokenData,
    activeKeyring: configKeyring,
  };
}

/**
 * Handle Configuration Change - Regenerate Token
 *
 * Regenerates token with new settings and resets the rotation timer.
 *
 * @param config - Updated app configuration
 * @param appUrl - App's HTTP URL
 * @param configKeyring - Keyring from config
 * @returns Token data and active keyring
 */
async function handleConfigChange(
  config: AppConfig,
  appUrl: string,
  configKeyring: string,
): Promise<{ tokenData: TokenData; activeKeyring: string }> {
  console.log("Config changed, regenerating key pair and token...");

  const tokenData = await generateKeyAndToken(config, appUrl);

  // Cancel existing timer and set new one with updated interval
  const { value: existingTimerId } = await kv.app.get(
    CONSTANTS.KEY_STORE.ROTATION_TIMER_KEY,
  );

  if (existingTimerId) {
    console.log("Cancelling existing timer due to config change");
    await timers.unset(existingTimerId);
  }

  // Set new timer with updated interval
  const newRotationInterval = calculateRotationInterval(
    config.expirationMinutes,
  );
  console.log(
    `Resetting timer for new interval: ${newRotationInterval} minutes`,
  );

  const newTimerId = await timers.set(newRotationInterval * 60, {
    description: `Key rotation rescheduled after config change (${newRotationInterval} minutes)`,
  });

  // Store new timer ID
  await kv.app.set({
    key: CONSTANTS.KEY_STORE.ROTATION_TIMER_KEY,
    value: newTimerId,
  });

  return {
    tokenData,
    activeKeyring: configKeyring,
  };
}

/**
 * Calculate Dynamic Key Rotation Interval
 *
 * Determines how often to rotate keys based on token expiration time.
 * Keys rotate at half the token lifetime for optimal security balance:
 * - Ensures keys are fresh before tokens expire
 * - Provides reasonable rotation frequency
 * - Maintains minimum 5-minute interval to prevent excessive rotation
 *
 * Examples:
 * - 60-minute tokens → 30-minute rotation
 * - 10-minute tokens → 5-minute rotation (minimum)
 * - 120-minute tokens → 60-minute rotation
 *
 * @param expirationMinutes - Token lifetime in minutes (assumed ≥ 10)
 * @returns Rotation interval in minutes (minimum 5 minutes)
 */
function calculateRotationInterval(expirationMinutes: number): number {
  // Rotate at half the token lifetime for good security
  // Minimum 5 minutes to avoid excessive rotation
  return Math.max(5, Math.floor(expirationMinutes / 2));
}

/**
 * Signal Updates Helper
 *
 * Creates the signal update object returned by onSync.
 *
 * @param tokenData - Current token with expiration and config hash
 * @param appUrl - App's HTTP URL for issuer derivation
 * @param keyring - Active keyring ID (only updated after successful key generation)
 * @returns Signal updates object for Flows runtime
 */
function createSignalUpdates(
  tokenData: TokenData,
  appUrl: string,
  keyring: string,
) {
  return {
    token: tokenData.token, // JWT token for consumption
    expiresAt: tokenData.expiresAt, // Unix timestamp for expiration
    issuer: new URL(appUrl).origin, // OIDC issuer URL (protocol + host)
    keyring: keyring, // Active keyring (race condition safe)
  };
}
