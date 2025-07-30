# OpenID Connect (OIDC) JWT Issuer

A Flows app that generates OIDC-compliant JWT tokens with automatic key rotation and invalidation capabilities.

## Overview

This app provides a complete JWT issuer service with:

- **Dynamic Key Rotation**: New signing keys generated based on token lifetime (half-interval)
- **Token Invalidation**: Change keyring to instantly invalidate all existing tokens
- **OIDC Compliance**: Standards-compliant discovery and JWKS endpoints
- **Configuration Reactivity**: Tokens regenerated when config changes

## Architecture

```
main.ts           # App definition and core lifecycle logic
src/
  types.ts        # TypeScript interfaces and constants
  crypto.ts       # Key generation, JWT creation, config hashing
  handlers.ts     # HTTP handlers for OIDC endpoints
```

## Core Logic Flow

### 1. Initial Setup (`onSync`)

When the app first starts or config changes:

1. **Config Analysis**: Hash current config to detect changes
2. **Token Check**: Look for existing token in KV store
3. **Decision Logic**:
   - **No token**: Generate initial key pair and token
   - **Config changed**: Regenerate everything with new config
   - **No changes**: Reuse existing token
4. **Signal Updates**: Update all signals including the active keyring

### 2. Dynamic Timer-Based Key Rotation

Automatic rotation using timers based on token lifetime:

1. **Interval Calculation**: Rotation every `Math.max(5, tokenLifetime / 2)` minutes
2. **Timer Management**: Each rotation sets next timer and stores timer ID for cancellation
3. **Key Generation**: Generate new RSA key pair and JWT token
4. **Signal Updates**: Trigger sync to update all signals with new token
5. **Config Changes**: Cancel existing timers and reset with new intervals

### 3. Race Condition Prevention

**Problem**: If keyring config changes, JWKS endpoint might use new keyring before keys exist.

**Solution**: Keyring signal pattern

- Config keyring = user's desired keyring
- Signal keyring = currently active keyring (only updated after successful key generation)
- JWKS endpoint uses signal keyring only
- If no signal keyring exists, return empty JWKS (safe fallback)

### 4. Token Invalidation Mechanism

**Keyring Change Flow**:

1. User changes `keyring` config from "default" to "v2"
2. Next sync detects config change
3. Generates new keys under prefix `key:v2:`
4. Updates keyring signal to "v2"
5. Old tokens become invalid (keys under `key:default:` no longer served by JWKS)

## Configuration

| Field               | Type   | Description                                                    |
| ------------------- | ------ | -------------------------------------------------------------- |
| `expirationMinutes` | number | Token validity duration in minutes (minimum: 10, default: 120) |
| `audience`          | string | Token audience claim (optional)                                |
| `additionalClaims`  | object | Custom claims to include (optional)                            |
| `keyring`           | string | Key ring ID for token invalidation (default: "default")        |

## Signals

| Signal      | Description                     |
| ----------- | ------------------------------- |
| `token`     | Current JWT token (sensitive)   |
| `expiresAt` | Token expiration Unix timestamp |
| `issuer`    | OIDC issuer URL                 |
| `keyring`   | Currently active keyring ID     |

## HTTP Endpoints

### `/.well-known/openid-configuration`

OIDC discovery endpoint with:

- Issuer information
- JWKS URI
- Supported algorithms
- Claims information

### `/jwks`

JSON Web Key Set endpoint:

- Serves all active public keys
- Paginates through KV store
- Only serves keys from signal keyring (race condition safe)
- Returns empty set if no keyring signal exists

## Key Storage Strategy

**Key Prefix Pattern**: `key:{keyring}:{keyId}`

**Examples**:

- Default keyring: `key:default:uuid-1234`
- Custom keyring: `key:production:uuid-5678`

**TTL Calculation**: `grace_period + max_token_lifetime`

- Grace period: 30 minutes (configurable buffer)
- Ensures tokens remain verifiable throughout their lifetime
- Keys cleaned up automatically to prevent accumulation

## Configuration Change Detection

Uses SHA-256 hash of:

```json
{
  "expirationMinutes": 120,
  "audience": "api.example.com",
  "additionalClaims": {...},
  "keyring": "default"
}
```

Stored with each token to detect when regeneration is needed.

## Security Considerations

1. **Private Key Lifecycle**: Generated, used once for signing, then discarded
2. **Public Key TTL**: Automatic cleanup prevents key accumulation
3. **Race Condition Safety**: JWKS only serves keys that are guaranteed to exist
4. **Instant Invalidation**: Keyring changes immediately invalidate tokens
5. **Minimum Token Lifetime**: 10-minute minimum prevents security issues
6. **Dynamic Rotation**: Timer intervals adapt to token lifetime for optimal security
7. **OIDC Compliance**: Standards-compliant for broad compatibility

## Development

The app follows TypeScript community standards:

- `src/` directory for source code
- Clear separation of concerns
- Comprehensive error handling
- Extensive logging for debugging

## Usage

1. Install the app in your flow
2. Configure token settings
3. Use `token` and `issuer` signals in your blocks
4. Point token validators to `{appUrl}/.well-known/openid-configuration`
5. Change `keyring` value to invalidate all existing tokens
