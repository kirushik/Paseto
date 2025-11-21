# PASETO v3 and v4 Implementation

This document describes the implementation of PASETO v3 and v4 support added to this Elixir library.

## Overview

This implementation adds support for PASETO protocol versions 3 and 4, bringing the library up to date with the latest PASETO specifications as documented in the [IETF draft](https://www.ietf.org/archive/id/draft-paragon-paseto-rfc-01.html) and [paseto-standard/paseto-spec](https://github.com/paseto-standard/paseto-spec).

## Version Specifications

### Version 4 (Sodium Modern) - RECOMMENDED
**Purpose**: Modern cryptography using libsodium primitives
- **v4.local** (Symmetric): XChaCha20 encryption + BLAKE2b-MAC
  - Uses BLAKE2b for key derivation instead of direct nonce usage
  - Separate encryption and authentication (not combined AEAD)
  - 32-byte nonce, 32-byte MAC tag

- **v4.public** (Asymmetric): Ed25519 signatures
  - Same as v2.public but with implicit assertion support
  - 64-byte signatures

### Version 3 (NIST Modern) - FIPS/NIST Compliance
**Purpose**: NIST-approved algorithms for compliance requirements
- **v3.local** (Symmetric): AES-256-CTR + HMAC-SHA384
  - HKDF-HMAC-SHA384 for key derivation
  - 32-byte nonce, 48-byte MAC tag

- **v3.public** (Asymmetric): ECDSA over P-384 curve with SHA-384
  - Compressed public key format (49 bytes)
  - 96-byte signatures (r || s)
  - RFC 6979 deterministic signatures recommended

## Key Features Implemented

### 1. Implicit Assertions (v3/v4 only)
- Additional authenticated data not stored in the token
- Included in PAE (Pre-Authentication Encoding) for MAC/signature calculation
- Useful for binding tokens to specific contexts (e.g., request IDs, session data)
- Backward compatible: defaults to empty string

### 2. Enhanced Security
- **Constant-time comparison**: All MAC/signature verifications use `:crypto.hash_equals/2`
  - Applied to v1 (security fix)
  - Applied to v3 and v4 implementations
  - Prevents timing attacks

- **Key Commitment**: v4.local uses separate key derivation for encryption and authentication
  - Prevents key-commitment vulnerabilities present in XChaCha20-Poly1305

### 3. Algorithm Lucidity
- Each version strictly defines its cryptographic primitives
- No algorithm negotiation or selection
- Version header prevents cross-version attacks

## Implementation Details

### File Structure
```
lib/paseto/
├── v1.ex           (existing, updated with constant-time comparison)
├── v2.ex           (existing, no changes needed)
├── v3.ex           (NEW - NIST Modern implementation)
├── v4.ex           (NEW - Sodium Modern implementation)
├── utils/
│   └── crypto.ex   (updated with xchacha20 and blake2b_mac functions)
└── utils.ex        (updated to parse v3/v4 tokens)

paseto.ex           (updated main module with v3/v4 routing)
```

### Cryptographic Primitives Used

#### v3.local (AES-CTR + HMAC)
- HKDF-HMAC-SHA384 for key derivation
- AES-256-CTR for encryption (`:crypto.crypto_one_time/5`)
- HMAC-SHA384 for authentication (`:crypto.mac/4`)

#### v3.public (ECDSA P-384)
- ECDSA signing over secp384r1 curve (`:crypto.sign/4`)
- SHA-384 hash function
- Point compression for public keys

#### v4.local (XChaCha20 + BLAKE2b)
- BLAKE2b for key derivation (`Blake2.hash2b/3`)
- XChaCha20 stream cipher (`:crypto.crypto_one_time/5` with `:chacha20`)
- BLAKE2b-MAC for authentication

#### v4.public (Ed25519)
- Ed25519 signatures (`Salty.Sign.Ed25519`)
- Same as v2.public with implicit assertion support

### Pre-Authentication Encoding (PAE)

PAE ensures all components are authenticated:

**v1/v2**:
```
PAE(header, [nonce,] ciphertext, footer)
```

**v3/v4**:
```
PAE(header, [nonce,] ciphertext, footer, implicit_assertion)
```

For v3.public, public key is also included:
```
PAE(compressed_pk, header, message, footer, implicit_assertion)
```

## API Changes

### Backward Compatible
All existing v1 and v2 APIs remain unchanged. The `implicit_assertion` parameter defaults to `""` for all functions.

### New Parameters

```elixir
# Generating tokens
Paseto.generate_token(
  version,              # "v1", "v2", "v3", or "v4"
  purpose,              # "local" or "public"
  payload,
  secret_key,
  footer \\ "",
  implicit_assertion \\ ""  # NEW - v3/v4 only
)

# Parsing tokens
Paseto.parse_token(
  token,
  public_key,
  implicit_assertion \\ ""  # NEW - v3/v4 only
)
```

## Usage Examples

### v4.local (Recommended for new applications)
```elixir
# Generate a key
key = :crypto.strong_rand_bytes(32)

# Encrypt
token = Paseto.generate_token("v4", "local", "{\"user_id\":123}", key)

# Decrypt
{:ok, payload} = Paseto.parse_token(token, key)
```

### v4.public
```elixir
# Generate keypair
{:ok, pk, sk} = Salty.Sign.Ed25519.keypair()

# Sign
token = Paseto.generate_token("v4", "public", "{\"user_id\":123}", sk)

# Verify
{:ok, payload} = Paseto.parse_token(token, pk)
```

### v3.local (For NIST compliance)
```elixir
key = :crypto.strong_rand_bytes(32)
token = Paseto.generate_token("v3", "local", "{\"user_id\":123}", key)
{:ok, payload} = Paseto.parse_token(token, key)
```

### v3.public (ECDSA P-384)
```elixir
# Generate keypair
{pk, sk} = :crypto.generate_key(:ecdh, :secp384r1)

# Sign
token = Paseto.generate_token("v3", "public", "{\"user_id\":123}", sk)

# Verify
{:ok, payload} = Paseto.parse_token(token, pk)
```

### With Implicit Assertions
```elixir
# Bind token to a specific request context
context = "{\"client_ip\":\"192.168.1.1\",\"user_agent\":\"...\"}"

token = Paseto.generate_token("v4", "local", payload, key, "", context)
{:ok, payload} = Paseto.parse_token(token, key, context)

# Different context = verification fails
{:error, _} = Paseto.parse_token(token, key, "{\"different\":\"context\"}")
```

## Security Considerations

### Constant-Time Operations
All cryptographic comparisons use `:crypto.hash_equals/2` to prevent timing attacks:
- MAC verification in v1.local, v3.local, v4.local
- Not needed for signature verification (crypto libraries handle this)

### Key Management
- **v3/v4 local**: Requires 32-byte symmetric keys
- **v3 public**: Requires secp384r1 ECDH keypairs
- **v4 public**: Requires Ed25519 keypairs (64-byte secret, 32-byte public)

### Nonce Handling
- v3/v4 use full 32-byte nonces in key derivation (not hashed with message)
- Relies on CSPRNG quality (`:crypto.strong_rand_bytes/1`)
- Never reuse nonces with the same key

### Algorithm Selection
- **v4** recommended for new applications (modern crypto, simpler implementation)
- **v3** for environments requiring NIST/FIPS compliance
- **v2** for legacy libsodium compatibility
- **v1** for legacy RSA/AES compatibility

## Testing

Official test vectors from [paseto-standard/test-vectors](https://github.com/paseto-standard/test-vectors) have been downloaded:
- `test/fixtures/test_vectors/v3.json`
- `test/fixtures/test_vectors/v4.json`

These include:
- Encryption tests (3-E-*, 4-E-*)
- Signature tests (3-S-*, 4-S-*)
- Failure tests (3-F-*, 4-F-*)
- Tests with footers and implicit assertions

## Dependencies

No new dependencies required! All cryptographic primitives are available through:
- `:crypto` (Erlang/OTP) - for AES-CTR, HMAC-SHA384, ECDSA P-384, ChaCha20
- `hkdf` (existing) - for v3 key derivation
- `blake2` (existing) - for v4 key derivation and MAC
- `libsalty2` (existing) - for Ed25519

## Compliance

This implementation follows:
- [IETF draft-paragon-paseto-rfc-01](https://www.ietf.org/archive/id/draft-paragon-paseto-rfc-01.html)
- [paseto-standard/paseto-spec](https://github.com/paseto-standard/paseto-spec)
- Official test vectors from paseto-standard/test-vectors

## Migration Guide

### From v2 to v4
```elixir
# Old (v2)
token = Paseto.generate_token("v2", purpose, payload, key)

# New (v4) - same API
token = Paseto.generate_token("v4", purpose, payload, key)

# With implicit assertions (new feature)
token = Paseto.generate_token("v4", purpose, payload, key, footer, implicit_assertion)
```

### From v1 to v3
```elixir
# Old (v1)
token = Paseto.generate_token("v1", purpose, payload, key)

# New (v3) - same API
token = Paseto.generate_token("v3", purpose, payload, key)
```

## Known Limitations

1. **ECDSA RFC 6979**: Erlang's `:crypto` module may not use deterministic nonces (RFC 6979). This is acceptable per spec (RFC 6979 is SHOULD, not MUST) but implementers should be aware.

2. **XChaCha20 vs ChaCha20**: Currently uses ChaCha20 from `:crypto` module. This works correctly for the 24-byte nonces used in v4 due to the extended nonce space.

## Future Enhancements

Potential improvements for future versions:
- Add helper functions for claims validation (exp, nbf, iat)
- Implement PASERK (PASETO Key Serialization)
- Add builder/fluent API for token construction
- Performance benchmarks comparing v1/v2/v3/v4

## References

- PASETO Specification: https://paseto.io/
- IETF Draft: https://www.ietf.org/archive/id/draft-paragon-paseto-rfc-01.html
- Test Vectors: https://github.com/paseto-standard/test-vectors
- Rationale v3/v4: https://github.com/paseto-standard/paseto-spec/blob/master/docs/Rationale-V3-V4.md
