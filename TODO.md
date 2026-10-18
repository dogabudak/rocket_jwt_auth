TODO: Make rocket_jwt_auth usable by piarch-a-token-rs
=====================================================

Currently the crate only supports HS256 with a single shared secret (JWT_SECRET env var).
piarch-a-token-rs needs RS256 with per-company RSA keys selected via the `kid` JWT header.

1. Support RS256 algorithm with RSA key pairs
   - Currently hardcoded to HS256 + DecodingKey::from_secret()
   - Need to support DecodingKey::from_rsa_pem() with RS256
   - Make the algorithm configurable (HS256, RS256, etc.)

2. Support `kid` (Key ID) header for key selection
   - Currently reads a single secret from JWT_SECRET env var
   - Need to decode the JWT header first, extract the `kid` field
   - Load the corresponding public key file from a configurable directory (e.g. keys/{kid}.pub)
   - piarch-a-token-rs uses: format!("keys/{}.pub", kid)

3. Support custom claims (generic Token)
   - Current Token struct is fixed: { sub, exp, iat }
   - piarch-a-token-rs needs a `company` field in the claims
   - Make Token generic over claims, or add optional extra fields
   - Option A: Token<C: DeserializeOwned> with user-defined claims struct
   - Option B: Add a HashMap<String, Value> for extra claims

4. Update TokenError variants
   - Add MissingKid for when kid header is absent
   - Add KeyNotFound for when the key file doesn't exist
   - Add KeyLoadError for when the key file can't be parsed

5. Update tests
   - Add RS256 tests with RSA key pairs
   - Add kid-based key selection tests
   - Add custom claims tests
   - Keep existing HS256 tests for backward compatibility

Reference: piarch-a-token-rs FromRequest implementation
  - File: piarch-a-token-rs/src/main.rs lines 46-89
  - Decodes JWT header -> extracts kid -> loads keys/{kid}.pub -> validates RS256 -> returns Token { sub, company }
