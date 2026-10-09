use sodiumoxide::crypto::sign::ed25519;

pub(crate) struct MatchResult {
    pub(crate) session_id: String,
    pub(crate) seed: [u8; 16],
}

/// Account information used during the search.
pub(crate) struct MatchResultWithMnemonic {
    pub(crate) session_id: String,
    pub(crate) mnemonic: String,
    pub(crate) seed: [u8; 16],
}

/// Generate a Session account ID.
///
/// The mnemonic is intentionally NOT generated here.
pub(crate) fn generate_account() -> MatchResult {
    /*
     * Session uses a 16-byte random seed.
     */
    let random = sodiumoxide::randombytes::randombytes(16);

    let mut seed = [0u8; 16];
    seed.copy_from_slice(&random);

    /*
     * Session pads the 16-byte seed to 32 bytes
     * before passing it to crypto_sign_seed_keypair().
     */
    let mut sodium_seed_bytes = [0u8; 32];

    sodium_seed_bytes[..16].copy_from_slice(&seed);

    let sodium_seed =
        ed25519::Seed::from_slice(&sodium_seed_bytes)
            .expect("32-byte seed must always be valid");

    /*
     * Generate Ed25519 key pair.
     */
    let (ed_public, _ed_secret) =
        ed25519::keypair_from_seed(&sodium_seed);

    /*
     * Convert Ed25519 public key to X25519 public key.
     */
    let x_public =
        ed25519::to_curve25519_pk(&ed_public)
            .expect("valid Ed25519 public key must convert");

    /*
     * Session Account ID:
     *
     *     05 + X25519 public key
     *
     * 66 hexadecimal characters in total.
     */
    let mut session_id = String::with_capacity(66);

    session_id.push_str("05");

    for byte in x_public.as_ref() {
        session_id.push_str(&format!("{:02X}", byte));
    }

    MatchResult {
        session_id,
        seed,
    }
}
