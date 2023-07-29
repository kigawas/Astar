use chacha20poly1305::{
    aead::{generic_array::GenericArray, AeadInPlace},
    KeyInit, XChaCha20Poly1305,
};
use hkdf::Hkdf;
use libsecp256k1::{util::FULL_PUBLIC_KEY_SIZE, Error as SecpError, PublicKey, SecretKey};
use sha2::Sha256;
use sp_std::vec::Vec;

type SharedSecret = [u8; 32];

pub const EMPTY_BYTES: [u8; 0] = [];
pub const NONCE_LENGTH: usize = 24; // xchacha20
pub const NONCE_TAG_LENGTH: usize = NONCE_LENGTH + 16;

pub fn encrypt(
    ephemeral_sk: &SecretKey,
    receiver_pub: &[u8],
    msg: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, SecpError> {
    let receiver_pk = PublicKey::parse_slice(receiver_pub, None)?;
    let ephemeral_pk = PublicKey::from_secret_key(ephemeral_sk);

    let aes_key = encapsulate(ephemeral_sk, &receiver_pk)?;
    let encrypted = sym_encrypt(&aes_key, msg, iv).ok_or(SecpError::InvalidMessage)?;

    let mut cipher_text = Vec::with_capacity(FULL_PUBLIC_KEY_SIZE + encrypted.len());
    cipher_text.extend(ephemeral_pk.serialize().iter());
    cipher_text.extend(encrypted);

    Ok(cipher_text)
}

fn encapsulate(sk: &SecretKey, peer_pk: &PublicKey) -> Result<SharedSecret, SecpError> {
    let mut shared_point = *peer_pk;
    shared_point.tweak_mul_assign(sk)?;
    let pk = PublicKey::from_secret_key(sk);
    derive_key(&pk, &shared_point)
}

fn derive_key(pk: &PublicKey, shared_point: &PublicKey) -> Result<SharedSecret, SecpError> {
    let mut master = Vec::with_capacity(FULL_PUBLIC_KEY_SIZE * 2);

    master.extend(pk.serialize().iter());
    master.extend(shared_point.serialize().iter());

    hkdf_sha256(master.as_slice())
}

fn hkdf_sha256(master: &[u8]) -> Result<SharedSecret, SecpError> {
    let h = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; 32];
    h.expand(&EMPTY_BYTES, &mut out)
        .map_err(|_| SecpError::InvalidInputLength)?;
    Ok(out)
}

fn sym_encrypt(key: &[u8], msg: &[u8], iv: &[u8]) -> Option<Vec<u8>> {
    let key = GenericArray::from_slice(key);
    let aead = XChaCha20Poly1305::new(key);

    let nonce = GenericArray::from_slice(iv);

    let mut out = Vec::with_capacity(msg.len());
    out.extend(msg);

    if let Ok(tag) = aead.encrypt_in_place_detached(nonce, &EMPTY_BYTES, &mut out) {
        let mut output = Vec::with_capacity(NONCE_TAG_LENGTH + msg.len());
        output.extend(nonce);
        output.extend(tag);
        output.extend(out);
        Some(output)
    } else {
        None
    }
}
