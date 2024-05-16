use base64::prelude::*;
use dryoc::classic::crypto_kdf::crypto_kdf_derive_from_key;
use dryoc::dryocsecretbox::*;
use dryoc::kx::{KeyPair};
use dryoc::classic::crypto_pwhash::*;
use dryoc::classic::crypto_secretbox::crypto_secretbox_open_easy;
use dryoc::constants::{CRYPTO_SECRETBOX_KEYBYTES, CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, CRYPTO_PWHASH_SALTBYTES, CRYPTO_SECRETBOX_MACBYTES};
use dryoc::dryocsecretbox;
use dryoc::pwhash::Salt;
use dryoc::rng::copy_randombytes;

pub fn generate_key_pair() -> (Vec<u8>, Vec<u8>) {
    // Generate a new asymmetric key pair
    let key_pair = KeyPair::gen();
    let string_public_key = key_pair.public_key.to_vec();
    let string_secret_key = key_pair.secret_key.to_vec();
    (string_public_key, string_secret_key)
}

pub fn generate_master_key() -> Vec<u8> {
    // Generate a new symmetric key
    let secret_key = dryocsecretbox::Key::gen();
    secret_key.to_vec()
}

pub fn encrypt_private_key(private_key: Vec<u8>, master_key: Vec<u8>) -> String {
    let nonce = Nonce::gen();
    let secret = DryocSecretBox::encrypt_to_vecbox(&private_key, &nonce, &master_key);
    let sodium_box = secret.to_vec();
    BASE64_STANDARD.encode(sodium_box)
}

pub fn encrypt_master_key(password: String, master_key: Vec<u8>) -> (String, String, String, String, String) {
    let mut key = [0u8; CRYPTO_SECRETBOX_KEYBYTES];

    // Randomly generate a salt
    let mut salt = [0u8; CRYPTO_PWHASH_SALTBYTES];
    copy_randombytes(&mut salt);

    crypto_pwhash(
        &mut key,
        password.as_ref(),
        &salt,
        CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        PasswordHashAlgorithm::Argon2id13,
    ).expect("pwhash failed");

    //Encrypt the master key with the derived key
    let nonce_master = Nonce::gen();
    let secret = DryocSecretBox::encrypt_to_vecbox(&master_key, &nonce_master, &key);
    let sodium_box = secret.to_vec();

    // Derive the challenge key
    let context = b"CHALLKEY";
    let main_key = key;
    let mut chall_key = [0u8; CRYPTO_SECRETBOX_KEYBYTES];
    crypto_kdf_derive_from_key(&mut chall_key, 1, context, &main_key).expect("kdf failed");

    // Derive the key that encrypt the challenge key
    let context = b"ENCCHALL";
    let mut enc_chall = [0u8; CRYPTO_SECRETBOX_KEYBYTES];
    crypto_kdf_derive_from_key(&mut enc_chall, 1, context, &main_key).expect("kdf failed");

    // Encrypt the challenge key
    let nonce_chall = Nonce::gen();
    let secret = DryocSecretBox::encrypt_to_vecbox(&chall_key, &nonce_chall, &enc_chall);
    let secret_challange_key = secret.to_vec();
    (BASE64_STANDARD.encode(sodium_box),BASE64_STANDARD.encode(nonce_master), BASE64_STANDARD.encode(salt), BASE64_STANDARD.encode(secret_challange_key), BASE64_STANDARD.encode(nonce_chall))
}

pub(crate) fn key_derivation(password: String, salt: String) -> (Vec<u8>, Vec<u8>) {
    let mut key = [0u8; CRYPTO_SECRETBOX_KEYBYTES];

    let salt = BASE64_STANDARD.decode(salt).unwrap();

    crypto_pwhash(
        &mut key,
        password.as_ref(),
        &salt.as_ref(),
        CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        PasswordHashAlgorithm::Argon2id13,
    ).expect("pwhash failed");

    // Derive the challenge key
    let context = b"CHALLKEY";
    let main_key = key;
    let mut challenge_encryption_key = [0u8; CRYPTO_SECRETBOX_KEYBYTES];
    crypto_kdf_derive_from_key(&mut challenge_encryption_key, 1, context, &main_key).expect("kdf failed");

    // Derive the key that encrypt the challenge key
    let context = b"ENCCHALL";
    let mut key_encryption_key = [0u8; CRYPTO_SECRETBOX_KEYBYTES];
    crypto_kdf_derive_from_key(&mut key_encryption_key, 1, context, &main_key).expect("kdf failed");

    (challenge_encryption_key.to_vec(), key_encryption_key.to_vec())

}

/*
pub(crate) fn decrypt_challenge_key(challenge_encryption_key: Vec<u8>, key_encryption_key: Vec<u8>, nonce: String) -> Vec<u8> {
 // Decode from Base64
    let challenge_key = BASE64_STANDARD.decode(challenge_encryption_key).unwrap();
    let key = BASE64_STANDARD.decode(key_encryption_key).unwrap();
    let nonce = BASE64_STANDARD.decode(nonce).unwrap();

    // Convert to correct types
    let nonce = nonce.as_slice().try_into().expect("nonce length invalid");
    let key = key.as_slice().try_into().expect("key length invalid");

    // Decrypt the challenge key
    let mut decrypted = vec![0u8; challenge_key.len() - CRYPTO_SECRETBOX_MACBYTES];
    crypto_secretbox_open_easy(&mut decrypted, &challenge_key, &nonce, &key).expect("decrypt failed");

    decrypted
}
 */

pub(crate) fn decrypt_challenge(challenge_key: Vec<u8>, challenge: String, nonce: String) -> Vec<u8> {
    // Decode from Base64
    let challenge = BASE64_STANDARD.decode(challenge).unwrap();
    let nonce = BASE64_STANDARD.decode(nonce).unwrap();

    // Convert to correct types
    let nonce = nonce.try_into().unwrap();
    let challenge_key = challenge_key.try_into().unwrap();

    // Decrypt the challenge key
    let mut decrypted = vec![0u8; challenge.len() - CRYPTO_SECRETBOX_MACBYTES];
    crypto_secretbox_open_easy(&mut decrypted, &challenge, &nonce, &challenge_key).expect("decrypt failed");

    decrypted
}