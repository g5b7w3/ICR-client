use dryoc::*;
use base64::prelude::*;
use dryoc::classic::crypto_box::SecretKey;
use dryoc::dryocsecretbox::*;
use dryoc::kx::{KeyPair, PublicKey};
use crate::User;
use dryoc::classic::crypto_pwhash::*;
use dryoc::constants::{CRYPTO_SECRETBOX_KEYBYTES, CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                       CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, CRYPTO_PWHASH_SALTBYTES};
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
    let secret_key = Key::gen();
    secret_key.to_vec()
}

pub fn encrypt_private_key(private_key: Vec<u8>, master_key: Vec<u8>) -> String {
    let nonce = Nonce::gen();
    let secret = DryocSecretBox::encrypt_to_vecbox(&private_key, &nonce, &master_key);
    let sodium_box = secret.to_vec();
    BASE64_STANDARD.encode(sodium_box)
}

pub fn encrypt_master_key(password: String, master_key: Vec<u8>) -> (String, String){
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
    let nonce = Nonce::gen();
    let secret = DryocSecretBox::encrypt_to_vecbox(&master_key, &nonce, &key);
    let sodium_box = secret.to_vec();

    (BASE64_STANDARD.encode(sodium_box), BASE64_STANDARD.encode(salt))
}