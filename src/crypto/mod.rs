use base64::prelude::*;
use dryoc::classic::crypto_kdf::crypto_kdf_derive_from_key;
use dryoc::dryocsecretbox::*;
use dryoc::kx::{KeyPair};
use dryoc::classic::crypto_pwhash::*;
use dryoc::classic::crypto_secretbox::crypto_secretbox_open_easy;
use dryoc::constants::{CRYPTO_SECRETBOX_KEYBYTES, CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, CRYPTO_PWHASH_SALTBYTES, CRYPTO_SECRETBOX_MACBYTES};
use dryoc::rng::copy_randombytes;
use dryoc::sign::*;
use crate::serialization::{LoggedUser, LoggedUserClient, ReadDirectory, WriteDirectory};
use dryoc::generichash::{GenericHash};
use dryoc::sign;

pub fn generate_key_pair() -> (Vec<u8>, Vec<u8>) {
    // Generate a new asymmetric key pair
    let keypair = SigningKeyPair::gen_with_defaults();
    let keypair_pub = keypair.public_key.to_vec();
    let keypair_sec = keypair.secret_key.to_vec();
    (keypair_pub, keypair_sec)
}

pub fn generate_sym_key() -> Vec<u8> {
    // Generate a new symmetric key
    let secret_key = Key::gen();
    secret_key.to_vec()
}

pub fn sym_encryption(message: Vec<u8>, master_key: Vec<u8>) -> (String, String) {
    let nonce = Nonce::gen();
    let secret = DryocSecretBox::encrypt_to_vecbox(&message, &nonce, &master_key);
    let sodium_box = secret.to_vec();
    (BASE64_STANDARD.encode(sodium_box), BASE64_STANDARD.encode(nonce))
}

pub fn sign(message: String, signing_key: Vec<u8>) -> (String) {

    let public_key = vec![0u8; 32];
    let mut keypair: SigningKeyPair<PublicKey, SecretKey> = SigningKeyPair::<StackByteArray<32>, StackByteArray<64>>::from_slices(&public_key,&signing_key).unwrap();

    let signed_message = keypair.sign::<Signature, Vec<u8>>(Vec::from(message)).unwrap().to_vec();
    BASE64_STANDARD.encode(signed_message)
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

    // Encrypt the challenge key TODO: clean this
    let nonce_chall = Nonce::gen();
    let secret = DryocSecretBox::encrypt_to_vecbox(&chall_key, &nonce_chall, &enc_chall);
    let secret_challange_key = secret.to_vec();
    (BASE64_STANDARD.encode(sodium_box),BASE64_STANDARD.encode(nonce_master), BASE64_STANDARD.encode(salt), BASE64_STANDARD.encode(secret_challange_key), BASE64_STANDARD.encode(nonce_chall))
}

pub(crate) fn key_derivation(password: String, salt: String) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut key = [0u8; CRYPTO_SECRETBOX_KEYBYTES];

    let salt = BASE64_STANDARD.decode(salt).unwrap();

    crypto_pwhash(
        &mut key,
        password.as_ref(),
        salt.as_ref(),
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

    (challenge_encryption_key.to_vec(), key_encryption_key.to_vec(), key.to_vec())

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

pub(crate) fn sym_decryption(key: Vec<u8>, message: String, nonce: String) -> Vec<u8> {
    // Decode from Base64
    let challenge = BASE64_STANDARD.decode(message).unwrap();
    let nonce = BASE64_STANDARD.decode(nonce).unwrap();

    // Convert to correct types
    let nonce = nonce.try_into().unwrap();
    let challenge_key = key.try_into().unwrap();

    // Decrypt the challenge key
    let mut decrypted = vec![0u8; challenge.len() - CRYPTO_SECRETBOX_MACBYTES];
    crypto_secretbox_open_easy(&mut decrypted, &challenge, &nonce, &challenge_key).expect("decrypt failed");

    decrypted
}

pub(crate) fn encrypt_directory_fields(root_key: Vec<u8>, read: ReadDirectory) -> (ReadDirectory, WriteDirectory) {

    let (pub_key, private_key) = generate_key_pair();
    let file_encryption_key = generate_sym_key();

    // Encrypt the file encryption key with the root key
    let (encrypted_key_file, nonce_key_file) = sym_encryption(file_encryption_key, root_key.clone());

    // Encrypt the private signing key with the root key
    let (encrypted_private_key, nonce_private_key) = sym_encryption(private_key,root_key.clone());

    // Encrypt the directory name with the root key
    let (encrypted_directory_name, nonce_name) = sym_encryption(read.directory_name.as_bytes().to_vec(), root_key.clone());


    let mut encrypted_name = vec![];
    let mut nonce= vec![];
    // Encrypt the files names if not empty
    if !read.files_names.is_empty(){
        for i in read.files_names.clone() {
            let (encrypted_directory_name, nonce_name) = sym_encryption(i.as_bytes().to_vec(), root_key.clone());
            encrypted_name.push(encrypted_directory_name);
            nonce.push(nonce_name);
        }
    }

    let read = ReadDirectory {
        uid_path: read.uid_path,
        directory_name: encrypted_directory_name,
        files_names: encrypted_name,
        files_uid: read.files_uid,
        files_encryption_keys: encrypted_key_file,
        nonce_key_file,
        files_signatures_verification_keys: BASE64_STANDARD.encode(pub_key),
        files_nonce: nonce,
        nonce_name,
    };

    let write = WriteDirectory {
        nonce_private_key,
        files_signing_keys: encrypted_private_key,
    };

    (read, write)
}




pub(crate) fn decrypt_user_info(user: LoggedUser, key: Vec<u8>) -> LoggedUserClient {
    // Decrypt master key
    let master_key = sym_decryption(key.clone(), user.master_key, user.nonce_master);

    // Decrypt the pk_signing key
    let pk_signing = sym_decryption(master_key.clone(), user.pk_signing, user.nonce_pk_signing);

    // Decrypt the pk_encryption key
    let pk_encryption = sym_decryption(master_key.clone(), user.pk_encryption, user.nonce_pk_encryption);

    // Decrypt the root key
    let root_key = sym_decryption(master_key.clone(), user.root_key, user.root_nonce);

    LoggedUserClient {
        pk_signing,
        pk_encryption,
        master_key,
        shared_files: user.shared_files,
        root_key,
        token: user.token,
        recovered_key: vec![],
        recovered_path: vec![],
        recovered_signing_key: vec![],
        recovered_verification_key: vec![],
    }

}

pub(crate) fn decrypt_directory_fields(key: Vec<u8>, read: ReadDirectory, write: WriteDirectory) -> (ReadDirectory, WriteDirectory) {

    let directory_name = sym_decryption(key.clone(), read.directory_name, read.nonce_name.clone());
    let directory_name = String::from_utf8(directory_name).unwrap();

    let files_encryption_keys = sym_decryption(key.clone(), read.files_encryption_keys, read.nonce_key_file.clone());
    let files_encryption_keys = BASE64_STANDARD.encode(files_encryption_keys);

    let read = ReadDirectory {
        uid_path: read.uid_path,
        directory_name,
        files_names: read.files_names, // todo! encrypt the names
        files_uid: read.files_uid,
        files_encryption_keys,
        files_signatures_verification_keys: read.files_signatures_verification_keys,
        files_nonce: read.files_nonce,
        nonce_name: read.nonce_name,
        nonce_key_file: read.nonce_key_file,
    };

    let files_signing_keys = sym_decryption(key.clone(), write.files_signing_keys, write.nonce_private_key.clone());
    let files_signing_keys = BASE64_STANDARD.encode(files_signing_keys);

    let write = WriteDirectory {
        nonce_private_key: write.nonce_private_key,
        files_signing_keys
    };

    (read, write)
}
