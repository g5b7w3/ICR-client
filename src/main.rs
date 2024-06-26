use std::io::read_to_string;
use std::path::Prefix::Verbatim;
use std::ptr::{read, write};
use axum::response::IntoResponse;
use base64::Engine;
use base64::prelude::*;
use reqwest::StatusCode;
use serde::__private::de::Content;
use crate::serialization::{Challenge, ChallengeResponse, Create, Directory, FileContent, FileCreation, GetDir, Hello, HelloResponse, LoggedUser, LoggedUserClient, Login, ReadDirectory, WriteDirectory};


pub mod crypto;
pub mod serialization;

enum CryptoOperation {
    Encrypt,
    Sign,
    Verify,
}

struct User {
    uid: String,
    password: String,
    signing_public_key: Vec<u8>,
    signing_private_key: Vec<u8>,
    encryption_public_key: Vec<u8>,
    encryption_private_key: Vec<u8>,
    master_key: Vec<u8>,
    root_key: Vec<u8>,
}

#[tokio::main]
async fn main() {
    // Create a new user
    let uid = "1".to_string();
    let password = "password".to_string();
    let user = create_user(uid, password);

    // Create a user and its root directory
    //send_user_request(user).await;



    // Try to log in with the user
    let (res, mut logged_user) = login(user.uid.clone(), user.password).await;
    match res.into_response().status() {
        StatusCode::OK => println!("Successfully logged in!"),
        StatusCode::UNAUTHORIZED => println!("Login failed!"),
        _ => println!("Error"),
    }

    //println!("{:?}", logged_user);

    //create_root_directory(user.uid, logged_user.root_key).await;



    let (res, read, write) = get_directory("1".to_string(), logged_user.clone()).await;
    match res.into_response().status() {
        StatusCode::OK => println!("Successfully got directory!"),
        StatusCode::UNAUTHORIZED => println!("Login failed!"),
        _ => println!("Error"),
    }

    //println!("{:?}", read);
    //println!("{:?}", write);


    logged_user.recovered_key.push(BASE64_STANDARD.decode(read.files_encryption_keys.as_bytes()).unwrap());
    logged_user.recovered_path.push(read.uid_path.clone());
    logged_user.recovered_signing_key.push(BASE64_STANDARD.decode(write.files_signing_keys.as_bytes()).unwrap());
    logged_user.recovered_verification_key.push(BASE64_STANDARD.decode(read.files_signatures_verification_keys.as_bytes()).unwrap());

    //create_directory("A new directory".to_string(), "1/1".to_string(), logged_user.recovered_key[0].clone()).await.into_response();



    let (res, read, write) = get_directory("1/1".to_string(), logged_user.clone()).await;
    match res.into_response().status() {
        StatusCode::OK => println!("Successfully got directory!"),
        StatusCode::UNAUTHORIZED => println!("Login failed!"),
        _ => println!("Error"),
    }

    logged_user.recovered_key.push(BASE64_STANDARD.decode(read.files_encryption_keys.as_bytes()).unwrap());
    logged_user.recovered_path.push(read.uid_path.clone());
    logged_user.recovered_signing_key.push(BASE64_STANDARD.decode(write.files_signing_keys.as_bytes()).unwrap());
    logged_user.recovered_verification_key.push(BASE64_STANDARD.decode(read.files_signatures_verification_keys.as_bytes()).unwrap());

    let (new_read_directory, encrypted_content, nonce, signature) = create_file(logged_user.clone(), "1/1/3".to_string(), "Mon fichier 3".to_string(), "Ceci est signé".to_string(), read);
    send_file(new_read_directory, logged_user.clone(), nonce, encrypted_content, false, signature).await.into_response();

    // Get a file
    let (res, content) = get_file("1/1/3".to_string(), logged_user.clone()).await;
    match res.into_response().status() {
        StatusCode::OK => println!("Successfully got file!"),
        StatusCode::UNAUTHORIZED => println!("Login failed!"),
        _ => println!("Error"),
    }

    println!("{:?}", content);


    /*
    // Create a root file
    let (new_read_directory, encrypted_content, nonce) = create_file(logged_user.clone(), "1/1".to_string(), "Mon fichier".to_string(), "Ceci est le contenu".to_string(), read);

    send_file(new_read_directory, logged_user.clone(), nonce, encrypted_content, true).await.into_response();
     */

    // Create a file
    //let (new_read_directory, encrypted_content, nonce, signature) = create_file(logged_user.clone(), "1/1/2".to_string(), "Mon fichier2".to_string(), "Ceci est le contenu".to_string(), read);

    //send_file(new_read_directory, logged_user.clone(), nonce, encrypted_content, false, signature).await.into_response();


    //create_directory("A new directory".to_string(), new_dir_path.clone(), logged_user.root_key.clone()).await.into_response();

    /*
    let (res, read, write) = get_directory(new_dir_path, logged_user).await;
    match res.into_response().status() {
        StatusCode::OK => println!("Successfully got directory!"),
        StatusCode::UNAUTHORIZED => println!("Login failed!"),
        _ => println!("Error"),
    }

    println!("NEW DIRECTORY: ");

    println!("{:?}", read);
    println!("{:?}", write);

     */
    // TODO: EVERY OTHER FUCKING FUNCTIONALITIES

}

// Function to create a new user
fn create_user(uid: String, password: String) -> User {
    // Generate a new key pair
    let (signing_public_key, signing_private_key) = crypto::generate_key_pair();
    let (encryption_public_key, encryption_private_key) = crypto::generate_key_pair();

    // Generate a new master key
    let master_key = crypto::generate_sym_key();

    // Generate root key
    let root_key = crypto::generate_sym_key();

    User {
        uid,
        password,
        signing_public_key,
        signing_private_key,
        master_key,
        encryption_public_key,
        encryption_private_key,
        root_key
    }
}

async fn send_user_request(user: User) -> impl IntoResponse {
    let (encrypted_master_key, nonce_master, salt, challenge_key, nonce_chall) = crypto::encrypt_master_key(user.password.clone(), user.master_key.clone());

    // Encrypt signing private key
    let (pk_signing, nonce_pk_signing) = crypto::sym_encryption(user.signing_private_key.clone(), user.master_key.clone());

    // Encrypt decryption private key
    let (pk_encryption, nonce_pk_encryption) = crypto::sym_encryption(user.encryption_private_key.clone(), user.master_key.clone());

    let (root_key, root_nonce) = crypto::sym_encryption(user.root_key.clone(), user.master_key.clone());

    // Serialize the user object
    let user = Create {
        uid: user.uid,
        salt,
        pk_signing,
        nonce_pk_signing,
        pk_encryption,
        nonce_pk_encryption,
        public_key_signing: BASE64_STANDARD.encode(user.signing_public_key),
        public_key_encryption: BASE64_STANDARD.encode(user.encryption_public_key),
        master_key: encrypted_master_key,
        shared_files: vec![],
        challenge_key,
        nonce_master,
        nonce_chall,
        root_key,
        root_nonce
    };

    // Send a POST request to the server
    let client = reqwest::Client::new();
    let res = client.post("http://localhost:3000/create_user")
        .json(&user)
        .send()
        .await
        .unwrap();
    (res.status(), res.text().await.unwrap())
}


async fn login (uid: String, password: String) -> (impl IntoResponse, LoggedUserClient) {

    let body: Hello = Hello {
        uid: uid.clone(),
    };

    // Send a Post request to log in
    let client = reqwest::Client::new();
    let res = client.post("http://localhost:3000/client_hello")
        .json(&body)
        .send()
        .await
        .unwrap();

    // Deserialize the response
    let res: HelloResponse = res.json().await.unwrap();
    let token = res.token;

    // Derive key from password
    let (challenge_encryption_key, key_encryption_key, key) = crypto::key_derivation(password, res.salt);

    // Send the challenge key to the server
    let res = client.post("http://localhost:3000/login")
        .json(&Login {
            uid,
            challenge_key: BASE64_STANDARD.encode(key_encryption_key),
        })
        .send()
        .await
        .unwrap();

    // Deserialize the response
    let res: Challenge = res.json().await.unwrap();

    // Decrypt the challenge
    let challenge = crypto::sym_decryption(challenge_encryption_key, res.challenge, res.nonce);

    // Try wrong challenge
    //let challenge = vec![0u8; challenge.len()];

    // Try wrong token
    //let token = "wrong_token".to_string();

    // Send a response to the server containing the challenge and the token
    let res = client.post("http://localhost:3000/response_challenge")
        .json(&ChallengeResponse {
            challenge: BASE64_STANDARD.encode(challenge),
            token,
        })
        .send()
        .await
        .unwrap();

    let status = res.status();

    let res2: LoggedUser = res.json().await.unwrap();
    // Decrypt all user info
    let logged_user = crypto::decrypt_user_info(res2, key);
    (status, logged_user)
}

async fn create_root_directory(uid: String, root_key: Vec<u8>) -> impl IntoResponse {

    let response = create_directory("root".to_string(), uid, root_key).await.into_response();
    match response.status() {
        StatusCode::OK => println!("Successfully created root directory!"),
        StatusCode::UNAUTHORIZED => println!("Login failed!"),
        _ => println!("Error"),
    }

}

async fn create_directory(directory_name: String, current_path: String, root_key: Vec<u8>) -> impl IntoResponse{

    // Create a new read directory structure
    let read_directory = ReadDirectory {
        uid_path: current_path.clone(),
        directory_name: directory_name.clone(),
        nonce_name: "".to_string(),
        files_names: vec![],
        files_uid: vec![],
        files_encryption_keys: "".to_string(),
        files_signatures_verification_keys: "".to_string(),
        files_nonce: vec![],
        nonce_key_file: "".to_string(),
    };

    // Encrypt needed fields
    let (read_directory, write_directory) = crypto::encrypt_directory_fields(root_key, read_directory);

    let payload = Directory {
        read: read_directory,
        write: write_directory,
    };

    // Send the request to the server
    let client = reqwest::Client::new();
    let res = client.post("http://localhost:3000/create_directory")
        .json(&payload)
        .send()
        .await
        .unwrap();

    (res.status(), res.text().await.unwrap())
}

async fn get_directory(mut uid_path: String, logged_user: LoggedUserClient) -> (impl IntoResponse, ReadDirectory, WriteDirectory) {

    let payload = GetDir {
        uid_path: uid_path.clone(),
        token: logged_user.token.clone(),
    };

    let client = reqwest::Client::new();
    let res = client.post("http://localhost:3000/get_directory")
        .json(&payload)
        .send()
        .await
        .unwrap();

    let status = res.status();
    let res2: Directory = res.json().await.unwrap();
    let read = res2.read;
    let write = res2.write;

    let key = match_key(uid_path.clone(), logged_user.clone(), CryptoOperation::Encrypt);
    let (read, write) = crypto::decrypt_directory_fields(key, read, write);

    (status, read, write)

}

fn create_file(logged_user: LoggedUserClient,path: String ,file_name: String, content: String, read_directory: ReadDirectory) -> (ReadDirectory, String, String, String) {
    // Recover encryption key
    let key = match_key(path.clone(), logged_user.clone(), CryptoOperation::Encrypt);

    let signing_key = match_key(path.clone(), logged_user.clone(), CryptoOperation::Sign);

    // Encrypt the content
    let (encrypted_content, nonce) = crypto::sym_encryption(content.as_bytes().to_vec(), key);

    let signature = crypto::sign(encrypted_content.clone(), signing_key);

    // Update the read directory information
    let mut new_read_directory = read_directory;
    new_read_directory.files_names.push(file_name.clone());
    new_read_directory.files_uid.push(path.clone());

    (new_read_directory, encrypted_content, nonce, signature)

}

async fn send_file(read_directory: ReadDirectory, logged_user: LoggedUserClient, content_nonce: String, content: String, is_root_flag: bool, signature: String) -> impl IntoResponse {

    // Get parent directory
    // TODO /!\ MANUALLY SELECT ROOT PARENT DIRECTORY FOR NOW /!\
    let (res, parent_read, parent_write) = get_directory("1/1".to_string(), logged_user.clone()).await;
    match res.into_response().status() {
        StatusCode::OK => println!("Successfully got directory!"),
        StatusCode::UNAUTHORIZED => println!("Login failed!"),
        _ => println!("Error"),
    }

    // Recover the parent key, depending of whether the file is in the root directory or not
    let parent_key = match is_root_flag {
        true => logged_user.root_key.clone(),
        false => BASE64_STANDARD.decode(parent_read.files_encryption_keys.as_bytes()).unwrap()
    };

    // Encrypt the directory fields
    let (read,write) = crypto::encrypt_directory_fields(parent_key, read_directory);


    let payload: FileCreation = FileCreation {
        read_directory: read,
        content,
        nonce: content_nonce,
        signature,
    };

    let client = reqwest::Client::new();
    let res = client.post("http://localhost:3000/create_file")
        .json(&payload)
        .send()
        .await
        .unwrap();

    (res.status(), res.text().await.unwrap())

}


async fn get_file(uid_path: String, logged_user: LoggedUserClient) -> (impl IntoResponse, String){

    let client = reqwest::Client::new();
    let res = client.post("http://localhost:3000/get_file")
        .json(&uid_path)
        .send()
        .await
        .unwrap();

    let status = res.status();
    let res:FileContent = res.json().await.unwrap();

    // Recover the key and decrypt the content of the file
    let key = match_key(uid_path.clone(), logged_user.clone(), CryptoOperation::Encrypt);
    let decrypted_content = crypto::sym_decryption(key, res.content, res.nonce);

    (status, String::from_utf8(decrypted_content).unwrap())
}


fn match_key(mut uid_path: String, logged_user: LoggedUserClient, crypto_operation: CryptoOperation) -> Vec<u8> {
    if uid_path.len().clone() > 2 {
        // Remove last char in the path // TODO Better shit than this so we can handle two digits uid
        uid_path.pop();
        uid_path.pop();
        for (i, path) in logged_user.recovered_path.iter().enumerate(){
            if uid_path == *path{
                match crypto_operation {
                    CryptoOperation::Encrypt => return logged_user.recovered_key[i].clone(),
                    CryptoOperation::Sign => return logged_user.recovered_signing_key[i].clone(),
                    CryptoOperation::Verify => return logged_user.recovered_verification_key[i].clone()
                }
            }
        }
        return vec![0u8]
    }
    else {
        return logged_user.root_key.clone()
    }
}