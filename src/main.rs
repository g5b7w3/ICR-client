use axum::response::IntoResponse;
use base64::Engine;
use base64::prelude::*;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

pub mod crypto;

struct User {
    uid: String,
    password: String,
    signing_public_key: Vec<u8>,
    signing_private_key: Vec<u8>,
    encryption_public_key: Vec<u8>,
    encryption_private_key: Vec<u8>,
    master_key: Vec<u8>,
}

#[tokio::main]
async fn main() {
    // Create a new user
    let uid = "1".to_string();
    let password = "password".to_string();
    let user = create_user(uid, password);

    //send_user_request(user).await;

    // Try to log in with the user
    let response = login(user.uid, user.password).await.into_response();
    match response.status() {
        StatusCode::OK => println!("Login successful!"),
        StatusCode::UNAUTHORIZED => println!("Login failed!"),
        _ => println!("Error"),
    }

    // TODO: EVERY OTHER FUCKING FUNCTIONALITIES
}

// Function to create a new user
fn create_user(uid: String, password: String) -> User {
    // Generate a new key pair
    let (signing_public_key, signing_private_key) = crypto::generate_key_pair();
    let (encryption_public_key, encryption_private_key) = crypto::generate_key_pair();

    // Generate a new master key
    let master_key = crypto::generate_master_key();

    let user = User {
        uid,
        password,
        signing_public_key,
        signing_private_key,
        master_key,
        encryption_public_key,
        encryption_private_key,
    };
    user
}

async fn send_user_request(user: User) -> impl IntoResponse {
    let (encrypted_master_key, nonce_master, salt, challenge_key, nonce_chall) = crypto::encrypt_master_key(user.password.clone(), user.master_key.clone());
    // Serialize the user object
    let user = Create {
        uid: user.uid,
        salt,
        pk_signing: crypto::encrypt_private_key(user.signing_private_key.clone(), user.master_key.clone()),
        pk_encryption: crypto::encrypt_private_key(user.encryption_private_key.clone(), user.master_key.clone()),
        public_key_signing: BASE64_STANDARD.encode(user.signing_public_key),
        public_key_encryption: BASE64_STANDARD.encode(user.encryption_public_key),
        master_key: encrypted_master_key,
        shared_files: vec![],
        challenge_key,
        nonce_master,
        nonce_chall,
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

async fn login (uid: String, password: String) -> impl IntoResponse {

    let body: HelloSer = HelloSer {
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
    let res: Hello = res.json().await.unwrap();
    let token = res.token;

    // Derive key from password
    let (challenge_encryption_key, key_encryption_key) = crypto::key_derivation(password, res.salt);


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
    let challenge = crypto::decrypt_challenge(challenge_encryption_key, res.challenge, res.nonce);

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

    (res.status(), res.text().await.unwrap())
}

#[derive(Serialize)]
struct Create {
    uid: String,
    salt: String,
    master_key: String,
    shared_files: Vec<String>,
    challenge_key: String,
    public_key_signing: String,
    public_key_encryption: String,
    pk_signing: String,
    pk_encryption: String,
    nonce_master: String,
    nonce_chall: String,
}

#[derive(Serialize)]
struct Login {
    uid: String,
    challenge_key: String,
}

#[derive(Deserialize)]
struct Hello {
    token: String,
    salt: String,
}
#[derive(Deserialize)]
struct Challenge {
    challenge: String,
    nonce: String,
    salt: String,
    nonce_chall: String,
}

#[derive(Serialize)]
struct ChallengeResponse {
    challenge: String,
    token: String,
}

#[derive(Serialize)]
struct HelloSer {
    uid: String,
}
