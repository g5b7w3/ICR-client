use axum::response::IntoResponse;
use base64::Engine;
use base64::prelude::*;
use serde::Serialize;

pub mod crypto;

struct User {
    uid: String,
    password: String,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    master_key: Vec<u8>,
}

#[tokio::main]
async fn main() {
    // Create a new user
    let uid = "1".to_string();
    let password = "password".to_string();
    let user = create_user(uid, password);

    send_user_request(user).await;
}

// Function to create a new user
fn create_user(uid: String, password: String) -> User {
    // Generate a new key pair
    let (public_key, private_key) = crypto::generate_key_pair();

    // Generate a new master key
    let master_key = crypto::generate_master_key();

    let user = User {
        uid,
        password,
        public_key,
        private_key,
        master_key,
    };
    user
}

async fn send_user_request(user: User) -> impl IntoResponse {
    let (encrypted_master_key, salt) = crypto::encrypt_master_key(user.password.clone(), user.master_key.clone());
    // Serialize the user object
    let user = Create {
        uid: user.uid,
        salt,
        pk: crypto::encrypt_private_key(user.private_key.clone(), user.master_key.clone()),
        public_key: BASE64_STANDARD.encode(user.public_key),
        master_key: encrypted_master_key,
        shared_files: vec![],
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

#[derive(Serialize)]
struct Create {
    uid: String,
    pk: String,
    public_key: String,
    master_key: String,
    shared_files: Vec<String>,
    salt: String,
}