use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct LoginSer{
    pub uid: String,
    pub challenge_key: String,
}

#[derive(Serialize)]
pub struct CreateSer {
    pub uid: String,
    pub salt: String,
    pub master_key: String,
    pub shared_files: Vec<String>,
    pub challenge_key: String,
    pub public_key_signing: String,
    pub public_key_encryption: String,
    pub pk_signing: String,
    pub pk_encryption: String,
    pub nonce_master: String,
    pub nonce_chall: String,
}

#[derive(Serialize)]
pub struct HelloSer {
    pub uid: String,
}

#[derive(Serialize)]
pub struct ChallengeResponseSer{
    pub challenge: String,
    pub token: String,
}

#[derive(Deserialize)]
pub struct UpdateUserDes {
    pub pk_signing: String,
    pub pk_encryption: String,
    pub master_key: String,
    pub shared_files: Vec<String>,
    pub salt: String,
    pub challenge_key: String,
    pub nonce_master: String,
    pub nonce_chall: String,
}

#[derive(Deserialize)]
pub struct PubKeyDes {
    pub signing_key: String,
    pub encryption_key: String,
}

#[derive(Deserialize)]
pub struct ChallengeDes {
    pub challenge: String,
    pub nonce: String,
    pub salt: String,
    pub nonce_chall: String,
}

#[derive(Deserialize)]
pub struct HelloResponseDes{
    pub token: String,
    pub salt: String,
}

