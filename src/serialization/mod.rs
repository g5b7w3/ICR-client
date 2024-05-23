use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct GetDirSer {
    pub uid_path: String,
    pub token: String,
}

#[derive(Serialize)]
pub struct DirectorySer {
    pub read: ReadDirectorySer,
    pub write: WriteDirectorySer,
}

#[derive(Serialize)]
pub struct ReadDirectorySer {
    pub uid_path: String,
    pub directory_name: String,
    pub files_names: Vec<String>,
    pub files_uid: Vec<String>,
    pub files_encryption_keys: String,
    pub files_signatures_verification_keys: String,
    pub files_nonce: Vec<String>,
    pub nonce_name: String,
    pub nonce_key_file: String,
}

#[derive(Serialize)]
pub struct WriteDirectorySer {
    pub files_signing_keys: String,
    pub nonce_private_key: String,
}

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
    pub nonce_pk_signing: String,
    pub nonce_pk_encryption: String,
    pub root_key: String,
    pub root_nonce: String,
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

#[derive(Deserialize, Debug)]
pub struct UpdateUserDes{
    pub pk_signing: String,
    pub pk_encryption: String,
    pub master_key: String,
    pub shared_files: Vec<String>,
    pub salt: String,
    pub challenge_key: String,
    pub nonce_master: String,
    pub nonce_chall: String,
    pub nonce_pk_signing: String,
    pub nonce_pk_encryption: String,
    pub root_key: String,
    pub root_nonce: String,
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

#[derive(Deserialize)]
pub struct LoggedUserDes{
    pub pk_signing : String,
    pub pk_encryption : String,
    pub master_key : String,
    pub shared_files : Vec<String>,
    pub nonce_master : String,
    pub nonce_pk_signing : String,
    pub nonce_pk_encryption : String,
    pub root_key : String,
    pub root_nonce : String,
    pub token : String,
}

#[derive(Debug)]
pub struct LoggedUser {
    pub pk_signing : Vec<u8>,
    pub pk_encryption : Vec<u8>,
    pub master_key : Vec<u8>,
    pub shared_files : Vec<String>,
    pub root_key : Vec<u8>,
    pub token : String
}


#[derive(Deserialize, Debug)]
pub struct ReadDirectoryDes {
    pub uid_path: String,
    pub directory_name: String,
    pub files_names: Vec<String>,
    pub files_uid: Vec<String>,
    pub files_encryption_keys: String,
    pub files_signatures_verification_keys: String,
    pub files_nonce: Vec<String>,
    pub nonce_name: String,
    pub nonce_key_file: String,
}

#[derive(Deserialize, Debug)]
pub struct WriteDirectoryDes {
    pub files_signing_keys: String,
    pub nonce_private_key: String,
}

#[derive(Deserialize)]
pub struct DirectoryDes {
    pub read: ReadDirectoryDes,
    pub write: WriteDirectoryDes,
}