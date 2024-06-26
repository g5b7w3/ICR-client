use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct GetDir {
    pub uid_path: String,
    pub token: String,
}
#[derive(Deserialize, Serialize)]
pub struct Directory {
    pub read: ReadDirectory,
    pub write: WriteDirectory,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct ReadDirectory {
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

#[derive(Deserialize, Debug, Serialize)]
pub struct WriteDirectory {
    pub files_signing_keys: String,
    pub nonce_private_key: String,
}
#[derive(Deserialize, Serialize)]
pub struct Login {
    pub uid: String,
    pub challenge_key: String,
}

#[derive(Deserialize, Serialize)]
pub struct Create {
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

#[derive(Deserialize, Serialize)]
pub struct Hello {
    pub uid: String,
}

#[derive(Deserialize, Serialize)]
pub struct ChallengeResponse {
    pub challenge: String,
    pub token: String,
}

#[derive(Deserialize, Serialize)]
pub struct UpdateUser {
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

#[derive(Deserialize, Serialize)]
pub struct PubKey {
    pub signing_key: String,
    pub encryption_key: String,
}

#[derive(Deserialize, Serialize)]
pub struct Challenge {
    pub challenge: String,
    pub nonce: String,
    pub salt: String,
    pub nonce_chall: String,
}

#[derive(Deserialize, Serialize)]
pub struct HelloResponse {
    pub token: String,
    pub salt: String,
}


#[derive(Deserialize, Serialize)]
pub struct LoggedUser {
    pub pk_signing : String,
    pub pk_encryption : String,
    pub master_key : String,
    pub shared_files : Vec<String>,
    pub nonce_master : String,
    pub nonce_pk_signing : String,
    pub nonce_pk_encryption : String,
    pub root_key : String,
    pub root_nonce : String,
    pub token: String,
}
#[derive(Deserialize, Serialize)]
pub struct LoggedUserClient {
    pub pk_signing: Vec<u8>,
    pub pk_encryption: Vec<u8>,
    pub master_key: Vec<u8>,
    pub shared_files: Vec<String>,
    pub root_key: Vec<u8>,
    pub token: String,
    pub recovered_key: Vec<Vec<u8>>,
    pub recovered_path: Vec<String>,
    pub recovered_signing_key: Vec<Vec<u8>>,
    pub recovered_verification_key: Vec<Vec<u8>>,
}

#[derive(Deserialize, Serialize)]
pub struct FileCreation {
    pub read_directory: ReadDirectory,
    pub content: String,
    pub nonce: String,
    pub signature: String,
}

#[derive(Deserialize, Serialize)]
pub struct FileContent {
    pub content: String,
    pub nonce: String,
}

impl LoggedUserClient {
    pub fn clone(&self) -> LoggedUserClient {
        LoggedUserClient {
            pk_signing: self.pk_signing.clone(),
            pk_encryption: self.pk_encryption.clone(),
            master_key: self.master_key.clone(),
            shared_files: self.shared_files.clone(),
            root_key: self.root_key.clone(),
            token: self.token.clone(),
            recovered_key: self.recovered_key.clone(),
            recovered_path: self.recovered_path.clone(),
            recovered_signing_key: self.recovered_signing_key.clone(),
            recovered_verification_key: self.recovered_verification_key.clone(),
        }
    }

}

pub struct DirectoryInfo {
    pub uid_path: String,
    pub directory_name: String,
    pub files_names: Vec<String>,
    pub files_uid: Vec<String>,
    pub files_encryption_keys: String,
    pub files_signatures_verification_keys: String,
    pub files_nonce: Vec<String>,
    pub nonce_name: String,
    pub nonce_key_file: String,
    pub files_signing_keys: String,
    pub nonce_private_key: String,
}
