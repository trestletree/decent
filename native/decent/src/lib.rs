use pgp::composed::message::Message;
use pgp::composed::signed_key::{SignedPublicKey, SignedSecretKey};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::SecretKeyTrait;
use pgp::Deserializable;
use rand::thread_rng;
use rustler::types::binary::OwnedBinary;
use rustler::NifResult;
use rustler::{Encoder, Env, Term};
use std::fs;
use std::io::{Cursor, Read};

use pgp::errors::Error as PgpLibError;
use std::io::Error as IoError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PgpError {
    #[error("Failed to read public key file: {0}")]
    PublicKeyFileReadError(#[from] IoError),
    #[error("Invalid public key format")]
    InvalidPublicKeyFormat,
    #[error("Invalid private key format")]
    InvalidPrivateKeyFormat,
    #[error("Encryption failed: {0}")]
    EncryptionError(#[from] PgpLibError),
    #[error("Decryption failed: {0}")]
    DecryptionError(String),
    #[error("Incorrect passphrase")]
    IncorrectPassphrase,
}

mod atoms {
    rustler::atoms! {
        ok,
        error,
    }
}

pub fn encrypt_internal(message: &str, public_key_path: &str) -> Result<Vec<u8>, PgpError> {
    let public_key_data = fs::read(public_key_path).map_err(PgpError::PublicKeyFileReadError)?;
    let (public_key, _) = SignedPublicKey::from_armor_single(Cursor::new(&public_key_data))
        .map_err(|_| PgpError::InvalidPublicKeyFormat)?;

    let literal_message = Message::new_literal("msg", message);
    let encrypted_message = literal_message.encrypt_to_keys_seipdv1(
        &mut thread_rng(),
        SymmetricKeyAlgorithm::AES256,
        &[&public_key],
    )?; // This now works because of the `From` implementation.

    Ok(encrypted_message.to_armored_bytes(Default::default())?)
}

pub fn decrypt_internal(
    encrypted_message: &[u8],
    private_key_path: &str,
    private_key_passphrase: Option<&str>,
) -> Result<String, PgpError> {
    let private_key_data = fs::read(private_key_path).map_err(PgpError::PublicKeyFileReadError)?;
    let (private_key, _) = SignedSecretKey::from_armor_single(Cursor::new(&private_key_data))
        .map_err(|_| PgpError::InvalidPrivateKeyFormat)?;

    if let Some(passphrase) = private_key_passphrase {
        private_key
            .unlock(|| passphrase.to_string(), |_| Ok(()))
            .map_err(|_| PgpError::IncorrectPassphrase)?;
    }

    let (message, _) = Message::from_armor_single(Cursor::new(encrypted_message))
        .map_err(|_| PgpError::DecryptionError(String::from("Invalid encrypted data")))?;

    let (decrypted_message, _) = message
        .decrypt(
            || private_key_passphrase.map(String::from).unwrap_or_default(),
            &[&private_key],
        )
        .map_err(|e| {
            if e.to_string().contains("incorrect keyring for this message")
                || e.to_string().contains("Session key decryption failed")
            {
                PgpError::IncorrectPassphrase
            } else {
                PgpError::DecryptionError(format!("{:?}", e))
            }
        })?;

    match decrypted_message {
        Message::Literal(literal_message) => {
            let mut data = Vec::new();
            literal_message
                .data()
                .read_to_end(&mut data)
                .map_err(|e| PgpError::DecryptionError(format!("{:?}", e)))?;
            String::from_utf8(data).map_err(|_| {
                PgpError::DecryptionError(String::from("Decrypted message is not valid UTF-8"))
            })
        }
        _ => Err(PgpError::DecryptionError(String::from(
            "Not a literal message",
        ))),
    }
}

#[rustler::nif]
fn encrypt<'a>(env: Env<'a>, message: &str, public_key_path: &str) -> NifResult<Term<'a>> {
    match encrypt_internal(message, public_key_path) {
        Ok(encrypted) => {
            let mut owned_binary = OwnedBinary::new(encrypted.len()).unwrap();
            owned_binary.as_mut_slice().copy_from_slice(&encrypted);
            Ok((
                atoms::ok(),
                rustler::types::Binary::from_owned(owned_binary, env),
            )
                .encode(env))
        }
        Err(e) => Ok((atoms::error(), e.to_string()).encode(env)),
    }
}

#[rustler::nif]
fn decrypt<'a>(
    env: Env<'a>,
    encrypted_message: rustler::types::Binary<'a>,
    private_key_path: &str,
    private_key_passphrase: Option<&str>,
) -> NifResult<Term<'a>> {
    match decrypt_internal(
        encrypted_message.as_slice(),
        private_key_path,
        private_key_passphrase,
    ) {
        Ok(decrypted) => Ok((atoms::ok(), decrypted).encode(env)),
        Err(e) => Ok((atoms::error(), e.to_string()).encode(env)),
    }
}

rustler::init!("Elixir.Decent");
