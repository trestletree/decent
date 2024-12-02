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

mod atoms {
    rustler::atoms! {
        ok,
        error,
    }
}

/// Encrypts a message using the recipient's public key.
pub fn encrypt_internal(
    plaintext: &str,
    public_key_path: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Load the public key
    let public_key_data = fs::read(public_key_path)?;
    let (public_key, _) = SignedPublicKey::from_armor_single(Cursor::new(&public_key_data))?;

    // Create a PGP message
    let literal_message = Message::new_literal("msg", plaintext);

    // Encrypt the message
    let encrypted_message = literal_message.encrypt_to_keys_seipdv1(
        &mut thread_rng(),
        SymmetricKeyAlgorithm::AES256,
        &[&public_key],
    )?;

    // Serialize the encrypted message to bytes
    Ok(encrypted_message.to_armored_bytes(Default::default())?)
}

/// Decrypts an encrypted message using the recipient's private key.
pub fn decrypt_internal(
    ciphertext: &[u8],
    private_key_path: &str,
    passphrase: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Load the private key
    let private_key_data = fs::read(private_key_path)?;
    let (private_key, _) = SignedSecretKey::from_armor_single(Cursor::new(&private_key_data))?;

    // Unlock the private key with the passphrase (this step might not be necessary for decryption)
    let _ = private_key.unlock(|| passphrase.to_string(), |_| Ok(()))?;

    // Parse the encrypted message
    let (message, _) = Message::from_armor_single(Cursor::new(ciphertext))?;

    // Decrypt the message
    let (decrypted_message, _) = message.decrypt(|| passphrase.to_string(), &[&private_key])?;

    // Extract the literal data
    match decrypted_message {
        Message::Literal(literal_message) => {
            let mut data = Vec::new();
            literal_message.data().read_to_end(&mut data)?;
            Ok(String::from_utf8(data)?)
        }
        _ => Err("Failed to decrypt: not a literal message".into()),
    }
}

#[rustler::nif]
fn encrypt<'a>(env: Env<'a>, plaintext: &str, public_key_path: &str) -> NifResult<Term<'a>> {
    match encrypt_internal(plaintext, public_key_path) {
        Ok(encrypted) => {
            // Create a new OwnedBinary with the size of the encrypted data
            let mut owned_binary = OwnedBinary::new(encrypted.len()).unwrap();
            // Copy the encrypted data into the OwnedBinary
            owned_binary.as_mut_slice().copy_from_slice(&encrypted);
            Ok((
                atoms::ok(),
                rustler::types::Binary::from_owned(owned_binary, env),
            )
                .encode(env))
        }
        Err(e) => {
            let error_message = format!("{:?}", e);
            Ok((atoms::error(), error_message).encode(env))
        }
    }
}

#[rustler::nif]
fn decrypt<'a>(
    env: Env<'a>,
    ciphertext: rustler::types::Binary<'a>,
    private_key_path: &str,
    passphrase: &str,
) -> NifResult<Term<'a>> {
    match decrypt_internal(ciphertext.as_slice(), private_key_path, passphrase) {
        Ok(decrypted) => Ok((atoms::ok(), decrypted).encode(env)),
        Err(e) => {
            let error_message = format!("{:?}", e);
            Ok((atoms::error(), error_message).encode(env))
        }
    }
}

rustler::init!("Elixir.Decent");
