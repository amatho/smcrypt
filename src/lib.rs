use std::{convert::TryInto, str::Chars};

use crypto_box::{
    aead::{generic_array::GenericArray, Aead},
    PublicKey, SecretKey,
};
use nanoserde::{DeRon, DeRonErr, DeRonState, SerRon, SerRonState};

#[derive(SerRon, DeRon, Debug)]
struct KeyContextArrays {
    my_secret: [u8; 32],
    their_public: [u8; 32],
}

#[derive(Debug)]
struct KeyContext {
    my_secret: SecretKey,
    their_public: PublicKey,
}

impl SerRon for KeyContext {
    fn ser_ron(&self, indent_level: usize, state: &mut SerRonState) {
        KeyContextArrays {
            my_secret: self.my_secret.to_bytes(),
            their_public: self.their_public.to_bytes(),
        }
        .ser_ron(indent_level, state)
    }
}

impl DeRon for KeyContext {
    fn de_ron(state: &mut DeRonState, input: &mut Chars) -> Result<Self, DeRonErr> {
        Ok(KeyContextArrays::de_ron(state, input)?.into())
    }
}

impl From<KeyContextArrays> for KeyContext {
    fn from(ctx_arrays: KeyContextArrays) -> Self {
        let my_secret = SecretKey::from(ctx_arrays.my_secret);
        let their_public = PublicKey::from(ctx_arrays.their_public);
        Self {
            my_secret,
            their_public,
        }
    }
}

pub fn run() -> Result<(), &'static str> {
    let mut args = std::env::args();
    args.next();

    let cmd = args.next().ok_or_else(usage)?;

    match cmd.as_ref() {
        "gen" => generate_keys(),
        "store" => {
            let secret = args.next().ok_or_else(usage)?;
            let public = args.next().ok_or_else(usage)?;
            store_keys(&secret, &public);
        }
        "encrypt" => {
            let plain_text = args.next().ok_or_else(usage)?;
            encrypt(&plain_text)?;
        }
        "decrypt" => {
            let encrypted = args.next().ok_or_else(usage)?;
            decrypt(&encrypted)?;
        }
        a => {
            eprintln!("smcrypt: '{}' is not a valid command.", a);
            return Err(usage());
        }
    }

    Ok(())
}

fn usage() -> &'static str {
    "\nusage: smcrypt <command> [<args>]

Valid commands are:

  gen  --  Generate a secret and public key
  store <secret key> <public key>  --  Store a secret key and the recipient's public key
  encrypt <message>  --  Encrypt a message using a randomly generated nonce and the stored keys
  decrypt <nonce> <message>  --  Decrypt a message using a nonce and the stored keys"
}

fn generate_keys() {
    let mut rng = rand::thread_rng();
    let secret = SecretKey::generate(&mut rng);
    let public = secret.public_key();

    println!(
        "Secret key (keep this for yourself): {}",
        base64::encode(secret.to_bytes())
    );
    println!(
        "Public key (give this to the recipient): {}",
        base64::encode(public.as_bytes())
    );
}

fn store_keys(secret_key_base64: &str, public_key_base64: &str) {
    let ctx = KeyContextArrays {
        my_secret: array_from_base64(secret_key_base64),
        their_public: array_from_base64(public_key_base64),
    };

    std::fs::write("smcrypt_keys.ron", ctx.serialize_ron()).unwrap();
}

fn read_keys() -> Result<KeyContext, &'static str> {
    let contents = std::fs::read_to_string("smcrypt_keys.ron")
        .map_err(|_| "smcrypt: could not read key file. Did you forget to store keys first?")?;
    KeyContext::deserialize_ron(&contents).map_err(|_| "smcrypt: invalid content in key file.")
}

fn encrypt(plain_text: &str) -> Result<(), &'static str> {
    let ctx = read_keys()?;
    let mut rng = rand::thread_rng();
    let nonce = crypto_box::generate_nonce(&mut rng);

    let my_box = crypto_box::Box::new(&ctx.their_public, &ctx.my_secret);
    let encrypted_text = my_box.encrypt(&nonce, plain_text.as_bytes()).unwrap();

    let encrypted_with_nonce: Vec<_> = nonce
        .into_iter()
        .chain(encrypted_text.into_iter())
        .collect();

    println!(
        "Encrypted message: {}",
        base64::encode(encrypted_with_nonce)
    );

    Ok(())
}

fn decrypt(encrypted_base64: &str) -> Result<(), &'static str> {
    const NONCE_LEN: usize = 24;

    let ctx = read_keys()?;
    let encrypted_with_nonce = base64::decode(encrypted_base64).unwrap();
    let nonce: [u8; 24] = encrypted_with_nonce[..NONCE_LEN].try_into().unwrap();
    let encrypted_text = &encrypted_with_nonce[NONCE_LEN..];

    let my_box = crypto_box::Box::new(&ctx.their_public, &ctx.my_secret);
    let plain_text = my_box
        .decrypt(&GenericArray::from(nonce), encrypted_text)
        .unwrap();

    println!("{}", String::from_utf8_lossy(&plain_text));

    Ok(())
}

fn array_from_base64<const N: usize>(input: &str) -> [u8; N] {
    let mut arr = [0u8; N];
    base64::decode_config_slice(input, base64::STANDARD, &mut arr).unwrap();
    arr
}
