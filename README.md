# smcrypt

A toy project for encrypting and decrypting messages, with configurable encryption keys.

## Warnings

Although the dependencies of this crate may be considered production grade and cryptographically secure, this crate itself makes no effort to maintain such standards.

**Use at your own risk.**

## Usage

```
usage: smcrypt <command> [<args>]

Valid commands are:

  gen  --  Generate a secret and public key
  store <secret key> <public key>  --  Store a secret key and the recipient's public key
  encrypt <message>  --  Encrypt a message using a randomly generated nonce and the stored keys
  decrypt <nonce> <message>  --  Decrypt a message using a nonce and the stored keys
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
