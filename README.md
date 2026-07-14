# Skerry Format

The open file format and reference cryptography for [Skerry](https://skerrynotes.com), a
local-first, encrypted Markdown notes app.

Skerry keeps your notes as plain Markdown files you own. This package is the auditable core: the
note format (see [FORMAT.md](FORMAT.md)) and the encryption that seals a note or a whole library
at rest. It is published so the cryptography can be **verified, not just trusted**, and so any
client can read and write the format without a sync engine or a server.

The Skerry app itself is a separate, closed-source product. This package is only the format and
the crypto, nothing about the app.

## What is here

- **FORMAT.md** — the note format contract: front matter, encryption envelope, attachments.
- **NoteCrypto** — AES-256-GCM with a key derived from a passphrase by PBKDF2-SHA256.
- **EncryptedNote** — seals a note into an opaque envelope so its title, tags, dates, and body
  are all ciphertext and the file name reveals nothing.
- **EncryptedBackup** — seals a whole library into a single encrypted blob for off-device storage.
- **Note**, **FrontMatter** — the note model and the front matter parser, so a client can read
  and write the format.

## Encryption at a glance

A passphrase derives a 256-bit key with PBKDF2-SHA256 (210,000 iterations, a random 16-byte
salt). AES-256-GCM encrypts the plaintext with a random nonce and an authentication tag. The
stored blob is `base64(salt || nonce || ciphertext || tag)`, so a note file stays plain UTF-8
text and remains safe to sync while its contents are unreadable without the passphrase. The
passphrase never touches disk; a client that lacks it can copy, move, and back up the file but
cannot read it.

## Build and test

```
swift test
```

## License

MIT. See [LICENSE](LICENSE).
