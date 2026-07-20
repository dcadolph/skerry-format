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
- **NoteCrypto** — authenticated sealing with AES-256-GCM or ChaCha20-Poly1305, chosen per
  envelope and recorded in it.
- **Argon2** — Argon2id (RFC 9106) implemented from scratch and gated on the RFC's own test
  vectors, deriving keys from passphrases.
- **VaultKey** — the master-key hierarchy: one random 256-bit key encrypts the library, wrapped
  separately by the passphrase and by a recovery code, so changing the passphrase re-wraps one
  key instead of re-encrypting every note.
- **EncryptedNote** — seals a note into an opaque envelope so its title, tags, dates, and body
  are all ciphertext and the file name reveals nothing.
- **EncryptedBackup** — seals a whole library into a single encrypted blob for off-device storage.
- **Note**, **FrontMatter** — the note model and the front matter parser, so a client can read
  and write the format.
- **skerry** — a command-line reader proving there is no lock-in.

## Encryption at a glance

A random 256-bit master key seals notes with AES-256-GCM by default, ChaCha20-Poly1305 as a
choice; every envelope is authenticated, so tampered files fail to open rather than opening
wrong. The master key is wrapped by a key derived from the passphrase with Argon2id (64 MiB,
3 passes, 4 lanes) and stored in a keyfile beside the notes; a recovery code is a second,
independent wrapping of the same key. Sealed blobs are base64 inside ordinary front matter,
so a note file stays plain UTF-8 text and remains safe to sync while its contents are
unreadable without the passphrase. Legacy per-note envelopes (PBKDF2-SHA256, 210,000
iterations) still open and upgrade on their next unlock.

## The command-line reader

Your notes must never need our app. The `skerry` executable in this repo lists, reads,
verifies, and restores a library using only the code you see here:

```
swift run skerry list ~/Notes
swift run skerry read ~/Notes "Harbor/Rope.md"
swift run skerry verify ~/Notes
SKERRY_PASSPHRASE=... swift run skerry restore-backup vault.skerrybackup ./restored
```

Sealed notes unlock with `SKERRY_PASSPHRASE` or `SKERRY_RECOVERY` in the environment, tried
against the `.skerryvault` keyfile at the library root. Without a credential, sealed notes
list as sealed and everything else reads normally.

## Build and test

```
swift test
```

## License

MIT. See [LICENSE](LICENSE).
