import CommonCrypto
import CryptoKit
import Foundation

/// NoteCrypto encrypts and decrypts note text with a passphrase.
///
/// A random salt feeds PBKDF2-SHA256 to derive a 256-bit key, which AES-GCM uses to seal
/// the plaintext with a random nonce and an authentication tag. The stored blob is
/// `base64(salt || nonce || ciphertext || tag)`, so a note file stays plain UTF-8 text and
/// remains safe to sync while its contents are unreadable without the passphrase.
public enum NoteCrypto {
    /// Errors raised during encryption or decryption.
    public enum CryptoError: Error, Equatable {
        /// The stored blob was malformed or truncated.
        case malformed
        /// Key derivation failed.
        case keyDerivation
        /// Decryption failed, usually a wrong passphrase or tampered data.
        case decryptionFailed
    }

    /// Salt length in bytes.
    private static let saltLength = 16
    /// PBKDF2 iteration count, chosen for brute-force resistance on current hardware.
    private static let iterations: UInt32 = 210_000
    /// Derived key length in bytes for AES-256.
    private static let keyLength = 32

    /// Seals raw bytes with a passphrase, returning `salt || nonce || ciphertext || tag`.
    ///
    /// Used for whole-file payloads like an encrypted backup, where the result is written as
    /// binary rather than base64 text.
    public static func seal(_ plaintext: Data, passphrase: String) throws -> Data {
        var salt = Data(count: saltLength)
        let generated = salt.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, saltLength, $0.baseAddress!)
        }
        guard generated == errSecSuccess else { throw CryptoError.keyDerivation }
        let key = try deriveKey(passphrase: passphrase, salt: salt)
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else { throw CryptoError.decryptionFailed }
        return salt + combined
    }

    /// Unseals bytes produced by ``seal(_:passphrase:)``, throwing on a wrong passphrase.
    public static func unseal(_ blob: Data, passphrase: String) throws -> Data {
        guard blob.count > saltLength else { throw CryptoError.malformed }
        let salt = blob.prefix(saltLength)
        let combined = blob.dropFirst(saltLength)
        let key = try deriveKey(passphrase: passphrase, salt: salt)
        do {
            let box = try AES.GCM.SealedBox(combined: combined)
            return try AES.GCM.open(box, using: key)
        } catch {
            throw CryptoError.decryptionFailed
        }
    }

    /// Encrypts plaintext with a passphrase and returns a base64 blob.
    public static func encrypt(_ plaintext: String, passphrase: String) throws -> String {
        try seal(Data(plaintext.utf8), passphrase: passphrase).base64EncodedString()
    }

    /// Decrypts a base64 blob with a passphrase, throwing when the passphrase is wrong.
    public static func decrypt(_ blob: String, passphrase: String) throws -> String {
        guard let data = Data(base64Encoded: blob) else { throw CryptoError.malformed }
        return String(decoding: try unseal(data, passphrase: passphrase), as: UTF8.self)
    }

    /// Reports whether text is shaped like a sealed blob rather than cleartext.
    ///
    /// A real blob is base64 of at least `salt || nonce || tag`, so cleartext prose, which is
    /// almost never valid base64 of that length, is rejected. Callers use this as a last-ditch
    /// guard before writing a note marked encrypted, so a decrypted body never reaches disk.
    public static func isSealedBlob(_ text: String) -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let data = Data(base64Encoded: trimmed) else { return false }
        // AES-GCM adds a 12-byte nonce and a 16-byte tag on top of our 16-byte salt.
        return data.count >= saltLength + 12 + 16
    }

    /// Derives an AES key from a passphrase and salt using PBKDF2-SHA256.
    private static func deriveKey(passphrase: String, salt: Data) throws -> SymmetricKey {
        var derived = Data(count: keyLength)
        let password = Data(passphrase.utf8)
        let status = derived.withUnsafeMutableBytes { derivedBytes in
            salt.withUnsafeBytes { saltBytes in
                password.withUnsafeBytes { passwordBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.bindMemory(to: Int8.self).baseAddress, password.count,
                        saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        iterations,
                        derivedBytes.bindMemory(to: UInt8.self).baseAddress, keyLength
                    )
                }
            }
        }
        guard status == kCCSuccess else { throw CryptoError.keyDerivation }
        return SymmetricKey(data: derived)
    }
}
