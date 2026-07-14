import CryptoKit
import Foundation

/// VaultKey is a random master key wrapped by a passphrase, the core of Skerry's key hierarchy.
///
/// A random 256-bit master key encrypts notes and backups. That master key is itself sealed under
/// a key-encryption key derived from the passphrase, so three things become possible: changing the
/// passphrase only re-wraps the master key rather than re-encrypting everything, a recovery code
/// can wrap the same master key as a second way in, and the app can hold the master key in memory
/// instead of the passphrase. Because the slow key derivation runs once at unlock rather than per
/// note, the iteration count can be set high.
public enum VaultKey {
    /// Errors raised by vault operations.
    public enum VaultError: Error, Equatable {
        /// The keyfile could not be parsed.
        case malformed
        /// The passphrase or recovery code was wrong.
        case wrongSecret
        /// The keyfile version is not understood.
        case unsupportedVersion
    }

    /// Current keyfile version.
    public static let version = 2
    /// PBKDF2 iterations for wrapping the master key, higher than the per-note default because it
    /// runs once per unlock.
    public static let kdfIterations = 600_000
    /// Salt length in bytes for a wrapping.
    private static let saltLength = 16
    /// Master key length in bytes.
    private static let masterKeyLength = 32

    /// One wrapping of the master key under a secret, passphrase or recovery code.
    public struct Wrapping: Equatable, Sendable, Codable {
        /// Salt for the key-encryption-key derivation.
        public var salt: Data
        /// Iteration count used to derive the key-encryption key.
        public var iterations: Int
        /// The master key sealed under the derived key: nonce, ciphertext, and tag.
        public var wrapped: Data
    }

    /// A vault keyfile: the wrapped master key, optionally with a recovery wrapping.
    public struct Keyfile: Equatable, Sendable, Codable {
        /// Format version.
        public var version: Int
        /// Master key wrapped under the passphrase.
        public var passphrase: Wrapping
        /// Master key wrapped under a recovery code, when one has been set.
        public var recovery: Wrapping?
    }

    /// Creates a new vault: a random master key wrapped by the passphrase.
    public static func create(passphrase: String) throws -> (key: SymmetricKey, keyfile: Keyfile) {
        let master = SymmetricKey(size: .bits256)
        let wrapping = try wrap(master: master, secret: passphrase)
        return (master, Keyfile(version: version, passphrase: wrapping, recovery: nil))
    }

    /// Unwraps the master key from a keyfile using the passphrase.
    public static func unlock(_ keyfile: Keyfile, passphrase: String) throws -> SymmetricKey {
        guard keyfile.version == version else { throw VaultError.unsupportedVersion }
        return try unwrap(keyfile.passphrase, secret: passphrase)
    }

    /// Unwraps the master key using the recovery code.
    public static func unlock(_ keyfile: Keyfile, recovery code: String) throws -> SymmetricKey {
        guard keyfile.version == version else { throw VaultError.unsupportedVersion }
        guard let recovery = keyfile.recovery else { throw VaultError.wrongSecret }
        return try unwrap(recovery, secret: normalizeRecovery(code))
    }

    /// Re-wraps the master key under a new passphrase, keeping any recovery wrapping.
    public static func changePassphrase(
        _ keyfile: Keyfile, master: SymmetricKey, to newPassphrase: String
    ) throws -> Keyfile {
        var updated = keyfile
        updated.passphrase = try wrap(master: master, secret: newPassphrase)
        return updated
    }

    /// Adds or replaces a recovery wrapping and returns the printable code to show once.
    public static func addRecovery(
        _ keyfile: Keyfile, master: SymmetricKey
    ) throws -> (code: String, keyfile: Keyfile) {
        let code = generateRecoveryCode()
        var updated = keyfile
        updated.recovery = try wrap(master: master, secret: normalizeRecovery(code))
        return (code, updated)
    }

    /// Encodes a keyfile to JSON bytes for storage.
    public static func encode(_ keyfile: Keyfile) -> Data {
        (try? JSONEncoder().encode(keyfile)) ?? Data()
    }

    /// Decodes a keyfile from JSON bytes.
    public static func decode(_ data: Data) throws -> Keyfile {
        do {
            return try JSONDecoder().decode(Keyfile.self, from: data)
        } catch {
            throw VaultError.malformed
        }
    }

    /// Wraps a master key under a secret, deriving the key-encryption key with a fresh salt.
    private static func wrap(master: SymmetricKey, secret: String) throws -> Wrapping {
        var salt = Data(count: saltLength)
        let generated = salt.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, saltLength, $0.baseAddress!)
        }
        guard generated == errSecSuccess else { throw VaultError.malformed }
        let kek = try NoteCrypto.deriveKey(
            passphrase: secret, salt: salt, iterations: kdfIterations
        )
        let masterBytes = master.withUnsafeBytes { Data($0) }
        let wrapped = try NoteCrypto.seal(masterBytes, key: kek)
        return Wrapping(salt: salt, iterations: kdfIterations, wrapped: wrapped)
    }

    /// Unwraps a master key from a wrapping, mapping crypto failures to a wrong-secret error.
    private static func unwrap(_ wrapping: Wrapping, secret: String) throws -> SymmetricKey {
        let kek = try NoteCrypto.deriveKey(
            passphrase: secret, salt: wrapping.salt, iterations: wrapping.iterations
        )
        do {
            let raw = try NoteCrypto.unseal(wrapping.wrapped, key: kek)
            guard raw.count == masterKeyLength else { throw VaultError.malformed }
            return SymmetricKey(data: raw)
        } catch is NoteCrypto.CryptoError {
            throw VaultError.wrongSecret
        }
    }

    /// Generates a printable recovery code in groups of Crockford base32 characters.
    private static func generateRecoveryCode() -> String {
        let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        var bytes = Data(count: 20)
        _ = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 20, $0.baseAddress!)
        }
        let chars = bytes.map { alphabet[Int($0) % alphabet.count] }
        var groups: [String] = []
        var index = 0
        while index < chars.count {
            groups.append(String(chars[index..<min(index + 5, chars.count)]))
            index += 5
        }
        return groups.joined(separator: "-")
    }

    /// Normalizes a recovery code so separators and case do not matter on entry.
    private static func normalizeRecovery(_ code: String) -> String {
        code.uppercased().filter { $0.isLetter || $0.isNumber }
    }
}
