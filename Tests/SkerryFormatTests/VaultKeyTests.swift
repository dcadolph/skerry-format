import CryptoKit
import Foundation
import Testing

@testable import SkerryFormat

@Suite struct VaultKeyTests {
    @Test func createThenUnlockReturnsSameMasterKey() throws {
        let (master, keyfile) = try VaultKey.create(passphrase: "correct horse staple")
        #expect(try VaultKey.unlock(keyfile, passphrase: "correct horse staple") == master)
    }

    @Test func wrongPassphraseThrowsWrongSecret() throws {
        let (_, keyfile) = try VaultKey.create(passphrase: "the right one")
        #expect(throws: VaultKey.VaultError.wrongSecret) {
            try VaultKey.unlock(keyfile, passphrase: "the wrong one")
        }
    }

    @Test func changingPassphraseKeepsTheMasterKey() throws {
        let (master, keyfile) = try VaultKey.create(passphrase: "old passphrase")
        let updated = try VaultKey.changePassphrase(keyfile, master: master, to: "new passphrase")
        #expect(try VaultKey.unlock(updated, passphrase: "new passphrase") == master)
        #expect(throws: VaultKey.VaultError.wrongSecret) {
            try VaultKey.unlock(updated, passphrase: "old passphrase")
        }
    }

    @Test func recoveryCodeUnlocksAndIgnoresCaseAndDashes() throws {
        let (master, keyfile) = try VaultKey.create(passphrase: "primary")
        let (code, withRecovery) = try VaultKey.addRecovery(keyfile, master: master)
        #expect(code.contains("-"))
        #expect(try VaultKey.unlock(withRecovery, recovery: code) == master)
        #expect(try VaultKey.unlock(withRecovery, recovery: code.lowercased()) == master)
        #expect(try VaultKey.unlock(withRecovery, recovery: code.replacingOccurrences(of: "-", with: " ")) == master)
    }

    @Test func keyfileRoundTripsThroughJSON() throws {
        let (master, keyfile) = try VaultKey.create(passphrase: "serialize me")
        let decoded = try VaultKey.decode(VaultKey.encode(keyfile))
        #expect(decoded == keyfile)
        #expect(try VaultKey.unlock(decoded, passphrase: "serialize me") == master)
    }
}
