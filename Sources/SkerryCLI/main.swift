import CryptoKit
import Foundation

import SkerryFormat

// skerry proves the format is open: it reads a Skerry library with no app installed.
// Plain notes read directly. Sealed notes unlock with the vault keyfile beside the
// notes plus a passphrase from SKERRY_PASSPHRASE or a recovery code from
// SKERRY_RECOVERY, both environment variables so nothing sensitive lands in shell
// history or process listings.

/// Prints usage to stderr and exits.
func usage() -> Never {
    let text = """
    usage:
      skerry list <library>                        list notes: path, title, tags
      skerry read <library> <note-path>            print one note's body
      skerry verify <library>                      parse everything; nonzero on problems
      skerry restore-backup <backup> <output-dir>  decrypt an encrypted backup

    Sealed content unlocks with SKERRY_PASSPHRASE or SKERRY_RECOVERY in the
    environment, tried against the .skerryvault keyfile at the library root.
    """
    FileHandle.standardError.write(Data((text + "\n").utf8))
    exit(64)
}

/// Writes a line to stderr.
func warn(_ message: String) {
    FileHandle.standardError.write(Data((message + "\n").utf8))
}

/// Relative paths of every note file under a library, dot folders skipped.
func notePaths(in library: URL) -> [String] {
    let extensions = ["md", "markdown", "txt"]
    var result: [String] = []
    let root = library.resolvingSymlinksInPath().path
    let walker = FileManager.default.enumerator(
        at: library, includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey]
    )
    while let entry = walker?.nextObject() as? URL {
        let name = entry.lastPathComponent
        if (try? entry.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true {
            if name.hasPrefix(".") { walker?.skipDescendants() }
            continue
        }
        guard !name.hasPrefix("."), extensions.contains(entry.pathExtension.lowercased())
        else { continue }
        let full = entry.resolvingSymlinksInPath().path
        guard full.hasPrefix(root + "/") else { continue }
        result.append(String(full.dropFirst(root.count + 1)))
    }
    return result.sorted()
}

/// The master key unwrapped from the library's keyfile, nil when no credential or no
/// keyfile is present. A wrong credential explains itself and exits.
func masterKey(in library: URL) -> SymmetricKey? {
    let keyfileURL = library.appendingPathComponent(".skerryvault")
    guard let data = try? Data(contentsOf: keyfileURL) else { return nil }
    let keyfile: VaultKey.Keyfile
    do {
        keyfile = try VaultKey.decode(data)
    } catch {
        warn("error: the .skerryvault keyfile does not parse: \(error)")
        exit(65)
    }
    let environment = ProcessInfo.processInfo.environment
    if let passphrase = environment["SKERRY_PASSPHRASE"] {
        do {
            return try VaultKey.unlock(keyfile, passphrase: passphrase)
        } catch {
            warn("error: SKERRY_PASSPHRASE does not unlock this vault")
            exit(65)
        }
    }
    if let recovery = environment["SKERRY_RECOVERY"] {
        do {
            return try VaultKey.unlock(keyfile, recovery: recovery)
        } catch {
            warn("error: SKERRY_RECOVERY does not unlock this vault")
            exit(65)
        }
    }
    return nil
}

/// A note parsed from disk, unsealed when possible.
struct ReadNote {
    /// Library-relative path.
    let path: String
    /// Parsed note, unsealed if a key was available.
    let note: Note
    /// Whether the note is a sealed envelope that stayed sealed.
    let sealed: Bool
}

/// Loads one note, unsealing with the master key or a legacy per-note passphrase.
func load(_ path: String, in library: URL, key: SymmetricKey?) -> ReadNote? {
    guard let text = try? String(
        contentsOf: library.appendingPathComponent(path), encoding: .utf8
    ) else {
        warn("error: cannot read \(path)")
        return nil
    }
    let parsed = FrontMatter.parseNote(text)
    guard parsed.metadata.encrypted else {
        return ReadNote(path: path, note: parsed, sealed: false)
    }
    if EncryptedNote.usesMasterKey(parsed), let key {
        if let open = try? EncryptedNote.unseal(parsed, key: key) {
            return ReadNote(path: path, note: open, sealed: false)
        }
        warn("error: \(path) is sealed but the key does not open it")
        return nil
    }
    if !EncryptedNote.usesMasterKey(parsed),
        let passphrase = ProcessInfo.processInfo.environment["SKERRY_PASSPHRASE"],
        let open = try? EncryptedNote.unseal(parsed, passphrase: passphrase) {
        return ReadNote(path: path, note: open, sealed: false)
    }
    return ReadNote(path: path, note: parsed, sealed: true)
}

let arguments = CommandLine.arguments
guard arguments.count >= 2 else { usage() }

switch arguments[1] {
case "list":
    guard arguments.count == 3 else { usage() }
    let library = URL(fileURLWithPath: arguments[2])
    let key = masterKey(in: library)
    for path in notePaths(in: library) {
        guard let read = load(path, in: library, key: key) else { continue }
        let title = read.sealed
            ? "[sealed]"
            : read.note.displayTitle ?? "(untitled)"
        let tags = read.note.metadata.tags.isEmpty
            ? ""
            : "  #" + read.note.metadata.tags.joined(separator: " #")
        print("\(path)\t\(title)\(tags)")
    }

case "read":
    guard arguments.count == 4 else { usage() }
    let library = URL(fileURLWithPath: arguments[2])
    let key = masterKey(in: library)
    guard let read = load(arguments[3], in: library, key: key) else { exit(66) }
    if read.sealed {
        warn("error: \(arguments[3]) is sealed; set SKERRY_PASSPHRASE or SKERRY_RECOVERY")
        exit(65)
    }
    print(read.note.body)

case "verify":
    guard arguments.count == 3 else { usage() }
    let library = URL(fileURLWithPath: arguments[2])
    let key = masterKey(in: library)
    var notes = 0
    var sealed = 0
    var problems = 0
    for path in notePaths(in: library) {
        guard let read = load(path, in: library, key: key) else {
            problems += 1
            continue
        }
        notes += 1
        if read.sealed { sealed += 1 }
    }
    let summary = "\(notes) notes parsed, \(sealed) sealed"
        + (key == nil ? " (no credential given)" : "")
        + (problems > 0 ? ", \(problems) problems" : ", no problems")
    print(summary)
    exit(problems > 0 ? 1 : 0)

case "restore-backup":
    guard arguments.count == 4 else { usage() }
    guard let passphrase = ProcessInfo.processInfo.environment["SKERRY_PASSPHRASE"] else {
        warn("error: restoring a backup needs SKERRY_PASSPHRASE")
        exit(65)
    }
    let backup = URL(fileURLWithPath: arguments[2])
    let output = URL(fileURLWithPath: arguments[3])
    do {
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        try EncryptedBackup.restore(backup, into: output, passphrase: passphrase)
        print("restored into \(output.path)")
    } catch {
        warn("error: restore failed: \(error)")
        exit(65)
    }

default:
    usage()
}
