import CryptoKit
import Foundation
import Security

struct ClaudeOAuthCredentials: Equatable {
    let accessToken: String
    let expiresAt: Date?
    let scopes: Set<String>
}

enum KeychainManager {
    static let claudeCodeService = "Claude Code-credentials"
    private static let notchiService = "com.ruban.notchi"
    private static let anthropicApiKeyAccount = "anthropicApiKey"
    private static let openAIApiKeyAccount = "openAIApiKey"
    static let cachedOAuthTokenAccount = "cachedOAuthToken"
    private static let recentCredentialCacheTTL: TimeInterval = 5
    private static let securityCLIBackoffInterval: TimeInterval = 60
    private static let credentialReadLock = NSLock()
    private nonisolated(unsafe) static var recentCredentialCacheEntries: [String: ClaudeCredentialCacheEntry] = [:]
    private nonisolated(unsafe) static var lastSecurityCLIFailureAt: [String: Date] = [:]
    private static let isoFractional: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
    private static let isoBasic = ISO8601DateFormatter()

    private struct ClaudeCredentialCacheEntry {
        let credentials: ClaudeOAuthCredentials
        let resolvedAt: Date
        let source: String
    }

    #if DEBUG
    private nonisolated(unsafe) static var taskSecurityCLIReadOverride: (() -> [String: Any]?)?
    private nonisolated(unsafe) static var taskSecurityFrameworkReadOverride: ((Bool) -> [String: Any]?)?
    private nonisolated(unsafe) static var taskNowOverride: (() -> Date)?
    #endif

    static func refreshAccessTokenSilently(
        service: String = claudeCodeService,
        cacheAccount: String = cachedOAuthTokenAccount
    ) -> String? {
        guard let credentials = getOAuthCredentials(allowInteraction: false, service: service) else {
            return nil
        }
        cacheOAuthToken(credentials.accessToken, account: cacheAccount)
        return credentials.accessToken
    }

    /// Claude Code stores each non-default CLAUDE_CONFIG_DIR under
    /// "Claude Code-credentials-<sha256(dir) prefix>". Attribute-only query, so no ACL prompt.
    private static func hashedClaudeServiceSuffixes() -> Set<String> {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let items = result as? [[String: Any]] else {
            return []
        }
        let prefix = claudeCodeService + "-"
        return Set(items
            .compactMap { $0[kSecAttrService as String] as? String }
            .filter { $0.hasPrefix(prefix) && $0.dropFirst(prefix.count).range(of: "^[0-9a-f]{8}$", options: .regularExpression) != nil }
            .map { String($0.dropFirst(prefix.count)) })
    }

    static func secondaryClaudeCodeService() -> String? {
        secondaryClaudeConfigDir().map { claudeCodeService + "-" + configDirHash($0.path) }
    }

    /// First 8 hex chars of sha256(path), the suffix Claude Code puts on the credentials entry.
    static func configDirHash(_ path: String) -> String {
        SHA256.hash(data: Data(path.utf8)).prefix(4).map { String(format: "%02x", $0) }.joined()
    }

    /// Hidden "~/.claude*" directory (other than ~/.claude) with a matching keychain entry.
    /// UserDefaults "secondaryClaudeConfigDir" overrides; else the most recently used one wins
    /// (Claude Code rewrites <dir>/.claude.json every session), so stale logins lose.
    static func secondaryClaudeConfigDir(home: String = NSHomeDirectory()) -> URL? {
        let suffixes = hashedClaudeServiceSuffixes()
        guard !suffixes.isEmpty else { return nil }
        let homeURL = URL(fileURLWithPath: home, isDirectory: true)
        let names = (try? FileManager.default.contentsOfDirectory(atPath: home)) ?? []
        let candidates = names
            .filter { $0.hasPrefix(".claude") && $0 != ".claude" }
            .map { homeURL.appendingPathComponent($0, isDirectory: true) }
            .filter { url in
                var isDir: ObjCBool = false
                return FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir) && isDir.boolValue
                    && suffixes.contains(configDirHash(url.path))
            }
        if let override = UserDefaults.standard.string(forKey: "secondaryClaudeConfigDir") {
            let path = URL(fileURLWithPath: (override as NSString).expandingTildeInPath).path
            if let match = candidates.first(where: { $0.path == path }) { return match }
        }
        func lastUsed(_ url: URL) -> Date {
            let file = url.appendingPathComponent(".claude.json").path
            return ((try? FileManager.default.attributesOfItem(atPath: file))?[.modificationDate] as? Date) ?? .distantPast
        }
        return candidates.max { lastUsed($0) < lastUsed($1) }
    }

    /// "Perso" for "<email>'s Organization", "Pro" for any other organization name, nil if unknown.
    /// configDir nil = default account (~/.claude.json).
    static func claudeAccountLabel(configDir: URL?) -> String? {
        let file = configDir?.appendingPathComponent(".claude.json")
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".claude.json")
        guard let data = try? Data(contentsOf: file),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return claudeAccountLabel(organizationName: (json["oauthAccount"] as? [String: Any])?["organizationName"] as? String)
    }

    static func claudeAccountLabel(organizationName: String?) -> String? {
        guard let name = organizationName, !name.isEmpty else { return nil }
        return name.hasSuffix("'s Organization") ? String(localized: "Perso") : String(localized: "Pro")
    }

    static let primaryLabel = claudeAccountLabel(configDir: nil)
    static let secondaryLabel = claudeAccountLabel(configDir: secondaryClaudeConfigDir())

    // MARK: - Anthropic API Key

    static func getAnthropicApiKey(allowInteraction: Bool = false) -> String? {
        readString(
            service: notchiService,
            account: anthropicApiKeyAccount,
            allowInteraction: allowInteraction
        )
    }

    static func setAnthropicApiKey(_ key: String?) {
        if let key, !key.isEmpty {
            saveString(key, service: notchiService, account: anthropicApiKeyAccount)
        } else {
            deleteItem(service: notchiService, account: anthropicApiKeyAccount)
        }
    }

    static func getOpenAIApiKey(allowInteraction: Bool = false) -> String? {
        readString(
            service: notchiService,
            account: openAIApiKeyAccount,
            allowInteraction: allowInteraction
        )
    }

    static func setOpenAIApiKey(_ key: String?) {
        if let key, !key.isEmpty {
            saveString(key, service: notchiService, account: openAIApiKeyAccount)
        } else {
            deleteItem(service: notchiService, account: openAIApiKeyAccount)
        }
    }

    // MARK: - Cached OAuth Token

    static func getCachedOAuthToken(allowInteraction: Bool = false, account: String = cachedOAuthTokenAccount) -> String? {
        readString(
            service: notchiService,
            account: account,
            allowInteraction: allowInteraction
        )
    }

    static func cacheOAuthToken(_ token: String, account: String = cachedOAuthTokenAccount) {
        saveString(token, service: notchiService, account: account)
    }

    static func clearCachedOAuthToken(account: String = cachedOAuthTokenAccount) {
        deleteItem(service: notchiService, account: account)
    }

    // MARK: - Claude Code Credentials

    static func getOAuthCredentials(allowInteraction: Bool, service: String = claudeCodeService) -> ClaudeOAuthCredentials? {
        let now = currentDate()
        if let cached = recentCredentialCache(service: service, at: now) {
            return cached.credentials
        }

        // Primary: /usr/bin/security CLI (avoids ACL dialog)
        if shouldAttemptSecurityCLI(service: service, at: now) {
            if let json = readClaudeCodeKeychainViaCLI(service: service),
               let credentials = decodeClaudeOAuthCredentials(from: json) {
                cacheRecentCredential(credentials, service: service, source: "/usr/bin/security CLI", at: now)
                clearSecurityCLIBackoff(service: service)
                return credentials
            }
            recordSecurityCLIFailure(service: service, at: now)
        }

        // Fallback: Security.framework using the caller's interaction policy.
        guard let json = readClaudeCodeKeychain(allowInteraction: allowInteraction, service: service),
              let credentials = decodeClaudeOAuthCredentials(from: json) else {
            return nil
        }
        cacheRecentCredential(credentials, service: service, source: "Security.framework", at: now)
        return credentials
    }

    private static func readClaudeCodeKeychainViaCLI(service: String) -> [String: Any]? {
        #if DEBUG
        if let override = taskSecurityCLIReadOverride {
            return override()
        }
        #endif

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        process.arguments = ["find-generic-password", "-s", service, "-w"]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        let done = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in done.signal() }

        do {
            try process.run()
        } catch {
            return nil
        }

        if done.wait(timeout: .now() + .seconds(2)) == .timedOut {
            process.terminate()
            return nil
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard !data.isEmpty,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return json
    }

    private static func readClaudeCodeKeychain(allowInteraction: Bool, service: String) -> [String: Any]? {
        #if DEBUG
        if let override = taskSecurityFrameworkReadOverride {
            return override(allowInteraction)
        }
        #endif

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        if !allowInteraction {
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }

        return json
    }

    private static func recentCredentialCache(service: String, at now: Date) -> ClaudeCredentialCacheEntry? {
        credentialReadLock.lock()
        defer { credentialReadLock.unlock() }

        guard let entry = recentCredentialCacheEntries[service] else {
            return nil
        }

        guard now.timeIntervalSince(entry.resolvedAt) <= recentCredentialCacheTTL else {
            recentCredentialCacheEntries[service] = nil
            return nil
        }

        return entry
    }

    private static func cacheRecentCredential(_ credentials: ClaudeOAuthCredentials, service: String, source: String, at now: Date) {
        credentialReadLock.lock()
        recentCredentialCacheEntries[service] = ClaudeCredentialCacheEntry(
            credentials: credentials,
            resolvedAt: now,
            source: source
        )
        credentialReadLock.unlock()
    }

    private static func shouldAttemptSecurityCLI(service: String, at now: Date) -> Bool {
        credentialReadLock.lock()
        defer { credentialReadLock.unlock() }

        guard let lastFailure = lastSecurityCLIFailureAt[service] else {
            return true
        }

        if now.timeIntervalSince(lastFailure) >= securityCLIBackoffInterval {
            lastSecurityCLIFailureAt[service] = nil
            return true
        }

        return false
    }

    private static func recordSecurityCLIFailure(service: String, at now: Date) {
        credentialReadLock.lock()
        lastSecurityCLIFailureAt[service] = now
        credentialReadLock.unlock()
    }

    private static func clearSecurityCLIBackoff(service: String) {
        credentialReadLock.lock()
        lastSecurityCLIFailureAt[service] = nil
        credentialReadLock.unlock()
    }

    private static func currentDate() -> Date {
        #if DEBUG
        if let override = taskNowOverride {
            return override()
        }
        #endif
        return Date()
    }

    #if DEBUG
    static func _setSecurityCLIReadOverrideForTesting(_ override: (() -> [String: Any]?)?) {
        taskSecurityCLIReadOverride = override
    }

    static func _setSecurityFrameworkReadOverrideForTesting(_ override: ((Bool) -> [String: Any]?)?) {
        taskSecurityFrameworkReadOverride = override
    }

    static func _setNowOverrideForTesting(_ override: (() -> Date)?) {
        taskNowOverride = override
    }

    static func _resetCredentialResolutionStateForTesting() {
        credentialReadLock.lock()
        recentCredentialCacheEntries = [:]
        lastSecurityCLIFailureAt = [:]
        credentialReadLock.unlock()
        taskSecurityCLIReadOverride = nil
        taskSecurityFrameworkReadOverride = nil
        taskNowOverride = nil
    }
    #endif

    static func decodeClaudeOAuthCredentials(from data: Data) -> ClaudeOAuthCredentials? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return decodeClaudeOAuthCredentials(from: json)
    }

    static func decodeClaudeOAuthCredentials(from json: [String: Any]) -> ClaudeOAuthCredentials? {
        guard let oauth = json["claudeAiOauth"] as? [String: Any],
              let rawToken = oauth["accessToken"] as? String else {
            return nil
        }

        let accessToken = rawToken.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !accessToken.isEmpty else {
            return nil
        }

        return ClaudeOAuthCredentials(
            accessToken: accessToken,
            expiresAt: parseExpiresAt(from: oauth["expiresAt"] ?? oauth["expires_at"]),
            scopes: parseScopes(from: oauth["scopes"])
        )
    }

    private static func parseScopes(from rawValue: Any?) -> Set<String> {
        if let scopes = rawValue as? [String] {
            return Set(scopes.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty })
        }

        if let scopeString = rawValue as? String {
            let separators = CharacterSet(charactersIn: ", ")
            let scopes = scopeString
                .components(separatedBy: separators)
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            return Set(scopes)
        }

        return []
    }

    private static func parseExpiresAt(from rawValue: Any?) -> Date? {
        switch rawValue {
        case let date as Date:
            return date
        case let number as NSNumber:
            return parseEpoch(number.doubleValue)
        case let string as String:
            let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return nil }
            if let epoch = Double(trimmed) {
                return parseEpoch(epoch)
            }
            return isoFractional.date(from: trimmed) ?? isoBasic.date(from: trimmed)
        default:
            return nil
        }
    }

    private static func parseEpoch(_ value: Double) -> Date {
        let seconds = value > 1_000_000_000_000 ? value / 1000.0 : value
        return Date(timeIntervalSince1970: seconds)
    }

    // MARK: - Generic Keychain Helpers

    // Even own-service keychain items can trigger a Security dialog when the app's
    // code signature changes between Xcode rebuilds, invalidating prior "Always Allow".
    private static func readString(service: String, account: String, allowInteraction: Bool) -> String? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        if !allowInteraction {
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data,
              let string = String(data: data, encoding: .utf8) else {
            return nil
        }

        return string
    }

    private static func saveString(_ value: String, service: String, account: String) {
        let data = Data(value.utf8)

        // Try to update existing item first
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let update: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)

        if status == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecValueData as String] = data
            SecItemAdd(addQuery as CFDictionary, nil)
        }
    }

    private static func deleteItem(service: String, account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}
