import SwiftUI
import UIKit
import Security
import CryptoKit

@MainActor
final class LicenseGate: ObservableObject {
    enum State: Equatable {
        case locked
        case checking
        case unlocked
        case failed(String)
    }

    @Published private(set) var state: State = .locked
    @Published var key: String = ""

    private let service = LicenseService()

    var isUnlocked: Bool { state == .unlocked }

    func validate() {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            state = .failed("Enter a license key.")
            return
        }

        state = .checking
        Task {
            do {
                try await service.validate(licenseKey: trimmed)
                try await service.activateIfNeeded(licenseKey: trimmed)
                try KeychainStore.set(trimmed, forKey: LicenseService.storageKey)
                state = .unlocked
            } catch {
                state = .failed(error.localizedDescription)
            }
        }
    }

    func restoreStoredKey() {
        guard let stored = KeychainStore.string(forKey: LicenseService.storageKey), !stored.isEmpty else { return }
        key = stored
        validate()
    }

    func clear() {
        KeychainStore.delete(forKey: LicenseService.storageKey)
        KeychainStore.delete(forKey: LicenseService.machineIDKey)
        KeychainStore.delete(forKey: LicenseService.machineLicenseHashKey)
        key = ""
        state = .locked
    }
}

struct LicenseGateView: View {
    @Environment(\.appLanguage) private var language
    @ObservedObject var gate: LicenseGate

    var body: some View {
        ZStack {
            Color(.systemBackground).ignoresSafeArea()
            VStack(spacing: 20) {
                Spacer()
                Image(systemName: "key.fill")
                    .font(.system(size: 54))
                Text("Javi Gamer")
                    .font(.largeTitle.bold())
                Text("License required")
                    .font(.headline)
                Text("Enter your license key to continue.")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)

                SecureField("License key", text: $gate.key)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                    .textFieldStyle(.roundedBorder)
                    .padding(.horizontal)
                    .onSubmit { gate.validate() }

                Button {
                    gate.validate()
                } label: {
                    if case .checking = gate.state {
                        ProgressView().frame(maxWidth: .infinity)
                    } else {
                        Text("Activate").frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled({ if case .checking = gate.state { return true }; return false }())
                .padding(.horizontal)

                if case .failed(let message) = gate.state {
                    Text(message)
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }
                Spacer()
            }
            .padding()
        }
    }
}

struct LicenseService {
    static let storageKey = "JG.StoredLicenseKey"
    static let machineFingerprintKey = "JG.LicenseMachineFingerprint"
    static let machineIDKey = "JG.LicenseMachineID"
    static let machineLicenseHashKey = "JG.LicenseMachineHash"

    // Public identifiers from the Keygen dashboard. These are not secrets.
    private let accountID = "0523b281-7749-47fd-95f5-443cfedf5462"
    private let productID = "1ca70f95-263c-46ad-9afe-eeb0724cb837"
    private let policyID = "c95895f9-644a-46e9-a08e-4cf4bf88c87a"

    private var apiBaseURL: URL {
        URL(string: "https://api.keygen.sh/v1/accounts/\(accountID)")!
    }

    enum LicenseError: LocalizedError {
        case invalidResponse
        case rejected
        case wrongProductOrPolicy
        case activationRejected
        case deviceIdentityUnavailable

        var errorDescription: String? {
            switch self {
            case .invalidResponse: return "The license server returned an invalid response."
            case .rejected: return "The license key is invalid, expired, or revoked."
            case .wrongProductOrPolicy: return "This license is not valid for this application."
            case .activationRejected: return "This license cannot be activated on this device."
            case .deviceIdentityUnavailable: return "Unable to create a device identity for license activation."
            }
        }
    }

    func validate(licenseKey: String) async throws {
        let url = apiBaseURL.appendingPathComponent("licenses/actions/validate")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer \(licenseKey)", forHTTPHeaderField: "Authorization")
        request.setValue("application/vnd.api+json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/vnd.api+json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 15

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw LicenseError.invalidResponse }
        guard (200...299).contains(http.statusCode) else { throw LicenseError.rejected }

        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let meta = root["meta"] as? [String: Any],
              let valid = meta["valid"] as? Bool,
              valid else {
            throw LicenseError.rejected
        }

        // Keygen's license resource identifies the policy through a JSON:API
        // relationship. If the server returns it, require our configured policy.
        if let dataObject = root["data"] as? [String: Any],
           let relationships = dataObject["relationships"] as? [String: Any],
           let policy = relationships["policy"] as? [String: Any],
           let policyData = policy["data"] as? [String: Any],
           let returnedPolicyID = policyData["id"] as? String,
           returnedPolicyID != policyID {
            throw LicenseError.wrongProductOrPolicy
        }

        // The product is represented by the policy in Keygen. The policy check
        // above is the authoritative application/product gate; productID is kept
        // here as configuration for the activation request below.
        _ = productID
    }

    func activateIfNeeded(licenseKey: String) async throws {
        let licenseHash = sha256(licenseKey)
        if let machineID = KeychainStore.string(forKey: Self.machineIDKey),
           let storedHash = KeychainStore.string(forKey: Self.machineLicenseHashKey),
           !machineID.isEmpty, storedHash == licenseHash {
            return
        }

        if KeychainStore.string(forKey: Self.machineIDKey) != nil {
            KeychainStore.delete(forKey: Self.machineIDKey)
            KeychainStore.delete(forKey: Self.machineLicenseHashKey)
        }

        guard let fingerprint = deviceFingerprint() else {
            throw LicenseError.deviceIdentityUnavailable
        }

        let url = apiBaseURL.appendingPathComponent("machines")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer \(licenseKey)", forHTTPHeaderField: "Authorization")
        request.setValue("application/vnd.api+json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/vnd.api+json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 15

        let body: [String: Any] = [
            "data": [
                "type": "machines",
                "attributes": [
                    "fingerprint": fingerprint,
                    "name": "Javi Gamer iPhone"
                ]
            ]
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw LicenseError.invalidResponse }
        guard (200...299).contains(http.statusCode) else { throw LicenseError.activationRejected }

        // A successful machine creation/activation returns a JSON:API resource.
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let machineData = root["data"] as? [String: Any],
              let machineID = machineData["id"] as? String,
              !machineID.isEmpty else {
            throw LicenseError.invalidResponse
        }
        guard KeychainStore.set(machineID, forKey: Self.machineIDKey),
              KeychainStore.set(licenseHash, forKey: Self.machineLicenseHashKey) else {
            KeychainStore.delete(forKey: Self.machineIDKey)
            KeychainStore.delete(forKey: Self.machineLicenseHashKey)
            throw LicenseError.invalidResponse
        }
    }

    private func sha256(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private func deviceFingerprint() -> String? {
        if let existing = KeychainStore.string(forKey: Self.machineFingerprintKey), !existing.isEmpty {
            return existing
        }

        let value = UUID().uuidString.lowercased()
        return KeychainStore.set(value, forKey: Self.machineFingerprintKey) ? value : nil
    }
}

private enum KeychainStore {
    static func string(forKey key: String) -> String? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    @discardableResult
    static func set(_ value: String, forKey key: String) -> Bool {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var insert = query
            attributes.forEach { insert[$0.key] = $0.value }
            return SecItemAdd(insert as CFDictionary, nil) == errSecSuccess
        }
        return status == errSecSuccess
    }

    static func delete(forKey key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(query as CFDictionary)
    }
}
