// credmgr-presence — the macOS Secure Enclave and Touch ID helper (ADR-098).
//
// One JSON request on stdin, one JSON reply on stdout, then exit. It holds no state and no secret of its
// own: the Secure Enclave private keys never leave the chip. What it persists is only the opaque
// `dataRepresentation` blob CryptoKit hands back, which the caller stores; the blob is useless without
// this Mac's Secure Enclave AND, for these keys, a successful Touch ID / device-password prompt per use.
//
// Why a helper process and not FFI: the Rust workspace keeps `#![forbid(unsafe_code)]` everywhere, and
// CryptoKit's SecureEnclave types (the only way to keep a Secure Enclave key usable without a Developer
// ID team entitlement; the keychain route fails with -34018 unsigned) are Swift-only.
//
// Commands (all reply {"ok":true,...} or {"ok":false,"error":<code>,"detail":<text>}):
//   probe                                   -> secureEnclave, biometry, passcode
//   enroll   {purpose: "presence"|"wrap"}   -> blob, public   (no prompt; the key is created, not used)
//   sign     {blob, message, reason}        -> signature      (PROMPTS; ECDSA P-256, raw r||s, SHA-256)
//   ecdh     {blob, peer, reason}           -> secret         (PROMPTS; raw 32-byte shared secret)
//   ephemeral {peer}                        -> public, secret (no prompt; a throwaway P-256 key does ECDH against
//                                              `peer` and is dropped. The Rust side then needs no secret-scalar
//                                              arithmetic at all: only ECDSA *verification*, on public values.)
// Binary fields are base64. `public` and `peer` are the 65-byte ANSI X9.63 uncompressed point.
// Error codes: unavailable, cancelled, locked_out, failed, bad_request.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

func reply(_ o: [String: Any]) -> Never {
    let data = (try? JSONSerialization.data(withJSONObject: o, options: [.sortedKeys])) ?? Data("{\"ok\":false,\"error\":\"failed\"}".utf8)
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
    exit(0)
}

func fail(_ code: String, _ detail: String = "") -> Never {
    reply(["ok": false, "error": code, "detail": detail])
}

func b64(_ d: Data) -> String { d.base64EncodedString() }

func unb64(_ o: [String: Any], _ k: String) -> Data {
    guard let s = o[k] as? String, let d = Data(base64Encoded: s) else { fail("bad_request", "missing or malformed field \(k)") }
    return d
}

/// Map a LocalAuthentication / CryptoKit failure to a stable code the caller can act on.
func classify(_ error: Error) -> Never {
    let ns = error as NSError
    if ns.domain == LAError.errorDomain {
        switch LAError.Code(rawValue: ns.code) {
        case .userCancel, .appCancel, .systemCancel, .userFallback: fail("cancelled", ns.localizedDescription)
        case .biometryLockout: fail("locked_out", ns.localizedDescription)
        case .biometryNotAvailable, .biometryNotEnrolled, .passcodeNotSet: fail("unavailable", ns.localizedDescription)
        default: fail("failed", ns.localizedDescription)
        }
    }
    if ns.domain == NSOSStatusErrorDomain || ns.domain == "CryptoKit.CryptoKitError" {
        // errSecUserCanceled -128, errSecAuthFailed -25293
        if ns.code == -128 || ns.code == -25293 { fail("cancelled", ns.localizedDescription) }
    }
    fail("failed", "\(error)")
}

#if TESTNOAUTH
let variant = "credmgr-presence-variant:unattended-test"
#else
let variant = "credmgr-presence-variant:production"
#endif

func accessControl() -> SecAccessControl {
    var err: Unmanaged<CFError>?
    #if TESTNOAUTH
    // Test builds ONLY (build.sh --test-noauth writes a different binary, never packaged): no prompt, so
    // automated tests can exercise the real Secure Enclave without a human at the sensor.
    let flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    #else
    // .userPresence = Touch ID or, when no biometry is enrolled/available, the device password. Not
    // .biometryCurrentSet: re-enrolling a fingerprint must not destroy the wrapped root key.
    let flags: SecAccessControlCreateFlags = [.privateKeyUsage, .userPresence]
    #endif
    guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &err) else {
        fail("failed", "access control: \(String(describing: err?.takeRetainedValue()))")
    }
    return ac
}

func context(_ reason: String) -> LAContext {
    let c = LAContext()
    c.localizedReason = reason
    c.touchIDAuthenticationAllowableReuseDuration = 0   // every use prompts
    return c
}

// ---- main ----
let input = FileHandle.standardInput.readDataToEndOfFile()
guard let obj = (try? JSONSerialization.jsonObject(with: input)) as? [String: Any], let cmd = obj["cmd"] as? String else {
    fail("bad_request", "stdin must be one JSON object with a cmd")
}

switch cmd {
case "probe":
    let ctx = LAContext()
    var e: NSError?
    let bio = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &e)
    var kind = "none"
    if bio {
        switch ctx.biometryType {
        case .touchID: kind = "touchid"
        case .faceID: kind = "faceid"
        default: kind = "other"
        }
    }
    let owner = LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
    reply(["ok": true, "secureEnclave": SecureEnclave.isAvailable, "biometry": kind, "passcode": owner, "variant": variant])

case "enroll":
    guard SecureEnclave.isAvailable else { fail("unavailable", "this Mac has no Secure Enclave") }
    let ac = accessControl()
    do {
        switch obj["purpose"] as? String {
        case "presence":
            let k = try SecureEnclave.P256.Signing.PrivateKey(accessControl: ac)
            reply(["ok": true, "blob": b64(k.dataRepresentation), "public": b64(k.publicKey.x963Representation)])
        case "wrap":
            let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
            reply(["ok": true, "blob": b64(k.dataRepresentation), "public": b64(k.publicKey.x963Representation)])
        default:
            fail("bad_request", "purpose must be presence or wrap")
        }
    } catch { classify(error) }

case "sign":
    guard SecureEnclave.isAvailable else { fail("unavailable", "this Mac has no Secure Enclave") }
    let blob = unb64(obj, "blob"), message = unb64(obj, "message")
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context(obj["reason"] as? String ?? "Confirm it is you"))
        let sig = try key.signature(for: message)
        reply(["ok": true, "signature": b64(sig.rawRepresentation), "public": b64(key.publicKey.x963Representation)])
    } catch { classify(error) }

case "ecdh":
    guard SecureEnclave.isAvailable else { fail("unavailable", "this Mac has no Secure Enclave") }
    let blob = unb64(obj, "blob"), peer = unb64(obj, "peer")
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: context(obj["reason"] as? String ?? "Unlock CredMgr"))
        let pub = try P256.KeyAgreement.PublicKey(x963Representation: peer)
        let secret = try key.sharedSecretFromKeyAgreement(with: pub)
        reply(["ok": true, "secret": b64(secret.withUnsafeBytes { Data($0) })])
    } catch { classify(error) }

case "ephemeral":
    let peer = unb64(obj, "peer")
    do {
        let pub = try P256.KeyAgreement.PublicKey(x963Representation: peer)
        let eph = P256.KeyAgreement.PrivateKey()
        let secret = try eph.sharedSecretFromKeyAgreement(with: pub)
        reply(["ok": true, "public": b64(eph.publicKey.x963Representation), "secret": b64(secret.withUnsafeBytes { Data($0) })])
    } catch { classify(error) }

default:
    fail("bad_request", "unknown cmd \(cmd)")
}
