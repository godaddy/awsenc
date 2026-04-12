#![allow(unsafe_code)]

use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFRelease, CFTypeRef as CFTypeRefSys, OSStatus};
use core_foundation_sys::string::CFStringRef;
use security_framework::key::SecKey;
use tracing::{debug, warn};

use crate::{Result, SecureStorage, StorageError};

/// Application tag used to identify our key in the Keychain.
const APPLICATION_TAG: &[u8] = b"com.awsenc.storage";

/// Key size in bits for EC P-256.
const KEY_SIZE_BITS: i32 = 256;

// ---------------------------------------------------------------------------
// External Security.framework symbols
// ---------------------------------------------------------------------------

extern "C" {
    // Key creation / query
    static kSecClass: CFStringRef;
    static kSecClassKey: CFStringRef;
    static kSecAttrKeyType: CFStringRef;
    static kSecAttrKeyTypeECSECPrimeRandom: CFStringRef;
    static kSecAttrKeySizeInBits: CFStringRef;
    static kSecAttrTokenID: CFStringRef;
    static kSecAttrTokenIDSecureEnclave: CFStringRef;
    static kSecAttrApplicationTag: CFStringRef;
    static kSecAttrIsPermanent: CFStringRef;
    static kSecPrivateKeyAttrs: CFStringRef;
    static kSecReturnRef: CFStringRef;
    static kSecMatchLimit: CFStringRef;
    static kSecMatchLimitOne: CFStringRef;
    static kSecAttrAccessControl: CFStringRef;

    // Encryption algorithm
    static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM: CFStringRef;

    fn SecKeyCreateRandomKey(
        parameters: core_foundation_sys::dictionary::CFDictionaryRef,
        error: *mut core_foundation_sys::base::CFTypeRef,
    ) -> core_foundation_sys::base::CFTypeRef;

    fn SecKeyCreateEncryptedData(
        key: core_foundation_sys::base::CFTypeRef,
        algorithm: CFStringRef,
        plaintext: core_foundation_sys::data::CFDataRef,
        error: *mut core_foundation_sys::base::CFTypeRef,
    ) -> core_foundation_sys::data::CFDataRef;

    fn SecKeyCreateDecryptedData(
        key: core_foundation_sys::base::CFTypeRef,
        algorithm: CFStringRef,
        ciphertext: core_foundation_sys::data::CFDataRef,
        error: *mut core_foundation_sys::base::CFTypeRef,
    ) -> core_foundation_sys::data::CFDataRef;

    fn SecKeyCopyPublicKey(
        key: core_foundation_sys::base::CFTypeRef,
    ) -> core_foundation_sys::base::CFTypeRef;

    fn SecItemCopyMatching(
        query: core_foundation_sys::dictionary::CFDictionaryRef,
        result: *mut CFTypeRefSys,
    ) -> OSStatus;

    fn SecAccessControlCreateWithFlags(
        allocator: core_foundation_sys::base::CFAllocatorRef,
        protection: CFTypeRefSys,
        flags: u64,
        error: *mut core_foundation_sys::base::CFTypeRef,
    ) -> core_foundation_sys::base::CFTypeRef;

    static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFStringRef;
}

/// Access control flags for `SecAccessControlCreateWithFlags`.
const K_SEC_ACCESS_CONTROL_PRIVATE_KEY_USAGE: u64 = 1 << 30;
const K_SEC_ACCESS_CONTROL_BIOMETRY_ANY: u64 = 1 << 1;

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

/// Convert a `CFTypeRef` returned from Security.framework into a `SecKey`,
/// taking ownership of the reference.
fn cftype_to_sec_key(cf_ref: CFTypeRefSys) -> Option<SecKey> {
    if cf_ref.is_null() {
        return None;
    }
    // Safety: Security.framework returned a SecKeyRef which is a CFTypeRef.
    // `SecKey::wrap_under_create_rule` takes ownership (balances the +1 from the API).
    Some(unsafe {
        SecKey::wrap_under_create_rule(
            cf_ref
                .cast::<security_framework_sys::base::OpaqueSecKeyRef>()
                .cast_mut(),
        )
    })
}

/// Extract a human-readable error message from a `CFError` reference.
fn cf_error_message(err_ref: CFTypeRefSys) -> String {
    if err_ref.is_null() {
        return "unknown error".into();
    }
    // Safety: err_ref is a valid CFErrorRef returned by Security.framework.
    let cf_type: CFType = unsafe { TCFType::wrap_under_create_rule(err_ref) };
    format!("{cf_type:?}")
}

// ---------------------------------------------------------------------------
// Secure Enclave availability check
// ---------------------------------------------------------------------------

/// Returns `true` if the Secure Enclave is available on this Mac.
///
/// The Secure Enclave is present on:
/// - All Apple Silicon Macs (M1 and later)
/// - Touch Bar `MacBook` Pro models (2016-2020, T1/T2 chip)
/// - iMac Pro (T2 chip)
/// - Mac mini/Mac Pro 2018+ (T2 chip)
///
/// We test availability by attempting to create an ephemeral Secure Enclave key.
fn is_secure_enclave_available() -> bool {
    let tag = CFData::from_buffer(b"com.awsenc.probe");
    let key_size = CFNumber::from(KEY_SIZE_BITS);

    let private_key_attrs = CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrIsPermanent) },
            CFBoolean::false_value().as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrApplicationTag) },
            tag.as_CFType(),
        ),
    ]);

    let params = CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyType) },
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom) }.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeySizeInBits) },
            key_size.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrTokenID) },
            unsafe { CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave) }.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecPrivateKeyAttrs) },
            private_key_attrs.as_CFType(),
        ),
    ]);

    let mut error: CFTypeRefSys = std::ptr::null_mut();
    let key_ref = unsafe { SecKeyCreateRandomKey(params.as_concrete_TypeRef(), &mut error) };

    if key_ref.is_null() {
        if !error.is_null() {
            unsafe { CFRelease(error) };
        }
        debug!("Secure Enclave not available on this system");
        return false;
    }
    unsafe { CFRelease(key_ref) };
    true
}

// ---------------------------------------------------------------------------
// MacosSecureEnclaveStorage
// ---------------------------------------------------------------------------

/// macOS Secure Enclave-backed storage using ECIES encryption.
///
/// The private key lives in the Secure Enclave and never leaves it.
/// Encryption uses the public key (no hardware call required).
/// Decryption requires the Secure Enclave to unwrap data with the private key.
#[derive(Debug)]
pub struct MacosSecureEnclaveStorage {
    private_key: SecKey,
    public_key: SecKey,
    biometric: bool,
}

// Safety: `SecKey` handles are thread-safe. The Secure Enclave serializes
// hardware access internally.
unsafe impl Send for MacosSecureEnclaveStorage {}
unsafe impl Sync for MacosSecureEnclaveStorage {}

impl MacosSecureEnclaveStorage {
    /// Create a new Secure Enclave storage, loading or generating the key pair.
    pub fn new(biometric: bool) -> Result<Self> {
        if !is_secure_enclave_available() {
            return Err(StorageError::NotAvailable);
        }

        let private_key = find_existing_key()
            .or_else(|| {
                debug!("no existing Secure Enclave key found, generating new key pair");
                generate_key(biometric).ok()
            })
            .ok_or_else(|| {
                StorageError::KeyInitFailed("failed to load or generate Secure Enclave key".into())
            })?;

        let pub_ref = unsafe { SecKeyCopyPublicKey(private_key.as_CFTypeRef()) };
        let public_key = cftype_to_sec_key(pub_ref).ok_or_else(|| {
            StorageError::KeyInitFailed(
                "failed to derive public key from Secure Enclave key".into(),
            )
        })?;

        debug!("Secure Enclave key pair ready (biometric={})", biometric);

        Ok(Self {
            private_key,
            public_key,
            biometric,
        })
    }
}

impl SecureStorage for MacosSecureEnclaveStorage {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cf_plaintext = CFData::from_buffer(plaintext);
        let mut error: CFTypeRefSys = std::ptr::null_mut();

        let cf_ciphertext = unsafe {
            SecKeyCreateEncryptedData(
                self.public_key.as_CFTypeRef(),
                kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
                cf_plaintext.as_concrete_TypeRef(),
                &mut error,
            )
        };

        if cf_ciphertext.is_null() {
            let msg = cf_error_message(error);
            return Err(StorageError::EncryptionFailed(msg));
        }

        // Safety: `SecKeyCreateEncryptedData` returned a +1 CFDataRef.
        let result = unsafe { CFData::wrap_under_create_rule(cf_ciphertext) };
        Ok(result.bytes().to_vec())
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cf_ciphertext = CFData::from_buffer(ciphertext);
        let mut error: CFTypeRefSys = std::ptr::null_mut();

        let cf_plaintext = unsafe {
            SecKeyCreateDecryptedData(
                self.private_key.as_CFTypeRef(),
                kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
                cf_ciphertext.as_concrete_TypeRef(),
                &mut error,
            )
        };

        if cf_plaintext.is_null() {
            let msg = cf_error_message(error);
            return Err(StorageError::DecryptionFailed(msg));
        }

        // Safety: `SecKeyCreateDecryptedData` returned a +1 CFDataRef.
        let result = unsafe { CFData::wrap_under_create_rule(cf_plaintext) };
        Ok(result.bytes().to_vec())
    }

    fn is_available(&self) -> bool {
        is_secure_enclave_available()
    }

    fn backend_name(&self) -> &'static str {
        if self.biometric {
            "Secure Enclave (biometric)"
        } else {
            "Secure Enclave"
        }
    }
}

// ---------------------------------------------------------------------------
// Key management helpers
// ---------------------------------------------------------------------------

/// Search the Keychain for an existing Secure Enclave key with our application tag.
fn find_existing_key() -> Option<SecKey> {
    let tag = CFData::from_buffer(APPLICATION_TAG);

    let query = CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassKey) }.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyType) },
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom) }.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrApplicationTag) },
            tag.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrTokenID) },
            unsafe { CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave) }.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecReturnRef) },
            CFBoolean::true_value().as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecMatchLimit) },
            unsafe { CFString::wrap_under_get_rule(kSecMatchLimitOne) }.as_CFType(),
        ),
    ]);

    let mut result: CFTypeRefSys = std::ptr::null_mut();
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };

    if status == 0 && !result.is_null() {
        debug!("found existing Secure Enclave key in Keychain");
        cftype_to_sec_key(result)
    } else {
        if !result.is_null() {
            unsafe { CFRelease(result) };
        }
        None
    }
}

/// Generate a new EC P-256 key pair in the Secure Enclave and persist it in the Keychain.
fn generate_key(biometric: bool) -> Result<SecKey> {
    let tag = CFData::from_buffer(APPLICATION_TAG);
    let key_size = CFNumber::from(KEY_SIZE_BITS);

    // Build access control
    let access_control = create_access_control(biometric)?;

    let mut private_attrs_pairs: Vec<(CFString, CFType)> = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrIsPermanent) },
            CFBoolean::true_value().as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrApplicationTag) },
            tag.as_CFType(),
        ),
    ];

    if !access_control.is_null() {
        private_attrs_pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) },
            // Safety: access_control is a valid SecAccessControlRef, which is a CFTypeRef.
            unsafe { CFType::wrap_under_get_rule(access_control) },
        ));
    }

    let private_key_attrs = CFDictionary::from_CFType_pairs(&private_attrs_pairs);

    let params = CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyType) },
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom) }.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeySizeInBits) },
            key_size.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrTokenID) },
            unsafe { CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave) }.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecPrivateKeyAttrs) },
            private_key_attrs.as_CFType(),
        ),
    ]);

    let mut error: CFTypeRefSys = std::ptr::null_mut();
    let key_ref = unsafe { SecKeyCreateRandomKey(params.as_concrete_TypeRef(), &mut error) };

    if key_ref.is_null() {
        let msg = cf_error_message(error);
        warn!("Secure Enclave key generation failed: {}", msg);
        return Err(StorageError::KeyInitFailed(msg));
    }

    // Clean up access_control if we created one (it was wrapped under get rule above,
    // so the CFDictionary owns a reference; we also need to release our +1).
    if !access_control.is_null() {
        unsafe { CFRelease(access_control) };
    }

    cftype_to_sec_key(key_ref)
        .ok_or_else(|| StorageError::KeyInitFailed("key ref was unexpectedly null".into()))
}

/// Create a `SecAccessControl` for the Secure Enclave key.
///
/// If `biometric` is true, the key will require biometric authentication (Touch ID / Face ID)
/// for private key operations (decryption).
fn create_access_control(biometric: bool) -> Result<CFTypeRefSys> {
    let mut flags = K_SEC_ACCESS_CONTROL_PRIVATE_KEY_USAGE;
    if biometric {
        flags |= K_SEC_ACCESS_CONTROL_BIOMETRY_ANY;
    }

    let mut error: CFTypeRefSys = std::ptr::null_mut();
    let access_control = unsafe {
        SecAccessControlCreateWithFlags(
            std::ptr::null(),
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                .cast::<std::ffi::c_void>()
                .cast_mut(),
            flags,
            &mut error,
        )
    };

    if access_control.is_null() {
        let msg = cf_error_message(error);
        return Err(StorageError::KeyInitFailed(format!(
            "failed to create access control: {msg}"
        )));
    }

    Ok(access_control)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::print_stdout)]

    use super::*;

    #[test]
    fn secure_enclave_availability_check() {
        // This test just verifies the availability check doesn't panic.
        // It may return true or false depending on the hardware.
        let available = is_secure_enclave_available();
        println!("Secure Enclave available: {available}");
    }

    #[test]
    fn find_existing_key_does_not_panic() {
        // Searching for a key that may or may not exist should not panic.
        let _key = find_existing_key();
    }

    // Integration tests that require actual Secure Enclave hardware
    // are gated behind the AWSENC_TEST_SECURE_ENCLAVE environment variable.
    #[test]
    fn encrypt_decrypt_roundtrip_if_hardware_available() {
        if std::env::var("AWSENC_TEST_SECURE_ENCLAVE").is_err() {
            println!("skipping: set AWSENC_TEST_SECURE_ENCLAVE=1 to run hardware tests");
            return;
        }

        let storage = MacosSecureEnclaveStorage::new(false)
            .expect("Secure Enclave should be available for this test");

        let plaintext = b"test credential data for Secure Enclave";
        let ciphertext = storage.encrypt(plaintext).expect("encryption failed");
        assert_ne!(&ciphertext[..], plaintext);

        let decrypted = storage.decrypt(&ciphertext).expect("decryption failed");
        assert_eq!(&decrypted[..], plaintext);
    }
}
