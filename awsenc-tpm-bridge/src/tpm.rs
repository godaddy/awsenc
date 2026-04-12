/// TPM 2.0 storage operations via Windows CNG/NCrypt.
///
/// On Windows, this uses the Microsoft Platform Crypto Provider to create
/// a TPM-backed ECDH P-256 key and performs ECIES encryption (ephemeral
/// ECDH key agreement + AES-256-GCM).
///
/// On non-Windows platforms, all operations return an error at runtime.

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
mod platform {
    use std::ptr;

    // NCrypt / BCrypt constants
    const MS_PLATFORM_CRYPTO_PROVIDER: &str = "Microsoft Platform Crypto Provider";
    const BCRYPT_ECDH_P256_ALGORITHM: &str = "ECDH_P256";
    const BCRYPT_AES_ALGORITHM: &str = "AES";
    const BCRYPT_SHA256_ALGORITHM: &str = "SHA256";
    const BCRYPT_CHAIN_MODE_GCM: &str = "ChainingModeGCM";
    const NCRYPT_LENGTH_PROPERTY: &str = "Length";
    const NCRYPT_EXPORT_POLICY_PROPERTY: &str = "Export Policy";
    const KEY_NAME: &str = "awsenc-tpm-key";

    // NCrypt flags
    const NCRYPT_OVERWRITE_KEY_FLAG: u32 = 0x0000_0080;
    const NCRYPT_MACHINE_KEY_FLAG: u32 = 0x0000_0020;
    const BCRYPT_PAD_NONE: u32 = 0x0000_0001;

    // GCM nonce and tag sizes
    const GCM_NONCE_SIZE: usize = 12;
    const GCM_TAG_SIZE: usize = 16;

    type NTSTATUS = i32;
    type NCRYPT_PROV_HANDLE = usize;
    type NCRYPT_KEY_HANDLE = usize;
    type BCRYPT_ALG_HANDLE = usize;
    type BCRYPT_KEY_HANDLE = usize;
    type BCRYPT_SECRET_HANDLE = usize;

    #[repr(C)]
    struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        cb_size: u32,
        dw_info_version: u32,
        pb_nonce: *mut u8,
        cb_nonce: u32,
        pb_auth_data: *mut u8,
        cb_auth_data: u32,
        pb_tag: *mut u8,
        cb_tag: u32,
        pb_mac_context: *mut u8,
        cb_mac_context: u32,
        cb_aad: u32,
        cb_data: u64,
        dw_flags: u32,
    }

    const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION: u32 = 1;

    extern "system" {
        // NCrypt functions
        fn NCryptOpenStorageProvider(
            ph_provider: *mut NCRYPT_PROV_HANDLE,
            psz_provider_name: *const u16,
            dw_flags: u32,
        ) -> NTSTATUS;

        fn NCryptCreatePersistedKey(
            h_provider: NCRYPT_PROV_HANDLE,
            ph_key: *mut NCRYPT_KEY_HANDLE,
            psz_alg_id: *const u16,
            psz_key_name: *const u16,
            dw_legacy_key_spec: u32,
            dw_flags: u32,
        ) -> NTSTATUS;

        fn NCryptOpenKey(
            h_provider: NCRYPT_PROV_HANDLE,
            ph_key: *mut NCRYPT_KEY_HANDLE,
            psz_key_name: *const u16,
            dw_legacy_key_spec: u32,
            dw_flags: u32,
        ) -> NTSTATUS;

        fn NCryptFinalizeKey(h_key: NCRYPT_KEY_HANDLE, dw_flags: u32) -> NTSTATUS;

        fn NCryptExportKey(
            h_key: NCRYPT_KEY_HANDLE,
            h_export_key: NCRYPT_KEY_HANDLE,
            psz_blob_type: *const u16,
            p_parameter_list: *const u8,
            pb_output: *mut u8,
            cb_output: u32,
            pcb_result: *mut u32,
            dw_flags: u32,
        ) -> NTSTATUS;

        fn NCryptFreeObject(h_object: usize) -> NTSTATUS;

        fn NCryptSetProperty(
            h_object: usize,
            psz_property: *const u16,
            pb_input: *const u8,
            cb_input: u32,
            dw_flags: u32,
        ) -> NTSTATUS;

        // BCrypt functions
        fn BCryptOpenAlgorithmProvider(
            ph_algorithm: *mut BCRYPT_ALG_HANDLE,
            psz_alg_id: *const u16,
            psz_implementation: *const u16,
            dw_flags: u32,
        ) -> NTSTATUS;

        fn BCryptCloseAlgorithmProvider(h_algorithm: BCRYPT_ALG_HANDLE, dw_flags: u32) -> NTSTATUS;

        fn BCryptGenerateKeyPair(
            h_algorithm: BCRYPT_ALG_HANDLE,
            ph_key: *mut BCRYPT_KEY_HANDLE,
            dw_length: u32,
            dw_flags: u32,
        ) -> NTSTATUS;

        fn BCryptFinalizeKeyPair(h_key: BCRYPT_KEY_HANDLE, dw_flags: u32) -> NTSTATUS;

        fn BCryptExportKey(
            h_key: BCRYPT_KEY_HANDLE,
            h_export_key: BCRYPT_KEY_HANDLE,
            psz_blob_type: *const u16,
            pb_output: *mut u8,
            cb_output: u32,
            pcb_result: *mut u32,
            dw_flags: u32,
        ) -> NTSTATUS;

        fn BCryptImportKeyPair(
            h_algorithm: BCRYPT_ALG_HANDLE,
            h_import_key: BCRYPT_KEY_HANDLE,
            psz_blob_type: *const u16,
            ph_key: *mut BCRYPT_KEY_HANDLE,
            pb_input: *const u8,
            cb_input: u32,
            dw_flags: u32,
        ) -> NTSTATUS;

        fn BCryptSecretAgreement(
            h_priv_key: usize, // can be NCRYPT_KEY_HANDLE or BCRYPT_KEY_HANDLE
            h_pub_key: BCRYPT_KEY_HANDLE,
            ph_agreed_secret: *mut BCRYPT_SECRET_HANDLE,
            dw_flags: u32,
        ) -> NTSTATUS;

        fn BCryptDeriveKey(
            h_shared_secret: BCRYPT_SECRET_HANDLE,
            psz_kdf: *const u16,
            p_parameter_list: *const u8,
            pb_derived_key: *mut u8,
            cb_derived_key: u32,
            pcb_result: *mut u32,
            dw_flags: u32,
        ) -> NTSTATUS;

        fn BCryptDestroySecret(h_secret: BCRYPT_SECRET_HANDLE) -> NTSTATUS;

        fn BCryptDestroyKey(h_key: BCRYPT_KEY_HANDLE) -> NTSTATUS;

        fn BCryptGenerateSymmetricKey(
            h_algorithm: BCRYPT_ALG_HANDLE,
            ph_key: *mut BCRYPT_KEY_HANDLE,
            pb_key_object: *mut u8,
            cb_key_object: u32,
            pb_secret: *const u8,
            cb_secret: u32,
            dw_flags: u32,
        ) -> NTSTATUS;

        fn BCryptEncrypt(
            h_key: BCRYPT_KEY_HANDLE,
            pb_input: *const u8,
            cb_input: u32,
            p_padding_info: *const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
            pb_iv: *mut u8,
            cb_iv: u32,
            pb_output: *mut u8,
            cb_output: u32,
            pcb_result: *mut u32,
            dw_flags: u32,
        ) -> NTSTATUS;

        fn BCryptDecrypt(
            h_key: BCRYPT_KEY_HANDLE,
            pb_input: *const u8,
            cb_input: u32,
            p_padding_info: *const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
            pb_iv: *mut u8,
            cb_iv: u32,
            pb_output: *mut u8,
            cb_output: u32,
            pcb_result: *mut u32,
            dw_flags: u32,
        ) -> NTSTATUS;

        fn BCryptGenRandom(
            h_algorithm: BCRYPT_ALG_HANDLE,
            pb_buffer: *mut u8,
            cb_buffer: u32,
            dw_flags: u32,
        ) -> NTSTATUS;

        fn BCryptSetProperty(
            h_object: usize,
            psz_property: *const u16,
            pb_input: *const u8,
            cb_input: u32,
            dw_flags: u32,
        ) -> NTSTATUS;
    }

    // BCRYPT_USE_SYSTEM_PREFERRED_RNG
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn check_status(status: NTSTATUS, context: &str) -> Result<(), String> {
        if status >= 0 {
            Ok(())
        } else {
            Err(format!("{context}: NTSTATUS 0x{status:08X}"))
        }
    }

    pub struct TpmStorage {
        provider: NCRYPT_PROV_HANDLE,
        key: NCRYPT_KEY_HANDLE,
        biometric: bool,
    }

    impl TpmStorage {
        pub fn new(biometric: bool) -> Result<Self, String> {
            let provider_name = to_wide(MS_PLATFORM_CRYPTO_PROVIDER);
            let key_name = to_wide(KEY_NAME);
            let alg = to_wide(BCRYPT_ECDH_P256_ALGORITHM);

            let mut provider: NCRYPT_PROV_HANDLE = 0;
            let mut key: NCRYPT_KEY_HANDLE = 0;

            unsafe {
                check_status(
                    NCryptOpenStorageProvider(&mut provider, provider_name.as_ptr(), 0),
                    "NCryptOpenStorageProvider",
                )?;

                // Try to open existing key first
                let open_result = NCryptOpenKey(provider, &mut key, key_name.as_ptr(), 0, 0);

                if open_result < 0 {
                    // Key doesn't exist, create a new one
                    check_status(
                        NCryptCreatePersistedKey(
                            provider,
                            &mut key,
                            alg.as_ptr(),
                            key_name.as_ptr(),
                            0,
                            NCRYPT_OVERWRITE_KEY_FLAG,
                        ),
                        "NCryptCreatePersistedKey",
                    )?;

                    // Make the key non-exportable
                    let export_policy: u32 = 0; // not exportable
                    let export_prop = to_wide(NCRYPT_EXPORT_POLICY_PROPERTY);
                    let _ = NCryptSetProperty(
                        key,
                        export_prop.as_ptr(),
                        &export_policy as *const u32 as *const u8,
                        4,
                        0,
                    );

                    check_status(NCryptFinalizeKey(key, 0), "NCryptFinalizeKey")?;
                }
            }

            Ok(Self {
                provider,
                key,
                biometric,
            })
        }

        /// ECIES encrypt: generate ephemeral ECDH keypair, derive shared secret
        /// with the TPM-backed key, then AES-256-GCM encrypt the plaintext.
        ///
        /// Output format: [ephemeral_pub_key_blob_len (4 bytes LE)] [ephemeral_pub_key_blob] [nonce (12 bytes)] [tag (16 bytes)] [ciphertext]
        pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
            unsafe {
                // 1. Get the TPM key's public key blob
                let eccpub_blob_type = to_wide("ECCPUBLICBLOB");
                let mut pub_blob_size: u32 = 0;
                check_status(
                    NCryptExportKey(
                        self.key,
                        0,
                        eccpub_blob_type.as_ptr(),
                        ptr::null(),
                        ptr::null_mut(),
                        0,
                        &mut pub_blob_size,
                        0,
                    ),
                    "NCryptExportKey (size)",
                )?;

                let mut pub_blob = vec![0u8; pub_blob_size as usize];
                check_status(
                    NCryptExportKey(
                        self.key,
                        0,
                        eccpub_blob_type.as_ptr(),
                        ptr::null(),
                        pub_blob.as_mut_ptr(),
                        pub_blob_size,
                        &mut pub_blob_size,
                        0,
                    ),
                    "NCryptExportKey",
                )?;

                // 2. Open BCrypt ECDH provider and generate ephemeral keypair
                let ecdh_alg_name = to_wide(BCRYPT_ECDH_P256_ALGORITHM);
                let mut ecdh_alg: BCRYPT_ALG_HANDLE = 0;
                check_status(
                    BCryptOpenAlgorithmProvider(
                        &mut ecdh_alg,
                        ecdh_alg_name.as_ptr(),
                        ptr::null(),
                        0,
                    ),
                    "BCryptOpenAlgorithmProvider(ECDH)",
                )?;

                let mut ephemeral_key: BCRYPT_KEY_HANDLE = 0;
                check_status(
                    BCryptGenerateKeyPair(ecdh_alg, &mut ephemeral_key, 256, 0),
                    "BCryptGenerateKeyPair",
                )?;
                check_status(
                    BCryptFinalizeKeyPair(ephemeral_key, 0),
                    "BCryptFinalizeKeyPair",
                )?;

                // 3. Export ephemeral public key
                let mut eph_pub_size: u32 = 0;
                check_status(
                    BCryptExportKey(
                        ephemeral_key,
                        0,
                        eccpub_blob_type.as_ptr(),
                        ptr::null_mut(),
                        0,
                        &mut eph_pub_size,
                        0,
                    ),
                    "BCryptExportKey ephemeral (size)",
                )?;

                let mut eph_pub_blob = vec![0u8; eph_pub_size as usize];
                check_status(
                    BCryptExportKey(
                        ephemeral_key,
                        0,
                        eccpub_blob_type.as_ptr(),
                        eph_pub_blob.as_mut_ptr(),
                        eph_pub_size,
                        &mut eph_pub_size,
                        0,
                    ),
                    "BCryptExportKey ephemeral",
                )?;

                // 4. Import the TPM public key into BCrypt for the agreement
                let mut tpm_pub_key: BCRYPT_KEY_HANDLE = 0;
                check_status(
                    BCryptImportKeyPair(
                        ecdh_alg,
                        0,
                        eccpub_blob_type.as_ptr(),
                        &mut tpm_pub_key,
                        pub_blob.as_ptr(),
                        pub_blob_size,
                        0,
                    ),
                    "BCryptImportKeyPair(tpm pub)",
                )?;

                // 5. Derive shared secret: ephemeral private + TPM public
                let mut secret: BCRYPT_SECRET_HANDLE = 0;
                check_status(
                    BCryptSecretAgreement(ephemeral_key, tpm_pub_key, &mut secret, 0),
                    "BCryptSecretAgreement",
                )?;

                // 6. Derive 32-byte AES key from shared secret via SHA-256 KDF
                let kdf_name = to_wide("HASH");
                let mut derived_key = vec![0u8; 32];
                let mut derived_len: u32 = 0;
                check_status(
                    BCryptDeriveKey(
                        secret,
                        kdf_name.as_ptr(),
                        ptr::null(),
                        derived_key.as_mut_ptr(),
                        32,
                        &mut derived_len,
                        0,
                    ),
                    "BCryptDeriveKey",
                )?;
                derived_key.truncate(derived_len as usize);

                // Cleanup ECDH handles
                BCryptDestroySecret(secret);
                BCryptDestroyKey(tpm_pub_key);
                BCryptDestroyKey(ephemeral_key);
                BCryptCloseAlgorithmProvider(ecdh_alg, 0);

                // 7. AES-256-GCM encrypt
                let aes_alg_name = to_wide(BCRYPT_AES_ALGORITHM);
                let mut aes_alg: BCRYPT_ALG_HANDLE = 0;
                check_status(
                    BCryptOpenAlgorithmProvider(
                        &mut aes_alg,
                        aes_alg_name.as_ptr(),
                        ptr::null(),
                        0,
                    ),
                    "BCryptOpenAlgorithmProvider(AES)",
                )?;

                let chain_mode = to_wide("ChainingMode");
                let gcm_mode = to_wide(BCRYPT_CHAIN_MODE_GCM);
                check_status(
                    BCryptSetProperty(
                        aes_alg,
                        chain_mode.as_ptr(),
                        gcm_mode.as_ptr() as *const u8,
                        (gcm_mode.len() * 2) as u32,
                        0,
                    ),
                    "BCryptSetProperty(GCM)",
                )?;

                let mut aes_key: BCRYPT_KEY_HANDLE = 0;
                check_status(
                    BCryptGenerateSymmetricKey(
                        aes_alg,
                        &mut aes_key,
                        ptr::null_mut(),
                        0,
                        derived_key.as_ptr(),
                        derived_key.len() as u32,
                        0,
                    ),
                    "BCryptGenerateSymmetricKey",
                )?;

                // Generate random nonce
                let mut nonce = [0u8; GCM_NONCE_SIZE];
                check_status(
                    BCryptGenRandom(
                        0,
                        nonce.as_mut_ptr(),
                        GCM_NONCE_SIZE as u32,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                    ),
                    "BCryptGenRandom",
                )?;

                let mut tag = [0u8; GCM_TAG_SIZE];
                let mut auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                    cb_size: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                    dw_info_version: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
                    pb_nonce: nonce.as_mut_ptr(),
                    cb_nonce: GCM_NONCE_SIZE as u32,
                    pb_auth_data: ptr::null_mut(),
                    cb_auth_data: 0,
                    pb_tag: tag.as_mut_ptr(),
                    cb_tag: GCM_TAG_SIZE as u32,
                    pb_mac_context: ptr::null_mut(),
                    cb_mac_context: 0,
                    cb_aad: 0,
                    cb_data: 0,
                    dw_flags: 0,
                };

                let mut ciphertext = vec![0u8; plaintext.len()];
                let mut ct_len: u32 = 0;
                check_status(
                    BCryptEncrypt(
                        aes_key,
                        plaintext.as_ptr(),
                        plaintext.len() as u32,
                        &auth_info,
                        ptr::null_mut(),
                        0,
                        ciphertext.as_mut_ptr(),
                        ciphertext.len() as u32,
                        &mut ct_len,
                        0,
                    ),
                    "BCryptEncrypt(AES-GCM)",
                )?;
                ciphertext.truncate(ct_len as usize);

                BCryptDestroyKey(aes_key);
                BCryptCloseAlgorithmProvider(aes_alg, 0);

                // 8. Build output: [eph_pub_len (4 LE)] [eph_pub] [nonce] [tag] [ciphertext]
                let eph_len_bytes = (eph_pub_blob.len() as u32).to_le_bytes();
                let mut output = Vec::with_capacity(
                    4 + eph_pub_blob.len() + GCM_NONCE_SIZE + GCM_TAG_SIZE + ciphertext.len(),
                );
                output.extend_from_slice(&eph_len_bytes);
                output.extend_from_slice(&eph_pub_blob);
                output.extend_from_slice(&nonce);
                output.extend_from_slice(&tag);
                output.extend_from_slice(&ciphertext);

                Ok(output)
            }
        }

        /// ECIES decrypt: read ephemeral public key from ciphertext, perform
        /// ECDH with the TPM private key, derive AES-256 key, decrypt.
        pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
            if data.len() < 4 {
                return Err("ciphertext too short".to_string());
            }

            let eph_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
            let min_len = 4 + eph_len + GCM_NONCE_SIZE + GCM_TAG_SIZE;
            if data.len() < min_len {
                return Err(format!(
                    "ciphertext too short: need at least {min_len}, got {}",
                    data.len()
                ));
            }

            let eph_pub_blob = &data[4..4 + eph_len];
            let nonce_start = 4 + eph_len;
            let nonce = &data[nonce_start..nonce_start + GCM_NONCE_SIZE];
            let tag_start = nonce_start + GCM_NONCE_SIZE;
            let tag = &data[tag_start..tag_start + GCM_TAG_SIZE];
            let ciphertext = &data[tag_start + GCM_TAG_SIZE..];

            unsafe {
                // 1. Import ephemeral public key into BCrypt
                let ecdh_alg_name = to_wide(BCRYPT_ECDH_P256_ALGORITHM);
                let eccpub_blob_type = to_wide("ECCPUBLICBLOB");
                let mut ecdh_alg: BCRYPT_ALG_HANDLE = 0;
                check_status(
                    BCryptOpenAlgorithmProvider(
                        &mut ecdh_alg,
                        ecdh_alg_name.as_ptr(),
                        ptr::null(),
                        0,
                    ),
                    "BCryptOpenAlgorithmProvider(ECDH) decrypt",
                )?;

                let mut eph_pub_key: BCRYPT_KEY_HANDLE = 0;
                check_status(
                    BCryptImportKeyPair(
                        ecdh_alg,
                        0,
                        eccpub_blob_type.as_ptr(),
                        &mut eph_pub_key,
                        eph_pub_blob.as_ptr(),
                        eph_pub_blob.len() as u32,
                        0,
                    ),
                    "BCryptImportKeyPair(ephemeral pub)",
                )?;

                // 2. ECDH: TPM private key + ephemeral public key
                //    NCryptSecretAgreement works with NCrypt key handles
                let mut secret: BCRYPT_SECRET_HANDLE = 0;
                // Use NCryptSecretAgreement for the TPM-backed private key
                extern "system" {
                    fn NCryptSecretAgreement(
                        h_priv_key: usize,
                        h_pub_key: usize,
                        ph_agreed_secret: *mut usize,
                        dw_flags: u32,
                    ) -> NTSTATUS;

                    fn NCryptDeriveKey(
                        h_shared_secret: usize,
                        psz_kdf: *const u16,
                        p_parameter_list: *const u8,
                        pb_derived_key: *mut u8,
                        cb_derived_key: u32,
                        pcb_result: *mut u32,
                        dw_flags: u32,
                    ) -> NTSTATUS;
                }

                check_status(
                    NCryptSecretAgreement(self.key, eph_pub_key, &mut secret, 0),
                    "NCryptSecretAgreement",
                )?;

                // 3. Derive 32-byte key using SHA-256 KDF
                let kdf_name = to_wide("HASH");
                let mut derived_key = vec![0u8; 32];
                let mut derived_len: u32 = 0;
                check_status(
                    NCryptDeriveKey(
                        secret,
                        kdf_name.as_ptr(),
                        ptr::null(),
                        derived_key.as_mut_ptr(),
                        32,
                        &mut derived_len,
                        0,
                    ),
                    "NCryptDeriveKey",
                )?;
                derived_key.truncate(derived_len as usize);

                NCryptFreeObject(secret);
                BCryptDestroyKey(eph_pub_key);
                BCryptCloseAlgorithmProvider(ecdh_alg, 0);

                // 4. AES-256-GCM decrypt
                let aes_alg_name = to_wide(BCRYPT_AES_ALGORITHM);
                let mut aes_alg: BCRYPT_ALG_HANDLE = 0;
                check_status(
                    BCryptOpenAlgorithmProvider(
                        &mut aes_alg,
                        aes_alg_name.as_ptr(),
                        ptr::null(),
                        0,
                    ),
                    "BCryptOpenAlgorithmProvider(AES) decrypt",
                )?;

                let chain_mode = to_wide("ChainingMode");
                let gcm_mode = to_wide(BCRYPT_CHAIN_MODE_GCM);
                check_status(
                    BCryptSetProperty(
                        aes_alg,
                        chain_mode.as_ptr(),
                        gcm_mode.as_ptr() as *const u8,
                        (gcm_mode.len() * 2) as u32,
                        0,
                    ),
                    "BCryptSetProperty(GCM) decrypt",
                )?;

                let mut aes_key: BCRYPT_KEY_HANDLE = 0;
                check_status(
                    BCryptGenerateSymmetricKey(
                        aes_alg,
                        &mut aes_key,
                        ptr::null_mut(),
                        0,
                        derived_key.as_ptr(),
                        derived_key.len() as u32,
                        0,
                    ),
                    "BCryptGenerateSymmetricKey decrypt",
                )?;

                let mut nonce_copy = [0u8; GCM_NONCE_SIZE];
                nonce_copy.copy_from_slice(nonce);
                let mut tag_copy = [0u8; GCM_TAG_SIZE];
                tag_copy.copy_from_slice(tag);

                let mut auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                    cb_size: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                    dw_info_version: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
                    pb_nonce: nonce_copy.as_mut_ptr(),
                    cb_nonce: GCM_NONCE_SIZE as u32,
                    pb_auth_data: ptr::null_mut(),
                    cb_auth_data: 0,
                    pb_tag: tag_copy.as_mut_ptr(),
                    cb_tag: GCM_TAG_SIZE as u32,
                    pb_mac_context: ptr::null_mut(),
                    cb_mac_context: 0,
                    cb_aad: 0,
                    cb_data: 0,
                    dw_flags: 0,
                };

                let mut plaintext = vec![0u8; ciphertext.len()];
                let mut pt_len: u32 = 0;
                check_status(
                    BCryptDecrypt(
                        aes_key,
                        ciphertext.as_ptr(),
                        ciphertext.len() as u32,
                        &auth_info,
                        ptr::null_mut(),
                        0,
                        plaintext.as_mut_ptr(),
                        plaintext.len() as u32,
                        &mut pt_len,
                        0,
                    ),
                    "BCryptDecrypt(AES-GCM)",
                )?;
                plaintext.truncate(pt_len as usize);

                BCryptDestroyKey(aes_key);
                BCryptCloseAlgorithmProvider(aes_alg, 0);

                Ok(plaintext)
            }
        }
    }

    impl Drop for TpmStorage {
        fn drop(&mut self) {
            unsafe {
                if self.key != 0 {
                    NCryptFreeObject(self.key);
                }
                if self.provider != 0 {
                    NCryptFreeObject(self.provider);
                }
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {
    pub struct TpmStorage {
        _biometric: bool,
    }

    impl TpmStorage {
        #[allow(clippy::unnecessary_wraps)]
        pub fn new(biometric: bool) -> Result<Self, String> {
            Ok(Self {
                _biometric: biometric,
            })
        }

        #[allow(clippy::unused_self)]
        pub fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>, String> {
            Err("TPM bridge is only supported on Windows".to_string())
        }

        #[allow(clippy::unused_self)]
        pub fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>, String> {
            Err("TPM bridge is only supported on Windows".to_string())
        }
    }
}

pub use platform::TpmStorage;
