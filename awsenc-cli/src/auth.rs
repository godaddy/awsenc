use std::io::{IsTerminal, Read};
use std::time::Duration;

use chrono::Utc;
use zeroize::Zeroizing;

use awsenc_core::cache::{
    self, CacheFile, CacheHeader, FLAG_HAS_OKTA_SESSION, FORMAT_VERSION, MAGIC,
};
use awsenc_core::config::{self, ConfigOverrides};
use awsenc_core::mfa::{self, MfaFactor};
use awsenc_core::okta::{AuthnResponse, OktaClient, OktaSession};
use awsenc_core::sts::{self, StsClient};
use awsenc_secure_storage::SecureStorage;

use crate::cli::AuthArgs;
use crate::usage;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Run the interactive authentication flow.
pub async fn run_auth(profile: &str, args: &AuthArgs, storage: &dyn SecureStorage) -> Result<()> {
    let global = config::load_global_config()?;
    let Ok(profile_config) = config::load_profile_config(profile) else {
        return Err(format!(
            "profile '{profile}' not found; run 'awsenc install --profile {profile}' first"
        )
        .into());
    };

    let overrides = build_overrides(args);
    let resolved = config::resolve_config(profile, &global, &profile_config, &overrides)?;
    let password = read_password(args, &resolved.okta_user)?;

    eprintln!("Authenticating as {} ...", resolved.okta_user);
    let okta = OktaClient::new(&resolved.okta_organization)?;
    let authn_result = okta.authenticate(&resolved.okta_user, &password).await?;

    let session_token = match authn_result {
        AuthnResponse::Success { session_token } => session_token,
        AuthnResponse::MfaRequired {
            state_token,
            factors,
        } => handle_mfa(&okta, &state_token, &factors, &resolved.okta_factor).await?,
        AuthnResponse::MfaChallenge { .. } => {
            return Err("unexpected MFA challenge state from primary auth".into());
        }
    };

    let creds = obtain_credentials(&okta, &session_token, &resolved).await?;

    encrypt_and_cache(profile, storage, &creds, &session_token)?;
    usage::record_usage(profile);

    let remaining = creds
        .expiration
        .signed_duration_since(Utc::now())
        .num_minutes();
    eprintln!("Authenticated profile '{profile}' (expires in {remaining}m)");

    Ok(())
}

fn build_overrides(args: &AuthArgs) -> ConfigOverrides {
    let env_overrides = ConfigOverrides::from_env();
    ConfigOverrides {
        user: args.user.clone().or(env_overrides.user),
        organization: args.organization.clone().or(env_overrides.organization),
        application: args.application.clone().or(env_overrides.application),
        role: args.role.clone().or(env_overrides.role),
        factor: args.factor.clone().or(env_overrides.factor),
        duration: args.duration.or(env_overrides.duration),
        biometric: if args.biometric {
            Some(true)
        } else {
            env_overrides.biometric
        },
        region: env_overrides.region,
    }
}

fn read_password(args: &AuthArgs, okta_user: &str) -> Result<Zeroizing<String>> {
    if args.pass_stdin {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        return Ok(Zeroizing::new(buf.trim_end().to_owned()));
    }

    if !std::io::stdin().is_terminal() {
        return Err("cannot prompt for password: stdin is not a TTY (use --pass-stdin)".into());
    }
    let p = rpassword::prompt_password(format!("Okta password for {okta_user}: "))?;
    Ok(Zeroizing::new(p))
}

async fn obtain_credentials(
    okta: &OktaClient,
    session_token: &Zeroizing<String>,
    resolved: &config::ResolvedConfig,
) -> Result<awsenc_core::credential::AwsCredentials> {
    eprintln!("Getting SAML assertion...");
    let saml_assertion = okta
        .get_saml_assertion(session_token, &resolved.okta_application)
        .await?;

    let roles = sts::parse_saml_roles(&saml_assertion)?;
    let matching_role = roles
        .iter()
        .find(|r| r.role_arn == resolved.okta_role)
        .ok_or_else(|| {
            let available: Vec<_> = roles.iter().map(|r| r.role_arn.as_str()).collect();
            format!(
                "role '{}' not found in SAML assertion; available roles: {}",
                resolved.okta_role,
                available.join(", ")
            )
        })?;

    eprintln!("Assuming role {}...", matching_role.role_arn);
    let sts_client = StsClient::new();
    let creds = sts_client
        .assume_role_with_saml(
            &matching_role.role_arn,
            &matching_role.principal_arn,
            &saml_assertion,
            resolved.okta_duration,
        )
        .await?;

    Ok(creds)
}

#[allow(clippy::cast_sign_loss)]
fn encrypt_and_cache(
    profile: &str,
    storage: &dyn SecureStorage,
    creds: &awsenc_core::credential::AwsCredentials,
    session_token: &Zeroizing<String>,
) -> Result<()> {
    let creds_json = serde_json::to_vec(creds)?;
    let aws_ciphertext = storage.encrypt(&creds_json)?;

    let okta_session = OktaSession {
        session_id: session_token.as_str().to_owned(),
        expiration: Utc::now() + chrono::Duration::hours(2),
    };
    let okta_json = serde_json::to_vec(&okta_session)?;
    let okta_ciphertext = storage.encrypt(&okta_json)?;

    let cache_file = CacheFile {
        header: CacheHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: FLAG_HAS_OKTA_SESSION,
            credential_expiration: creds.expiration.timestamp() as u64,
            okta_session_expiration: okta_session.expiration.timestamp() as u64,
        },
        aws_ciphertext,
        okta_session_ciphertext: Some(okta_ciphertext),
    };

    cache::write_cache(profile, &cache_file)?;
    Ok(())
}

/// Handle MFA challenges interactively.
async fn handle_mfa(
    okta: &OktaClient,
    state_token: &Zeroizing<String>,
    factors: &[awsenc_core::mfa::MfaChallenge],
    preferred_factor: &str,
) -> Result<Zeroizing<String>> {
    let preferred = preferred_factor.parse::<MfaFactor>().ok();
    let factor = mfa::select_factor(factors, preferred.as_ref())?;

    eprintln!(
        "MFA required: using {} ({})",
        factor.factor_type, factor.provider
    );

    let result = if mfa::factor_matches(factor, &MfaFactor::Push) {
        eprintln!("Waiting for push approval...");
        okta.poll_push(&factor.factor_id, state_token, Duration::from_secs(60))
            .await?
    } else if mfa::factor_matches(factor, &MfaFactor::Totp) {
        let code = rpassword::prompt_password("Enter TOTP code: ")?;
        okta.verify_totp(&factor.factor_id, state_token, code.trim())
            .await?
    } else if mfa::factor_matches(factor, &MfaFactor::YubikeyOtp) {
        let otp = rpassword::prompt_password("Touch YubiKey: ")?;
        okta.verify_yubikey(&factor.factor_id, state_token, otp.trim())
            .await?
    } else {
        return Err(format!("unsupported factor type: {}", factor.factor_type).into());
    };

    match result {
        AuthnResponse::Success { session_token } => Ok(session_token),
        AuthnResponse::MfaChallenge { factor_result, .. } => {
            Err(format!("MFA verification failed: {factor_result}").into())
        }
        AuthnResponse::MfaRequired { .. } => Err("unexpected additional MFA required".into()),
    }
}
