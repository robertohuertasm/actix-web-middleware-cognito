use actix_web_httpauth::extractors::bearer::BearerAuth;
use jsonwebtokens as jwt;
use jsonwebtokens_cognito::{Error as CognitoError, KeySet};
use std::env;

/// Helper to validate the Cognito token.
/// It relies on environment variables and will check the token against Amazon servers.
pub struct CognitoValidator {
    keyset: Option<KeySet>,
    verifier: Option<jwt::Verifier>,
    pub disabled: bool,
}

impl CognitoValidator {
    /// Creates a CognitoValidator instance.
    /// It can fail when building the token verifiers.
    /// It will try to fetch information from the environment.
    /// This are the needed variables:
    ///
    /// - **COGNITO_REGION**: The region of the Cognito pool.
    /// - **COGNITO_POOLID**: The Cognito pool id.
    /// - **COGNITO_CLIENTID**: The client id of your app.
    /// - **COGNITO_ENABLED** (optional): if not present no validation will be done.
    ///
    pub fn create() -> Result<Self, CognitoError> {
        log::debug!("🔐 Cognito Validator created");
        let region = env::var("COGNITO_REGION").unwrap_or_else(|_| "".to_string());
        let pool_id = env::var("COGNITO_POOLID").unwrap_or_else(|_| "".to_string());
        let client_id = env::var("COGNITO_CLIENTID").unwrap_or_else(|_| "".to_string());
        let disabled = env::var("COGNITO_ENABLED").is_err();

        if disabled {
            Ok(Self {
                keyset: None,
                verifier: None,
                disabled,
            })
        } else {
            let keyset = KeySet::new(region, pool_id)?;
            let verifier = keyset.new_id_token_verifier(&[&client_id]).build()?;
            Ok(Self {
                keyset: Some(keyset),
                verifier: Some(verifier),
                disabled,
            })
        }
    }

    /// Validates the token.
    /// Note that if the validation is disabled it will always return true.
    pub async fn validate(&self, credentials: BearerAuth) -> bool {
        if self.disabled {
            return true;
        }

        if let (Some(keyset), Some(verifier)) = (self.keyset.as_ref(), self.verifier.as_ref()) {
            keyset.verify(credentials.token(), verifier).await.is_ok()
        } else {
            false
        }
    }
}
