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
    /// - **COGNITO_ENABLED** (optional): if not present or 0 no validation will be done.
    /// - **COGNITO_VERIFY_ACCESSTOKEN** (optional): if not present or 0 idToken will be validated. If present, the accessToken will be validated instead.
    ///
    pub fn create() -> Result<Self, CognitoError> {
        Self::create_with_extractor(EnvironmentExtractor {})
    }

    /// Creates a CognitoValidator instance.
    /// It can fail when building the token verifiers.
    /// It accepts a custom extractor to get the values needed in order to be configured.
    /// If you want to get them from the environment, use the [create] method.
    pub fn create_with_extractor(extractor: impl ValueExtractor) -> Result<Self, CognitoError> {
        let region = extractor
            .var("COGNITO_REGION")
            .unwrap_or_else(|_| "".to_string());
        let pool_id = extractor
            .var("COGNITO_POOLID")
            .unwrap_or_else(|_| "".to_string());
        let client_id = extractor
            .var("COGNITO_CLIENTID")
            .unwrap_or_else(|_| "".to_string());
        let enabled = extractor.var("COGNITO_ENABLED").map_or(false, |x| x != "0");
        let verify_access_token = extractor
            .var("COGNITO_VERIFY_ACCESSTOKEN")
            .map_or(false, |x| x != "0");

        if enabled {
            let keyset = KeySet::new(region, pool_id)?;
            let verifier = if verify_access_token {
                keyset.new_access_token_verifier(&[&client_id]).build()?
            } else {
                keyset.new_id_token_verifier(&[&client_id]).build()?
            };

            log::debug!("🔐 Cognito Validator created and enabled");
            Ok(Self {
                keyset: Some(keyset),
                verifier: Some(verifier),
                disabled: false,
            })
        } else {
            log::debug!("🔐 Cognito Validator created and disabled");
            Ok(Self {
                keyset: None,
                verifier: None,
                disabled: true,
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

/// Extracts a value by key
pub trait ValueExtractor {
    fn var(&self, var: &'static str) -> Result<String, env::VarError>;
}

/// This extractor gets values from the environment.
/// It uses std::env::var under the hood.
pub struct EnvironmentExtractor {}
impl ValueExtractor for EnvironmentExtractor {
    fn var(&self, key: &'static str) -> Result<String, env::VarError> {
        env::var(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, FromRequest};

    #[derive(Default)]
    struct MockEnabledExtractor {}
    impl ValueExtractor for MockEnabledExtractor {
        fn var(&self, key: &'static str) -> Result<String, env::VarError> {
            if key == "COGNITO_ENABLED" {
                Ok("1".to_owned())
            } else {
                Err(env::VarError::NotPresent)
            }
        }
    }

    #[test]
    fn validator_create_will_not_break_if_no_env_vars_found() {
        let validator = CognitoValidator::create();
        assert!(validator.is_ok());
        assert!(validator.unwrap().disabled);
    }

    #[test]
    fn validator_create_with_no_env_vars_is_disabled() {
        let validator = CognitoValidator::create();
        assert!(validator.unwrap().disabled);
    }

    #[test]
    fn validator_is_enabled_when_var_is_enabled() {
        let validator =
            CognitoValidator::create_with_extractor(MockEnabledExtractor::default()).unwrap();
        assert!(!validator.disabled);
    }

    #[actix_rt::test]
    async fn validate_returns_false_if_token_is_wrong() {
        let req = test::TestRequest::with_header("authorization", "Bearer token").to_http_request();

        let auth = BearerAuth::from_request(&req, &mut actix_web::dev::Payload::None)
            .await
            .unwrap();

        let validator =
            CognitoValidator::create_with_extractor(MockEnabledExtractor::default()).unwrap();

        let result = validator.validate(auth).await;

        assert!(!result);
    }

    #[actix_rt::test]
    async fn validate_returns_true_if_disabled() {
        let req = test::TestRequest::with_header("authorization", "Bearer token").to_http_request();

        let auth = BearerAuth::from_request(&req, &mut actix_web::dev::Payload::None)
            .await
            .unwrap();

        let validator = CognitoValidator {
            keyset: None,
            verifier: None,
            disabled: true,
        };

        let result = validator.validate(auth).await;

        assert!(result);
    }

    #[actix_rt::test]
    async fn validate_returns_false_if_enabled_and_no_keyset_verifier() {
        let req = test::TestRequest::with_header("authorization", "Bearer token").to_http_request();

        let auth = BearerAuth::from_request(&req, &mut actix_web::dev::Payload::None)
            .await
            .unwrap();

        let validator = CognitoValidator {
            keyset: None,
            verifier: None,
            disabled: false,
        };

        let result = validator.validate(auth).await;

        assert!(!result);
    }
}
