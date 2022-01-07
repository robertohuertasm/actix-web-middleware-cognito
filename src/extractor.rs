use actix_web::{dev::Payload, Error, FromRequest, HttpMessage, HttpRequest};
use futures::future::{err, ok, Ready};
use jsonwebtokens as jwt;

/// This extractor will only work if you have enabled the Cognito middleware.
/// It will provide information about the token and the user id
#[derive(Debug, Clone)]
pub struct CognitoInfo {
    /// The sub claim
    pub user: Option<String>,
    /// The Cognito JWT
    pub token: Option<String>,
}

impl CognitoInfo {
    /// Creates a CognitoInfo with no information about the token or the user.
    pub fn disabled() -> Self {
        Self {
            user: None,
            token: None,
        }
    }

    /// Creates a CognitoInfo with information regarding the token and the user.
    pub fn enabled(token: String) -> Self {
        Self {
            user: CognitoInfo::get_claim("sub", &token),
            token: Some(token),
        }
    }

    /// Extracts a claim from the token.
    pub fn claim(&self, claim: &str) -> Option<String> {
        let token = self.token.as_ref()?;
        Self::get_claim(claim, token)
    }

    /// Extracts any claim from a token.
    pub fn get_claim(claim: &str, token: &str) -> Option<String> {
        jwt::raw::decode_only(token)
            .ok()?
            .claims
            .get(claim)?
            .as_str()
            .map(|x| x.to_string())
    }
}

/// Extractor from the HttpRequest
impl FromRequest for CognitoInfo {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        if let Some(info) = req.extensions().get::<Self>() {
            ok(info.to_owned())
        } else {
            err(actix_web::error::ErrorBadRequest("No Cognito info found"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;

    #[test]
    async fn extractor_works() {
        let req = test::TestRequest::default()
            .insert_header(("authorization", "Bearer token"))
            .to_http_request();
        let info = CognitoInfo::enabled("token".to_string());
        req.extensions_mut().insert(info);

        let result = CognitoInfo::from_request(&req, &mut Payload::None).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().token, Some("token".to_string()));
    }
}
