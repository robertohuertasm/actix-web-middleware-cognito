use actix_service::{Service, Transform};
use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    Error, HttpMessage,
};
use actix_web_httpauth::{extractors::bearer::BearerAuth, extractors::AuthExtractor};
use future::{ok, LocalBoxFuture, Ready};
use futures::prelude::*;

use crate::{extractor::CognitoInfo, validator::CognitoValidator};
use std::{
    cell::RefCell,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};

/// Middleware to use in your Actix-web services
pub struct Cognito {
    pub validator: Arc<CognitoValidator>,
}

impl Cognito {
    /// Creates a new Cognito middleware
    pub fn new(validator: Arc<CognitoValidator>) -> Self {
        Self { validator }
    }
}

impl<S, B> Transform<S, ServiceRequest> for Cognito
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = CognitoMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(CognitoMiddleware {
            service: Rc::new(RefCell::new(service)),
            validator: self.validator.clone(),
        })
    }
}

pub struct CognitoMiddleware<S> {
    pub service: Rc<RefCell<S>>,
    pub validator: Arc<CognitoValidator>,
}

impl<S, B> Service<ServiceRequest> for CognitoMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = S::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.borrow_mut().poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if self.validator.disabled {
            log::info!("🔓 Cognito validation is disabled");
            req.extensions_mut().insert(CognitoInfo::disabled());
            self.service.call(req).boxed_local()
        } else {
            log::debug!("🔒 Cognito validation is enabled");
            let service = Rc::clone(&self.service);
            let validator = self.validator.clone();
            async move {
                let credentials = BearerAuth::from_service_request(&req).await.map_err(|_| {
                    log::warn!("👎 No Cognito token present");
                    actix_web::error::ErrorUnauthorized("❌ No Token")
                })?;
                let token = credentials.token().to_string();
                let is_valid_token = validator.validate(credentials).await;
                if is_valid_token {
                    log::debug!("👍 Valid Cognito token");
                    req.extensions_mut().insert(CognitoInfo::enabled(token));
                    service.borrow_mut().call(req).await
                } else {
                    log::warn!("👎 Invalid Cognito token");
                    Err(actix_web::error::ErrorUnauthorized("❌ Invalid Token"))
                }
            }
            .boxed_local()
        }
    }
}
