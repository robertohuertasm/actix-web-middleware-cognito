//! Middleware for [actix-web](https://github.com/actix/actix-web) that helps you validate Cognito tokens.
//!
//! ## Cognito validator
//!
//! Before setting up the middleware we have to create a `CognitoValidator` that will be built by receiving some vari ables from the environment:
//!
//! - **COGNITO_REGION**: The region of the Cognito pool.
//! - **COGNITO_POOLID**: The Cognito pool id.
//! - **COGNITO_CLIENTID**: The client id of your app.
//! - **COGNITO_ENABLED** (optional): if not present no validation will be done.
//!
//! ## Usage
//!
//! Setting up the middleware:
//!
//! ```rust,no_run
//! # use actix_web::{web, App, HttpServer};
//! # use actix_web_middleware_cognito::{Cognito, CognitoValidator};
//! # use std::sync::Arc;
//! # const PORT: &str = "3000";
//! # async fn index() -> &'static str {
//! #   "Hello world"
//! # }
//! # #[actix_rt::main]
//! # async fn main() -> std::io::Result<()> {
//! // builidng the validator in order to be shared between all threads.
//! let cognito_validator =
//!     Arc::new(CognitoValidator::create().expect("Cognito configuration not found"));
//!
//! HttpServer::new(move || {
//!     // cognito middleware
//!     let cognito = Cognito::new(cognito_validator.clone());
//!
//!     // set up the app
//!     App::new()
//!         .wrap(cognito)
//!         .route("/", web::get().to(index))
//! })
//! .bind(format!("0.0.0.0:{}", PORT))
//! .unwrap_or_else(|_| panic!("🔥 Couldn't start the server at port {}", PORT))
//! .run()
//! .await
//! # }
//! ```
//!
//! ## Extracting the token from the request
//!
//! The library provides a `CognitoInfo` extractor for you to get information about the Cognito token. If the token is invalid or you disable the middleware (by omitting the `COGNITO_ENABLED` environment variable) you will always get a disabled `CognitoInfo`, i.e. a `CognitoInfo` with no `token`.
//!
//! ```rust,no_run
//! # use actix_web::{Responder, HttpResponse};
//! # use actix_web_middleware_cognito::CognitoInfo;
//! async fn index(auth: CognitoInfo) -> impl Responder {
//!     let msg = format!(
//!         "User with id {} made this call with token {}",
//!         auth.user.unwrap(),
//!         auth.token.unwrap()
//!     );
//!     HttpResponse::Ok().body(msg)
//! }
//! ```

mod extractor;
mod middleware;
mod validator;

pub use extractor::CognitoInfo;
pub use middleware::Cognito;
pub use validator::CognitoValidator;
