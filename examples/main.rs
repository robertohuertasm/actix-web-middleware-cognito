use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpResponse, HttpServer, Responder};
use actix_web_middleware_cognito::{Cognito, CognitoInfo, CognitoValidator};
use std::sync::Arc;

async fn index(auth: CognitoInfo) -> impl Responder {
    let msg = format!(
        "User with id {} made this call with token {}",
        auth.user.unwrap(),
        auth.token.unwrap()
    );
    HttpResponse::Ok().body(msg)
}

const PORT: &str = "3000";

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    dotenv::from_filename("examples/.env").ok();
    env_logger::init();

    // We instantiate the validator here and not in the HttpServer closure
    // to avoid having multiple instances.
    // The validator will be built by using some environment variables.
    // Read the docs for more information.
    let cognito_validator =
        Arc::new(CognitoValidator::create().expect("Cognito configuration not found"));

    HttpServer::new(move || {
        // cognito middleware
        let cognito = Cognito::new(cognito_validator.clone());

        // cors middleware
        let cors = Cors::new().allowed_methods(vec!["GET"]).finish();

        // set up the app
        App::new()
            .wrap(cors)
            .wrap(Logger::default())
            .wrap(cognito)
            .route("/", web::get().to(index))
    })
    .bind(format!("0.0.0.0:{}", PORT))
    .unwrap_or_else(|_| panic!("🔥 Couldn't start the server at port {}", PORT))
    .run()
    .await
}
