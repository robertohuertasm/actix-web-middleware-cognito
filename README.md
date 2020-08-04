# actix-web-middleware-cognito

[![ActionsStatus](https://github.com/robertohuertasm/actix-web-middleware-cognito/workflows/Build/badge.svg)](https://github.com/robertohuertasm/actix-web-middleware-cognito/actions) [![Crates.io](https://img.shields.io/crates/v/actix-web-middleware-cognito.svg)](https://crates.io/crates/actix-web-middleware-cognito) [![API](https://docs.rs/actix-web-middleware-cognito/badge.svg)](https://docs.rs/actix-web-middleware-cognito)

Middleware for [actix-web](https://github.com/actix/actix-web) that helps you validate Cognito tokens.

## Cognito validator

Before setting up the middleware we have to create a `CognitoValidator` that will be built by receiving some variables from the environment:

- **COGNITO_REGION**: The region of the Cognito pool.
- **COGNITO_POOLID**: The Cognito pool id.
- **COGNITO_CLIENTID**: The client id of your app.
- **COGNITO_ENABLED** (optional): if not present or 0 no validation will be done.
- **COGNITO_VERIFY_ACCESSTOKEN** (optional): if not present or 0 idToken will be validated. If present, the accessToken will be validated instead.

## Usage

Setting up the middleware:

```rust
// builidng the validator in order to be shared between all threads.
let cognito_validator =
    Arc::new(CognitoValidator::create().expect("Cognito configuration error"));

HttpServer::new(move || {
    // cognito middleware
    let cognito = Cognito::new(cognito_validator.clone());

    // set up the app
    App::new()
        .wrap(cognito)
        .route("/", web::get().to(index))
})
.bind(format!("0.0.0.0:{}", PORT))
.unwrap_or_else(|_| panic!("🔥 Couldn't start the server at port {}", PORT))
.run()
.await
```

## Extracting the token from the request

The library provides a `CognitoInfo` extractor for you to get information about the Cognito token. If the token is invalid or you disable the middleware (by omitting the `COGNITO_ENABLED` environment variable) you will always get a disabled `CognitoInfo`, i.e. a `CognitoInfo` with no `token`.

```rust
async fn index(auth: CognitoInfo) -> impl Responder {
    let msg = format!(
        "User with id {} made this call with token {}",
        auth.user.unwrap(),
        auth.token.unwrap()
    );
    HttpResponse::Ok().body(msg)
}
```

## Example

You can check the `example` in the repo or run it: `cargo run --example main`.
