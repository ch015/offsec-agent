use actix_web::{get, post, web, App, HttpServer, HttpResponse};
use serde::Deserialize;

mod db;

#[derive(Deserialize)]
struct UserInput {
    name: String,
    email: String,
}

#[get("/api/users/{id}")]
async fn get_user(path: web::Path<String>) -> HttpResponse {
    let id = path.into_inner();
    let user = db::find_user(&id).await;
    HttpResponse::Ok().json(user)
}

#[post("/api/users")]
async fn create_user(body: web::Json<UserInput>) -> HttpResponse {
    let result = db::insert_user(&body.name, &body.email).await;
    HttpResponse::Created().json(result)
}

fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(get_user).service(create_user);
}
