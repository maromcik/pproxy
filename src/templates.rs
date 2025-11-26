use askama::Template;
use serde::Serialize;

#[derive(Template, Serialize)]
#[template(path = "control.html")]
pub struct ControlPageTemplate {
    pub message: Option<String>,
    pub enabled: bool,
    pub suspended: bool,
    pub waking_up: bool,
    pub limit: String,
    pub elapsed: String,
    pub active_time: String,
    pub suspended_time: String
}

#[derive(Template, Serialize)]
#[template(path = "public.html")]
pub struct PublicPageTemplate {
    pub message: Option<String>,
    pub enabled: bool,
    pub suspended: bool,
    pub waking_up: bool,
}
