use askama::Template;
use serde::Serialize;

#[derive(Template, Serialize)]
#[template(path = "control.html")]
pub struct ControlPageTemplate {
    pub message: Option<String>,
    pub enabled: bool,
    pub suspended: bool,
    pub limit: String,
}